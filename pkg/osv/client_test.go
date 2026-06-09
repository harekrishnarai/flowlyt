/*
Copyright 2025 Hare Krishna Rai

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/harekrishnarai/flowlyt/v2/pkg/rules"
)

func TestNewClient(t *testing.T) {
	c := NewClient()
	if c == nil {
		t.Fatal("NewClient returned nil")
	}
	if c.baseURL != "https://api.osv.dev" {
		t.Errorf("baseURL = %q, want https://api.osv.dev", c.baseURL)
	}
	if c.httpClient == nil {
		t.Error("httpClient is nil")
	}
	if c.timeout != 30*time.Second {
		t.Errorf("timeout = %v, want 30s", c.timeout)
	}
}

func TestCVSSToSeverity(t *testing.T) {
	c := NewClient()
	tests := []struct {
		score string
		want  string
	}{
		{"CVSS:3.1 CRITICAL", "CRITICAL"},
		{"9.8", "CRITICAL"},
		{"10.0", "CRITICAL"},
		{"HIGH", "HIGH"},
		{"7.5", "HIGH"},
		{"8.1", "HIGH"},
		{"MEDIUM", "MEDIUM"},
		{"5.5", "MEDIUM"},
		{"4.0", "MEDIUM"},
		{"6.9", "MEDIUM"},
		{"2.1", "LOW"},
		{"", "LOW"},
	}
	for _, tt := range tests {
		if got := c.cvssToSeverity(tt.score); got != tt.want {
			t.Errorf("cvssToSeverity(%q) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestExtractActionWithVersion(t *testing.T) {
	c := NewClient()
	evidence := `steps:
  uses: actions/checkout@v4
  uses: actions/setup-go@v5.0.0
  uses: actions/checkout@v4
  uses: some/action@main
  uses: pinned/action@a1b2c3d4e5`

	pkgs := c.extractActionWithVersion(evidence)

	// v4 (deduped), v5.0.0 — but NOT @main (branch) and NOT a SHA without v/dot.
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d: %+v", len(pkgs), pkgs)
	}
	byName := map[string]string{}
	for _, p := range pkgs {
		if p.Ecosystem != "GitHub Actions" {
			t.Errorf("ecosystem = %q, want GitHub Actions", p.Ecosystem)
		}
		byName[p.Name] = p.Purl
	}
	if byName["actions/checkout"] != "v4" {
		t.Errorf("checkout version = %q, want v4", byName["actions/checkout"])
	}
	if byName["actions/setup-go"] != "v5.0.0" {
		t.Errorf("setup-go version = %q, want v5.0.0", byName["actions/setup-go"])
	}
}

func TestExtractPackageInfo(t *testing.T) {
	c := NewClient()
	// No "uses:" present -> no packages.
	if pkgs := c.extractPackageInfo("run: echo hello"); len(pkgs) != 0 {
		t.Errorf("expected 0 packages for non-action evidence, got %d", len(pkgs))
	}
	if pkgs := c.extractPackageInfo("uses: actions/checkout@v4"); len(pkgs) != 1 {
		t.Errorf("expected 1 package, got %d", len(pkgs))
	}
}

func TestExtractCVEIDs(t *testing.T) {
	c := NewClient()
	evidence := "Affected by CVE-2021-44228 and GHSA-jfh8-c2jp-5v3q please patch"
	ids := c.extractCVEIDs(evidence)

	hasCVE, hasGHSA := false, false
	for _, id := range ids {
		if id == "CVE-2021-44228" {
			hasCVE = true
		}
		if id == "GHSA-jfh8-c2jp-5v3q" {
			hasGHSA = true
		}
	}
	if !hasCVE {
		t.Errorf("expected CVE-2021-44228 in %v", ids)
	}
	if !hasGHSA {
		t.Errorf("expected GHSA-jfh8-c2jp-5v3q in %v", ids)
	}

	if ids := c.extractCVEIDs("nothing relevant here"); len(ids) != 0 {
		t.Errorf("expected no IDs, got %v", ids)
	}
}

func TestCalculateBaseRiskScore(t *testing.T) {
	c := NewClient()

	// Critical(40) + MaliciousPattern(20) + evidence "token" (10) = 70
	high := c.calculateBaseRiskScore(rules.Finding{
		Severity: rules.Critical,
		Category: rules.MaliciousPattern,
		Evidence: "leaked token found",
	})
	if high != 70 {
		t.Errorf("base score = %d, want 70", high)
	}

	// Low(10) + unscored category + no sensitive evidence = 10
	low := c.calculateBaseRiskScore(rules.Finding{
		Severity: rules.Low,
		Category: rules.InjectionAttack,
		Evidence: "echo hello",
	})
	if low != 10 {
		t.Errorf("base score = %d, want 10", low)
	}
}

func TestCalculateEnhancedRiskScore(t *testing.T) {
	c := NewClient()

	// Base 70 + CRITICAL(30) + CVE(15) + recent(10) = 125 -> capped at 100.
	capped := c.calculateEnhancedRiskScore(
		rules.Finding{Severity: rules.Critical, Category: rules.MaliciousPattern, Evidence: "token"},
		&VulnerabilityInfo{Severity: "CRITICAL", CVEID: "CVE-2021-1", Published: time.Now()},
	)
	if capped != 100 {
		t.Errorf("enhanced score = %d, want 100 (capped)", capped)
	}

	// Base 10 + LOW(5), no CVE, old publish (no recent bonus) = 15.
	low := c.calculateEnhancedRiskScore(
		rules.Finding{Severity: rules.Low, Category: rules.InjectionAttack},
		&VulnerabilityInfo{Severity: "LOW", Published: time.Now().Add(-3 * 365 * 24 * time.Hour)},
	)
	if low != 15 {
		t.Errorf("enhanced score = %d, want 15", low)
	}
}

func TestDetermineIntelligenceLevel(t *testing.T) {
	c := NewClient()
	tests := []struct {
		name string
		info *VulnerabilityInfo
		want string
	}{
		{"cve+critical", &VulnerabilityInfo{CVEID: "CVE-1", Severity: "CRITICAL"}, "HIGH"},
		{"cve only", &VulnerabilityInfo{CVEID: "CVE-1", Severity: "LOW"}, "MEDIUM"},
		{"high severity", &VulnerabilityInfo{Severity: "HIGH"}, "MEDIUM"},
		{"summary only", &VulnerabilityInfo{Summary: "something"}, "LOW"},
		{"empty", &VulnerabilityInfo{}, "NONE"},
	}
	for _, tt := range tests {
		if got := c.determineIntelligenceLevel(tt.info); got != tt.want {
			t.Errorf("%s: determineIntelligenceLevel = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestIsRelevantVulnerability(t *testing.T) {
	c := NewClient()

	if !c.isRelevantVulnerability(
		Vulnerability{Summary: "contains malicious backdoor"},
		rules.Finding{Category: rules.MaliciousPattern},
	) {
		t.Error("malicious summary should be relevant to MaliciousPattern finding")
	}

	if !c.isRelevantVulnerability(
		Vulnerability{Summary: "leaked token credential"},
		rules.Finding{Category: rules.SecretExposure},
	) {
		t.Error("token summary should be relevant to SecretExposure finding")
	}

	// Unrelated summary, but a HIGH CVSS rating makes it relevant regardless.
	if !c.isRelevantVulnerability(
		Vulnerability{Summary: "unrelated", Severity: []SeverityRating{{Type: "CVSS_V3", Score: "7.5 HIGH"}}},
		rules.Finding{Category: rules.InjectionAttack},
	) {
		t.Error("high-severity vuln should always be relevant")
	}

	if c.isRelevantVulnerability(
		Vulnerability{Summary: "totally unrelated"},
		rules.Finding{Category: rules.InjectionAttack},
	) {
		t.Error("unrelated low-severity vuln should not be relevant")
	}
}

func TestConvertToVulnerabilityInfo(t *testing.T) {
	c := NewClient()
	vuln := Vulnerability{
		Summary:    "test vuln",
		Aliases:    []string{"CVE-2021-1234", "GHSA-aaaa-bbbb-cccc"},
		Severity:   []SeverityRating{{Type: "CVSS_V3", Score: "9.8 CRITICAL"}},
		References: []Reference{{Type: "WEB", URL: "https://example.com/advisory"}},
		Affected:   []AffectedPackage{{Package: Package{Ecosystem: "npm", Name: "lodash"}}},
	}

	info := c.convertToVulnerabilityInfo(vuln)
	if info.CVEID != "CVE-2021-1234" {
		t.Errorf("CVEID = %q", info.CVEID)
	}
	if info.GHSAID != "GHSA-aaaa-bbbb-cccc" {
		t.Errorf("GHSAID = %q", info.GHSAID)
	}
	if info.Severity != "CRITICAL" {
		t.Errorf("Severity = %q, want CRITICAL", info.Severity)
	}
	if info.Ecosystem != "npm" || info.PackageName != "lodash" {
		t.Errorf("package = %s/%s, want npm/lodash", info.Ecosystem, info.PackageName)
	}
	if len(info.References) != 1 || info.References[0] != "https://example.com/advisory" {
		t.Errorf("references = %v", info.References)
	}
}

func TestQueryVulnerability(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/query" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method %q", r.Method)
		}
		_ = json.NewEncoder(w).Encode(QueryResponse{
			Vulns: []Vulnerability{{ID: "GHSA-test", Summary: "test"}},
		})
	}))
	defer srv.Close()

	c := NewClient()
	c.baseURL = srv.URL

	vulns, err := c.QueryVulnerability(context.Background(), "npm", "lodash", "1.0.0")
	if err != nil {
		t.Fatalf("QueryVulnerability error: %v", err)
	}
	if len(vulns) != 1 || vulns[0].ID != "GHSA-test" {
		t.Errorf("vulns = %+v", vulns)
	}
}

func TestQueryVulnerability_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient()
	c.baseURL = srv.URL

	if _, err := c.QueryVulnerability(context.Background(), "npm", "lodash", "1.0.0"); err == nil {
		t.Error("expected error on non-200 status")
	}
}

func TestGetVulnerabilityByID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/vulns/GHSA-found":
			_ = json.NewEncoder(w).Encode(Vulnerability{ID: "GHSA-found", Summary: "x"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := NewClient()
	c.baseURL = srv.URL

	vuln, err := c.GetVulnerabilityByID(context.Background(), "GHSA-found")
	if err != nil {
		t.Fatalf("GetVulnerabilityByID error: %v", err)
	}
	if vuln == nil || vuln.ID != "GHSA-found" {
		t.Errorf("vuln = %+v", vuln)
	}

	// 404 should return (nil, nil), not an error.
	missing, err := c.GetVulnerabilityByID(context.Background(), "GHSA-missing")
	if err != nil {
		t.Fatalf("unexpected error for missing vuln: %v", err)
	}
	if missing != nil {
		t.Errorf("expected nil for missing vuln, got %+v", missing)
	}
}
