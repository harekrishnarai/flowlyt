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

package vulndb

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// VulnerabilityDatabase provides access to vulnerability information
type VulnerabilityDatabase struct {
	client *http.Client
}

// NewVulnerabilityDatabase creates a new vulnerability database client
func NewVulnerabilityDatabase() *VulnerabilityDatabase {
	return &VulnerabilityDatabase{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ActionVulnerability represents a vulnerability in a GitHub Action
type ActionVulnerability struct {
	ID          string   `json:"id"`
	Action      string   `json:"action"`
	Affected    []string `json:"affected"`
	Summary     string   `json:"summary"`
	Severity    string   `json:"severity"`
	CVEID       string   `json:"cve_id,omitempty"`
	References  []string `json:"references,omitempty"`
	PublishedAt string   `json:"published_at"`
}

// OSVResponse represents the response from OSV.dev API
type OSVResponse struct {
	Vulns []OSVVulnerability `json:"vulns"`
}

// OSVVulnerability represents a vulnerability from OSV.dev
type OSVVulnerability struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced,omitempty"`
				Fixed      string `json:"fixed,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific interface{} `json:"database_specific"`
}

// KnownVulnerableActions contains a hardcoded list of known vulnerable actions
// This is based on Poutine's vulnerability database
var KnownVulnerableActions = map[string][]ActionVulnerability{
	"actions/checkout": {
		{
			ID:       "CHECKOUT-001",
			Action:   "actions/checkout",
			Affected: []string{"v1", "v2.0.0", "v2.1.0"},
			Summary:  "actions/checkout vulnerable to command injection via branch names",
			Severity: "HIGH",
			References: []string{
				"https://github.com/actions/checkout/security/advisories/GHSA-mw99-9chc-xw7r",
			},
			PublishedAt: "2020-12-15T00:00:00Z",
		},
	},
	"actions/cache": {
		{
			ID:       "CACHE-001",
			Action:   "actions/cache",
			Affected: []string{"v1", "v2.0.0", "v2.0.1"},
			Summary:  "Cache action vulnerable to cache poisoning in public repositories",
			Severity: "MEDIUM",
			References: []string{
				"https://github.com/actions/cache/issues/319",
			},
			PublishedAt: "2020-10-02T00:00:00Z",
		},
	},
}

// UnpinnableActions contains actions that cannot be pinned to specific versions
// Based on Poutine's unpinnable_actions.txt
var UnpinnableActions = []string{
	"0daryo/labelcommit",
	"0h-n0/flet-action-windows",
	"0x61nas/aur-release-action",
	"1024pix/pix-actions/auto-merge",
	"1024pix/pix-actions/release",
	"104corp/docker-php-testing",
	"10up/action-wordpress-plugin-build-zip",
	"10up/action-wordpress-plugin-deploy",
	"10up/wpcs-action",
	// ... (truncated for brevity, full list available in Poutine's file)
}

// TrustedPublishers contains a list of trusted action publishers
var TrustedPublishers = []string{
	"actions",
	"github",
	"microsoft",
	"azure",
	"docker",
	"aws-actions",
	"google-github-actions",
	"hashicorp",
}

// CheckActionVulnerability checks if an action has known vulnerabilities
func (vdb *VulnerabilityDatabase) CheckActionVulnerability(actionName, version string) []ActionVulnerability {
	var vulnerabilities []ActionVulnerability

	// Extract action name without version
	actionParts := strings.Split(actionName, "@")
	if len(actionParts) == 0 {
		return vulnerabilities
	}

	baseAction := actionParts[0]

	// Check against known vulnerable actions
	if vulns, exists := KnownVulnerableActions[baseAction]; exists {
		for _, vuln := range vulns {
			// If no version specified, report all vulnerabilities
			if version == "" {
				vulnerabilities = append(vulnerabilities, vuln)
				continue
			}

			// Check if the version is affected
			for _, affectedVersion := range vuln.Affected {
				if version == affectedVersion || affectedVersion == "*" {
					vulnerabilities = append(vulnerabilities, vuln)
					break
				}
			}
		}
	}

	return vulnerabilities
}

// IsActionUnpinnable checks if an action cannot be pinned to a specific version
func (vdb *VulnerabilityDatabase) IsActionUnpinnable(actionName string) bool {
	// Remove "pkg:githubactions/" prefix if present
	cleanName := strings.TrimPrefix(actionName, "pkg:githubactions/")

	for _, unpinnableAction := range UnpinnableActions {
		if cleanName == unpinnableAction {
			return true
		}
	}

	return false
}

// IsTrustedPublisher checks if an action comes from a trusted publisher
func (vdb *VulnerabilityDatabase) IsTrustedPublisher(actionName string) bool {
	actionParts := strings.Split(actionName, "/")
	if len(actionParts) < 2 {
		return false
	}

	publisher := actionParts[0]

	for _, trustedPublisher := range TrustedPublishers {
		if publisher == trustedPublisher {
			return true
		}
	}

	return false
}

// QueryOSVDatabase queries the OSV.dev database for vulnerabilities
func (vdb *VulnerabilityDatabase) QueryOSVDatabase(packageName, version string) ([]OSVVulnerability, error) {
	// OSV.dev API endpoint
	url := "https://api.osv.dev/v1/query"

	query := map[string]interface{}{
		"package": map[string]string{
			"name":      packageName,
			"ecosystem": "GitHub Actions",
		},
	}

	if version != "" {
		query["version"] = version
	}

	queryJSON, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	resp, err := vdb.client.Post(url, "application/json", strings.NewReader(string(queryJSON)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var osvResp OSVResponse
	if err := json.Unmarshal(body, &osvResp); err != nil {
		return nil, err
	}

	return osvResp.Vulns, nil
}

// CheckTyposquatting checks if an action name might be a typosquatting attempt
func (vdb *VulnerabilityDatabase) CheckTyposquatting(actionName string) bool {
	// Common legitimate actions that are often typosquatted
	legitimateActions := []string{
		"actions/checkout",
		"actions/setup-node",
		"actions/setup-python",
		"actions/setup-go",
		"actions/setup-java",
		"actions/cache",
		"actions/upload-artifact",
		"actions/download-artifact",
		"docker/build-push-action",
		"docker/setup-buildx-action",
	}

	actionParts := strings.Split(actionName, "@")
	if len(actionParts) == 0 {
		return false
	}

	baseAction := actionParts[0]

	// Calculate edit distance and check for suspicious similarities
	for _, legitimate := range legitimateActions {
		if editDistance(baseAction, legitimate) <= 2 && baseAction != legitimate {
			return true
		}
	}

	return false
}

// editDistance calculates the Levenshtein distance between two strings
func editDistance(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	matrix := make([][]int, len(a)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(b)+1)
	}

	for i := 0; i <= len(a); i++ {
		matrix[i][0] = i
	}
	for j := 0; j <= len(b); j++ {
		matrix[0][j] = j
	}

	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}

			matrix[i][j] = min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(a)][len(b)]
}

func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
