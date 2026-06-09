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

package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/harekrishnarai/flowlyt/pkg/platform"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

func TestOwnerFromRemoteURL(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://github.com/owner/repo.git", "owner"},
		{"https://github.com/owner/repo", "owner"},
		{"git@github.com:owner/repo.git", "owner"},
		{"ssh://git@github.com/owner/repo.git", "owner"},
		{"https://gitlab.com/group/project.git", "group"},
		{"", ""},
		{"not-a-url", ""},
	}
	for _, tt := range tests {
		if got := ownerFromRemoteURL(tt.url); got != tt.want {
			t.Errorf("ownerFromRemoteURL(%q) = %q, want %q", tt.url, got, tt.want)
		}
	}
}

func TestDetectRepositoryOwner(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := "[remote \"origin\"]\n\turl = https://github.com/acme/widgets.git\n"
	if err := os.WriteFile(filepath.Join(gitDir, "config"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := detectRepositoryOwner(dir); got != "acme" {
		t.Errorf("detectRepositoryOwner = %q, want acme", got)
	}

	// No .git/config -> empty owner (rather than a wrong guess).
	if got := detectRepositoryOwner(t.TempDir()); got != "" {
		t.Errorf("detectRepositoryOwner with no config = %q, want empty", got)
	}
}

func TestDetectPlatformFromPath(t *testing.T) {
	he, err := NewHybridEngine(Config{EnableGoRules: true})
	if err != nil {
		t.Fatalf("NewHybridEngine: %v", err)
	}
	tests := []struct {
		path string
		want string
	}{
		{".github/workflows/ci.yml", "github-actions"},
		{"/repo/.github/workflows/release.yaml", "github-actions"},
		{".gitlab-ci.yml", "gitlab-ci"},
		{"/repo/.gitlab-ci.yaml", "gitlab-ci"},
		{"random.yaml", "github-actions"},
		{"noextension", "github-actions"},
	}
	for _, tt := range tests {
		if got := he.detectPlatformFromPath(tt.path); got != tt.want {
			t.Errorf("detectPlatformFromPath(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.EnableGoRules {
		t.Error("expected EnableGoRules true")
	}
	if !cfg.EnableOPARules {
		t.Error("expected EnableOPARules true")
	}
	if len(cfg.GoRulesConfig.EnabledCategories) == 0 {
		t.Error("expected enabled categories")
	}
	if !cfg.PlatformConfig.AutoDetect {
		t.Error("expected AutoDetect true")
	}
}

func TestNewHybridEngine_RegistersPlatforms(t *testing.T) {
	he, err := NewHybridEngine(Config{EnableGoRules: true})
	if err != nil {
		t.Fatalf("NewHybridEngine: %v", err)
	}
	platforms := he.GetSupportedPlatforms()
	if len(platforms) != 2 {
		t.Fatalf("expected 2 platforms, got %v", platforms)
	}
	want := map[string]bool{"github-actions": true, "gitlab-ci": true}
	for _, p := range platforms {
		if !want[p] {
			t.Errorf("unexpected platform %q", p)
		}
	}
	if len(he.GetGoRules()) == 0 {
		t.Error("expected non-empty Go rules")
	}
}

func TestNewHybridEngine_WithOPA(t *testing.T) {
	he, err := NewHybridEngine(DefaultConfig())
	if err != nil {
		t.Fatalf("NewHybridEngine with OPA: %v", err)
	}
	if got := len(he.GetOPAPolicies()); got != 3 {
		t.Errorf("expected 3 builtin OPA policies, got %d", got)
	}
}

func TestAnalyzeWorkflow(t *testing.T) {
	dir := t.TempDir()
	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	wfPath := filepath.Join(wfDir, "ci.yml")
	content := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "hello"
`
	if err := os.WriteFile(wfPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	he, err := NewHybridEngine(Config{EnableGoRules: true})
	if err != nil {
		t.Fatalf("NewHybridEngine: %v", err)
	}

	result, err := he.AnalyzeWorkflow(wfPath)
	if err != nil {
		t.Fatalf("AnalyzeWorkflow: %v", err)
	}
	if result.Statistics.TotalWorkflows != 1 {
		t.Errorf("TotalWorkflows = %d, want 1", result.Statistics.TotalWorkflows)
	}
	if len(result.Workflows) != 1 {
		t.Fatalf("expected 1 parsed workflow, got %d", len(result.Workflows))
	}
	if result.Workflows[0].Platform != "github-actions" {
		t.Errorf("platform = %q, want github-actions", result.Workflows[0].Platform)
	}
	if result.Statistics.PlatformBreakdown["github-actions"] != 1 {
		t.Errorf("platform breakdown = %v", result.Statistics.PlatformBreakdown)
	}
}

func TestAnalyzeWorkflow_UnparseablePath(t *testing.T) {
	he, err := NewHybridEngine(Config{EnableGoRules: true})
	if err != nil {
		t.Fatalf("NewHybridEngine: %v", err)
	}
	if _, err := he.AnalyzeWorkflow("/nonexistent/path/to/workflow.yml"); err == nil {
		t.Error("expected error for nonexistent workflow file")
	}
}

func TestUpdateStatistics(t *testing.T) {
	he, err := NewHybridEngine(Config{EnableGoRules: true})
	if err != nil {
		t.Fatalf("NewHybridEngine: %v", err)
	}
	stats := Statistics{
		FindingsByCategory: make(map[rules.Category]int),
		FindingsBySeverity: make(map[rules.Severity]int),
	}
	findings := []rules.Finding{
		{Category: rules.SecretExposure, Severity: rules.High},
		{Category: rules.SecretExposure, Severity: rules.Critical},
		{Category: rules.SupplyChain, Severity: rules.High},
	}
	he.updateStatistics(&stats, findings)

	if stats.FindingsByCategory[rules.SecretExposure] != 2 {
		t.Errorf("SecretExposure count = %d, want 2", stats.FindingsByCategory[rules.SecretExposure])
	}
	if stats.FindingsBySeverity[rules.High] != 2 {
		t.Errorf("High count = %d, want 2", stats.FindingsBySeverity[rules.High])
	}
	if stats.FindingsBySeverity[rules.Critical] != 1 {
		t.Errorf("Critical count = %d, want 1", stats.FindingsBySeverity[rules.Critical])
	}
}

func TestConvertToLegacyWorkflow(t *testing.T) {
	he, err := NewHybridEngine(Config{EnableGoRules: true})
	if err != nil {
		t.Fatalf("NewHybridEngine: %v", err)
	}
	wf := &platform.Workflow{
		Platform:        "github-actions",
		Name:            "CI",
		FilePath:        "/repo/.github/workflows/ci.yml",
		RepositoryOwner: "acme",
		Content: []byte(`name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`),
	}

	legacy := he.convertToLegacyWorkflow(wf)
	if legacy.Name != "CI" {
		t.Errorf("legacy.Name = %q, want CI", legacy.Name)
	}
	if legacy.Path != "/repo/.github/workflows/ci.yml" {
		t.Errorf("legacy.Path = %q", legacy.Path)
	}
	if legacy.RepositoryOwner != "acme" {
		t.Errorf("legacy.RepositoryOwner = %q, want acme", legacy.RepositoryOwner)
	}
	if len(legacy.Workflow.Jobs) == 0 {
		t.Error("expected parsed jobs in legacy workflow")
	}
}
