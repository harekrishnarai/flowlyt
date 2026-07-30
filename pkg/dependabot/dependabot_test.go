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

package dependabot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeConfig parses inline YAML into a ConfigFile ready for rule checks.
func makeConfig(t *testing.T, yamlContent string) ConfigFile {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "dependabot.yml")
	if err := os.WriteFile(path, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	return cfg
}

// findingsFor runs a single named rule against a config file.
func findingsFor(t *testing.T, ruleID string, cfg ConfigFile) []string {
	t.Helper()

	var evidence []string
	for _, rule := range StandardRules() {
		if rule.ID != ruleID {
			continue
		}
		for _, f := range rule.Check(cfg) {
			evidence = append(evidence, f.Evidence)
		}
		return evidence
	}
	t.Fatalf("rule %q not found in StandardRules", ruleID)
	return nil
}

// ---------------------------------------------------------------------------
// Discovery and parsing
// ---------------------------------------------------------------------------

func TestFindConfigs_NoFileIsNotAnError(t *testing.T) {
	configs, err := FindConfigs(t.TempDir())
	if err != nil {
		t.Fatalf("expected no error for a repo without dependabot config, got: %v", err)
	}
	if len(configs) != 0 {
		t.Fatalf("expected 0 configs, got %d", len(configs))
	}
}

func TestFindConfigs_LocatesFile(t *testing.T) {
	root := t.TempDir()
	githubDir := filepath.Join(root, ".github")
	if err := os.MkdirAll(githubDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := `version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"
`
	if err := os.WriteFile(filepath.Join(githubDir, "dependabot.yml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	configs, err := FindConfigs(root)
	if err != nil {
		t.Fatalf("FindConfigs: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("expected 1 config, got %d", len(configs))
	}

	// The path must be repository-relative so findings and URLs line up.
	want := filepath.Join(".github", "dependabot.yml")
	if configs[0].Path != want {
		t.Errorf("Path = %q, want %q", configs[0].Path, want)
	}
	if len(configs[0].Config.Updates) != 1 {
		t.Errorf("expected 1 update entry, got %d", len(configs[0].Config.Updates))
	}
	if configs[0].Config.Updates[0].PackageEcosystem != "npm" {
		t.Errorf("unexpected ecosystem: %q", configs[0].Config.Updates[0].PackageEcosystem)
	}
}

// ---------------------------------------------------------------------------
// DEPENDABOT_COOLDOWN_MISSING
// ---------------------------------------------------------------------------

func TestCooldown_MissingEntirely(t *testing.T) {
	cfg := makeConfig(t, `version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "daily"
`)

	findings := findingsFor(t, "DEPENDABOT_COOLDOWN_MISSING", cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for missing cooldown, got %d", len(findings))
	}
	if !strings.Contains(findings[0], "declares no `cooldown`") {
		t.Errorf("unexpected evidence: %q", findings[0])
	}
}

func TestCooldown_SufficientIsClean(t *testing.T) {
	cfg := makeConfig(t, `version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "daily"
    cooldown:
      default-days: 7
`)

	if findings := findingsFor(t, "DEPENDABOT_COOLDOWN_MISSING", cfg); len(findings) != 0 {
		t.Fatalf("expected no findings for a sufficient cooldown, got %d", len(findings))
	}
}

func TestCooldown_TooShort(t *testing.T) {
	cfg := makeConfig(t, `version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"
    cooldown:
      default-days: 2
`)

	findings := findingsFor(t, "DEPENDABOT_COOLDOWN_MISSING", cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for a short cooldown, got %d", len(findings))
	}
	if !strings.Contains(findings[0], "below the recommended minimum") {
		t.Errorf("unexpected evidence: %q", findings[0])
	}
}

// Each ecosystem is configured independently and must be reported independently.
func TestCooldown_PerEcosystem(t *testing.T) {
	cfg := makeConfig(t, `version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"
    cooldown:
      default-days: 7
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
`)

	findings := findingsFor(t, "DEPENDABOT_COOLDOWN_MISSING", cfg)
	if len(findings) != 1 {
		t.Fatalf("expected only the uncovered ecosystem to be reported, got %d", len(findings))
	}
	if !strings.Contains(findings[0], "github-actions") {
		t.Errorf("expected the github-actions entry to be reported, got: %q", findings[0])
	}
}

// ---------------------------------------------------------------------------
// DEPENDABOT_INSECURE_EXECUTION
// ---------------------------------------------------------------------------

func TestInsecureExecution_Allow(t *testing.T) {
	cfg := makeConfig(t, `version: 2
updates:
  - package-ecosystem: "bundler"
    directory: "/"
    schedule:
      interval: "daily"
    insecure-external-code-execution: allow
`)

	findings := findingsFor(t, "DEPENDABOT_INSECURE_EXECUTION", cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for insecure-external-code-execution: allow, got %d", len(findings))
	}
}

func TestInsecureExecution_DenyIsClean(t *testing.T) {
	cfg := makeConfig(t, `version: 2
updates:
  - package-ecosystem: "bundler"
    directory: "/"
    schedule:
      interval: "daily"
    insecure-external-code-execution: deny
`)

	if findings := findingsFor(t, "DEPENDABOT_INSECURE_EXECUTION", cfg); len(findings) != 0 {
		t.Fatalf("expected no findings for deny, got %d", len(findings))
	}
}

func TestInsecureExecution_OmittedIsClean(t *testing.T) {
	cfg := makeConfig(t, `version: 2
updates:
  - package-ecosystem: "bundler"
    directory: "/"
    schedule:
      interval: "daily"
`)

	if findings := findingsFor(t, "DEPENDABOT_INSECURE_EXECUTION", cfg); len(findings) != 0 {
		t.Fatalf("expected no findings when the key is omitted, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// CheckAll wiring
// ---------------------------------------------------------------------------

func TestCheckAll_RunsAllRulesWithNilConfig(t *testing.T) {
	cfg := makeConfig(t, `version: 2
updates:
  - package-ecosystem: "bundler"
    directory: "/"
    schedule:
      interval: "daily"
    insecure-external-code-execution: allow
`)

	findings := CheckAll([]ConfigFile{cfg}, nil)
	if len(findings) != 2 {
		t.Fatalf("expected both cooldown and insecure-execution findings, got %d", len(findings))
	}

	ids := map[string]bool{}
	for _, f := range findings {
		ids[f.RuleID] = true
		if f.LineNumber <= 0 {
			t.Errorf("finding %s has no line number", f.RuleID)
		}
	}
	for _, want := range []string{"DEPENDABOT_COOLDOWN_MISSING", "DEPENDABOT_INSECURE_EXECUTION"} {
		if !ids[want] {
			t.Errorf("missing expected rule %s", want)
		}
	}
}
