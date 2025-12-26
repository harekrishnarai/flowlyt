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

package config

import (
	"os"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Version != "1" {
		t.Errorf("Expected version '1', got '%s'", config.Version)
	}

	if config.Output.Format != "cli" {
		t.Errorf("Expected default format 'cli', got '%s'", config.Output.Format)
	}

	if config.Output.MinSeverity != "LOW" {
		t.Errorf("Expected default min severity 'LOW', got '%s'", config.Output.MinSeverity)
	}
}

func TestLoadConfig(t *testing.T) {
	// Test loading non-existent file returns default config
	config, err := LoadConfig("non-existent-file.yml")
	if err != nil {
		t.Fatalf("Expected no error for non-existent file, got: %v", err)
	}

	if config.Version != "1" {
		t.Errorf("Expected default config, got version '%s'", config.Version)
	}
}

func TestConfigValidation(t *testing.T) {
	config := &Config{
		Version: "",
		Rules: Rules{
			CustomRules: []CustomRule{
				{
					ID:       "TEST_RULE",
					Name:     "Test Rule",
					Type:     "regex",
					Pattern:  "test.*pattern",
					Severity: "HIGH",
				},
			},
		},
	}

	err := validateConfig(config)
	if err != nil {
		t.Errorf("Expected no validation error, got: %v", err)
	}

	// Check that version was set to default
	if config.Version != "1" {
		t.Errorf("Expected version to be set to '1', got '%s'", config.Version)
	}

	// Check that category was set to default after validation
	if config.Rules.CustomRules[0].Category != "" {
		t.Errorf("Expected category to remain empty (will be set during conversion), got '%s'", config.Rules.CustomRules[0].Category)
	}
}

func TestIsRuleEnabled(t *testing.T) {
	// Test with no specific enabled rules (all enabled by default)
	config := DefaultConfig()

	if !config.IsRuleEnabled("ANY_RULE") {
		t.Error("Expected rule to be enabled when no specific rules configured")
	}

	// Test with specific enabled rules
	config.Rules.Enabled = []string{"RULE1", "RULE2"}

	if !config.IsRuleEnabled("RULE1") {
		t.Error("Expected RULE1 to be enabled")
	}

	if config.IsRuleEnabled("RULE3") {
		t.Error("Expected RULE3 to be disabled")
	}

	// Test with disabled rules
	config.Rules.Enabled = []string{} // Reset enabled rules
	config.Rules.Disabled = []string{"RULE1"}

	if config.IsRuleEnabled("RULE1") {
		t.Error("Expected RULE1 to be disabled")
	}

	if !config.IsRuleEnabled("RULE2") {
		t.Error("Expected RULE2 to be enabled")
	}
}

func TestShouldIgnoreGlobal(t *testing.T) {
	config := DefaultConfig()
	config.Rules.FalsePositives.Global.Strings = []string{"test", "example"}
	config.Rules.FalsePositives.Global.Patterns = []string{".*_test$"}

	if !config.ShouldIgnoreGlobal("test") {
		t.Error("Expected 'test' to be ignored")
	}

	if !config.ShouldIgnoreGlobal("my_test") {
		t.Error("Expected 'my_test' to be ignored by pattern")
	}

	if config.ShouldIgnoreGlobal("production") {
		t.Error("Expected 'production' to not be ignored")
	}
}

func TestShouldIgnoreForRule(t *testing.T) {
	config := DefaultConfig()
	config.Rules.FalsePositives.Files = []string{"test/**"}
	config.Rules.FalsePositives.Rules = map[string]RuleIgnores{
		"HARDCODED_SECRET": {
			Strings: []string{"fake-token"},
			Files:   []string{"examples/**"},
		},
	}

	// Test file pattern ignore
	if !config.ShouldIgnoreForRule("ANY_RULE", "some text", "test/file.yml") {
		t.Error("Expected finding in test/ to be ignored")
	}

	// Test rule-specific ignore
	if !config.ShouldIgnoreForRule("HARDCODED_SECRET", "fake-token", "src/file.yml") {
		t.Error("Expected 'fake-token' to be ignored for HARDCODED_SECRET rule")
	}

	// Test rule-specific file ignore
	if !config.ShouldIgnoreForRule("HARDCODED_SECRET", "real-secret", "examples/demo.yml") {
		t.Error("Expected findings in examples/ to be ignored for HARDCODED_SECRET rule")
	}

	// Test no ignore
	if config.ShouldIgnoreForRule("OTHER_RULE", "real-issue", "src/file.yml") {
		t.Error("Expected finding to not be ignored")
	}
}

func TestSaveAndLoadConfig(t *testing.T) {
	// Create a test config
	config := DefaultConfig()
	config.Rules.Disabled = []string{"TEST_RULE"}
	config.Output.MinSeverity = "HIGH"

	// Save to temporary file
	tmpFile := "test_config.yml"
	defer os.Remove(tmpFile)

	err := SaveConfig(config, tmpFile)
	if err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Load the config back
	loadedConfig, err := LoadConfig(tmpFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify the loaded config
	if len(loadedConfig.Rules.Disabled) != 1 || loadedConfig.Rules.Disabled[0] != "TEST_RULE" {
		t.Error("Disabled rules not loaded correctly")
	}

	if loadedConfig.Output.MinSeverity != "HIGH" {
		t.Errorf("MinSeverity not loaded correctly, expected 'HIGH', got '%s'", loadedConfig.Output.MinSeverity)
	}
}
