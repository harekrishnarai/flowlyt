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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/harekrishnarai/flowlyt/pkg/constants"
	"gopkg.in/yaml.v3"
)

// Config represents the complete Flowlyt configuration
type Config struct {
	Version      string           `yaml:"version" json:"version"`
	Rules        Rules            `yaml:"rules" json:"rules"`
	Output       Output           `yaml:"output" json:"output"`
	Policies     []Policy         `yaml:"policies,omitempty" json:"policies,omitempty"`
	Templates    []RuleTemplate   `yaml:"templates,omitempty" json:"templates,omitempty"`
	Compliance   ComplianceConfig `yaml:"compliance,omitempty" json:"compliance,omitempty"`
	Organization OrgConfig        `yaml:"organization,omitempty" json:"organization,omitempty"`
}

// Rules configuration for rule management
type Rules struct {
	Enabled        []string       `yaml:"enabled" json:"enabled"`
	Disabled       []string       `yaml:"disabled" json:"disabled"`
	CustomRules    []CustomRule   `yaml:"custom_rules" json:"custom_rules"`
	FalsePositives FalsePositives `yaml:"false_positives" json:"false_positives"`
}

// CustomRule represents a user-defined rule
type CustomRule struct {
	ID          string                 `yaml:"id" json:"id"`
	Name        string                 `yaml:"name" json:"name"`
	Description string                 `yaml:"description" json:"description"`
	Severity    string                 `yaml:"severity" json:"severity"`
	Category    string                 `yaml:"category" json:"category"`
	Type        string                 `yaml:"type" json:"type"` // "regex", "script", "plugin"
	Pattern     string                 `yaml:"pattern,omitempty" json:"pattern,omitempty"`
	Patterns    []string               `yaml:"patterns,omitempty" json:"patterns,omitempty"`
	Script      string                 `yaml:"script,omitempty" json:"script,omitempty"`
	Config      map[string]interface{} `yaml:"config,omitempty" json:"config,omitempty"`
	Target      RuleTarget             `yaml:"target" json:"target"`
	Remediation string                 `yaml:"remediation" json:"remediation"`
}

// RuleTarget specifies what the rule should check
type RuleTarget struct {
	Commands    bool `yaml:"commands" json:"commands"`       // Check run commands
	Actions     bool `yaml:"actions" json:"actions"`         // Check uses actions
	Environment bool `yaml:"environment" json:"environment"` // Check env vars
	Permissions bool `yaml:"permissions" json:"permissions"` // Check permissions
	Events      bool `yaml:"events" json:"events"`           // Check workflow events
}

// FalsePositives configuration for filtering false positives
type FalsePositives struct {
	Global  GlobalIgnores          `yaml:"global" json:"global"`
	Secrets SecretsIgnores         `yaml:"secrets" json:"secrets"`
	Actions ActionsIgnores         `yaml:"actions" json:"actions"`
	Files   []string               `yaml:"files" json:"files"` // File patterns to ignore
	Rules   map[string]RuleIgnores `yaml:"rules" json:"rules"` // Per-rule ignores
}

// GlobalIgnores for all rules
type GlobalIgnores struct {
	Patterns []string `yaml:"patterns" json:"patterns"`
	Strings  []string `yaml:"strings" json:"strings"`
}

// SecretsIgnores for secret detection
type SecretsIgnores struct {
	Patterns []string `yaml:"patterns" json:"patterns"`
	Strings  []string `yaml:"strings" json:"strings"`
	Contexts []string `yaml:"contexts" json:"contexts"` // Context patterns like "uses:", "${{ secrets."
}

// ActionsIgnores for action-related rules
type ActionsIgnores struct {
	Actions []string `yaml:"actions" json:"actions"` // Specific actions to ignore
	Orgs    []string `yaml:"orgs" json:"orgs"`       // Trusted organizations
}

// RuleIgnores for specific rule overrides
type RuleIgnores struct {
	Patterns []string `yaml:"patterns" json:"patterns"`
	Strings  []string `yaml:"strings" json:"strings"`
	Files    []string `yaml:"files" json:"files"`
}

// Output configuration
type Output struct {
	Format          string          `yaml:"format" json:"format"` // "cli", "json", "sarif", "junit"
	File            string          `yaml:"file,omitempty" json:"file,omitempty"`
	MinSeverity     string          `yaml:"min_severity" json:"min_severity"`
	ShowRemediation bool            `yaml:"show_remediation" json:"show_remediation"`
	Template        string          `yaml:"template,omitempty" json:"template,omitempty"`
	Fields          map[string]bool `yaml:"fields,omitempty" json:"fields,omitempty"`
}

// ComplianceConfig configures compliance framework integration
type ComplianceConfig struct {
	Enabled          bool                           `yaml:"enabled" json:"enabled"`
	Frameworks       []string                       `yaml:"frameworks" json:"frameworks"`
	ReportPath       string                         `yaml:"report_path,omitempty" json:"report_path,omitempty"`
	CustomFrameworks map[string]ComplianceFramework `yaml:"custom_frameworks,omitempty" json:"custom_frameworks,omitempty"`
}

// OrgConfig configures organization-wide settings
type OrgConfig struct {
	Name            string            `yaml:"name" json:"name"`
	PolicyRepo      string            `yaml:"policy_repo,omitempty" json:"policy_repo,omitempty"`
	DefaultPolicies []string          `yaml:"default_policies" json:"default_policies"`
	Inheritance     InheritanceConfig `yaml:"inheritance" json:"inheritance"`
	Contacts        ContactConfig     `yaml:"contacts" json:"contacts"`
}

// InheritanceConfig configures policy inheritance
type InheritanceConfig struct {
	Enabled       bool     `yaml:"enabled" json:"enabled"`
	ParentConfigs []string `yaml:"parent_configs" json:"parent_configs"`
	MergeStrategy string   `yaml:"merge_strategy" json:"merge_strategy"` // "override", "merge", "append"
}

// ContactConfig configures organizational contacts
type ContactConfig struct {
	SecurityTeam string   `yaml:"security_team,omitempty" json:"security_team,omitempty"`
	Owners       []string `yaml:"owners" json:"owners"`
	Escalation   string   `yaml:"escalation,omitempty" json:"escalation,omitempty"`
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Version: "1",
		Rules: Rules{
			Enabled:     []string{}, // Empty means all enabled
			Disabled:    []string{},
			CustomRules: []CustomRule{},
			FalsePositives: FalsePositives{
				Global: GlobalIgnores{
					Patterns: []string{},
					Strings:  constants.DefaultIgnorePatterns[:5], // First 5 patterns
				},
				Secrets: SecretsIgnores{
					Patterns: []string{},
					Strings:  constants.DefaultIgnorePatterns, // All ignore patterns
					Contexts: []string{
						`uses:.*@[a-f0-9]{40}`, // Action SHAs
						`uses:.*@v\d+`,         // Version tags
						`\$\{\{ secrets\.`,     // Secret references
						`\$\{\{ env\.`,         // Env references
					},
				},
				Actions: ActionsIgnores{
					Actions: []string{},
					Orgs:    []string{"actions", "github"},
				},
				Files: []string{"test/**", "tests/**", "examples/**", "docs/**"},
				Rules: make(map[string]RuleIgnores),
			},
		},
		Output: Output{
			Format:          constants.DefaultOutputFormat,
			MinSeverity:     constants.DefaultMinSeverity,
			ShowRemediation: true,
			Fields: map[string]bool{
				"line_number": true,
				"evidence":    true,
				"remediation": true,
				"category":    true,
			},
		},
	}
}

// LoadConfig loads configuration from file or returns default
func LoadConfig(configPath string) (*Config, error) {
	// If no config path specified, try to find one
	if configPath == "" {
		configPath = findConfigFile()
	}

	// If still no config file, return default
	if configPath == "" {
		return DefaultConfig(), nil
	}

	file, err := os.Open(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, fmt.Errorf("failed to open config file %s: %w", configPath, err)
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", configPath, err)
	}

	config := DefaultConfig()
	if err := yaml.Unmarshal(content, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", configPath, err)
	}

	// Validate configuration
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// findConfigFile searches for configuration files in common locations
func findConfigFile() string {
	// Search order: current dir, home dir
	candidates := []string{
		constants.ConfigFileFlowlytYML,
		constants.ConfigFileFlowlytYAML,
		constants.ConfigFileBaseYML,
		constants.ConfigFileBaseYAML,
	}

	// Check current directory first
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	// Check home directory
	if homeDir, err := os.UserHomeDir(); err == nil {
		for _, candidate := range candidates {
			fullPath := filepath.Join(homeDir, candidate)
			if _, err := os.Stat(fullPath); err == nil {
				return fullPath
			}
		}
	}

	return ""
}

// validateConfig validates the configuration structure
func validateConfig(config *Config) error {
	if config.Version == "" {
		config.Version = "1"
	}

	// Validate custom rules
	for i, rule := range config.Rules.CustomRules {
		if rule.ID == "" {
			return fmt.Errorf("custom rule %d: ID is required", i)
		}
		if rule.Name == "" {
			return fmt.Errorf("custom rule %s: Name is required", rule.ID)
		}
		if rule.Type == "" {
			rule.Type = "regex"
		}
		if !isValidRuleType(rule.Type) {
			return fmt.Errorf("custom rule %s: invalid type %s", rule.ID, rule.Type)
		}
		if rule.Type == "regex" && rule.Pattern == "" && len(rule.Patterns) == 0 {
			return fmt.Errorf("custom rule %s: regex rules require pattern or patterns", rule.ID)
		}
		if rule.Severity == "" {
			rule.Severity = "MEDIUM"
		}
		if !isValidSeverity(rule.Severity) {
			return fmt.Errorf("custom rule %s: invalid severity %s", rule.ID, rule.Severity)
		}

		// Update the rule in the slice
		config.Rules.CustomRules[i] = rule
	}

	// Validate false positive patterns are valid regex
	allPatterns := append(config.Rules.FalsePositives.Global.Patterns, config.Rules.FalsePositives.Secrets.Patterns...)
	for ruleName, ruleIgnores := range config.Rules.FalsePositives.Rules {
		allPatterns = append(allPatterns, ruleIgnores.Patterns...)
		_ = ruleName // avoid unused variable
	}

	for _, pattern := range allPatterns {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("invalid regex pattern '%s': %w", pattern, err)
		}
	}

	return nil
}

// isValidRuleType checks if the rule type is supported
func isValidRuleType(ruleType string) bool {
	validTypes := []string{"regex", "script", "plugin"}
	for _, valid := range validTypes {
		if ruleType == valid {
			return true
		}
	}
	return false
}

// isValidSeverity checks if the severity level is valid
func isValidSeverity(severity string) bool {
	validSeverities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
	for _, valid := range validSeverities {
		if strings.ToUpper(severity) == valid {
			return true
		}
	}
	return false
}

// ShouldIgnoreGlobal checks if a string should be ignored globally
func (config *Config) ShouldIgnoreGlobal(text string) bool {
	return config.shouldIgnore(text, config.Rules.FalsePositives.Global.Patterns, config.Rules.FalsePositives.Global.Strings)
}

// ShouldIgnoreSecret checks if a secret should be ignored
func (config *Config) ShouldIgnoreSecret(text, context string) bool {
	fp := config.Rules.FalsePositives.Secrets

	// Check context patterns first
	for _, contextPattern := range fp.Contexts {
		if matched, _ := regexp.MatchString(contextPattern, context); matched {
			return true
		}
	}

	return config.shouldIgnore(text, fp.Patterns, fp.Strings)
}

// ShouldIgnoreForRule checks if a finding should be ignored for a specific rule
func (config *Config) ShouldIgnoreForRule(ruleID, text, filePath string) bool {
	// Check global ignores first
	if config.ShouldIgnoreGlobal(text) {
		return true
	}

	normalizedPath := filepath.ToSlash(filePath)

	// Check file patterns
	for _, filePattern := range config.Rules.FalsePositives.Files {
		if matchGlobPattern(filePattern, normalizedPath) {
			return true
		}
	}

	// Check rule-specific ignores
	if ruleIgnores, exists := config.Rules.FalsePositives.Rules[ruleID]; exists {
		// Check file patterns for this rule
		for _, filePattern := range ruleIgnores.Files {
			if matchGlobPattern(filePattern, normalizedPath) {
				return true
			}
		}

		// Check text patterns for this rule
		if config.shouldIgnore(text, ruleIgnores.Patterns, ruleIgnores.Strings) {
			return true
		}
	}

	return false
}

// IsRuleEnabled checks if a rule should be enabled
func (config *Config) IsRuleEnabled(ruleID string) bool {
	// If specific rules are enabled, only those are active
	if len(config.Rules.Enabled) > 0 {
		for _, enabled := range config.Rules.Enabled {
			if enabled == ruleID {
				return true
			}
		}
		return false
	}

	// If no specific enabled rules, check disabled list
	for _, disabled := range config.Rules.Disabled {
		if disabled == ruleID {
			return false
		}
	}

	return true
}

// shouldIgnore checks if text matches any of the ignore patterns or strings
func (config *Config) shouldIgnore(text string, patterns, stringList []string) bool {
	textLower := strings.ToLower(text)

	// Check exact string matches
	for _, str := range stringList {
		if textLower == strings.ToLower(str) ||
			strings.HasPrefix(textLower, strings.ToLower(str)) ||
			strings.HasSuffix(textLower, strings.ToLower(str)) {
			return true
		}
	}

	// Check regex patterns
	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, text); matched {
			return true
		}
	}

	return false
}

func matchGlobPattern(pattern, path string) bool {
	if pattern == "" {
		return false
	}

	normalizedPattern := filepath.ToSlash(pattern)
	matchers := []string{normalizedPattern}

	// Automatically add a glob that searches anywhere in the tree when the pattern isn't absolute
	if !strings.HasPrefix(normalizedPattern, "**/") &&
		!strings.HasPrefix(normalizedPattern, "./") &&
		!strings.HasPrefix(normalizedPattern, "/") &&
		!strings.Contains(normalizedPattern, ":") {
		matchers = append(matchers, "**/"+normalizedPattern)
	}

	for _, candidate := range matchers {
		matched, err := doublestar.Match(candidate, path)
		if err == nil && matched {
			return true
		}
	}

	return false
}

// SaveConfig saves configuration to a file
func SaveConfig(config *Config, filepath string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(filepath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Ensure Config implements the ConfigInterface from rules package
// This will be checked at compile time
var _ interface {
	IsRuleEnabled(ruleID string) bool
	ShouldIgnoreForRule(ruleID, text, filePath string) bool
	ShouldIgnoreSecret(text, context string) bool
} = (*Config)(nil)
