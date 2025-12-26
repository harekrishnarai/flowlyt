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
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

// PolicyEngine handles organization-wide policy enforcement
type PolicyEngine struct {
	config    *Config
	policies  []Policy
	templates map[string]RuleTemplate
}

// Policy represents an organization-wide security policy
type Policy struct {
	ID          string            `yaml:"id" json:"id"`
	Name        string            `yaml:"name" json:"name"`
	Description string            `yaml:"description" json:"description"`
	Version     string            `yaml:"version" json:"version"`
	Enabled     bool              `yaml:"enabled" json:"enabled"`
	Enforcement EnforcementLevel  `yaml:"enforcement" json:"enforcement"`
	Scope       PolicyScope       `yaml:"scope" json:"scope"`
	Rules       []PolicyRule      `yaml:"rules" json:"rules"`
	Exceptions  []PolicyException `yaml:"exceptions" json:"exceptions"`
	Metadata    PolicyMetadata    `yaml:"metadata" json:"metadata"`
	Compliance  []string          `yaml:"compliance" json:"compliance"` // SOX, PCI-DSS, etc.
}

// EnforcementLevel defines how strictly a policy is enforced
type EnforcementLevel string

const (
	EnforcementDisabled EnforcementLevel = "disabled"
	EnforcementWarn     EnforcementLevel = "warn"
	EnforcementError    EnforcementLevel = "error"
	EnforcementBlock    EnforcementLevel = "block"
)

// PolicyScope defines where a policy applies
type PolicyScope struct {
	Organizations []string          `yaml:"organizations" json:"organizations"`
	Repositories  []string          `yaml:"repositories" json:"repositories"`
	Teams         []string          `yaml:"teams" json:"teams"`
	Branches      []string          `yaml:"branches" json:"branches"`
	Environments  []string          `yaml:"environments" json:"environments"`
	FilePatterns  []string          `yaml:"file_patterns" json:"file_patterns"`
	Conditions    map[string]string `yaml:"conditions" json:"conditions"`
}

// PolicyRule defines a rule within a policy
type PolicyRule struct {
	RuleID       string                 `yaml:"rule_id" json:"rule_id"`
	Severity     string                 `yaml:"severity,omitempty" json:"severity,omitempty"`
	Enforcement  EnforcementLevel       `yaml:"enforcement,omitempty" json:"enforcement,omitempty"`
	Parameters   map[string]string      `yaml:"parameters,omitempty" json:"parameters,omitempty"`
	CustomConfig map[string]interface{} `yaml:"custom_config,omitempty" json:"custom_config,omitempty"`
}

// PolicyException defines exceptions to policy rules
type PolicyException struct {
	ID            string      `yaml:"id" json:"id"`
	Description   string      `yaml:"description" json:"description"`
	RuleID        string      `yaml:"rule_id" json:"rule_id"`
	Scope         PolicyScope `yaml:"scope" json:"scope"`
	Justification string      `yaml:"justification" json:"justification"`
	Approver      string      `yaml:"approver" json:"approver"`
	ExpiryDate    *time.Time  `yaml:"expiry_date,omitempty" json:"expiry_date,omitempty"`
	TicketURL     string      `yaml:"ticket_url,omitempty" json:"ticket_url,omitempty"`
}

// PolicyMetadata contains policy metadata
type PolicyMetadata struct {
	Owner       string            `yaml:"owner" json:"owner"`
	Contact     string            `yaml:"contact" json:"contact"`
	Created     time.Time         `yaml:"created" json:"created"`
	Updated     time.Time         `yaml:"updated" json:"updated"`
	Tags        []string          `yaml:"tags" json:"tags"`
	Labels      map[string]string `yaml:"labels" json:"labels"`
	DocumentURL string            `yaml:"document_url,omitempty" json:"document_url,omitempty"`
}

// RuleTemplate defines reusable rule configurations
type RuleTemplate struct {
	ID          string                       `yaml:"id" json:"id"`
	Name        string                       `yaml:"name" json:"name"`
	Description string                       `yaml:"description" json:"description"`
	Category    string                       `yaml:"category" json:"category"`
	Severity    string                       `yaml:"severity" json:"severity"`
	Parameters  map[string]TemplateParameter `yaml:"parameters" json:"parameters"`
	BaseRule    CustomRule                   `yaml:"base_rule" json:"base_rule"`
	Examples    []TemplateExample            `yaml:"examples" json:"examples"`
}

// TemplateParameter defines configurable parameters in templates
type TemplateParameter struct {
	Type        string      `yaml:"type" json:"type"` // string, number, boolean, array
	Description string      `yaml:"description" json:"description"`
	Default     interface{} `yaml:"default,omitempty" json:"default,omitempty"`
	Required    bool        `yaml:"required" json:"required"`
	Validation  string      `yaml:"validation,omitempty" json:"validation,omitempty"` // regex for validation
}

// TemplateExample provides example usage of a template
type TemplateExample struct {
	Name        string                 `yaml:"name" json:"name"`
	Description string                 `yaml:"description" json:"description"`
	Parameters  map[string]interface{} `yaml:"parameters" json:"parameters"`
	Expected    string                 `yaml:"expected" json:"expected"`
}

// ComplianceFramework defines compliance framework requirements
type ComplianceFramework struct {
	ID          string              `yaml:"id" json:"id"`
	Name        string              `yaml:"name" json:"name"`
	Version     string              `yaml:"version" json:"version"`
	Description string              `yaml:"description" json:"description"`
	Controls    []ComplianceControl `yaml:"controls" json:"controls"`
	URL         string              `yaml:"url,omitempty" json:"url,omitempty"`
}

// ComplianceControl maps to specific security controls
type ComplianceControl struct {
	ID            string   `yaml:"id" json:"id"`
	Title         string   `yaml:"title" json:"title"`
	Description   string   `yaml:"description" json:"description"`
	RequiredRules []string `yaml:"required_rules" json:"required_rules"`
	Severity      string   `yaml:"severity" json:"severity"`
}

// NewPolicyEngine creates a new policy engine
func NewPolicyEngine(config *Config) *PolicyEngine {
	return &PolicyEngine{
		config:    config,
		policies:  []Policy{},
		templates: make(map[string]RuleTemplate),
	}
}

// LoadPolicies loads policies from configuration
func (pe *PolicyEngine) LoadPolicies(policyFiles []string) error {
	// Implementation for loading policy files
	// This would read YAML files with policy definitions
	return nil
}

// LoadTemplates loads rule templates from configuration
func (pe *PolicyEngine) LoadTemplates(templateFiles []string) error {
	// Implementation for loading template files
	return nil
}

// EvaluatePolicy evaluates if a finding violates any policies
func (pe *PolicyEngine) EvaluatePolicy(finding rules.Finding, context PolicyContext) PolicyEvaluation {
	var violations []PolicyViolation
	var exceptions []PolicyException

	for _, policy := range pe.policies {
		if !policy.Enabled {
			continue
		}

		// Check if policy scope applies to this context
		if !pe.policyApplies(policy, context) {
			continue
		}

		// Check if finding violates any rules in this policy
		for _, policyRule := range policy.Rules {
			if policyRule.RuleID == finding.RuleID {
				// Check for exceptions
				exception := pe.findException(policy, policyRule, context)
				if exception != nil {
					exceptions = append(exceptions, *exception)
					continue
				}

				// Create violation
				violation := PolicyViolation{
					PolicyID:    policy.ID,
					PolicyName:  policy.Name,
					RuleID:      policyRule.RuleID,
					Enforcement: policyRule.Enforcement,
					Severity:    policyRule.Severity,
					Finding:     finding,
					Context:     context,
				}
				violations = append(violations, violation)
			}
		}
	}

	return PolicyEvaluation{
		Violations: violations,
		Exceptions: exceptions,
		Compliant:  len(violations) == 0,
	}
}

// PolicyContext provides context for policy evaluation
type PolicyContext struct {
	Repository   string
	Organization string
	Branch       string
	Environment  string
	FilePath     string
	JobName      string
	StepName     string
	EventType    string
	Metadata     map[string]string
}

// PolicyViolation represents a policy violation
type PolicyViolation struct {
	PolicyID    string           `json:"policy_id"`
	PolicyName  string           `json:"policy_name"`
	RuleID      string           `json:"rule_id"`
	Enforcement EnforcementLevel `json:"enforcement"`
	Severity    string           `json:"severity"`
	Finding     rules.Finding    `json:"finding"`
	Context     PolicyContext    `json:"context"`
}

// PolicyEvaluation represents the result of policy evaluation
type PolicyEvaluation struct {
	Violations []PolicyViolation `json:"violations"`
	Exceptions []PolicyException `json:"exceptions"`
	Compliant  bool              `json:"compliant"`
}

// policyApplies checks if a policy applies to the given context
func (pe *PolicyEngine) policyApplies(policy Policy, context PolicyContext) bool {
	scope := policy.Scope

	// Check organization scope
	if len(scope.Organizations) > 0 && !contains(scope.Organizations, context.Organization) {
		return false
	}

	// Check repository scope
	if len(scope.Repositories) > 0 && !matchesPatterns(scope.Repositories, context.Repository) {
		return false
	}

	// Check branch scope
	if len(scope.Branches) > 0 && !matchesPatterns(scope.Branches, context.Branch) {
		return false
	}

	// Check environment scope
	if len(scope.Environments) > 0 && !contains(scope.Environments, context.Environment) {
		return false
	}

	// Check file pattern scope
	if len(scope.FilePatterns) > 0 && !matchesPatterns(scope.FilePatterns, context.FilePath) {
		return false
	}

	// Check custom conditions
	for key, pattern := range scope.Conditions {
		if value, exists := context.Metadata[key]; exists {
			if matched, _ := regexp.MatchString(pattern, value); !matched {
				return false
			}
		}
	}

	return true
}

// findException finds an applicable exception for a policy rule
func (pe *PolicyEngine) findException(policy Policy, rule PolicyRule, context PolicyContext) *PolicyException {
	for _, exception := range policy.Exceptions {
		if exception.RuleID != rule.RuleID {
			continue
		}

		// Check if exception has expired
		if exception.ExpiryDate != nil && time.Now().After(*exception.ExpiryDate) {
			continue
		}

		// Check if exception scope applies
		if pe.policyApplies(Policy{Scope: exception.Scope}, context) {
			return &exception
		}
	}
	return nil
}

// InstantiateTemplate creates a custom rule from a template
func (pe *PolicyEngine) InstantiateTemplate(templateID string, parameters map[string]interface{}) (*CustomRule, error) {
	template, exists := pe.templates[templateID]
	if !exists {
		return nil, fmt.Errorf("template not found: %s", templateID)
	}

	// Validate parameters
	if err := pe.validateTemplateParameters(template, parameters); err != nil {
		return nil, err
	}

	// Create custom rule from template
	rule := template.BaseRule

	// Replace parameter placeholders in rule configuration
	rule = pe.replaceTemplateParameters(rule, parameters)

	return &rule, nil
}

// validateTemplateParameters validates template parameters
func (pe *PolicyEngine) validateTemplateParameters(template RuleTemplate, parameters map[string]interface{}) error {
	for paramName, paramDef := range template.Parameters {
		value, provided := parameters[paramName]

		// Check required parameters
		if paramDef.Required && !provided {
			return fmt.Errorf("required parameter missing: %s", paramName)
		}

		// Use default if not provided
		if !provided && paramDef.Default != nil {
			parameters[paramName] = paramDef.Default
			continue
		}

		// Validate parameter value
		if paramDef.Validation != "" {
			strValue := fmt.Sprintf("%v", value)
			if matched, err := regexp.MatchString(paramDef.Validation, strValue); err != nil || !matched {
				return fmt.Errorf("parameter %s validation failed: %v", paramName, value)
			}
		}
	}

	return nil
}

// replaceTemplateParameters replaces parameter placeholders in rule
func (pe *PolicyEngine) replaceTemplateParameters(rule CustomRule, parameters map[string]interface{}) CustomRule {
	// Replace parameters in patterns
	for i, pattern := range rule.Patterns {
		rule.Patterns[i] = pe.replacePlaceholders(pattern, parameters)
	}

	if rule.Pattern != "" {
		rule.Pattern = pe.replacePlaceholders(rule.Pattern, parameters)
	}

	// Replace parameters in description and remediation
	rule.Description = pe.replacePlaceholders(rule.Description, parameters)
	rule.Remediation = pe.replacePlaceholders(rule.Remediation, parameters)

	return rule
}

// replacePlaceholders replaces {{param}} placeholders with values
func (pe *PolicyEngine) replacePlaceholders(text string, parameters map[string]interface{}) string {
	result := text
	for key, value := range parameters {
		placeholder := fmt.Sprintf("{{%s}}", key)
		replacement := fmt.Sprintf("%v", value)
		result = strings.ReplaceAll(result, placeholder, replacement)
	}
	return result
}

// GetComplianceReport generates a compliance report
func (pe *PolicyEngine) GetComplianceReport(findings []rules.Finding, context PolicyContext) ComplianceReport {
	report := ComplianceReport{
		Context:     context,
		GeneratedAt: time.Now(),
		Frameworks:  make(map[string]FrameworkCompliance),
	}

	// Evaluate each finding against policies
	for _, finding := range findings {
		evaluation := pe.EvaluatePolicy(finding, context)

		for _, violation := range evaluation.Violations {
			report.TotalViolations++

			// Count violations by enforcement level
			switch violation.Enforcement {
			case EnforcementBlock:
				report.BlockingViolations++
			case EnforcementError:
				report.ErrorViolations++
			case EnforcementWarn:
				report.WarningViolations++
			}
		}
	}

	report.Compliant = report.BlockingViolations == 0 && report.ErrorViolations == 0

	return report
}

// ComplianceReport represents compliance status
type ComplianceReport struct {
	Context            PolicyContext                  `json:"context"`
	GeneratedAt        time.Time                      `json:"generated_at"`
	Compliant          bool                           `json:"compliant"`
	TotalViolations    int                            `json:"total_violations"`
	BlockingViolations int                            `json:"blocking_violations"`
	ErrorViolations    int                            `json:"error_violations"`
	WarningViolations  int                            `json:"warning_violations"`
	Frameworks         map[string]FrameworkCompliance `json:"frameworks"`
}

// FrameworkCompliance represents compliance with a specific framework
type FrameworkCompliance struct {
	FrameworkID   string                   `json:"framework_id"`
	FrameworkName string                   `json:"framework_name"`
	Version       string                   `json:"version"`
	Compliant     bool                     `json:"compliant"`
	Controls      map[string]ControlStatus `json:"controls"`
	Score         float64                  `json:"score"`
}

// ControlStatus represents the status of a compliance control
type ControlStatus struct {
	ControlID  string   `json:"control_id"`
	Title      string   `json:"title"`
	Compliant  bool     `json:"compliant"`
	Violations []string `json:"violations"`
	Severity   string   `json:"severity"`
}

// Helper functions
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func matchesPatterns(patterns []string, text string) bool {
	for _, pattern := range patterns {
		if matched, _ := filepath.Match(pattern, text); matched {
			return true
		}
		if matched, _ := regexp.MatchString(pattern, text); matched {
			return true
		}
	}
	return false
}
