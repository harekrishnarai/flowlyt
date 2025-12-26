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
	"regexp"
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/parser"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

// CustomRuleEngine handles loading and execution of custom rules
type CustomRuleEngine struct {
	config *Config
}

// NewCustomRuleEngine creates a new custom rule engine
func NewCustomRuleEngine(config *Config) *CustomRuleEngine {
	return &CustomRuleEngine{config: config}
}

// LoadCustomRules converts config custom rules to executable rules
func (cre *CustomRuleEngine) LoadCustomRules() ([]rules.Rule, error) {
	var customRules []rules.Rule

	for _, customRule := range cre.config.Rules.CustomRules {
		rule, err := cre.convertCustomRule(customRule)
		if err != nil {
			return nil, fmt.Errorf("failed to load custom rule %s: %w", customRule.ID, err)
		}
		customRules = append(customRules, rule)
	}

	return customRules, nil
}

// convertCustomRule converts a config custom rule to an executable rule
func (cre *CustomRuleEngine) convertCustomRule(customRule CustomRule) (rules.Rule, error) {
	// Convert severity
	severity, err := convertSeverity(customRule.Severity)
	if err != nil {
		return rules.Rule{}, err
	}

	// Convert category
	category, err := convertCategory(customRule.Category)
	if err != nil {
		return rules.Rule{}, err
	}

	rule := rules.Rule{
		ID:          customRule.ID,
		Name:        customRule.Name,
		Description: customRule.Description,
		Severity:    severity,
		Category:    category,
	}

	// Create check function based on rule type
	switch customRule.Type {
	case "regex":
		checkFunc, err := cre.createRegexCheck(customRule)
		if err != nil {
			return rules.Rule{}, err
		}
		rule.Check = checkFunc

	case "script":
		return rules.Rule{}, fmt.Errorf("script rules not implemented yet")

	case "plugin":
		return rules.Rule{}, fmt.Errorf("plugin rules not implemented yet")

	default:
		return rules.Rule{}, fmt.Errorf("unsupported rule type: %s", customRule.Type)
	}

	return rule, nil
}

// createRegexCheck creates a check function for regex-based custom rules
func (cre *CustomRuleEngine) createRegexCheck(customRule CustomRule) (func(workflow parser.WorkflowFile) []rules.Finding, error) {
	// Compile patterns
	var patterns []*regexp.Regexp

	if customRule.Pattern != "" {
		compiled, err := regexp.Compile(customRule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern '%s': %w", customRule.Pattern, err)
		}
		patterns = append(patterns, compiled)
	}

	for _, pattern := range customRule.Patterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern '%s': %w", pattern, err)
		}
		patterns = append(patterns, compiled)
	}

	if len(patterns) == 0 {
		return nil, fmt.Errorf("regex rule must have at least one pattern")
	}

	// Convert severity and category for the check function
	severity, _ := convertSeverity(customRule.Severity)
	category, _ := convertCategory(customRule.Category)

	return func(workflow parser.WorkflowFile) []rules.Finding {
		var findings []rules.Finding

		// Check what targets this rule should examine
		target := customRule.Target

		// Check run commands if enabled
		if target.Commands {
			findings = append(findings, cre.checkCommands(workflow, patterns, customRule, severity, category)...)
		}

		// Check actions if enabled
		if target.Actions {
			findings = append(findings, cre.checkActions(workflow, patterns, customRule, severity, category)...)
		}

		// Check environment variables if enabled
		if target.Environment {
			findings = append(findings, cre.checkEnvironment(workflow, patterns, customRule, severity, category)...)
		}

		// Check permissions if enabled
		if target.Permissions {
			findings = append(findings, cre.checkPermissions(workflow, patterns, customRule, severity, category)...)
		}

		// Check events if enabled
		if target.Events {
			findings = append(findings, cre.checkEvents(workflow, patterns, customRule, severity, category)...)
		}

		// If no specific targets, check entire content
		if !target.Commands && !target.Actions && !target.Environment && !target.Permissions && !target.Events {
			findings = append(findings, cre.checkContent(workflow, patterns, customRule, severity, category)...)
		}

		// Filter findings based on configuration
		var filteredFindings []rules.Finding
		for _, finding := range findings {
			if !cre.config.ShouldIgnoreForRule(customRule.ID, finding.Evidence, workflow.Path) {
				filteredFindings = append(filteredFindings, finding)
			}
		}

		return filteredFindings
	}, nil
}

// checkCommands checks run commands against patterns
func (cre *CustomRuleEngine) checkCommands(workflow parser.WorkflowFile, patterns []*regexp.Regexp, customRule CustomRule, severity rules.Severity, category rules.Category) []rules.Finding {
	var findings []rules.Finding
	content := string(workflow.Content)

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			for _, pattern := range patterns {
				if pattern.MatchString(step.Run) {
					lineNumber := cre.findLineNumber(content, "run:", step.Run)
					findings = append(findings, rules.Finding{
						RuleID:      customRule.ID,
						RuleName:    customRule.Name,
						Description: customRule.Description,
						Severity:    severity,
						Category:    category,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    step.Name,
						Evidence:    step.Run,
						LineNumber:  lineNumber,
						Remediation: customRule.Remediation,
					})
					break // Only report once per step
				}
			}
		}
	}

	return findings
}

// checkActions checks uses actions against patterns
func (cre *CustomRuleEngine) checkActions(workflow parser.WorkflowFile, patterns []*regexp.Regexp, customRule CustomRule, severity rules.Severity, category rules.Category) []rules.Finding {
	var findings []rules.Finding
	content := string(workflow.Content)

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Uses == "" {
				continue
			}

			for _, pattern := range patterns {
				if pattern.MatchString(step.Uses) {
					lineNumber := cre.findLineNumber(content, "uses:", step.Uses)
					findings = append(findings, rules.Finding{
						RuleID:      customRule.ID,
						RuleName:    customRule.Name,
						Description: customRule.Description,
						Severity:    severity,
						Category:    category,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    step.Name,
						Evidence:    step.Uses,
						LineNumber:  lineNumber,
						Remediation: customRule.Remediation,
					})
					break // Only report once per step
				}
			}
		}
	}

	return findings
}

// checkEnvironment checks environment variables against patterns
func (cre *CustomRuleEngine) checkEnvironment(workflow parser.WorkflowFile, patterns []*regexp.Regexp, customRule CustomRule, severity rules.Severity, category rules.Category) []rules.Finding {
	var findings []rules.Finding
	content := string(workflow.Content)

	// Check workflow-level env
	if workflow.Workflow.Env != nil {
		for key, value := range workflow.Workflow.Env {
			for _, pattern := range patterns {
				if pattern.MatchString(value) || pattern.MatchString(key) {
					lineNumber := cre.findLineNumber(content, key+":", value)
					findings = append(findings, rules.Finding{
						RuleID:      customRule.ID,
						RuleName:    customRule.Name,
						Description: customRule.Description,
						Severity:    severity,
						Category:    category,
						FilePath:    workflow.Path,
						Evidence:    key + ": " + value,
						LineNumber:  lineNumber,
						Remediation: customRule.Remediation,
					})
					break
				}
			}
		}
	}

	// Check job-level env
	for jobName, job := range workflow.Workflow.Jobs {
		if job.Env != nil {
			for key, value := range job.Env {
				for _, pattern := range patterns {
					if pattern.MatchString(value) || pattern.MatchString(key) {
						lineNumber := cre.findLineNumber(content, key+":", value)
						findings = append(findings, rules.Finding{
							RuleID:      customRule.ID,
							RuleName:    customRule.Name,
							Description: customRule.Description,
							Severity:    severity,
							Category:    category,
							FilePath:    workflow.Path,
							JobName:     jobName,
							Evidence:    key + ": " + value,
							LineNumber:  lineNumber,
							Remediation: customRule.Remediation,
						})
						break
					}
				}
			}
		}
	}

	return findings
}

// checkPermissions checks permissions against patterns
func (cre *CustomRuleEngine) checkPermissions(workflow parser.WorkflowFile, patterns []*regexp.Regexp, customRule CustomRule, severity rules.Severity, category rules.Category) []rules.Finding {
	var findings []rules.Finding
	content := string(workflow.Content)

	if workflow.Workflow.Permissions != nil {
		permStr := fmt.Sprintf("%v", workflow.Workflow.Permissions)
		for _, pattern := range patterns {
			if pattern.MatchString(permStr) {
				lineNumber := cre.findLineNumber(content, "permissions:", permStr)
				findings = append(findings, rules.Finding{
					RuleID:      customRule.ID,
					RuleName:    customRule.Name,
					Description: customRule.Description,
					Severity:    severity,
					Category:    category,
					FilePath:    workflow.Path,
					Evidence:    "permissions: " + permStr,
					LineNumber:  lineNumber,
					Remediation: customRule.Remediation,
				})
				break
			}
		}
	}

	return findings
}

// checkEvents checks workflow events against patterns
func (cre *CustomRuleEngine) checkEvents(workflow parser.WorkflowFile, patterns []*regexp.Regexp, customRule CustomRule, severity rules.Severity, category rules.Category) []rules.Finding {
	var findings []rules.Finding
	content := string(workflow.Content)

	onStr := fmt.Sprintf("%v", workflow.Workflow.On)
	for _, pattern := range patterns {
		if pattern.MatchString(onStr) {
			lineNumber := cre.findLineNumber(content, "on:", onStr)
			findings = append(findings, rules.Finding{
				RuleID:      customRule.ID,
				RuleName:    customRule.Name,
				Description: customRule.Description,
				Severity:    severity,
				Category:    category,
				FilePath:    workflow.Path,
				Evidence:    "on: " + onStr,
				LineNumber:  lineNumber,
				Remediation: customRule.Remediation,
			})
			break
		}
	}

	return findings
}

// checkContent checks entire workflow content against patterns
func (cre *CustomRuleEngine) checkContent(workflow parser.WorkflowFile, patterns []*regexp.Regexp, customRule CustomRule, severity rules.Severity, category rules.Category) []rules.Finding {
	var findings []rules.Finding
	content := string(workflow.Content)

	for _, pattern := range patterns {
		matches := pattern.FindAllStringIndex(content, -1)
		for _, match := range matches {
			matchStr := content[match[0]:match[1]]

			// Calculate line number
			lineNumber := 1
			for i := 0; i < match[0]; i++ {
				if content[i] == '\n' {
					lineNumber++
				}
			}

			findings = append(findings, rules.Finding{
				RuleID:      customRule.ID,
				RuleName:    customRule.Name,
				Description: customRule.Description,
				Severity:    severity,
				Category:    category,
				FilePath:    workflow.Path,
				Evidence:    matchStr,
				LineNumber:  lineNumber,
				Remediation: customRule.Remediation,
			})
		}
	}

	return findings
}

// findLineNumber finds the line number for a pattern in content
func (cre *CustomRuleEngine) findLineNumber(content, key, value string) int {
	lines := strings.Split(content, "\n")

	// Try to find key-value pattern first
	if key != "" && value != "" {
		searchPatterns := []string{
			key + " " + value,
			key + " '" + value + "'",
			key + " \"" + value + "\"",
		}

		for i, line := range lines {
			for _, pattern := range searchPatterns {
				if strings.Contains(line, pattern) {
					return i + 1
				}
			}
		}
	}

	// Fallback to just searching for the value
	if value != "" {
		for i, line := range lines {
			if strings.Contains(line, value) {
				return i + 1
			}
		}
	}

	return 1
}

// convertSeverity converts string severity to rules.Severity
func convertSeverity(severity string) (rules.Severity, error) {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return rules.Critical, nil
	case "HIGH":
		return rules.High, nil
	case "MEDIUM":
		return rules.Medium, nil
	case "LOW":
		return rules.Low, nil
	case "INFO":
		return rules.Info, nil
	default:
		return rules.Medium, fmt.Errorf("invalid severity: %s", severity)
	}
}

// convertCategory converts string category to rules.Category
func convertCategory(category string) (rules.Category, error) {
	switch strings.ToUpper(category) {
	case "MALICIOUS_PATTERN":
		return rules.MaliciousPattern, nil
	case "MISCONFIGURATION":
		return rules.Misconfiguration, nil
	case "SECRET_EXPOSURE":
		return rules.SecretExposure, nil
	case "SHELL_OBFUSCATION":
		return rules.ShellObfuscation, nil
	case "POLICY_VIOLATION":
		return rules.PolicyViolation, nil
	default:
		return rules.Misconfiguration, fmt.Errorf("invalid category: %s", category)
	}
}
