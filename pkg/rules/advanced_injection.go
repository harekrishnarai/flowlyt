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

package rules

import (
	"fmt"
	"regexp"

	"github.com/harekrishnarai/flowlyt/pkg/parser"
)

// AdvancedInjectionDetector detects obfuscated and indirect injection attacks
// Addresses Issue #17: Indirect and Obfuscated Injection Attacks Bypass Detection
type AdvancedInjectionDetector struct {
	// Base64 patterns
	base64Patterns []*regexp.Regexp

	// Variable indirection patterns
	varIndirectPatterns []*regexp.Regexp

	// Command substitution patterns
	cmdSubPatterns []*regexp.Regexp

	// Multi-stage injection patterns
	multiStagePatterns []*regexp.Regexp
}

// NewAdvancedInjectionDetector creates a new advanced injection detector
func NewAdvancedInjectionDetector() *AdvancedInjectionDetector {
	return &AdvancedInjectionDetector{
		base64Patterns: []*regexp.Regexp{
			// Base64 pipe to bash/sh
			regexp.MustCompile(`echo\s+[A-Za-z0-9+/=]+\s*\|\s*base64\s+(-d|--decode)\s*\|\s*(bash|sh|/bin/(ba)?sh)`),
			// Base64 with untrusted input
			regexp.MustCompile(`\$\{\{[^}]+\}\}\s*\|\s*base64`),
			// Suspicious base64 decode
			regexp.MustCompile(`base64\s+(-d|--decode).*\$\{\{`),
		},
		varIndirectPatterns: []*regexp.Regexp{
			// Variable assignment from untrusted + eval
			regexp.MustCompile(`(\w+)=.*\$\{\{[^}]+\}\}.*;\s*eval\s+\$\1`),
			// Variable assignment + execution
			regexp.MustCompile(`(\w+)=.*\$\{\{[^}]+\}\}.*;\s*\$\1`),
			// Variable assignment + source
			regexp.MustCompile(`(\w+)=.*\$\{\{[^}]+\}\}.*;\s*source\s+\$\1`),
		},
		cmdSubPatterns: []*regexp.Regexp{
			// Command substitution with untrusted input
			regexp.MustCompile(`\$\(.*\$\{\{[^}]+\}\}.*\)`),
			// Backtick command substitution
			regexp.MustCompile("`.*\\$\\{\\{[^}]+\\}\\}.*`"),
		},
		multiStagePatterns: []*regexp.Regexp{
			// Write to file then execute
			regexp.MustCompile(`echo.*\$\{\{[^}]+\}\}.*>\s*[\w/.-]+.*;\s*(bash|sh|source)`),
			// Curl/wget piped to execution
			regexp.MustCompile(`(curl|wget).*\$\{\{[^}]+\}\}.*\|\s*(bash|sh|python)`),
		},
	}
}

// DetectObfuscatedInjections scans for obfuscated injection attacks
func (d *AdvancedInjectionDetector) DetectObfuscatedInjections(workflow *parser.Workflow) []Finding {
	findings := []Finding{}

	// 1. Base64 encoded injections
	findings = append(findings, d.detectBase64Injection(workflow)...)

	// 2. Variable indirection
	findings = append(findings, d.detectVariableIndirection(workflow)...)

	// 3. Command substitution
	findings = append(findings, d.detectCommandSubstitution(workflow)...)

	// 4. Multi-stage injection
	findings = append(findings, d.detectMultiStageInjection(workflow)...)

	// 5. Heredoc injection
	findings = append(findings, d.detectHeredocInjection(workflow)...)

	return findings
}

// detectBase64Injection finds base64 encoded command injection
func (d *AdvancedInjectionDetector) detectBase64Injection(workflow *parser.Workflow) []Finding {
	findings := []Finding{}

	for jobName, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			// Check all base64 patterns
			for _, pattern := range d.base64Patterns {
				if pattern.MatchString(step.Run) {
					findings = append(findings, Finding{
						RuleID:      "OBFUSCATED_BASE64_INJECTION",
						RuleName:    "Obfuscated Command Injection via Base64",
						Severity:    "CRITICAL",
						Category:    "injection",
						Description: "Detected base64 encoded command injection with untrusted input. Base64 encoding is being used to obfuscate command injection. Attacker-controlled data is decoded and executed.",
						Remediation: "Never decode and execute base64 data from untrusted sources. Validate and sanitize all inputs.",
						FilePath:    workflow.Name,
						LineNumber:  0,
						JobName:     jobName,
						StepName:    step.Name,
						Evidence:    truncate(step.Run, 200),
					})
				}
			}
		}
	}

	return findings
}

// detectVariableIndirection finds variable indirection injection
func (d *AdvancedInjectionDetector) detectVariableIndirection(workflow *parser.Workflow) []Finding {
	findings := []Finding{}

	for jobName, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			// Check variable indirection patterns
			for _, pattern := range d.varIndirectPatterns {
				if matches := pattern.FindStringSubmatch(step.Run); matches != nil {
					varName := ""
					if len(matches) > 1 {
						varName = matches[1]
					}

					findings = append(findings, Finding{
						RuleID:      "VARIABLE_INDIRECTION_INJECTION",
						RuleName:        "Command Injection via Variable Indirection",
						Severity:    "CRITICAL",
						Category:    "injection",
						Description:     fmt.Sprintf("Detected command injection through variable '%s' indirection", varName),
						Remediation: "Avoid storing untrusted data in variables that are later executed. Use parameterized commands.",
						FilePath:        workflow.Name,
						LineNumber:        0,
						JobName:     jobName,
						StepName:    step.Name,
						Evidence:     truncate(step.Run, 200),
					})
				}
			}
		}
	}

	return findings
}

// detectCommandSubstitution finds command substitution injection
func (d *AdvancedInjectionDetector) detectCommandSubstitution(workflow *parser.Workflow) []Finding {
	findings := []Finding{}

	for jobName, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			// Check command substitution patterns
			for _, pattern := range d.cmdSubPatterns {
				if pattern.MatchString(step.Run) {
					findings = append(findings, Finding{
						RuleID:      "COMMAND_SUBSTITUTION_INJECTION",
						RuleName:        "Command Injection via Command Substitution",
						Severity:    "HIGH",
						Category:    "injection",
						Description:     "Detected command injection through command substitution $() or backticks",
						Remediation: "Never use untrusted data in command substitution. Use safe alternatives or proper escaping.",
						FilePath:        workflow.Name,
						LineNumber:        0,
						JobName:     jobName,
						StepName:    step.Name,
						Evidence:     truncate(step.Run, 200),
					})
				}
			}
		}
	}

	return findings
}

// detectMultiStageInjection finds multi-stage injection attacks
func (d *AdvancedInjectionDetector) detectMultiStageInjection(workflow *parser.Workflow) []Finding {
	findings := []Finding{}

	for jobName, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			// Check multi-stage patterns
			for _, pattern := range d.multiStagePatterns {
				if pattern.MatchString(step.Run) {
					findings = append(findings, Finding{
						RuleID:      "MULTI_STAGE_INJECTION",
						RuleName:        "Multi-Stage Command Injection",
						Severity:    "CRITICAL",
						Category:    "injection",
						Description:     "Detected multi-stage command injection (write then execute)",
						Remediation: "Avoid writing untrusted data to files that are later executed. Validate all inputs.",
						FilePath:        workflow.Name,
						LineNumber:        0,
						JobName:     jobName,
						StepName:    step.Name,
						Evidence:     truncate(step.Run, 200),
					})
				}
			}
		}
	}

	return findings
}

// detectHeredocInjection finds heredoc injection attacks
func (d *AdvancedInjectionDetector) detectHeredocInjection(workflow *parser.Workflow) []Finding {
	findings := []Finding{}

	heredocPattern := regexp.MustCompile(`<<\s*(\w+).*\$\{\{[^}]+\}\}.*\1`)

	for jobName, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			// Check for heredoc with untrusted input
			if heredocPattern.MatchString(step.Run) {
				findings = append(findings, Finding{
					RuleID:      "HEREDOC_INJECTION",
					RuleName:        "Command Injection via Heredoc",
					Severity:    "HIGH",
						Category:    "injection",
					Description:     "Detected command injection through heredoc with untrusted input",
					Remediation: "Use quoted heredocs (<<'EOF') to prevent variable expansion, or avoid untrusted data in heredocs.",
					FilePath:        workflow.Name,
					LineNumber:        0,
					JobName:     jobName,
					StepName:    step.Name,
					Evidence:     truncate(step.Run, 200),
				})
			}
		}
	}

	return findings
}

// Helper function to truncate long strings
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
