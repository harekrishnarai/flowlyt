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
	"regexp"
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/linenum"
	"github.com/harekrishnarai/flowlyt/pkg/parser"
)

// CheckShellInjectionVulnerabilities is the main entry point for shell injection checks
func CheckShellInjectionVulnerabilities(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	findings = append(findings, checkShellInjectionVulnerabilities(workflow)...)
	findings = append(findings, checkSelfHostedRunnerSecurity(workflow)...)
	findings = append(findings, checkScriptInjectionVulnerabilities(workflow)...)

	return findings
}

// checkShellInjectionVulnerabilities detects shell injection vulnerabilities in scripts
func checkShellInjectionVulnerabilities(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	// More specific patterns for shell injection detection that avoid common false positives
	shellInjectionPatterns := []string{
		// Eval with direct user input (high risk)
		`eval.*\$\{\{\s*(github\.event\.(issue\.(title|body)|pull_request\.(title|body)|comment\.body)|github\.head_ref)`,
		// Direct command execution with user-controlled input
		`(bash|sh|zsh)\s+-c\s+["'].*\$\{\{\s*(github\.event\.(issue|pull_request|comment)|github\.head_ref)`,
		// Dangerous piping of user input to shell
		`echo.*\$\{\{\s*(github\.event\.(issue|pull_request|comment)|github\.head_ref).*\|\s*(bash|sh|zsh)`,
	}

	// Less specific patterns that might have legitimate use but still worth flagging
	potentialPatterns := []string{
		// Command substitution with any user input (medium risk)
		`\$\([^)]*\$\{\{\s*github\.event\.[^}]*\}\}[^)]*\)`,
	}

	// Compile patterns
	var compiledHighRiskPatterns []*regexp.Regexp
	var compiledMediumRiskPatterns []*regexp.Regexp

	for _, pattern := range shellInjectionPatterns {
		if compiled, err := regexp.Compile(pattern); err == nil {
			compiledHighRiskPatterns = append(compiledHighRiskPatterns, compiled)
		}
	}

	for _, pattern := range potentialPatterns {
		if compiled, err := regexp.Compile(pattern); err == nil {
			compiledMediumRiskPatterns = append(compiledMediumRiskPatterns, compiled)
		}
	}

	// Check each job
	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			stepName := step.Name
			if stepName == "" {
				stepName = "Step " + string(rune('1'+stepIdx))
			}

			if step.Run != "" {
				// Check high-risk patterns first
				for _, pattern := range compiledHighRiskPatterns {
					if pattern.MatchString(step.Run) {
						pattern := linenum.FindPattern{
							Key:   "run",
							Value: step.Run,
						}
						lineResult := lineMapper.FindLineNumber(pattern)
						lineNumber := 0
						if lineResult != nil {
							lineNumber = lineResult.LineNumber
						}

						findings = append(findings, Finding{
							RuleID:      "SHELL_INJECTION",
							RuleName:    "Shell Injection Vulnerability",
							Description: "The script contains shell injection vulnerability where user input is executed directly in shell context",
							Severity:    Critical,
							Category:    InjectionAttack,
							FilePath:    workflow.Path,
							JobName:     jobName,
							StepName:    stepName,
							Evidence:    step.Run,
							Remediation: "Sanitize user input or use environment variables instead of direct interpolation in shell commands",
							LineNumber:  lineNumber,
						})
					}
				}

				// Check medium-risk patterns
				for _, pattern := range compiledMediumRiskPatterns {
					if pattern.MatchString(step.Run) {
						pattern := linenum.FindPattern{
							Key:   "run",
							Value: step.Run,
						}
						lineResult := lineMapper.FindLineNumber(pattern)
						lineNumber := 0
						if lineResult != nil {
							lineNumber = lineResult.LineNumber
						}

						findings = append(findings, Finding{
							RuleID:      "SHELL_INJECTION",
							RuleName:    "Shell Injection Vulnerability",
							Description: "The script contains potential shell injection where GitHub Actions expressions are used in command substitution",
							Severity:    High,
							Category:    InjectionAttack,
							FilePath:    workflow.Path,
							JobName:     jobName,
							StepName:    stepName,
							Evidence:    step.Run,
							Remediation: "Use environment variables or validate input before using in command substitution",
							LineNumber:  lineNumber,
						})
					}
				}

				// Check for dangerous command patterns
				dangerousCommands := []string{
					`curl.*\|.*bash`,
					`wget.*\|.*sh`,
					`echo.*\|.*sh`,
					`printf.*\|.*bash`,
				}

				for _, cmdPattern := range dangerousCommands {
					if matched, _ := regexp.MatchString(cmdPattern, step.Run); matched {
						// Check if it contains user input
						if strings.Contains(step.Run, "${{") {
							pattern := linenum.FindPattern{
								Key:   "run",
								Value: step.Run,
							}
							lineResult := lineMapper.FindLineNumber(pattern)
							lineNumber := 0
							if lineResult != nil {
								lineNumber = lineResult.LineNumber
							}

							findings = append(findings, Finding{
								RuleID:      "SHELL_INJECTION",
								RuleName:    "Dangerous Shell Command with User Input",
								Description: "The script executes potentially dangerous shell commands with user-controlled input",
								Severity:    High,
								Category:    InjectionAttack,
								FilePath:    workflow.Path,
								JobName:     jobName,
								StepName:    stepName,
								Evidence:    step.Run,
								Remediation: "Avoid piping user input directly to shell interpreters; validate and sanitize input first",
								LineNumber:  lineNumber,
							})
						}
					}
				}
			}
		}
	}

	return findings
}

// checkSelfHostedRunnerSecurity detects security issues with self-hosted runners
func checkSelfHostedRunnerSecurity(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Check if workflow can be triggered by pull requests from forks or other untrusted events
	isPRTriggered := isPullRequestTriggered(workflow)
	hasUntrustedTriggers := hasUntrustedWorkflowTriggers(workflow)

	// Check each job for self-hosted runner usage
	for jobName, job := range workflow.Workflow.Jobs {
		if isJobUsingSelfHostedRunner(job) {
			// Find line number for runs-on
			pattern := linenum.FindPattern{
				Key:   "runs-on",
				Value: getRunsOnValue(job),
			}
			lineResult := lineMapper.FindLineNumber(pattern)
			lineNumber := 0
			if lineResult != nil {
				lineNumber = lineResult.LineNumber
			}

			// Only flag self-hosted runners when they are exposed to untrusted triggers
			if isPRTriggered {
				findings = append(findings, Finding{
					RuleID:      "SELF_HOSTED_RUNNER_SECURITY",
					RuleName:    "Self-Hosted Runner Security Risk",
					Description: "Job uses self-hosted runner and can be triggered by pull requests, allowing potential code execution on your infrastructure",
					Severity:    Critical,
					Category:    AccessControl,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    "",
					Evidence:    getRunsOnValue(job),
					Remediation: "Consider using GitHub-hosted runners for public repositories, or restrict self-hosted runners to trusted events only",
					LineNumber:  lineNumber,
				})
			} else if hasUntrustedTriggers {
				findings = append(findings, Finding{
					RuleID:      "SELF_HOSTED_RUNNER_SECURITY",
					RuleName:    "Self-Hosted Runner Security Risk",
					Description: "Job uses self-hosted runner with potentially untrusted triggers, which may have security implications",
					Severity:    Medium,
					Category:    AccessControl,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    "",
					Evidence:    getRunsOnValue(job),
					Remediation: "Review trigger events and consider using GitHub-hosted runners for workflows triggered by external events",
					LineNumber:  lineNumber,
				})
			}
			// If the workflow only has trusted triggers (push, workflow_dispatch to main branch, etc.),
			// don't flag the self-hosted runner as a security risk
		}
	}

	return findings
}

// isPullRequestTriggered checks if workflow can be triggered by pull requests
func isPullRequestTriggered(workflow parser.WorkflowFile) bool {
	prEvents := []string{
		"pull_request",
		"pull_request_target",
		"pull_request_review",
		"pull_request_review_comment",
	}

	if workflow.Workflow.On == nil {
		return false
	}

	switch on := workflow.Workflow.On.(type) {
	case string:
		for _, event := range prEvents {
			if on == event {
				return true
			}
		}
	case []interface{}:
		for _, eventInterface := range on {
			if eventStr, ok := eventInterface.(string); ok {
				for _, event := range prEvents {
					if eventStr == event {
						return true
					}
				}
			}
		}
	case map[interface{}]interface{}:
		for eventInterface := range on {
			if eventStr, ok := eventInterface.(string); ok {
				for _, event := range prEvents {
					if eventStr == event {
						return true
					}
				}
			}
		}
	case map[string]interface{}:
		for eventStr := range on {
			for _, event := range prEvents {
				if eventStr == event {
					return true
				}
			}
		}
	}

	return false
}

// hasUntrustedWorkflowTriggers checks if workflow has triggers that might be untrusted
func hasUntrustedWorkflowTriggers(workflow parser.WorkflowFile) bool {
	// Events that might be triggered by external or untrusted sources
	untrustedEvents := []string{
		"issues",
		"issue_comment",
		"repository_dispatch",
		"workflow_run",
		"schedule", // While not untrusted per se, scheduled jobs on self-hosted can be concerning
		"discussion",
		"discussion_comment",
		"public", // Repository made public
		"gollum", // Wiki updates
	}

	if workflow.Workflow.On == nil {
		return false
	}

	switch on := workflow.Workflow.On.(type) {
	case string:
		for _, event := range untrustedEvents {
			if on == event {
				return true
			}
		}
	case []interface{}:
		for _, eventInterface := range on {
			if eventStr, ok := eventInterface.(string); ok {
				for _, event := range untrustedEvents {
					if eventStr == event {
						return true
					}
				}
			}
		}
	case map[interface{}]interface{}:
		for eventInterface := range on {
			if eventStr, ok := eventInterface.(string); ok {
				for _, event := range untrustedEvents {
					if eventStr == event {
						return true
					}
				}
			}
		}
	case map[string]interface{}:
		for eventStr := range on {
			for _, event := range untrustedEvents {
				if eventStr == event {
					return true
				}
			}
		}
	}

	return false
}

// isJobUsingSelfHostedRunner checks if a job uses self-hosted runners
func isJobUsingSelfHostedRunner(job parser.Job) bool {
	// GitHub-hosted runner labels
	githubHostedRunners := map[string]bool{
		"ubuntu-latest":          true,
		"ubuntu-20.04":           true,
		"ubuntu-18.04":           true,
		"ubuntu-22.04":           true,
		"windows-latest":         true,
		"windows-2019":           true,
		"windows-2022":           true,
		"macos-latest":           true,
		"macos-11":               true,
		"macos-12":               true,
		"macos-13":               true,
		"macos-latest-large":     true,
		"ubuntu-latest-4-cores":  true,
		"ubuntu-latest-8-cores":  true,
		"ubuntu-latest-16-cores": true,
	}

	switch runsOn := job.RunsOn.(type) {
	case string:
		// Handle matrix expressions like ${{ matrix.os }}
		if strings.Contains(runsOn, "${{") && strings.Contains(runsOn, "matrix") {
			// For matrix expressions, be conservative and don't flag as self-hosted
			// unless we can definitively determine otherwise
			return false
		}
		return !githubHostedRunners[runsOn]
	case []interface{}:
		for _, runner := range runsOn {
			if runnerStr, ok := runner.(string); ok {
				if strings.Contains(runnerStr, "${{") && strings.Contains(runnerStr, "matrix") {
					return false // Conservative approach for matrix runners
				}
				if !githubHostedRunners[runnerStr] {
					return true
				}
			}
		}
	}

	return false
}

// getRunsOnValue returns the runs-on value as a string for evidence
func getRunsOnValue(job parser.Job) string {
	switch runsOn := job.RunsOn.(type) {
	case string:
		return runsOn
	case []interface{}:
		var runners []string
		for _, runner := range runsOn {
			if runnerStr, ok := runner.(string); ok {
				runners = append(runners, runnerStr)
			}
		}
		return strings.Join(runners, ", ")
	default:
		return "Unknown runner configuration"
	}
}

// checkScriptInjectionVulnerabilities detects inline script injection vulnerabilities
func checkScriptInjectionVulnerabilities(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Check each job
	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			stepName := step.Name
			if stepName == "" {
				stepName = "Step " + string(rune('1'+stepIdx))
			}

			// Check for dangerous script injection in github-script action
			if strings.HasPrefix(step.Uses, "actions/github-script@") && step.With != nil {
				if script, ok := step.With["script"].(string); ok {
					// Look for dangerous patterns in JavaScript
					dangerousPatterns := []string{
						// Direct eval with user input
						`eval\s*\(\s*.*\$\{\{[^}]*\}\}.*\)`,
						// Function constructor with user input
						`new\s+Function\s*\(\s*.*\$\{\{[^}]*\}\}.*\)`,
						// Dynamic require/import with user input
						`require\s*\(\s*.*\$\{\{[^}]*\}\}.*\)`,
						`import\s*\(\s*.*\$\{\{[^}]*\}\}.*\)`,
						// Process execution with user input
						`exec\s*\(\s*.*\$\{\{[^}]*\}\}.*\)`,
						`spawn\s*\(\s*.*\$\{\{[^}]*\}\}.*\)`,
					}

					for _, pattern := range dangerousPatterns {
						if matched, _ := regexp.MatchString(pattern, script); matched {
							pattern := linenum.FindPattern{
								Key:   "script",
								Value: script,
							}
							lineResult := lineMapper.FindLineNumber(pattern)
							lineNumber := 0
							if lineResult != nil {
								lineNumber = lineResult.LineNumber
							}

							findings = append(findings, Finding{
								RuleID:      "SCRIPT_INJECTION",
								RuleName:    "Script Injection Vulnerability",
								Description: "The github-script action contains dangerous patterns that could lead to script injection",
								Severity:    Critical,
								Category:    InjectionAttack,
								FilePath:    workflow.Path,
								JobName:     jobName,
								StepName:    stepName,
								Evidence:    script,
								Remediation: "Avoid using eval, Function constructor, or dynamic imports with user input; use safe alternatives",
								LineNumber:  lineNumber,
							})
							break
						}
					}
				}
			}

			// Check for PowerShell injection in Windows runners
			if step.Shell == "powershell" || step.Shell == "pwsh" {
				if step.Run != "" && strings.Contains(step.Run, "${{") {
					// PowerShell injection patterns
					powershellPatterns := []string{
						`Invoke-Expression.*\$\{\{[^}]*\}\}`,
						`Invoke-Command.*\$\{\{[^}]*\}\}`,
						`&\s*\$\{\{[^}]*\}\}`,
						`\.\s*\$\{\{[^}]*\}\}`,
					}

					for _, pattern := range powershellPatterns {
						if matched, _ := regexp.MatchString(pattern, step.Run); matched {
							pattern := linenum.FindPattern{
								Key:   "run",
								Value: step.Run,
							}
							lineResult := lineMapper.FindLineNumber(pattern)
							lineNumber := 0
							if lineResult != nil {
								lineNumber = lineResult.LineNumber
							}

							findings = append(findings, Finding{
								RuleID:      "SCRIPT_INJECTION",
								RuleName:    "PowerShell Injection Vulnerability",
								Description: "The PowerShell script contains injection vulnerability with user-controlled input",
								Severity:    Critical,
								Category:    InjectionAttack,
								FilePath:    workflow.Path,
								JobName:     jobName,
								StepName:    stepName,
								Evidence:    step.Run,
								Remediation: "Use PowerShell parameters or environment variables instead of direct string interpolation",
								LineNumber:  lineNumber,
							})
							break
						}
					}
				}
			}
		}
	}

	return findings
}
