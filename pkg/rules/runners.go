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

// checkRunnerLabels validates GitHub-hosted and self-hosted runner labels
func checkRunnerLabels(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Known GitHub-hosted runner labels
	githubHostedRunners := map[string]bool{
		"ubuntu-latest":  true,
		"ubuntu-22.04":   true,
		"ubuntu-20.04":   true,
		"windows-latest": true,
		"windows-2022":   true,
		"windows-2019":   true,
		"macos-latest":   true,
		"macos-13":       true,
		"macos-12":       true,
		"macos-11":       true,
	}

	for jobName, job := range workflow.Workflow.Jobs {
		runsOnStr := ""

		// Handle both string and array formats for runs-on
		switch runsOn := job.RunsOn.(type) {
		case string:
			runsOnStr = runsOn
		case []interface{}:
			if len(runsOn) > 0 {
				if str, ok := runsOn[0].(string); ok {
					runsOnStr = str
				}
			}
		}

		if runsOnStr != "" {
			// Check for suspicious self-hosted runner patterns
			suspiciousPatterns := []*regexp.Regexp{
				regexp.MustCompile(`(?i)self-hosted.*production`),
				regexp.MustCompile(`(?i)self-hosted.*internal`),
				regexp.MustCompile(`(?i)self-hosted.*private`),
				regexp.MustCompile(`(?i)runner-\d+`), // Generic numbered runners
			}

			for _, pattern := range suspiciousPatterns {
				if pattern.MatchString(runsOnStr) {
					lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
						Key:   "runs-on",
						Value: runsOnStr,
					})

					lineNumber := 0
					if lineResult != nil {
						lineNumber = lineResult.LineNumber
					}

					findings = append(findings, Finding{
						RuleID:      "RUNNER_LABEL_VALIDATION",
						RuleName:    "Runner Label Validation",
						Description: "Potentially insecure self-hosted runner configuration detected",
						Severity:    Medium,
						Category:    Misconfiguration,
						FilePath:    workflow.Path,
						JobName:     jobName,
						Evidence:    runsOnStr,
						LineNumber:  lineNumber,
						Remediation: "Use specific, well-managed self-hosted runner labels or GitHub-hosted runners",
					})
				}
			}

			// Check for unknown runner labels (not GitHub-hosted and not self-hosted format).
			// Skip dynamic matrix expressions like ${{ matrix.os }} — these are valid at runtime.
			if !githubHostedRunners[runsOnStr] && !strings.Contains(runsOnStr, "self-hosted") && !strings.Contains(runsOnStr, "${{") {
				lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
					Key:   "runs-on",
					Value: runsOnStr,
				})

				lineNumber := 0
				if lineResult != nil {
					lineNumber = lineResult.LineNumber
				}

				findings = append(findings, Finding{
					RuleID:      "RUNNER_LABEL_VALIDATION",
					RuleName:    "Runner Label Validation",
					Description: "Unknown runner label that may not exist or be misconfigured",
					Severity:    Low,
					Category:    Misconfiguration,
					FilePath:    workflow.Path,
					JobName:     jobName,
					Evidence:    runsOnStr,
					LineNumber:  lineNumber,
					Remediation: "Verify runner label exists and is properly configured",
				})
			}
		}
	}

	return findings
}

// checkBotIdentity checks for if statements based on bot identity
func checkBotIdentity(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Patterns for bot identity checks that could be exploited
	botPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)github\.actor\s*==\s*['"]dependabot\[bot\]['"]`),
		regexp.MustCompile(`(?i)github\.actor\s*==\s*['"]renovate\[bot\]['"]`),
		regexp.MustCompile(`(?i)github\.actor\s*!=\s*['"]dependabot\[bot\]['"]`),
		regexp.MustCompile(`(?i)github\.actor\s*!=\s*['"]renovate\[bot\]['"]`),
		regexp.MustCompile(`(?i)contains\(github\.actor,\s*['"]bot['"]`),
		regexp.MustCompile(`(?i)endswith\(github\.actor,\s*['"]\[bot\]['"]`),
	}

	for jobName, job := range workflow.Workflow.Jobs {
		// Check job-level if conditions
		if job.If != "" {
			for _, pattern := range botPatterns {
				if pattern.MatchString(job.If) {
					lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
						Key:   "if",
						Value: job.If,
					})

					lineNumber := 0
					if lineResult != nil {
						lineNumber = lineResult.LineNumber
					}

					findings = append(findings, Finding{
						RuleID:      "BOT_IDENTITY_CHECK",
						RuleName:    "Bot Identity Check",
						Description: "Bot identity check in if statement may be exploitable by attackers",
						Severity:    Medium,
						Category:    AccessControl,
						FilePath:    workflow.Path,
						JobName:     jobName,
						Evidence:    strings.TrimSpace(job.If),
						LineNumber:  lineNumber,
						Remediation: "Use more specific conditions or validate bot identity through other means",
					})
				}
			}
		}

		// Check step-level if conditions
		for _, step := range job.Steps {
			if step.If != "" {
				for _, pattern := range botPatterns {
					if pattern.MatchString(step.If) {
						lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
							Key:   "if",
							Value: step.If,
						})

						lineNumber := 0
						if lineResult != nil {
							lineNumber = lineResult.LineNumber
						}

						findings = append(findings, Finding{
							RuleID:      "BOT_IDENTITY_CHECK",
							RuleName:    "Bot Identity Check",
							Description: "Bot identity check in step if condition may be exploitable",
							Severity:    Medium,
							Category:    AccessControl,
							FilePath:    workflow.Path,
							JobName:     jobName,
							StepName:    step.Name,
							Evidence:    strings.TrimSpace(step.If),
							LineNumber:  lineNumber,
							Remediation: "Use more specific conditions or validate bot identity through other means",
						})
					}
				}
			}
		}
	}

	return findings
}
