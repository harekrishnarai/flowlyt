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
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/linenum"
	"github.com/harekrishnarai/flowlyt/pkg/parser"
)

// checkDebugArtifacts detects workflows that upload artifacts
func checkDebugArtifacts(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Look for artifact upload actions
	artifactActions := []string{
		"actions/upload-artifact",
		"actions/download-artifact",
	}

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Uses != "" {
				for _, action := range artifactActions {
					if strings.Contains(step.Uses, action) {
						lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
							Key:   "uses",
							Value: step.Uses,
						})

						lineNumber := 0
						if lineResult != nil {
							lineNumber = lineResult.LineNumber
						}

						findings = append(findings, Finding{
							RuleID:      "DEBUG_ARTIFACTS_UPLOAD",
							RuleName:    "Debug Artifacts Upload",
							Description: "Workflow uploads or downloads artifacts which may contain sensitive data",
							Severity:    Info,
							Category:    DataExposure,
							FilePath:    workflow.Path,
							JobName:     jobName,
							StepName:    step.Name,
							Evidence:    step.Uses,
							LineNumber:  lineNumber,
							Remediation: "Review artifact contents to ensure no sensitive data is exposed",
						})
					}
				}
			}
		}
	}

	return findings
}

// checkDebugJsExecution detects JavaScript execution of system commands
func checkDebugJsExecution(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Patterns for JavaScript system command execution
	jsExecPatterns := []*regexp.Regexp{
		regexp.MustCompile(`require\(['"]child_process['"]\)`),
		regexp.MustCompile(`\.exec\(`),
		regexp.MustCompile(`\.spawn\(`),
		regexp.MustCompile(`\.execSync\(`),
		regexp.MustCompile(`\.spawnSync\(`),
		regexp.MustCompile(`process\.exec`),
		regexp.MustCompile(`import.*child_process`),
		regexp.MustCompile(`from.*child_process`),
	}

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			// Check JavaScript actions (actions that use JavaScript)
			if step.Uses != "" && strings.Contains(step.Uses, "actions/github-script") {
				// Check the script content for system command execution
				if step.With != nil {
					if script, exists := step.With["script"]; exists {
						scriptStr := fmt.Sprintf("%v", script)

						for _, pattern := range jsExecPatterns {
							if pattern.MatchString(scriptStr) {
								lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
									Key:   "script",
									Value: scriptStr,
								})

								lineNumber := 0
								if lineResult != nil {
									lineNumber = lineResult.LineNumber
								}

								findings = append(findings, Finding{
									RuleID:      "DEBUG_JS_EXECUTION",
									RuleName:    "Debug JavaScript Execution",
									Description: "JavaScript script executes system commands which may be dangerous",
									Severity:    Medium,
									Category:    InjectionAttack,
									FilePath:    workflow.Path,
									JobName:     jobName,
									StepName:    step.Name,
									Evidence:    strings.TrimSpace(scriptStr),
									LineNumber:  lineNumber,
									Remediation: "Avoid executing system commands in JavaScript scripts, use safer alternatives",
								})
							}
						}
					}
				}
			}

			// Also check run commands that might contain JavaScript execution
			if step.Run != "" {
				for _, pattern := range jsExecPatterns {
					if pattern.MatchString(step.Run) {
						lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
							Key:   "run",
							Value: step.Run,
						})

						lineNumber := 0
						if lineResult != nil {
							lineNumber = lineResult.LineNumber
						}

						findings = append(findings, Finding{
							RuleID:      "DEBUG_JS_EXECUTION",
							RuleName:    "Debug JavaScript Execution",
							Description: "Script contains JavaScript system command execution patterns",
							Severity:    Medium,
							Category:    InjectionAttack,
							FilePath:    workflow.Path,
							JobName:     jobName,
							StepName:    step.Name,
							Evidence:    strings.TrimSpace(step.Run),
							LineNumber:  lineNumber,
							Remediation: "Review JavaScript system command usage for potential security risks",
						})
					}
				}
			}
		}
	}

	return findings
}

// checkDebugOidcActions detects workflows that use OIDC token authentication
func checkDebugOidcActions(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// OIDC-related patterns
	oidcPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)id-token:\s*write`),
		regexp.MustCompile(`(?i)ACTIONS_ID_TOKEN_REQUEST_TOKEN`),
		regexp.MustCompile(`(?i)ACTIONS_ID_TOKEN_REQUEST_URL`),
		regexp.MustCompile(`(?i)aws-actions/configure-aws-credentials`),
		regexp.MustCompile(`(?i)azure/login`),
		regexp.MustCompile(`(?i)google-github-actions/auth`),
	}

	// Check job permissions for id-token
	for jobName, job := range workflow.Workflow.Jobs {
		if job.Permissions != nil {
			if permMap, ok := job.Permissions.(map[string]interface{}); ok {
				if idTokenValue, exists := permMap["id-token"]; exists {
					if idToken, ok := idTokenValue.(string); ok && idToken == "write" {
						lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
							Key:   "id-token",
							Value: "write",
						})

						lineNumber := 0
						if lineResult != nil {
							lineNumber = lineResult.LineNumber
						}

						findings = append(findings, Finding{
							RuleID:      "DEBUG_OIDC_ACTIONS",
							RuleName:    "Debug OIDC Actions",
							Description: "Workflow uses OIDC token authentication with id-token: write permission",
							Severity:    Info,
							Category:    AccessControl,
							FilePath:    workflow.Path,
							JobName:     jobName,
							Evidence:    "id-token: write",
							LineNumber:  lineNumber,
							Remediation: "Ensure OIDC token usage is properly scoped and necessary",
						})
					}
				}
			}
		}

		// Check steps for OIDC-related actions and environment variables
		for _, step := range job.Steps {
			if step.Uses != "" {
				for _, pattern := range oidcPatterns {
					if pattern.MatchString(step.Uses) {
						lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
							Key:   "uses",
							Value: step.Uses,
						})

						lineNumber := 0
						if lineResult != nil {
							lineNumber = lineResult.LineNumber
						}

						findings = append(findings, Finding{
							RuleID:      "DEBUG_OIDC_ACTIONS",
							RuleName:    "Debug OIDC Actions",
							Description: "Workflow uses OIDC-enabled action for cloud authentication",
							Severity:    Info,
							Category:    AccessControl,
							FilePath:    workflow.Path,
							JobName:     jobName,
							StepName:    step.Name,
							Evidence:    step.Uses,
							LineNumber:  lineNumber,
							Remediation: "Verify OIDC configuration is secure and follows best practices",
						})
					}
				}
			}

			// Check environment variables for OIDC tokens
			if step.Env != nil {
				for envKey := range step.Env {
					for _, pattern := range oidcPatterns {
						if pattern.MatchString(envKey) {
							lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
								Key:   envKey,
								Value: "",
							})

							lineNumber := 0
							if lineResult != nil {
								lineNumber = lineResult.LineNumber
							}

							findings = append(findings, Finding{
								RuleID:      "DEBUG_OIDC_ACTIONS",
								RuleName:    "Debug OIDC Actions",
								Description: "Workflow references OIDC token environment variables",
								Severity:    Info,
								Category:    AccessControl,
								FilePath:    workflow.Path,
								JobName:     jobName,
								StepName:    step.Name,
								Evidence:    envKey,
								LineNumber:  lineNumber,
								Remediation: "Ensure OIDC token environment variables are used securely",
							})
						}
					}
				}
			}
		}
	}

	// Check workflow-level permissions
	if workflow.Workflow.Permissions != nil {
		if permMap, ok := workflow.Workflow.Permissions.(map[string]interface{}); ok {
			if idTokenValue, exists := permMap["id-token"]; exists {
				if idToken, ok := idTokenValue.(string); ok && idToken == "write" {
					lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
						Key:   "id-token",
						Value: "write",
					})

					lineNumber := 0
					if lineResult != nil {
						lineNumber = lineResult.LineNumber
					}

					findings = append(findings, Finding{
						RuleID:      "DEBUG_OIDC_ACTIONS",
						RuleName:    "Debug OIDC Actions",
						Description: "Workflow has global id-token: write permission for OIDC authentication",
						Severity:    Info,
						Category:    AccessControl,
						FilePath:    workflow.Path,
						Evidence:    "id-token: write (global)",
						LineNumber:  lineNumber,
						Remediation: "Consider limiting id-token permissions to specific jobs that need OIDC",
					})
				}
			}
		}
	}

	return findings
}
