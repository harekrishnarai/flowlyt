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

// prtCheckoutRisk classifies the risk level of a pull_request_target + checkout combination.
type prtCheckoutRisk int

const (
	prtNoCheckout   prtCheckoutRisk = iota // no checkout step at all
	prtBaseCheckout                        // checkout without an untrusted ref (defaults to base branch)
	prtHeadCheckout                        // checkout of head.sha or head.ref — CRITICAL
)

// untrustedHeadRefPat matches expressions that resolve to the attacker-controlled PR head.
var untrustedHeadRefPat = regexp.MustCompile(
	`\$\{\{\s*(github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref)\s*\}\}`,
)

// classifyPRTCheckout scans the steps of a job and returns the highest checkout risk seen.
func classifyPRTCheckout(steps []parser.Step) prtCheckoutRisk {
	risk := prtNoCheckout
	for _, step := range steps {
		if !strings.HasPrefix(step.Uses, "actions/checkout") {
			continue
		}
		// Found a checkout step — at least base-checkout risk.
		if risk < prtBaseCheckout {
			risk = prtBaseCheckout
		}
		// Check whether the ref parameter points at the untrusted PR head.
		if step.With != nil {
			if ref, ok := step.With["ref"].(string); ok {
				if untrustedHeadRefPat.MatchString(ref) {
					return prtHeadCheckout
				}
			}
		}
	}
	return risk
}

// checkInsecurePullRequestTarget checks for insecure pull_request_target usage
func checkInsecurePullRequestTarget(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	// Check if workflow uses pull_request_target event
	usesPullRequestTarget := false

	switch on := workflow.Workflow.On.(type) {
	case string:
		usesPullRequestTarget = on == "pull_request_target"
	case map[string]interface{}:
		_, usesPullRequestTarget = on["pull_request_target"]
	case []interface{}:
		for _, event := range on {
			if eventStr, ok := event.(string); ok && eventStr == "pull_request_target" {
				usesPullRequestTarget = true
				break
			}
		}
	}

	if !usesPullRequestTarget {
		return findings
	}

	// Evaluate risk per job and emit one finding per job.
	for jobName, job := range workflow.Workflow.Jobs {
		risk := classifyPRTCheckout(job.Steps)

		var severity Severity
		var evidence string

		switch risk {
		case prtHeadCheckout:
			severity = Critical
			evidence = "pull_request_target with checkout of untrusted PR head ref (head.sha/head.ref/github.head_ref)"
		case prtBaseCheckout:
			severity = Medium
			evidence = "pull_request_target with checkout (no untrusted ref — checks out base branch)"
		case prtNoCheckout:
			// No-checkout PRT workflows (labelers, commenters) are safe by design.
			// Emitting an Info finding per job pollutes reports without actionable value.
			continue
		}

		// Find a representative line number (first checkout step, or step 0).
		lineNumber := 0
		for _, step := range job.Steps {
			if strings.HasPrefix(step.Uses, "actions/checkout") {
				lineNumber = findLineNumberWithMapper(workflow, step.Name, "uses: "+step.Uses)
				break
			}
		}

		findings = append(findings, Finding{
			RuleID:      "INSECURE_PULL_REQUEST_TARGET",
			RuleName:    "Insecure pull_request_target usage",
			Description: "Workflow uses pull_request_target event and checks out PR code, which can lead to code execution with write permissions",
			Severity:    severity,
			Category:    Misconfiguration,
			FilePath:    workflow.Path,
			JobName:     jobName,
			LineNumber:  lineNumber,
			Evidence:    evidence,
			Remediation: "Use pull_request event instead, or don't checkout PR code with pull_request_target",
		})
	}

	return findings
}

// checkPRTargetAbuse checks for dangerous usage of pull_request_target trigger
func checkPRTargetAbuse(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Check if pull_request_target is used (handle different On types)
	hasPRTarget := false
	switch on := workflow.Workflow.On.(type) {
	case string:
		hasPRTarget = on == "pull_request_target"
	case map[string]interface{}:
		_, hasPRTarget = on["pull_request_target"]
	case []interface{}:
		for _, event := range on {
			if eventStr, ok := event.(string); ok && eventStr == "pull_request_target" {
				hasPRTarget = true
				break
			}
		}
	}

	if !hasPRTarget {
		return findings // No pull_request_target trigger found
	}

	// Check for dangerous patterns with pull_request_target
	for jobName, job := range workflow.Workflow.Jobs {
		// Check for write permissions
		if job.Permissions != nil {
			if perms, ok := job.Permissions.(map[string]interface{}); ok {
				for permission, levelInterface := range perms {
					if level, ok := levelInterface.(string); ok {
						if (permission == "contents" || permission == "actions" || permission == "packages") && level == "write" {
							lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
								Key:   permission,
								Value: level,
							})

							lineNumber := 0
							if lineResult != nil {
								lineNumber = lineResult.LineNumber
							}

							findings = append(findings, Finding{
								RuleID:      "PR_TARGET_ABUSE",
								RuleName:    "Pull Request Target Abuse",
								Description: "pull_request_target with write permissions allows untrusted code to access secrets and write to repository",
								Severity:    Critical,
								Category:    AccessControl,
								FilePath:    workflow.Path,
								JobName:     jobName,
								StepName:    "",
								Evidence:    fmt.Sprintf("pull_request_target trigger with %s: %s permission", permission, level),
								LineNumber:  lineNumber,
								Remediation: "Use pull_request trigger instead, or implement proper security controls before accessing secrets",
							})
						}
					}
				}
			}
		}

		// Check for secret usage in steps
		for _, step := range job.Steps {
			if step.With != nil {
				for key, valueInterface := range step.With {
					if value, ok := valueInterface.(string); ok {
						// GITHUB_TOKEN is an auto-provisioned built-in token, not a user secret —
						// using it in a labeler or commenter workflow is standard practice.
						if strings.Contains(value, "${{ secrets.GITHUB_TOKEN") {
							continue
						}
						if strings.Contains(value, "${{ secrets.") {
							lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
								Key:   key,
								Value: value,
							})

							lineNumber := 0
							if lineResult != nil {
								lineNumber = lineResult.LineNumber
							}

							findings = append(findings, Finding{
								RuleID:      "PR_TARGET_ABUSE",
								RuleName:    "Pull Request Target Abuse",
								Description: "pull_request_target trigger with secret access allows untrusted pull requests to access sensitive data",
								Severity:    Critical,
								Category:    AccessControl,
								FilePath:    workflow.Path,
								JobName:     jobName,
								StepName:    step.Name,
								Evidence:    fmt.Sprintf("Secret access in pull_request_target: %s", value),
								LineNumber:  lineNumber,
								Remediation: "Use pull_request trigger or implement proper authorization checks before accessing secrets",
							})
						}
					}
				}
			}

			// Check for secret usage in environment variables
			for envKey, envValue := range step.Env {
				if strings.Contains(envValue, "${{ secrets.") {
					lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
						Key:   envKey,
						Value: envValue,
					})

					lineNumber := 0
					if lineResult != nil {
						lineNumber = lineResult.LineNumber
					}

					findings = append(findings, Finding{
						RuleID:      "PR_TARGET_ABUSE",
						RuleName:    "Pull Request Target Abuse",
						Description: "pull_request_target trigger with secret access in environment variables",
						Severity:    Critical,
						Category:    AccessControl,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    step.Name,
						Evidence:    fmt.Sprintf("Secret in env var: %s = %s", envKey, envValue),
						LineNumber:  lineNumber,
						Remediation: "Use pull_request trigger or implement proper authorization checks before accessing secrets",
					})
				}
			}
		}
	}

	return findings
}

// checkArtifactPoisoning checks for potentially malicious artifact patterns
func checkArtifactPoisoning(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			// Check for artifact upload actions
			if step.Uses != "" && strings.Contains(step.Uses, "actions/upload-artifact") {
				// Check for suspicious artifact patterns
				if step.With != nil {
					if pathInterface, exists := step.With["path"]; exists {
						if path, ok := pathInterface.(string); ok {
							// Check for dangerous absolute paths — must start with the dangerous prefix
							// (avoids false positives on relative paths like "dist/*.tar.gz" which
							// contain "/" as a path separator but are not absolute system paths).
							dangerousPaths := []string{
								"/", "~", "~/", "$HOME",
								"/etc/", "/usr/", "/bin/", "/sbin/",
								"C:\\", "C:\\Windows", "C:\\Program Files",
							}

							var matchedDangerous string
							for _, dangerousPath := range dangerousPaths {
								// Use HasPrefix so "dist/*.tar.gz" doesn't match "/"
								for _, line := range strings.Split(path, "\n") {
									line = strings.TrimSpace(line)
									if strings.HasPrefix(line, dangerousPath) {
										matchedDangerous = line
										break
									}
								}
								if matchedDangerous != "" {
									break
								}
							}

							if matchedDangerous != "" {
								lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
									Key:   "path",
									Value: path,
								})

								lineNumber := 0
								if lineResult != nil {
									lineNumber = lineResult.LineNumber
								}

								findings = append(findings, Finding{
									RuleID:      "ARTIFACT_POISONING",
									RuleName:    "Artifact Poisoning",
									Description: "Artifact upload includes dangerous system paths that could expose sensitive files",
									Severity:    High,
									Category:    SupplyChain,
									FilePath:    workflow.Path,
									JobName:     jobName,
									StepName:    step.Name,
									Evidence:    fmt.Sprintf("Dangerous artifact path: %s", matchedDangerous),
									LineNumber:  lineNumber,
									Remediation: "Restrict artifact uploads to specific, safe directories only",
								})
							}

							// Check for overly broad patterns (exact match against each line of a multi-line path)
							broadPatterns := []string{"*", "**", "**/*", "."}
							var matchedBroad string
							for _, line := range strings.Split(path, "\n") {
								line = strings.TrimSpace(line)
								for _, pattern := range broadPatterns {
									if line == pattern {
										matchedBroad = line
										break
									}
								}
								if matchedBroad != "" {
									break
								}
							}

							if matchedBroad != "" {
								lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
									Key:   "path",
									Value: path,
								})

								lineNumber := 0
								if lineResult != nil {
									lineNumber = lineResult.LineNumber
								}

								findings = append(findings, Finding{
									RuleID:      "ARTIFACT_POISONING",
									RuleName:    "Artifact Poisoning",
									Description: "Artifact upload uses overly broad patterns that may include sensitive files",
									Severity:    Medium,
									Category:    SupplyChain,
									FilePath:    workflow.Path,
									JobName:     jobName,
									StepName:    step.Name,
									Evidence:    fmt.Sprintf("Broad artifact pattern: %s", matchedBroad),
									LineNumber:  lineNumber,
									Remediation: "Use specific file patterns instead of broad wildcards for artifact uploads",
								})
							}
						}
					}
				}
			}

			// Check for artifact download actions
			if step.Uses != "" && strings.Contains(step.Uses, "actions/download-artifact") {
				// Check for unsafe download patterns
				if step.With != nil {
					if nameInterface, exists := step.With["name"]; exists {
						if name, ok := nameInterface.(string); ok {
							// Check for user-controlled artifact names - but only flag if triggered by untrusted events
							if strings.Contains(name, "${{ github.event.") || strings.Contains(name, "${{ inputs.") {
								// Only flag this as a security issue if the workflow can be triggered by untrusted events
								if hasUntrustedWorkflowTriggersForArtifacts(workflow) {
									lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
										Key:   "name",
										Value: name,
									})

									lineNumber := 0
									if lineResult != nil {
										lineNumber = lineResult.LineNumber
									}

									findings = append(findings, Finding{
										RuleID:      "ARTIFACT_POISONING",
										RuleName:    "Artifact Poisoning",
										Description: "Artifact download uses user-controlled input for artifact name in a workflow that can be triggered by untrusted events, which could lead to path traversal",
										Severity:    High,
										Category:    SupplyChain,
										FilePath:    workflow.Path,
										JobName:     jobName,
										StepName:    step.Name,
										Evidence:    fmt.Sprintf("User-controlled artifact name in untrusted context: %s", name),
										LineNumber:  lineNumber,
										Remediation: "Validate and sanitize artifact names, use predefined artifact names only, or restrict workflow to trusted triggers",
									})
								}
								// If only triggered by trusted events (push to main, workflow_dispatch), don't flag as vulnerability
							}
						}
					}
				}
			}
		}
	}

	return findings
}

// hasUntrustedWorkflowTriggersForArtifacts checks if workflow has triggers that could make artifact poisoning risky
func hasUntrustedWorkflowTriggersForArtifacts(workflow parser.WorkflowFile) bool {
	// Events that could allow untrusted actors to control artifacts
	untrustedEvents := []string{
		"pull_request",
		"pull_request_target",
		"pull_request_review",
		"pull_request_review_comment",
		"issues",
		"issue_comment",
		"repository_dispatch",
		"workflow_run", // Can be triggered by other workflows
		"discussion",
		"discussion_comment",
		"public", // Repository made public
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

// checkMatrixInjection checks for injection vulnerabilities through matrix strategy
func checkMatrixInjection(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	for jobName, job := range workflow.Workflow.Jobs {
		if job.Strategy != nil {
			// Check if matrix strategy is defined
			if matrix, exists := job.Strategy["matrix"]; exists && matrix != nil {
				matrixStr := fmt.Sprintf("%v", matrix)
				isUserControlledMatrix := strings.Contains(matrixStr, "fromJSON(inputs.") ||
					strings.Contains(matrixStr, "fromJSON(github.event.")

				// Check for matrix values used in shell commands
				for _, step := range job.Steps {
					if step.Run == "" {
						continue
					}

					// Look for matrix variable usage in shell commands
					matrixVarPattern := regexp.MustCompile(`\$\{\{\s*matrix\.([^}]+)\}\}`)
					matches := matrixVarPattern.FindAllStringSubmatch(step.Run, -1)

					for _, match := range matches {
						if len(match) > 1 {
							matrixVar := match[1]

							// Check if the matrix variable is used in dangerous contexts
							dangerousPatterns := []*regexp.Regexp{
								regexp.MustCompile(`\$\{\{\s*matrix\.` + regexp.QuoteMeta(matrixVar) + `\s*\}\}.*\|\s*(sh|bash|zsh)`), // Pipe to shell
								regexp.MustCompile(`eval.*\$\{\{\s*matrix\.` + regexp.QuoteMeta(matrixVar) + `\s*\}\}`),               // Eval with matrix
								regexp.MustCompile(`\$\{\{\s*matrix\.` + regexp.QuoteMeta(matrixVar) + `\s*\}\}.*>>`),                 // Redirect to file
								regexp.MustCompile(`curl.*\$\{\{\s*matrix\.` + regexp.QuoteMeta(matrixVar) + `\s*\}\}`),               // Curl with matrix
								regexp.MustCompile(`wget.*\$\{\{\s*matrix\.` + regexp.QuoteMeta(matrixVar) + `\s*\}\}`),               // Wget with matrix
							}

							for _, pattern := range dangerousPatterns {
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
										RuleID:      "MATRIX_INJECTION",
										RuleName:    "Matrix Strategy Injection",
										Description: "Matrix variable used in dangerous shell context without proper validation",
										Severity:    High,
										Category:    InjectionAttack,
										FilePath:    workflow.Path,
										JobName:     jobName,
										StepName:    step.Name,
										Evidence:    fmt.Sprintf("Matrix variable '%s' used in: %s", matrixVar, strings.TrimSpace(step.Run)),
										LineNumber:  lineNumber,
										Remediation: "Validate and sanitize matrix variables before using in shell commands, or use safer alternatives",
									})
								}
							}

							// Check for unquoted matrix variables (simpler check)
							unquotedPattern := regexp.MustCompile(`[^"']\$\{\{\s*matrix\.` + regexp.QuoteMeta(matrixVar) + `\s*\}\}[^"']`)
							if unquotedPattern.MatchString(step.Run) {
								// Arithmetic expansion $((...)) cannot execute arbitrary code via
								// string injection when matrix values are statically defined.
								// Per-line string check avoids regex fragility with inner-paren
								// expressions like $(( (a+b) * ${{ matrix.nr }} )).
								// Note: suppression is per-step; if the same var appears in both
								// arithmetic and non-arithmetic contexts on separate lines of the
								// same run block, the finding is suppressed for both occurrences.
								matrixExpr := "${{ matrix." + matrixVar
								isArithmetic := false
								for _, runLine := range strings.Split(step.Run, "\n") {
									if strings.Contains(runLine, "$((") && strings.Contains(runLine, matrixExpr) {
										isArithmetic = true
										break
									}
								}
								if !isArithmetic || isUserControlledMatrix {
									lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
										Key:   "run",
										Value: step.Run,
									})

									lineNumber := 0
									if lineResult != nil {
										lineNumber = lineResult.LineNumber
									}

									findings = append(findings, Finding{
										RuleID:      "MATRIX_INJECTION",
										RuleName:    "Matrix Strategy Injection",
										Description: "Unquoted matrix variable usage may lead to command injection",
										Severity:    Medium,
										Category:    InjectionAttack,
										FilePath:    workflow.Path,
										JobName:     jobName,
										StepName:    step.Name,
										Evidence:    fmt.Sprintf("Unquoted matrix variable '%s' in: %s", matrixVar, strings.TrimSpace(step.Run)),
										LineNumber:  lineNumber,
										Remediation: "Always quote matrix variables in shell commands: \"${{ matrix.var }}\"",
									})
								}
							}
						}
					}
				}
			}
		}
	}

	return findings
}

// checkExternalTrigger checks for workflows that can be externally triggered
func checkExternalTrigger(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Get the trigger events
	var triggerEvents []string

	switch on := workflow.Workflow.On.(type) {
	case string:
		triggerEvents = []string{on}
	case []interface{}:
		for _, event := range on {
			if str, ok := event.(string); ok {
				triggerEvents = append(triggerEvents, str)
			}
		}
	case map[string]interface{}:
		for event := range on {
			triggerEvents = append(triggerEvents, event)
		}
	}

	// Check for dangerous external triggers
	// pull_request_target is always dangerous (elevated permissions on fork code).
	// Other triggers are only flagged when the workflow has write permissions.
	dangerousTriggers := map[string]string{
		"pull_request_target": "Can be triggered by external pull requests with elevated permissions",
	}

	// These triggers are only concerning when the workflow has write permissions
	writeRequiredTriggers := map[string]string{
		"issue_comment":       "Can be triggered by anyone who can comment on issues",
		"workflow_run":        "Can be triggered by completion of other workflows",
		"repository_dispatch": "Can be triggered via API by repository collaborators",
		"workflow_dispatch":   "Can be manually triggered with potential for abuse",
	}

	for _, trigger := range triggerEvents {
		// pull_request_target is always dangerous — elevated permissions on fork code
		if risk, isDangerous := dangerousTriggers[trigger]; isDangerous {
			lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
				Key:   "on",
				Value: trigger,
			})

			lineNumber := 0
			if lineResult != nil {
				lineNumber = lineResult.LineNumber
			}

			findings = append(findings, Finding{
				RuleID:      "UNTRUSTED_TRIGGER",
				RuleName:    "Untrusted Workflow Trigger",
				Description: fmt.Sprintf("Workflow uses external trigger '%s': %s", trigger, risk),
				Severity:    High,
				Category:    AccessControl,
				FilePath:    workflow.Path,
				Evidence:    trigger,
				LineNumber:  lineNumber,
				Remediation: "Review trigger necessity and add appropriate security controls",
			})
		}

		// Other external triggers: only flag when the workflow has effective write
		// permissions. A read-only workflow with these triggers poses minimal risk.
		if risk, isWriteRequired := writeRequiredTriggers[trigger]; isWriteRequired {
			workflowHasWrite := permsImplyWrite(workflow.Workflow.Permissions)
			if !workflowHasWrite {
				for _, job := range workflow.Workflow.Jobs {
					if job.Permissions != nil && permsImplyWrite(job.Permissions) {
						workflowHasWrite = true
						break
					}
				}
			}
			if !workflowHasWrite {
				continue
			}

			severity := Medium
			if strings.Contains(workflow.Path, "test") ||
				strings.Contains(workflow.Path, "dev") ||
				strings.Contains(workflow.Path, "debug") ||
				strings.Contains(workflow.Path, "marketplace") ||
				strings.Contains(workflow.Path, "action") {
				severity = Low
			}
			// workflow_dispatch can only be invoked by a user who already has
			// repo write access, so its residual risk is informational rather
			// than a finding that should surface at default severities.
			if trigger == "workflow_dispatch" {
				severity = Info
			}

			lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
				Key:   "on",
				Value: trigger,
			})

			lineNumber := 0
			if lineResult != nil {
				lineNumber = lineResult.LineNumber
			}

			findings = append(findings, Finding{
				RuleID:      "UNTRUSTED_TRIGGER",
				RuleName:    "Untrusted Workflow Trigger",
				Description: fmt.Sprintf("Workflow uses external trigger '%s': %s", trigger, risk),
				Severity:    severity,
				Category:    AccessControl,
				FilePath:    workflow.Path,
				Evidence:    trigger,
				LineNumber:  lineNumber,
				Remediation: "Review trigger necessity and add appropriate security controls",
			})
		}
	}

	return findings
}
