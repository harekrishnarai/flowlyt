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

	"github.com/harekrishnarai/flowlyt/pkg/context"
	"github.com/harekrishnarai/flowlyt/pkg/linenum"
	"github.com/harekrishnarai/flowlyt/pkg/parser"
)

// CheckAdvancedPrivilegeAnalysis performs advanced workflow privilege analysis
func CheckAdvancedPrivilegeAnalysis(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	// Analyze repository context
	repoAnalyzer := context.NewRepositoryAnalyzer(workflow.Path)
	repoCtx, err := repoAnalyzer.AnalyzeRepository()
	if err != nil {
		repoCtx = &context.RepositoryContext{
			IsPublic:  true,
			IsPrivate: false,
		}
	}

	// Analyze workflow context
	workflowCtx := context.AnalyzeWorkflowContext(workflow, repoCtx)

	// Run advanced privilege checks
	findings = append(findings, checkTokenPermissionEscalation(workflow, workflowCtx)...)
	findings = append(findings, checkCrossRepositoryAccess(workflow, workflowCtx)...)
	findings = append(findings, checkEnvironmentBypass(workflow, workflowCtx)...)
	findings = append(findings, checkSecretsAccess(workflow, workflowCtx)...)
	findings = append(findings, checkRepositoryWriteAccess(workflow, workflowCtx)...)
	findings = append(findings, checkPullRequestTargetRisks(workflow, workflowCtx)...)

	return findings
}

// checkTokenPermissionEscalation checks for potential token permission escalation
func checkTokenPermissionEscalation(workflow parser.WorkflowFile, ctx *context.WorkflowContext) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Check for patterns that could lead to permission escalation
	escalationPatterns := []*regexp.Regexp{
		regexp.MustCompile(`gh\s+auth\s+token`),
		regexp.MustCompile(`GITHUB_TOKEN.*base64`),
		regexp.MustCompile(`echo.*GITHUB_TOKEN.*\|\s*base64`),
		regexp.MustCompile(`curl.*-H.*Authorization.*Bearer.*GITHUB_TOKEN`),
		regexp.MustCompile(`git\s+config.*credential.*helper.*token`),
	}

	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			for _, pattern := range escalationPatterns {
				if pattern.MatchString(step.Run) {
					stepName := step.Name
					if stepName == "" {
						stepName = "Step " + string(rune('1'+stepIdx))
					}

					linePattern := linenum.FindPattern{
						Key:   "run",
						Value: step.Run,
					}
					lineResult := lineMapper.FindLineNumber(linePattern)
					lineNumber := 1
					if lineResult != nil {
						lineNumber = lineResult.LineNumber
					}

					finding := Finding{
						RuleID:      "TOKEN_PERMISSION_ESCALATION",
						RuleName:    "Potential Token Permission Escalation",
						Description: "Step contains patterns that could be used to escalate token permissions or extract token data",
						Severity:    High,
						Category:    PrivilegeEscalation,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    stepName,
						Evidence:    step.Run,
						Remediation: "Avoid manipulating tokens directly; use built-in GitHub Actions permissions instead",
						LineNumber:  lineNumber,
					}
					findings = append(findings, finding)
					break
				}
			}
		}
	}

	return findings
}

// checkCrossRepositoryAccess checks for unauthorized cross-repository access
func checkCrossRepositoryAccess(workflow parser.WorkflowFile, ctx *context.WorkflowContext) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Patterns that suggest cross-repository access
	crossRepoPatterns := []*regexp.Regexp{
		regexp.MustCompile(`gh\s+repo\s+clone\s+[^/]+/[^/\s]+`),
		regexp.MustCompile(`git\s+clone\s+https://github\.com/[^/]+/[^/\s]+`),
		regexp.MustCompile(`curl.*api\.github\.com/repos/[^/]+/[^/\s]+`),
		regexp.MustCompile(`actions/checkout@.*repository:\s*[^/]+/[^/\s]+`),
	}

	for jobName, job := range workflow.Workflow.Jobs {
		// Check actions using checkout with different repositories
		for stepIdx, step := range job.Steps {
			if step.Uses != "" && strings.Contains(step.Uses, "actions/checkout") {
				if step.With != nil {
					if repo, exists := step.With["repository"]; exists {
						if repoStr, ok := repo.(string); ok && repoStr != "" {
							// Check if it's accessing a different repository
							currentRepo := ctx.Repository.Owner + "/" + ctx.Repository.Name
							if !strings.EqualFold(repoStr, currentRepo) && !strings.Contains(repoStr, "${{") {
								stepName := step.Name
								if stepName == "" {
									stepName = "Step " + string(rune('1'+stepIdx))
								}

								finding := Finding{
									RuleID:      "CROSS_REPOSITORY_ACCESS",
									RuleName:    "Cross-Repository Access",
									Description: "Workflow accesses a different repository, which may have security implications",
									Severity:    Medium,
									Category:    AccessControl,
									FilePath:    workflow.Path,
									JobName:     jobName,
									StepName:    stepName,
									Evidence:    "Repository: " + repoStr,
									Remediation: "Ensure cross-repository access is intentional and properly secured",
									LineNumber:  1,
								}
								findings = append(findings, finding)
							}
						}
					}
				}
			}

			// Check run commands for cross-repo access
			if step.Run != "" {
				for _, pattern := range crossRepoPatterns {
					if pattern.MatchString(step.Run) {
						stepName := step.Name
						if stepName == "" {
							stepName = "Step " + string(rune('1'+stepIdx))
						}

						linePattern := linenum.FindPattern{
							Key:   "run",
							Value: step.Run,
						}
						lineResult := lineMapper.FindLineNumber(linePattern)
						lineNumber := 1
						if lineResult != nil {
							lineNumber = lineResult.LineNumber
						}

						finding := Finding{
							RuleID:      "CROSS_REPOSITORY_ACCESS_COMMAND",
							RuleName:    "Cross-Repository Access via Command",
							Description: "Command accesses external repositories, which may have security implications",
							Severity:    Medium,
							Category:    AccessControl,
							FilePath:    workflow.Path,
							JobName:     jobName,
							StepName:    stepName,
							Evidence:    step.Run,
							Remediation: "Ensure external repository access is intentional and secure",
							LineNumber:  lineNumber,
						}
						findings = append(findings, finding)
						break
					}
				}
			}
		}
	}

	return findings
}

// checkEnvironmentBypass checks for potential environment protection bypass
func checkEnvironmentBypass(workflow parser.WorkflowFile, ctx *context.WorkflowContext) []Finding {
	var findings []Finding

	// Check if workflow can bypass environment protections
	if ctx.IsTriggeredByPR && ctx.Repository.IsPublic {
		// Look for actions that might bypass environment controls
		bypassPatterns := []*regexp.Regexp{
			regexp.MustCompile(`gh\s+workflow\s+run`),
			regexp.MustCompile(`repository_dispatch`),
			regexp.MustCompile(`workflow_dispatch`),
		}

		lineMapper := linenum.NewLineMapper(workflow.Content)

		for jobName, job := range workflow.Workflow.Jobs {
			for stepIdx, step := range job.Steps {
				if step.Run == "" {
					continue
				}

				for _, pattern := range bypassPatterns {
					if pattern.MatchString(step.Run) {
						stepName := step.Name
						if stepName == "" {
							stepName = "Step " + string(rune('1'+stepIdx))
						}

						linePattern := linenum.FindPattern{
							Key:   "run",
							Value: step.Run,
						}
						lineResult := lineMapper.FindLineNumber(linePattern)
						lineNumber := 1
						if lineResult != nil {
							lineNumber = lineResult.LineNumber
						}

						finding := Finding{
							RuleID:      "ENVIRONMENT_BYPASS_RISK",
							RuleName:    "Potential Environment Protection Bypass",
							Description: "Pull request triggered workflow may bypass environment protections through workflow dispatch",
							Severity:    Medium,
							Category:    AccessControl,
							FilePath:    workflow.Path,
							JobName:     jobName,
							StepName:    stepName,
							Evidence:    step.Run,
							Remediation: "Ensure environment protections cannot be bypassed through workflow triggers",
							LineNumber:  lineNumber,
						}
						findings = append(findings, finding)
						break
					}
				}
			}
		}
	}

	return findings
}

// checkSecretsAccess checks for improper secrets access patterns
func checkSecretsAccess(workflow parser.WorkflowFile, ctx *context.WorkflowContext) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Check for secrets being passed to untrusted actions
	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			if step.Uses == "" {
				continue
			}

			stepName := step.Name
			if stepName == "" {
				stepName = "Step " + string(rune('1'+stepIdx))
			}

			// Check if action is from untrusted source and has access to secrets
			if isUntrustedAction(step.Uses) && hasSecretsAccess(step) {
				finding := Finding{
					RuleID:      "SECRETS_TO_UNTRUSTED_ACTION",
					RuleName:    "Secrets Passed to Untrusted Action",
					Description: "Secrets are being passed to an action from an untrusted source",
					Severity:    High,
					Category:    SecretsExposure,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    stepName,
					Evidence:    step.Uses,
					Remediation: "Only pass secrets to trusted, verified actions",
					LineNumber:  1,
				}
				findings = append(findings, finding)
			}

			// Check for secrets in environment variables of steps
			if step.Env != nil {
				for envKey, envValue := range step.Env {
					if strings.Contains(envValue, "secrets.") {
						linePattern := linenum.FindPattern{
							Key:   envKey,
							Value: envValue,
						}
						lineResult := lineMapper.FindLineNumber(linePattern)
						lineNumber := 1
						if lineResult != nil {
							lineNumber = lineResult.LineNumber
						}

						finding := Finding{
							RuleID:      "SECRET_IN_ENVIRONMENT",
							RuleName:    "Secret in Environment Variable",
							Description: "Secret is directly exposed in environment variable, which may be logged or visible",
							Severity:    Medium,
							Category:    SecretsExposure,
							FilePath:    workflow.Path,
							JobName:     jobName,
							StepName:    stepName,
							Evidence:    envKey + ": " + envValue,
							Remediation: "Use input parameters or secure secret handling instead of environment variables",
							LineNumber:  lineNumber,
						}
						findings = append(findings, finding)
					}
				}
			}
		}
	}

	return findings
}

// checkRepositoryWriteAccess checks for unnecessary repository write access
func checkRepositoryWriteAccess(workflow parser.WorkflowFile, ctx *context.WorkflowContext) []Finding {
	var findings []Finding

	// Check if workflow has write access but only performs read operations
	if hasWritePermissions(workflow) {
		readOnlyOperations := []string{"test", "build", "lint", "check", "validate", "scan"}

		workflowName := strings.ToLower(workflow.Workflow.Name)
		isReadOnlyWorkflow := false

		for _, operation := range readOnlyOperations {
			if strings.Contains(workflowName, operation) {
				isReadOnlyWorkflow = true
				break
			}
		}

		if isReadOnlyWorkflow {
			finding := Finding{
				RuleID:      "EXCESSIVE_WRITE_PERMISSIONS",
				RuleName:    "Excessive Write Permissions for Read-Only Workflow",
				Description: "Workflow appears to be read-only but has write permissions",
				Severity:    Medium,
				Category:    AccessControl,
				FilePath:    workflow.Path,
				Evidence:    "Write permissions on workflow: " + workflow.Workflow.Name,
				Remediation: "Use minimal required permissions; consider read-only permissions for test/build workflows",
				LineNumber:  1,
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// checkPullRequestTargetRisks checks for pull_request_target security risks
func checkPullRequestTargetRisks(workflow parser.WorkflowFile, ctx *context.WorkflowContext) []Finding {
	var findings []Finding

	// Check if workflow uses pull_request_target
	if !hasPullRequestTargetTrigger(workflow) {
		return findings
	}

	// pull_request_target is risky - check for dangerous patterns
	dangerousPatterns := []*regexp.Regexp{
		regexp.MustCompile(`actions/checkout.*ref:.*github\.event\.pull_request\.head\.sha`),
		regexp.MustCompile(`github\.event\.pull_request\.head`),
		regexp.MustCompile(`\$\{\{\s*github\.event\.pull_request\.head\.[^}]+\}\}`),
	}

	lineMapper := linenum.NewLineMapper(workflow.Content)

	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			// Check checkout actions
			if step.Uses != "" && strings.Contains(step.Uses, "actions/checkout") {
				if step.With != nil {
					if ref, exists := step.With["ref"]; exists {
						if refStr, ok := ref.(string); ok {
							if strings.Contains(refStr, "github.event.pull_request.head") {
								finding := Finding{
									RuleID:      "PULL_REQUEST_TARGET_CHECKOUT_RISK",
									RuleName:    "Dangerous pull_request_target Checkout",
									Description: "pull_request_target workflow checks out untrusted code from pull request head",
									Severity:    Critical,
									Category:    AccessControl,
									FilePath:    workflow.Path,
									JobName:     jobName,
									StepName:    step.Name,
									Evidence:    "ref: " + refStr,
									Remediation: "Use pull_request trigger instead, or ensure untrusted code is not executed",
									LineNumber:  1,
								}
								findings = append(findings, finding)
							}
						}
					}
				}
			}

			// Check run commands for dangerous patterns
			if step.Run != "" {
				for _, pattern := range dangerousPatterns {
					if pattern.MatchString(step.Run) {
						stepName := step.Name
						if stepName == "" {
							stepName = "Step " + string(rune('1'+stepIdx))
						}

						linePattern := linenum.FindPattern{
							Key:   "run",
							Value: step.Run,
						}
						lineResult := lineMapper.FindLineNumber(linePattern)
						lineNumber := 1
						if lineResult != nil {
							lineNumber = lineResult.LineNumber
						}

						finding := Finding{
							RuleID:      "PULL_REQUEST_TARGET_EXECUTION_RISK",
							RuleName:    "Dangerous pull_request_target Execution",
							Description: "pull_request_target workflow executes untrusted code from pull request",
							Severity:    Critical,
							Category:    InjectionAttack,
							FilePath:    workflow.Path,
							JobName:     jobName,
							StepName:    stepName,
							Evidence:    step.Run,
							Remediation: "Avoid executing untrusted code in pull_request_target workflows",
							LineNumber:  lineNumber,
						}
						findings = append(findings, finding)
						break
					}
				}
			}
		}
	}

	return findings
}

// Helper functions

func isUntrustedAction(actionUses string) bool {
	// List of trusted action publishers
	trustedPublishers := []string{
		"actions/",
		"github/",
		"microsoft/",
		"azure/",
		"docker/",
		"hashicorp/",
		"google-github-actions/",
		"aws-actions/",
		"step-security/",
	}

	for _, trusted := range trustedPublishers {
		if strings.HasPrefix(actionUses, trusted) {
			return false
		}
	}

	return true
}

func hasSecretsAccess(step parser.Step) bool {
	// Check step's with parameters for secrets
	if step.With != nil {
		for _, value := range step.With {
			if valueStr, ok := value.(string); ok {
				if strings.Contains(valueStr, "secrets.") {
					return true
				}
			}
		}
	}

	// Check step's environment for secrets
	if step.Env != nil {
		for _, value := range step.Env {
			if strings.Contains(value, "secrets.") {
				return true
			}
		}
	}

	return false
}

func hasWritePermissions(workflow parser.WorkflowFile) bool {
	// Check workflow-level permissions
	if perms, ok := workflow.Workflow.Permissions.(string); ok {
		return perms == "write-all" || perms == "write"
	}

	if perms, ok := workflow.Workflow.Permissions.(map[string]interface{}); ok {
		for _, perm := range perms {
			if permStr, ok := perm.(string); ok {
				if permStr == "write" {
					return true
				}
			}
		}
	}

	// Check job-level permissions
	for _, job := range workflow.Workflow.Jobs {
		if perms, ok := job.Permissions.(string); ok {
			if perms == "write-all" || perms == "write" {
				return true
			}
		}

		if perms, ok := job.Permissions.(map[string]interface{}); ok {
			for _, perm := range perms {
				if permStr, ok := perm.(string); ok {
					if permStr == "write" {
						return true
					}
				}
			}
		}
	}

	return false
}

func hasPullRequestTargetTrigger(workflow parser.WorkflowFile) bool {
	if workflow.Workflow.On == nil {
		return false
	}

	switch on := workflow.Workflow.On.(type) {
	case map[string]interface{}:
		_, hasPRTarget := on["pull_request_target"]
		return hasPRTarget
	case []interface{}:
		for _, trigger := range on {
			if triggerStr, ok := trigger.(string); ok {
				if triggerStr == "pull_request_target" {
					return true
				}
			}
		}
	case string:
		return on == "pull_request_target"
	}

	return false
}
