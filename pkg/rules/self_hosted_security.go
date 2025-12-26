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

// CheckSelfHostedRunnerSecurity performs comprehensive self-hosted runner security analysis
func CheckSelfHostedRunnerSecurity(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	// Analyze repository context
	repoAnalyzer := context.NewRepositoryAnalyzer(workflow.Path)
	repoCtx, err := repoAnalyzer.AnalyzeRepository()
	if err != nil {
		// Continue with default context if analysis fails
		repoCtx = &context.RepositoryContext{
			IsPublic:  true, // Default to public for conservative security
			IsPrivate: false,
		}
	}

	// Analyze workflow context
	workflowCtx := context.AnalyzeWorkflowContext(workflow, repoCtx)

	// Run specific security checks
	findings = append(findings, checkSelfHostedRunnerExposure(workflow, workflowCtx)...)
	findings = append(findings, checkRunnerLabelConfusion(workflow, workflowCtx)...)
	findings = append(findings, checkSelfHostedRunnerPrivileges(workflow, workflowCtx)...)
	findings = append(findings, checkRepositoryVisibilityRisks(workflow, workflowCtx)...)
	findings = append(findings, checkSelfHostedRunnerSecrets(workflow, workflowCtx)...)
	findings = append(findings, checkRunnerEnvironmentSecurity(workflow, workflowCtx)...)

	return findings
}

// checkSelfHostedRunnerExposure checks for exposure of self-hosted runners to untrusted code
func checkSelfHostedRunnerExposure(workflow parser.WorkflowFile, ctx *context.WorkflowContext) []Finding {
	var findings []Finding

	if !ctx.UsesSelHostedRunners {
		return findings
	}

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Check if self-hosted runners are exposed to pull requests from forks
	if ctx.IsTriggeredByPR && ctx.Repository.IsPublic {
		finding := Finding{
			RuleID:      "SELF_HOSTED_RUNNER_PR_EXPOSURE",
			RuleName:    "Self-Hosted Runner Exposed to Pull Requests",
			Description: "Self-hosted runners are exposed to pull requests in a public repository, allowing potential code execution from forks",
			Severity:    Critical,
			Category:    AccessControl,
			FilePath:    workflow.Path,
			Evidence:    "Self-hosted runner with pull_request trigger in public repository",
			Remediation: "Use GitHub-hosted runners for public repositories, or restrict self-hosted runners to trusted events only (push, workflow_dispatch)",
			LineNumber:  1,
		}
		findings = append(findings, finding)
	}

	// Check for self-hosted runners with issue triggers
	if ctx.IsTriggeredByIssue && ctx.Repository.IsPublic {
		finding := Finding{
			RuleID:      "SELF_HOSTED_RUNNER_ISSUE_EXPOSURE",
			RuleName:    "Self-Hosted Runner Exposed to Issue Events",
			Description: "Self-hosted runners can be triggered by issue events in a public repository, allowing potential abuse",
			Severity:    High,
			Category:    AccessControl,
			FilePath:    workflow.Path,
			Evidence:    "Self-hosted runner with issue trigger in public repository",
			Remediation: "Restrict self-hosted runners to trusted events only, or use GitHub-hosted runners for issue-triggered workflows",
			LineNumber:  1,
		}
		findings = append(findings, finding)
	}

	// Check each job using self-hosted runners
	for jobName, job := range workflow.Workflow.Jobs {
		if job.RunsOn == nil {
			continue
		}

		runners := parseRunsOnForSecurity(job.RunsOn)
		for _, runner := range runners {
			if strings.Contains(runner, "self-hosted") {
				// Find line number for runs-on
				pattern := linenum.FindPattern{
					Key:   "runs-on",
					Value: runner,
				}
				lineResult := lineMapper.FindLineNumber(pattern)
				lineNumber := 1
				if lineResult != nil {
					lineNumber = lineResult.LineNumber
				}

				// Check for dangerous combinations
				if hasUntrustedCodeExecution(job) {
					finding := Finding{
						RuleID:      "SELF_HOSTED_RUNNER_UNTRUSTED_CODE",
						RuleName:    "Self-Hosted Runner Executes Untrusted Code",
						Description: "Self-hosted runner executes potentially untrusted user input, creating code injection risk",
						Severity:    Critical,
						Category:    InjectionAttack,
						FilePath:    workflow.Path,
						JobName:     jobName,
						Evidence:    "Self-hosted runner with user input execution",
						Remediation: "Sanitize user input, use environment variables, or switch to GitHub-hosted runners for untrusted input",
						LineNumber:  lineNumber,
					}
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings
}

// checkRunnerLabelConfusion checks for runner label confusion attacks
func checkRunnerLabelConfusion(workflow parser.WorkflowFile, ctx *context.WorkflowContext) []Finding {
	var findings []Finding

	if !ctx.UsesSelHostedRunners {
		return findings
	}

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Common label confusion patterns
	confusingLabels := map[string]string{
		"ubuntu-latest":       "May be confused with GitHub-hosted runners",
		"windows-latest":      "May be confused with GitHub-hosted runners",
		"macos-latest":        "May be confused with GitHub-hosted runners",
		"linux":               "Generic label that could be confused",
		"windows":             "Generic label that could be confused",
		"macos":               "Generic label that could be confused",
		"self-hosted-ubuntu":  "Could be confused with ubuntu-latest",
		"self-hosted-windows": "Could be confused with windows-latest",
		"self-hosted-macos":   "Could be confused with macos-latest",
	}

	for jobName, job := range workflow.Workflow.Jobs {
		if job.RunsOn == nil {
			continue
		}

		runners := parseRunsOnForSecurity(job.RunsOn)
		for _, runner := range runners {
			if strings.Contains(runner, "self-hosted") {
				// Check for confusing label combinations
				for confusingLabel, description := range confusingLabels {
					if strings.Contains(runner, confusingLabel) ||
						(len(runners) > 1 && containsLabel(runners, confusingLabel)) {

						pattern := linenum.FindPattern{
							Key:   "runs-on",
							Value: runner,
						}
						lineResult := lineMapper.FindLineNumber(pattern)
						lineNumber := 1
						if lineResult != nil {
							lineNumber = lineResult.LineNumber
						}

						finding := Finding{
							RuleID:      "RUNNER_LABEL_CONFUSION",
							RuleName:    "Potential Runner Label Confusion",
							Description: "Runner labels may be confusing and could lead to jobs running on unintended infrastructure: " + description,
							Severity:    Medium,
							Category:    Misconfiguration,
							FilePath:    workflow.Path,
							JobName:     jobName,
							Evidence:    "Confusing runner label: " + runner,
							Remediation: "Use distinct, clear labels for self-hosted runners to avoid confusion with GitHub-hosted runners",
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

// checkSelfHostedRunnerPrivileges checks for excessive privileges on self-hosted runners
func checkSelfHostedRunnerPrivileges(workflow parser.WorkflowFile, ctx *context.WorkflowContext) []Finding {
	var findings []Finding

	if !ctx.UsesSelHostedRunners {
		return findings
	}

	// Check for write-all permissions with self-hosted runners
	if hasWriteAllPermissions(workflow) {
		finding := Finding{
			RuleID:      "SELF_HOSTED_RUNNER_WRITE_ALL",
			RuleName:    "Self-Hosted Runner with Write-All Permissions",
			Description: "Self-hosted runner has write-all permissions, creating excessive privilege risk",
			Severity:    Critical,
			Category:    AccessControl,
			FilePath:    workflow.Path,
			Evidence:    "write-all permissions with self-hosted runner",
			Remediation: "Use minimal required permissions instead of write-all, especially with self-hosted runners",
			LineNumber:  1,
		}
		findings = append(findings, finding)
	}

	// Check for admin privileges in scripts
	adminPatterns := []*regexp.Regexp{
		regexp.MustCompile(`sudo\s+`),
		regexp.MustCompile(`su\s+`),
		regexp.MustCompile(`runas\s+`),
		regexp.MustCompile(`Start-Process.*-Verb RunAs`),
		regexp.MustCompile(`-Command.*Administrator`),
	}

	lineMapper := linenum.NewLineMapper(workflow.Content)

	for jobName, job := range workflow.Workflow.Jobs {
		if !usesSelfHostedRunner(job) {
			continue
		}

		for stepIdx, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			for _, pattern := range adminPatterns {
				if pattern.MatchString(step.Run) {
					stepName := step.Name
					if stepName == "" {
						stepName = "Step " + string(rune('1'+stepIdx))
					}

					// Find line number
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
						RuleID:      "SELF_HOSTED_RUNNER_ADMIN_PRIVILEGES",
						RuleName:    "Self-Hosted Runner Uses Administrative Privileges",
						Description: "Self-hosted runner step uses administrative privileges, increasing security risk",
						Severity:    High,
						Category:    AccessControl,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    stepName,
						Evidence:    step.Run,
						Remediation: "Avoid using administrative privileges in workflows, or ensure proper access controls",
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

// checkRepositoryVisibilityRisks checks for risks based on repository visibility
func checkRepositoryVisibilityRisks(workflow parser.WorkflowFile, ctx *context.WorkflowContext) []Finding {
	var findings []Finding

	// Public repository specific risks
	if ctx.Repository.IsPublic && ctx.UsesSelHostedRunners {
		// Check for secrets exposure risk
		if ctx.HasSecrets {
			finding := Finding{
				RuleID:      "PUBLIC_REPO_SELF_HOSTED_SECRETS",
				RuleName:    "Self-Hosted Runner Secrets in Public Repository",
				Description: "Self-hosted runner in public repository has access to secrets, creating potential exposure risk",
				Severity:    High,
				Category:    SecretsExposure,
				FilePath:    workflow.Path,
				Evidence:    "Self-hosted runner with secrets in public repository",
				Remediation: "Use GitHub-hosted runners for public repositories, or ensure secrets are properly scoped and protected",
				LineNumber:  1,
			}
			findings = append(findings, finding)
		}

		// Check for environment access
		if hasEnvironmentAccess(workflow) {
			finding := Finding{
				RuleID:      "PUBLIC_REPO_SELF_HOSTED_ENVIRONMENT",
				RuleName:    "Self-Hosted Runner Environment Access in Public Repository",
				Description: "Self-hosted runner in public repository has environment access, creating potential privilege escalation risk",
				Severity:    Medium,
				Category:    AccessControl,
				FilePath:    workflow.Path,
				Evidence:    "Self-hosted runner with environment access in public repository",
				Remediation: "Restrict environment access for self-hosted runners in public repositories",
				LineNumber:  1,
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// checkSelfHostedRunnerSecrets checks for secrets management issues with self-hosted runners
func checkSelfHostedRunnerSecrets(workflow parser.WorkflowFile, ctx *context.WorkflowContext) []Finding {
	var findings []Finding

	if !ctx.UsesSelHostedRunners || !ctx.HasSecrets {
		return findings
	}

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Check for secrets in run commands
	secretsInRunPattern := regexp.MustCompile(`\$\{\{\s*secrets\.[^}]+\}\}`)

	for jobName, job := range workflow.Workflow.Jobs {
		if !usesSelfHostedRunner(job) {
			continue
		}

		for stepIdx, step := range job.Steps {
			if step.Run != "" && secretsInRunPattern.MatchString(step.Run) {
				stepName := step.Name
				if stepName == "" {
					stepName = "Step " + string(rune('1'+stepIdx))
				}

				pattern := linenum.FindPattern{
					Key:   "run",
					Value: step.Run,
				}
				lineResult := lineMapper.FindLineNumber(pattern)
				lineNumber := 1
				if lineResult != nil {
					lineNumber = lineResult.LineNumber
				}

				finding := Finding{
					RuleID:      "SELF_HOSTED_RUNNER_SECRETS_IN_RUN",
					RuleName:    "Self-Hosted Runner Secrets in Run Commands",
					Description: "Secrets are directly used in run commands on self-hosted runner, potentially exposing them in process lists or logs",
					Severity:    High,
					Category:    SecretsExposure,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    stepName,
					Evidence:    step.Run,
					Remediation: "Use environment variables instead of direct secret interpolation in run commands",
					LineNumber:  lineNumber,
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// checkRunnerEnvironmentSecurity checks for environment-specific security issues
func checkRunnerEnvironmentSecurity(workflow parser.WorkflowFile, ctx *context.WorkflowContext) []Finding {
	var findings []Finding

	if !ctx.UsesSelHostedRunners {
		return findings
	}

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Check for environment-specific security risks
	for jobName, job := range workflow.Workflow.Jobs {
		if !usesSelfHostedRunner(job) {
			continue
		}

		// Check for network access patterns that might be risky
		networkRisks := []*regexp.Regexp{
			regexp.MustCompile(`curl.*\|\s*bash`),
			regexp.MustCompile(`wget.*\|\s*sh`),
			regexp.MustCompile(`Invoke-WebRequest.*\|\s*iex`),
			regexp.MustCompile(`docker\s+run.*--privileged`),
			regexp.MustCompile(`docker\s+run.*--cap-add`),
		}

		for stepIdx, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			for _, pattern := range networkRisks {
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
						RuleID:      "SELF_HOSTED_RUNNER_NETWORK_RISK",
						RuleName:    "Self-Hosted Runner Network Security Risk",
						Description: "Self-hosted runner performs risky network operations that could compromise the runner environment",
						Severity:    High,
						Category:    Misconfiguration,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    stepName,
						Evidence:    step.Run,
						Remediation: "Avoid downloading and executing scripts from the internet on self-hosted runners, or implement proper network security controls",
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

// Helper functions

func parseRunsOnForSecurity(runsOn interface{}) []string {
	var runners []string

	switch r := runsOn.(type) {
	case string:
		runners = append(runners, r)
	case []interface{}:
		for _, runner := range r {
			if runnerStr, ok := runner.(string); ok {
				runners = append(runners, runnerStr)
			}
		}
	}

	return runners
}

func containsLabel(runners []string, label string) bool {
	for _, runner := range runners {
		if strings.Contains(runner, label) {
			return true
		}
	}
	return false
}

func hasUntrustedCodeExecution(job parser.Job) bool {
	// Check for user input in run commands
	userInputPatterns := []*regexp.Regexp{
		regexp.MustCompile(`\$\{\{\s*github\.event\.[^}]+\}\}`),
		regexp.MustCompile(`\$\{\{\s*github\.head_ref\s*\}\}`),
		regexp.MustCompile(`\$\{\{\s*github\.base_ref\s*\}\}`),
	}

	for _, step := range job.Steps {
		for _, pattern := range userInputPatterns {
			if pattern.MatchString(step.Run) {
				return true
			}
		}
	}
	return false
}

func hasWriteAllPermissions(workflow parser.WorkflowFile) bool {
	// Check workflow-level permissions
	if perms, ok := workflow.Workflow.Permissions.(string); ok && perms == "write-all" {
		return true
	}

	// Check job-level permissions
	for _, job := range workflow.Workflow.Jobs {
		if perms, ok := job.Permissions.(string); ok && perms == "write-all" {
			return true
		}
	}

	return false
}

func usesSelfHostedRunner(job parser.Job) bool {
	if job.RunsOn == nil {
		return false
	}

	runners := parseRunsOnForSecurity(job.RunsOn)
	for _, runner := range runners {
		if strings.Contains(runner, "self-hosted") {
			return true
		}
	}
	return false
}

func hasEnvironmentAccess(workflow parser.WorkflowFile) bool {
	// Check for environment references in workflow
	// Since parser.Job doesn't have Environment field, check for environment patterns
	for _, job := range workflow.Workflow.Jobs {
		// Check if job has environment-related configurations
		if job.Env != nil && len(job.Env) > 0 {
			return true
		}

		// Check steps for environment usage
		for _, step := range job.Steps {
			if step.Env != nil && len(step.Env) > 0 {
				return true
			}
		}
	}
	return false
}
