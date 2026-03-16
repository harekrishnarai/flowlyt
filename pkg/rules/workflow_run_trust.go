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
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/parser"
)

// artifactDownloadActions lists known artifact download actions that pull from workflow runs.
var artifactDownloadActions = []string{
	"dawidd6/action-download-artifact",
	"actions/download-artifact",
}

// CheckWorkflowRunTrust is the main entry point for WRT-001, WRT-002, and WRT-003.
// It returns findings for all three rules covering the CVE-2025-30066 (tj-actions/reviewdog)
// supply chain attack pattern where workflow_run triggers allow untrusted artifact injection.
func CheckWorkflowRunTrust(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	if !isWorkflowRunTrigger(workflow) {
		return findings
	}

	findings = append(findings, checkWRT001(workflow)...)
	findings = append(findings, checkWRT002(workflow)...)
	findings = append(findings, checkWRT003(workflow)...)

	return findings
}

// checkWRT001 detects artifact downloads in workflow_run workflows that lack a run_id constraint.
// Without run_id, an attacker who can trigger the parent workflow controls the artifact content.
func checkWRT001(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if !isArtifactDownloadStep(step) {
				continue
			}

			// Safe if run_id is explicitly set in the with: block
			if _, hasRunID := step.With["run_id"]; hasRunID {
				continue
			}

			findings = append(findings, Finding{
				RuleID:      "WORKFLOW_RUN_ARTIFACT_UNTRUSTED",
				RuleName:    "Untrusted Artifact Download in workflow_run",
				Severity:    Critical,
				Category:    SupplyChain,
				Description: "workflow_run downloads artifacts without constraining run_id, enabling supply chain attacks (CVE-2025-30066 pattern). An attacker who controls the triggering workflow can inject malicious artifact content.",
				Remediation: "Pin the artifact download to a trusted run_id, or verify the artifact's integrity (checksum/signature) before using it. Consider using actions/download-artifact with an explicit run_id.",
				FilePath:    workflow.Path,
				JobName:     jobName,
				StepName:    step.Name,
				Evidence:    truncateWRT("step uses: " + step.Uses + " — no run_id in with: block"),
			})
		}
	}

	return findings
}

// checkWRT002 detects env-var injection via downloaded artifacts in workflow_run workflows.
// A subsequent step writing to $GITHUB_ENV or $GITHUB_PATH after an artifact download can
// allow the artifact to inject arbitrary environment variables or PATH entries.
func checkWRT002(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	for jobName, job := range workflow.Workflow.Jobs {
		if !jobHasArtifactDownload(job) {
			continue
		}

		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			if writesToGitHubEnvOrPath(step.Run) {
				findings = append(findings, Finding{
					RuleID:      "WORKFLOW_RUN_ENV_INJECTION",
					RuleName:    "Environment Variable Injection via Artifact in workflow_run",
					Severity:    Critical,
					Category:    SupplyChain,
					Description: "A workflow_run job downloads an artifact and then writes to $GITHUB_ENV or $GITHUB_PATH. If the artifact content is attacker-controlled, this enables environment variable injection into subsequent steps.",
					Remediation: "Validate and sanitize artifact content before writing to $GITHUB_ENV or $GITHUB_PATH. Consider using a separate trusted workflow to process artifacts, or avoid writing artifact-derived data to runner environment files.",
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    step.Name,
					Evidence:    truncateWRT(step.Run),
				})
			}
		}
	}

	return findings
}

// checkWRT003 detects elevated permissions in workflow_run jobs that also download artifacts.
// Combining write permissions with untrusted artifact downloads amplifies the blast radius of
// a compromised artifact (e.g., it could push code, create releases, or modify issues).
func checkWRT003(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	for jobName, job := range workflow.Workflow.Jobs {
		if !jobHasArtifactDownload(job) {
			continue
		}

		if jobHasWritePermission(job, workflow.Workflow) {
			findings = append(findings, Finding{
				RuleID:      "WORKFLOW_RUN_ELEVATED_CONTEXT",
				RuleName:    "Elevated Permissions with Untrusted Artifact Download in workflow_run",
				Severity:    High,
				Category:    SupplyChain,
				Description: "A workflow_run job downloads artifacts while running with write permissions. If artifact content is attacker-controlled, the elevated context enables privilege escalation (e.g., code push, release creation).",
				Remediation: "Apply least-privilege permissions. If the job must download artifacts, restrict permissions to read-only. Consider separating the artifact download into a job with minimal permissions from the privileged processing step.",
				FilePath:    workflow.Path,
				JobName:     jobName,
				StepName:    "",
				Evidence:    "job has artifact download step and write-level permissions",
			})
		}
	}

	return findings
}

// isWorkflowRunTrigger returns true if the workflow is triggered by the workflow_run event.
// It handles all YAML forms: plain string, list of strings, or map of trigger configs.
func isWorkflowRunTrigger(workflow parser.WorkflowFile) bool {
	on := workflow.Workflow.On
	if on == nil {
		return false
	}

	switch v := on.(type) {
	case string:
		return v == "workflow_run"
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && s == "workflow_run" {
				return true
			}
		}
	case map[interface{}]interface{}:
		for key := range v {
			if s, ok := key.(string); ok && s == "workflow_run" {
				return true
			}
		}
	case map[string]interface{}:
		if _, ok := v["workflow_run"]; ok {
			return true
		}
	}

	return false
}

// jobHasArtifactDownload returns true if any step in the job uses a known artifact download action.
func jobHasArtifactDownload(job parser.Job) bool {
	for _, step := range job.Steps {
		if isArtifactDownloadStep(step) {
			return true
		}
	}
	return false
}

// isArtifactDownloadStep returns true if the step's uses field refers to an artifact download action.
func isArtifactDownloadStep(step parser.Step) bool {
	for _, action := range artifactDownloadActions {
		if strings.HasPrefix(step.Uses, action) {
			return true
		}
	}
	return false
}

// writesToGitHubEnvOrPath returns true if the shell script appends to $GITHUB_ENV or $GITHUB_PATH.
func writesToGitHubEnvOrPath(run string) bool {
	patterns := []string{
		">> $GITHUB_ENV",
		">>$GITHUB_ENV",
		">> $GITHUB_PATH",
		">>$GITHUB_PATH",
	}
	for _, p := range patterns {
		if strings.Contains(run, p) {
			return true
		}
	}
	return false
}

// jobHasWritePermission returns true if the job or the workflow-level permissions grant any write access.
// It recognises "write-all" (string) and maps where any permission value is "write".
func jobHasWritePermission(job parser.Job, workflow parser.Workflow) bool {
	if hasWriteInPermissions(job.Permissions) {
		return true
	}
	if hasWriteInPermissions(workflow.Permissions) {
		return true
	}
	return false
}

// hasWriteInPermissions inspects a permissions value (string or map) for write access.
func hasWriteInPermissions(perms interface{}) bool {
	if perms == nil {
		return false
	}

	switch v := perms.(type) {
	case string:
		return v == "write-all"
	case map[interface{}]interface{}:
		for _, val := range v {
			if s, ok := val.(string); ok && s == "write" {
				return true
			}
		}
	case map[string]interface{}:
		for _, val := range v {
			if s, ok := val.(string); ok && s == "write" {
				return true
			}
		}
	}

	return false
}

// truncateWRT truncates evidence strings for WRT rule findings.
func truncateWRT(s string) string {
	const maxLen = 300
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
