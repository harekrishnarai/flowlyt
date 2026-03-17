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
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/parser"
)

// CheckOIDCAbuse is the entry point for OIDC token abuse detection.
// It checks for OA-001 (workflow-level id-token:write) and OA-002 (id-token:write without environment scope).
func CheckOIDCAbuse(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	findings = append(findings, checkOIDCWorkflowLevelPermission(workflow)...)
	findings = append(findings, checkOIDCWithoutEnvironmentScope(workflow)...)
	return findings
}

// checkOIDCWorkflowLevelPermission implements OA-001.
// Flags id-token: write at the workflow level when there is more than 1 job,
// because all jobs inherit the permission even if only one needs OIDC.
func checkOIDCWorkflowLevelPermission(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	if !hasIDTokenWrite(workflow.Workflow.Permissions) {
		return findings
	}

	// Single-job workflows have no cross-job exposure, so skip them.
	if len(workflow.Workflow.Jobs) <= 1 {
		return findings
	}

	findings = append(findings, Finding{
		RuleID:      "OIDC_WORKFLOW_LEVEL_PERMISSION",
		RuleName:    "OIDC id-token:write at Workflow Level",
		Description: "id-token: write at workflow level exposes all jobs to OIDC token access, enabling privilege escalation via expression injection",
		Severity:    High,
		Category:    PrivilegeEscalation,
		FilePath:    workflow.Path,
		JobName:     "",
		StepName:    "",
		Evidence:    "permissions.id-token: write (workflow-level affects all jobs)",
		Remediation: "Move 'id-token: write' to the specific job that needs it (the deploy job). Remove it from workflow-level permissions.",
	})

	return findings
}

// checkOIDCWithoutEnvironmentScope implements OA-002.
// Flags jobs that have id-token: write in their job-level permissions but no environment: set.
// An environment adds deployment protection rules (required reviewers, wait timers) that scope OIDC claims.
func checkOIDCWithoutEnvironmentScope(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	for jobID, job := range workflow.Workflow.Jobs {
		if !hasIDTokenWrite(job.Permissions) {
			continue
		}

		if jobHasEnvironment(job) {
			continue
		}

		jobName := job.Name
		if jobName == "" {
			jobName = jobID
		}

		findings = append(findings, Finding{
			RuleID:      "OIDC_WITHOUT_ENVIRONMENT_SCOPE",
			RuleName:    "OIDC id-token:write Without Environment Scope",
			Description: "Job has id-token: write permission but no environment: set, allowing OIDC tokens to be issued without deployment protection rules",
			Severity:    Medium,
			Category:    PrivilegeEscalation,
			FilePath:    workflow.Path,
			JobName:     jobName,
			StepName:    "",
			Evidence:    fmt.Sprintf("job '%s': id-token: write without environment scope", jobName),
			Remediation: "Add 'environment: <name>' to this job so OIDC tokens are scoped to a deployment environment with protection rules (required reviewers, wait timers).",
		})
	}

	return findings
}

// hasIDTokenWrite returns true if the given permissions value grants id-token: write access.
// It handles:
//   - nil → false
//   - string "write-all" → true (grants all permissions including id-token)
//   - map[string]interface{} with key "id-token" value "write" → true (case-insensitive key match)
func hasIDTokenWrite(perms interface{}) bool {
	if perms == nil {
		return false
	}

	switch v := perms.(type) {
	case string:
		return strings.EqualFold(v, "write-all")
	case map[string]interface{}:
		for key, val := range v {
			if strings.EqualFold(key, "id-token") {
				if strVal, ok := val.(string); ok && strings.EqualFold(strVal, "write") {
					return true
				}
			}
		}
	// gopkg.in/yaml.v3 may decode map keys as interface{} on some Go versions.
	case map[interface{}]interface{}:
		for key, val := range v {
			if keyStr, ok := key.(string); ok && strings.EqualFold(keyStr, "id-token") {
				if strVal, ok := val.(string); ok && strings.EqualFold(strVal, "write") {
					return true
				}
			}
		}
	}

	return false
}

// jobHasEnvironment returns true when the job has a non-empty environment: field.
// The field can be a plain string (environment: production) or a map with a name key
// (environment: { name: production, url: ... }).
func jobHasEnvironment(job parser.Job) bool {
	if job.Environment == nil {
		return false
	}

	switch v := job.Environment.(type) {
	case string:
		return strings.TrimSpace(v) != ""
	case map[string]interface{}:
		name, ok := v["name"]
		if !ok {
			return false
		}
		if nameStr, ok := name.(string); ok {
			return strings.TrimSpace(nameStr) != ""
		}
		return false
	case map[interface{}]interface{}:
		for key, val := range v {
			if keyStr, ok := key.(string); ok && keyStr == "name" {
				if nameStr, ok := val.(string); ok {
					return strings.TrimSpace(nameStr) != ""
				}
			}
		}
	}

	return false
}
