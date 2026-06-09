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

	"github.com/harekrishnarai/flowlyt/v2/pkg/linenum"
	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
)

// checkContinueOnErrorCriticalJob checks for critical jobs with continue-on-error set to true
func checkContinueOnErrorCriticalJob(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	// List of critical job names (common patterns)
	criticalJobPatterns := []string{
		"deploy", "prod", "production", "release", "publish", "security", "authorization",
		"authentication", "auth", "iam", "admin", "validate", "verification",
	}

	for jobName, job := range workflow.Workflow.Jobs {
		// Check if this is a critical job
		isCritical := false
		jobNameLower := strings.ToLower(jobName)
		for _, pattern := range criticalJobPatterns {
			if strings.Contains(jobNameLower, pattern) {
				isCritical = true
				break
			}
		}

		if isCritical && parser.ContinueOnErrorEnabled(job.ContinueOnError) {
			// Find line number for this job using the LineMapper
			lineNumber := findLineNumberWithMapper(workflow, jobName+":", "")

			findings = append(findings, Finding{
				RuleID:      "CONTINUE_ON_ERROR_CRITICAL_JOB",
				RuleName:    "Continue On Error in Critical Job",
				Description: "Critical job has continue-on-error set to true, which may mask failures",
				Severity:    Medium,
				Category:    Misconfiguration,
				FilePath:    workflow.Path,
				JobName:     jobName,
				StepName:    "",
				Evidence:    "continue-on-error: true",
				LineNumber:  lineNumber,
				Remediation: "Remove continue-on-error from critical jobs or handle errors explicitly",
			})
		}
	}

	return findings
}

// checkBroadPermissions checks for overly broad permissions in workflows
func checkBroadPermissions(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)
	content := string(workflow.Content)

	// Check for write-all permissions at workflow level
	if workflow.Workflow.Permissions != nil {
		if permStr, ok := workflow.Workflow.Permissions.(string); ok && permStr == "write-all" {
			// Find line number for permissions
			lines := strings.Split(content, "\n")
			lineNumber := 1

			for i, line := range lines {
				if strings.Contains(line, "permissions:") && strings.Contains(line, "write-all") {
					lineNumber = i + 1
					break
				}
			}

			findings = append(findings, Finding{
				RuleID:      "BROAD_PERMISSIONS",
				RuleName:    "Overly Broad Permissions",
				Description: "Workflow uses 'write-all' permissions, granting excessive access to all repository resources",
				Severity:    Critical,
				Category:    Misconfiguration,
				FilePath:    workflow.Path,
				JobName:     "",
				StepName:    "",
				Evidence:    "permissions: write-all",
				LineNumber:  lineNumber,
				Remediation: "Use specific permissions instead of 'write-all'. Define only the permissions your workflow actually needs.",
			})
		}
	}

	// Check for missing permissions: block at workflow level (defaults to write-all)
	// GitHub Actions defaults to write-all if permissions are not explicitly set
	hasWorkflowPermissions := workflow.Workflow.Permissions != nil
	if !hasWorkflowPermissions {
		// Check if there are any jobs that might need permissions
		hasJobs := len(workflow.Workflow.Jobs) > 0
		if hasJobs {
			// Find a good line number (after 'on:' trigger)
			lines := strings.Split(content, "\n")
			lineNumber := 1
			for i, line := range lines {
				if strings.Contains(line, "on:") {
					// Look for permissions after the trigger section
					for j := i + 1; j < len(lines) && j < i+20; j++ {
						if strings.Contains(lines[j], "jobs:") {
							lineNumber = j
							break
						}
					}
					break
				}
			}

			findings = append(findings, Finding{
				RuleID:      "BROAD_PERMISSIONS",
				RuleName:    "Missing Permissions Block",
				Description: "Workflow does not set permissions, defaulting to write-all which grants excessive access",
				Severity:    High,
				Category:    Misconfiguration,
				FilePath:    workflow.Path,
				JobName:     "",
				StepName:    "",
				Evidence:    "default permissions used due to no permissions: block",
				LineNumber:  lineNumber,
				Remediation: "Add 'permissions: {}' or specific minimal permissions to restrict access. Use 'permissions: read-all' for read-only workflows.",
			})
		}
	}

	// Check for missing permissions: block at job level.
	// When the workflow itself has no permissions block, the workflow-level finding already
	// captures the issue — avoid emitting one finding per job (N-times amplification).
	for jobName, job := range workflow.Workflow.Jobs {
		// Check if job has permissions set
		hasJobPermissions := job.Permissions != nil

		// When the workflow has no permissions block, the workflow-level finding covers it.
		// Only check jobs that explicitly set permissions, to catch write-all overrides.
		if hasJobPermissions {
			// Job has permissions — check if it's overly broad
			if permStr, ok := job.Permissions.(string); ok && permStr == "write-all" {
				pattern := linenum.FindPattern{
					Key:   "permissions",
					Value: "write-all",
				}
				lineResult := lineMapper.FindLineNumber(pattern)
				lineNumber := 0
				if lineResult != nil {
					lineNumber = lineResult.LineNumber
				}

				findings = append(findings, Finding{
					RuleID:      "BROAD_PERMISSIONS",
					RuleName:    "Overly Broad Permissions",
					Description: fmt.Sprintf("Job '%s' uses 'write-all' permissions, granting excessive access", jobName),
					Severity:    Critical,
					Category:    Misconfiguration,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    "",
					Evidence:    fmt.Sprintf("permissions: write-all in job '%s'", jobName),
					LineNumber:  lineNumber,
					Remediation: "Use specific permissions instead of 'write-all'. Define only the permissions this job actually needs.",
				})
			}
		}
	}

	return findings
}

// permsImplyWrite returns true if the permissions value implies at least
// one write-level scope. It handles the three forms GitHub Actions supports:
//
//   - nil (no permissions block) → true (GitHub default is write-all)
//   - string shorthand: "write-all" → true, "read-all" → false
//   - map[string]interface{}: any scope with value "write" → true
//
// An empty map (permissions: {}) is treated as explicitly restricting all
// permissions to none/read, so it returns false.
func permsImplyWrite(perms interface{}) bool {
	if perms == nil {
		return true // no block → GitHub write-all default
	}
	switch p := perms.(type) {
	case string:
		return p == "write-all"
	case bool:
		return p // false → no permissions; true → write-all (non-standard but defensible)
	case map[string]interface{}:
		if len(p) == 0 {
			return false // permissions: {} → no permissions granted
		}
		for _, v := range p {
			if v == "write" {
				return true
			}
		}
		return false
	}
	return true // unknown type — be conservative and flag
}
