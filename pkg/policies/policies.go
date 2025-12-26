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

package policies

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/harekrishnarai/flowlyt/pkg/parser"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
	"github.com/open-policy-agent/opa/v1/rego"
)

// PolicyEngine represents a policy engine for enforcing custom rules
type PolicyEngine struct {
	policyFiles []string
	Debug       bool
}

// NewPolicyEngine creates a new policy engine
func NewPolicyEngine(policyFiles []string) *PolicyEngine {
	return &PolicyEngine{
		policyFiles: policyFiles,
		Debug:       false,
	}
}

// EvaluateWorkflow evaluates a workflow against the configured policies
func (e *PolicyEngine) EvaluateWorkflow(workflow parser.WorkflowFile) ([]rules.Finding, error) {
	var findings []rules.Finding

	// Skip if no policies are configured
	if len(e.policyFiles) == 0 {
		return findings, nil
	}

	// Prepare workflow data for OPA
	workflowData, err := prepareWorkflowData(workflow)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare workflow data: %w", err)
	}

	// Evaluate each policy file
	for _, policyFile := range e.policyFiles {
		fileFindings, err := e.evaluatePolicyFile(policyFile, workflowData, workflow.Path)
		if err != nil {
			return nil, fmt.Errorf("policy evaluation error for %s: %w", policyFile, err)
		}
		findings = append(findings, fileFindings...)
	}

	return findings, nil
}

// evaluatePolicyFile evaluates a single policy file against a workflow
func (e *PolicyEngine) evaluatePolicyFile(policyFile string, workflowData interface{}, workflowPath string) ([]rules.Finding, error) {
	var findings []rules.Finding

	// Read policy file
	policyContent, err := os.ReadFile(policyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	// Use a simpler, more direct approach with Rego
	ctx := context.Background()
	policyName := filepath.Base(policyFile)

	r := rego.New(
		rego.Query("data.flowlyt.deny[x]"),
		rego.Module(policyName, string(policyContent)),
		rego.Input(workflowData),
	)

	// Execute the policy
	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}

	// Process results
	for _, result := range rs {
		for _, expr := range result.Expressions {
			// The result will be an array of violations
			violations, ok := expr.Value.([]interface{})
			if !ok {
				continue
			}

			// Each violation is a map
			for _, v := range violations {
				violation, ok := v.(map[string]interface{})
				if !ok {
					continue
				}

				finding := convertViolationToFinding(violation, workflowPath)
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// prepareWorkflowData prepares workflow data for OPA evaluation
func prepareWorkflowData(workflow parser.WorkflowFile) (map[string]interface{}, error) {
	// Create a map representation of the workflow for OPA
	workflowData := map[string]interface{}{
		"path":    workflow.Path,
		"name":    workflow.Name,
		"content": string(workflow.Content),
		"workflow": map[string]interface{}{
			"name": workflow.Workflow.Name,
			"on":   workflow.Workflow.On,
			"jobs": convertJobsToMap(workflow.Workflow.Jobs),
		},
	}

	// Add env if present
	if workflow.Workflow.Env != nil {
		workflowData["workflow"].(map[string]interface{})["env"] = workflow.Workflow.Env
	}

	// Add permissions if present
	if workflow.Workflow.Permissions != nil {
		workflowData["workflow"].(map[string]interface{})["permissions"] = workflow.Workflow.Permissions
	}

	return workflowData, nil
}

// convertJobsToMap converts the jobs map to a format suitable for OPA
func convertJobsToMap(jobs map[string]parser.Job) map[string]interface{} {
	result := make(map[string]interface{})

	for name, job := range jobs {
		jobMap := map[string]interface{}{
			"runs-on": job.RunsOn,
			"steps":   convertStepsToList(job.Steps),
		}

		// Add optional fields if present
		if job.Name != "" {
			jobMap["name"] = job.Name
		}
		if job.Permissions != nil {
			jobMap["permissions"] = job.Permissions
		}
		if job.If != "" {
			jobMap["if"] = job.If
		}
		if job.Needs != nil {
			jobMap["needs"] = job.Needs
		}
		if job.Env != nil {
			jobMap["env"] = job.Env
		}
		if job.ContinueOnError {
			jobMap["continue-on-error"] = job.ContinueOnError
		}

		result[name] = jobMap
	}

	return result
}

// convertStepsToList converts the steps slice to a format suitable for OPA
func convertStepsToList(steps []parser.Step) []map[string]interface{} {
	result := make([]map[string]interface{}, len(steps))

	for i, step := range steps {
		stepMap := make(map[string]interface{})

		// Add fields if present
		if step.Name != "" {
			stepMap["name"] = step.Name
		}
		if step.ID != "" {
			stepMap["id"] = step.ID
		}
		if step.Uses != "" {
			stepMap["uses"] = step.Uses
		}
		if step.Run != "" {
			stepMap["run"] = step.Run
		}
		if step.Shell != "" {
			stepMap["shell"] = step.Shell
		}
		if step.If != "" {
			stepMap["if"] = step.If
		}
		if step.With != nil {
			stepMap["with"] = step.With
		}
		if step.Env != nil {
			stepMap["env"] = step.Env
		}
		if step.ContinueOnError {
			stepMap["continue-on-error"] = step.ContinueOnError
		}
		if step.WorkingDirectory != "" {
			stepMap["working-directory"] = step.WorkingDirectory
		}

		result[i] = stepMap
	}

	return result
}

// convertViolationToFinding converts an OPA policy violation to a finding
func convertViolationToFinding(violation map[string]interface{}, workflowPath string) rules.Finding {
	// Extract fields from the violation
	id, _ := violation["id"].(string)
	if id == "" {
		id = "POLICY_VIOLATION"
	}

	name, _ := violation["name"].(string)
	if name == "" {
		name = "Custom Policy Violation"
	}

	description, _ := violation["description"].(string)
	if description == "" {
		description = "Workflow violates a custom policy rule"
	}

	severityStr, _ := violation["severity"].(string)
	severity := rules.Medium // Default severity
	switch severityStr {
	case "CRITICAL":
		severity = rules.Critical
	case "HIGH":
		severity = rules.High
	case "MEDIUM":
		severity = rules.Medium
	case "LOW":
		severity = rules.Low
	case "INFO":
		severity = rules.Info
	}

	jobName, _ := violation["job"].(string)
	stepName, _ := violation["step"].(string)
	evidence, _ := violation["evidence"].(string)
	remediation, _ := violation["remediation"].(string)

	return rules.Finding{
		RuleID:      id,
		RuleName:    name,
		Description: description,
		Severity:    severity,
		Category:    rules.PolicyViolation,
		FilePath:    workflowPath,
		JobName:     jobName,
		StepName:    stepName,
		Evidence:    evidence,
		Remediation: remediation,
	}
}

// LoadPolicyFiles loads policy files from a directory or file
func LoadPolicyFiles(policyPath string) ([]string, error) {
	var policyFiles []string

	fileInfo, err := os.Stat(policyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to access policy path: %w", err)
	}

	if fileInfo.IsDir() {
		// Walk the directory to find .rego files
		err = filepath.Walk(policyPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && filepath.Ext(path) == ".rego" {
				policyFiles = append(policyFiles, path)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed to walk policy directory: %w", err)
		}
	} else {
		// Single file
		if filepath.Ext(policyPath) == ".rego" {
			policyFiles = append(policyFiles, policyPath)
		} else {
			return nil, fmt.Errorf("policy file must have .rego extension")
		}
	}

	if len(policyFiles) == 0 {
		return nil, fmt.Errorf("no policy files found at %s", policyPath)
	}

	return policyFiles, nil
}

// CreateExamplePolicy creates an example policy file
func CreateExamplePolicy(filePath string) error {
	examplePolicy := `package flowlyt

# Example policy to detect workflows with broad permissions
deny[violation] {
    input.workflow.permissions == "write-all"
    
    violation := {
        "id": "POLICY_BROAD_PERMISSIONS",
        "name": "Workflow Has Broad Permissions",
        "description": "Workflow has 'write-all' permissions, which grants excessive access",
        "severity": "HIGH",
        "evidence": "permissions: write-all",
        "remediation": "Use more specific permissions instead of 'write-all'"
    }
}

# Example policy to enforce use of specific runner
deny[violation] {
    job := input.workflow.jobs[job_name]
    not startswith(job["runs-on"], "self-hosted")
    
    violation := {
        "id": "POLICY_NON_SELFHOSTED_RUNNER",
        "name": "Non Self-Hosted Runner",
        "description": "Job uses a non self-hosted runner",
        "severity": "MEDIUM",
        "job": job_name,
        "evidence": sprintf("runs-on: %v", [job["runs-on"]]),
        "remediation": "Use a self-hosted runner for improved security"
    }
}

# Example policy to detect workflows without pin to SHA
deny[violation] {
    job := input.workflow.jobs[job_name]
    step := job.steps[_]
    step.uses
    not regex.match("@[0-9a-f]{40}$", step.uses)
    
    violation := {
        "id": "POLICY_UNPINNED_ACTION",
        "name": "Action Not Pinned to SHA",
        "description": "GitHub Action is not pinned to a full SHA commit",
        "severity": "MEDIUM",
        "job": job_name,
        "step": step.name,
        "evidence": sprintf("uses: %s", [step.uses]),
        "remediation": "Pin the action to a full SHA commit hash"
    }
}`

	// Create the directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write the example policy file
	if err := os.WriteFile(filePath, []byte(examplePolicy), 0644); err != nil {
		return fmt.Errorf("failed to write example policy file: %w", err)
	}

	return nil
}
