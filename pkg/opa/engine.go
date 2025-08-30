package opa

import (
	"context"
	"fmt"

	"github.com/harekrishnarai/flowlyt/pkg/platform"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
	"github.com/open-policy-agent/opa/rego"
)

// Engine represents the OPA-based rule engine
type Engine struct {
	policies map[string]*Policy
	modules  map[string]string
}

// Policy represents an OPA policy with metadata
type Policy struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Severity    rules.Severity         `json:"severity"`
	Category    rules.Category         `json:"category"`
	Module      string                 `json:"module"`
	Query       string                 `json:"query"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Finding represents a security finding from OPA evaluation
type Finding struct {
	RuleID      string                 `json:"rule_id"`
	RuleName    string                 `json:"rule_name"`
	Description string                 `json:"description"`
	Severity    rules.Severity         `json:"severity"`
	Category    rules.Category         `json:"category"`
	FilePath    string                 `json:"file_path"`
	LineNumber  int                    `json:"line_number"`
	Evidence    string                 `json:"evidence"`
	Context     string                 `json:"context"`
	JobID       string                 `json:"job_id"`
	StepID      string                 `json:"step_id"`
	Platform    string                 `json:"platform"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// NewEngine creates a new OPA engine
func NewEngine() *Engine {
	return &Engine{
		policies: make(map[string]*Policy),
		modules:  make(map[string]string),
	}
}

// LoadPolicy loads a policy from Rego code
func (e *Engine) LoadPolicy(policy *Policy, regoCode string) error {
	// Validate the Rego code by compiling it
	r := rego.New(
		rego.Query(policy.Query),
		rego.Module(policy.ID, regoCode),
	)

	// Test compilation
	_, err := r.PrepareForEval(context.Background())
	if err != nil {
		return fmt.Errorf("failed to compile policy %s: %w", policy.ID, err)
	}

	// Store the policy and module
	e.policies[policy.ID] = policy
	e.modules[policy.ID] = regoCode

	return nil
}

// LoadPolicyFromFile loads a policy from a file
func (e *Engine) LoadPolicyFromFile(policyFile string) error {
	// This would read from a file containing both policy metadata and Rego code
	// For now, we'll implement some built-in policies
	return e.loadBuiltinPolicies()
}

// EvaluateWorkflow evaluates a workflow against all loaded policies
func (e *Engine) EvaluateWorkflow(workflow *platform.Workflow) ([]Finding, error) {
	var allFindings []Finding

	// Create input for OPA evaluation
	input := map[string]interface{}{
		"workflow":         workflow,
		"security_context": e.extractSecurityContext(workflow),
	}

	// Evaluate each policy
	for policyID, policy := range e.policies {
		findings, err := e.evaluatePolicy(policy, input)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate policy %s: %w", policyID, err)
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

// evaluatePolicy evaluates a single policy against the input
func (e *Engine) evaluatePolicy(policy *Policy, input map[string]interface{}) ([]Finding, error) {
	// Get the Rego module for this policy
	module, exists := e.modules[policy.ID]
	if !exists {
		return nil, fmt.Errorf("module not found for policy %s", policy.ID)
	}

	// Create Rego query
	r := rego.New(
		rego.Query(policy.Query),
		rego.Module(policy.ID, module),
		rego.Input(input),
	)

	// Prepare for evaluation
	query, err := r.PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to prepare query for policy %s: %w", policy.ID, err)
	}

	// Execute the query
	results, err := query.Eval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate policy %s: %w", policy.ID, err)
	}

	// Convert results to findings
	var findings []Finding
	for _, result := range results {
		for _, expression := range result.Expressions {
			if violations, ok := expression.Value.([]interface{}); ok {
				for _, violation := range violations {
					finding, err := e.convertToFinding(policy, violation, input)
					if err != nil {
						continue // Skip invalid findings
					}
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings, nil
}

// convertToFinding converts OPA result to Finding struct
func (e *Engine) convertToFinding(policy *Policy, violation interface{}, input map[string]interface{}) (Finding, error) {
	finding := Finding{
		RuleID:      policy.ID,
		RuleName:    policy.Name,
		Description: policy.Description,
		Severity:    policy.Severity,
		Category:    policy.Category,
		Platform:    e.getPlatformFromInput(input),
	}

	// Extract finding details from violation
	switch v := violation.(type) {
	case map[string]interface{}:
		if msg, ok := v["message"].(string); ok {
			finding.Evidence = msg
		}
		if context, ok := v["context"].(string); ok {
			finding.Context = context
		}
		if jobID, ok := v["job_id"].(string); ok {
			finding.JobID = jobID
		}
		if stepID, ok := v["step_id"].(string); ok {
			finding.StepID = stepID
		}
		if lineNum, ok := v["line_number"].(float64); ok {
			finding.LineNumber = int(lineNum)
		}
		if filePath, ok := v["file_path"].(string); ok {
			finding.FilePath = filePath
		}
		if metadata, ok := v["metadata"].(map[string]interface{}); ok {
			finding.Metadata = metadata
		}
	case string:
		finding.Evidence = v
	default:
		finding.Evidence = fmt.Sprintf("%v", violation)
	}

	// Set file path from workflow if not set
	if finding.FilePath == "" {
		if workflow, ok := input["workflow"].(*platform.Workflow); ok {
			finding.FilePath = workflow.FilePath
		}
	}

	return finding, nil
}

// getPlatformFromInput extracts platform from input
func (e *Engine) getPlatformFromInput(input map[string]interface{}) string {
	if workflow, ok := input["workflow"].(*platform.Workflow); ok {
		return workflow.Platform
	}
	return "unknown"
}

// extractSecurityContext creates a simplified security context for OPA
func (e *Engine) extractSecurityContext(workflow *platform.Workflow) map[string]interface{} {
	context := map[string]interface{}{
		"platform":             workflow.Platform,
		"jobs":                 []map[string]interface{}{},
		"secrets":              []string{},
		"external_actions":     []string{},
		"user_controlled_vars": []string{},
	}

	// Simplify jobs for OPA processing
	for _, job := range workflow.Jobs {
		jobMap := map[string]interface{}{
			"id":       job.ID,
			"name":     job.Name,
			"platform": job.Platform,
			"image":    job.Image,
			"steps":    []map[string]interface{}{},
		}

		// Simplify steps
		for _, step := range job.Steps {
			stepMap := map[string]interface{}{
				"id":          step.ID,
				"name":        step.Name,
				"type":        step.Type,
				"action":      step.Action,
				"script":      step.Script,
				"image":       step.Image,
				"shell":       step.Shell,
				"environment": step.Environment,
				"inputs":      step.Inputs,
			}
			jobMap["steps"] = append(jobMap["steps"].([]map[string]interface{}), stepMap)
		}

		context["jobs"] = append(context["jobs"].([]map[string]interface{}), jobMap)
	}

	return context
}

// GetPolicies returns all loaded policies
func (e *Engine) GetPolicies() map[string]*Policy {
	return e.policies
}

// GetPolicy returns a specific policy
func (e *Engine) GetPolicy(id string) (*Policy, bool) {
	policy, exists := e.policies[id]
	return policy, exists
}

// RemovePolicy removes a policy
func (e *Engine) RemovePolicy(id string) {
	delete(e.policies, id)
	delete(e.modules, id)
}

// loadBuiltinPolicies loads built-in security policies
func (e *Engine) loadBuiltinPolicies() error {
	// Built-in policy: Hardcoded secrets detection
	secretsPolicy := &Policy{
		ID:          "HARDCODED_SECRETS_OPA",
		Name:        "Hardcoded Secrets Detection (OPA)",
		Description: "Detects hardcoded secrets in workflow files using OPA",
		Severity:    rules.High,
		Category:    rules.SecretExposure,
		Query:       "data.flowlyt.secrets.violations[_]",
	}

	secretsRego := `
package flowlyt.secrets

import rego.v1

# Define secret patterns
secret_patterns := [
    "(?i)(password|passwd|pwd)\\s*[:=]\\s*['\"][^'\"\\s]{8,}['\"]",
    "(?i)(api[_-]?key|apikey)\\s*[:=]\\s*['\"][^'\"\\s]{16,}['\"]",
    "(?i)(secret|token)\\s*[:=]\\s*['\"][^'\"\\s]{16,}['\"]",
    "(?i)(access[_-]?token)\\s*[:=]\\s*['\"][^'\"\\s]{16,}['\"]"
]

violations contains violation if {
    job := input.workflow.jobs[_]
    step := job.steps[_]
    script := step.script[_]
    
    some pattern in secret_patterns
    regex.match(pattern, script)
    
    violation := {
        "message": sprintf("Potential hardcoded secret detected in script: %s", [script]),
        "context": sprintf("Job: %s, Step: %s", [job.id, step.id]),
        "job_id": job.id,
        "step_id": step.id,
        "metadata": {
            "pattern": pattern,
            "script": script
        }
    }
}

violations contains violation if {
    job := input.workflow.jobs[_]
    step := job.steps[_]
    env_value := step.environment[env_key]
    
    some pattern in secret_patterns
    regex.match(pattern, env_value)
    
    violation := {
        "message": sprintf("Potential hardcoded secret in environment variable %s: %s", [env_key, env_value]),
        "context": sprintf("Job: %s, Step: %s", [job.id, step.id]),
        "job_id": job.id,
        "step_id": step.id,
        "metadata": {
            "pattern": pattern,
            "env_key": env_key,
            "env_value": env_value
        }
    }
}
`

	if err := e.LoadPolicy(secretsPolicy, secretsRego); err != nil {
		return err
	}

	// Built-in policy: Dangerous commands detection
	dangerousPolicy := &Policy{
		ID:          "DANGEROUS_COMMANDS_OPA",
		Name:        "Dangerous Commands Detection (OPA)",
		Description: "Detects dangerous shell commands in workflow files using OPA",
		Severity:    rules.Medium,
		Category:    rules.MaliciousPattern,
		Query:       "data.flowlyt.dangerous.violations[_]",
	}

	dangerousRego := `
package flowlyt.dangerous

import rego.v1

# Define dangerous command patterns
dangerous_commands := [
    "rm -rf /",
    ":(){ :|:& };:",
    "wget.*\\|.*sh",
    "curl.*\\|.*sh",
    "eval\\s*\\$",
    "exec\\s*\\$"
]

violations contains violation if {
    job := input.workflow.jobs[_]
    step := job.steps[_]
    script := step.script[_]
    
    some cmd in dangerous_commands
    regex.match(cmd, script)
    
    violation := {
        "message": sprintf("Dangerous command detected: %s", [script]),
        "context": sprintf("Job: %s, Step: %s", [job.id, step.id]),
        "job_id": job.id,
        "step_id": step.id,
        "metadata": {
            "command_pattern": cmd,
            "script": script
        }
    }
}
`

	if err := e.LoadPolicy(dangerousPolicy, dangerousRego); err != nil {
		return err
	}

	// Built-in policy: Unpinned actions detection
	unpinnedPolicy := &Policy{
		ID:          "UNPINNED_ACTIONS_OPA",
		Name:        "Unpinned Actions Detection (OPA)",
		Description: "Detects unpinned external actions using OPA",
		Severity:    rules.Medium,
		Category:    rules.SupplyChain,
		Query:       "data.flowlyt.unpinned.violations[_]",
	}

	unpinnedRego := `
package flowlyt.unpinned

import rego.v1

violations contains violation if {
    job := input.workflow.jobs[_]
    step := job.steps[_]
    step.type == "action"
    action := step.action
    
    # Check if action is unpinned (no @ or @main/@master)
    not contains(action, "@")
    
    violation := {
        "message": sprintf("Unpinned action detected: %s", [action]),
        "context": sprintf("Job: %s, Step: %s", [job.id, step.id]),
        "job_id": job.id,
        "step_id": step.id,
        "metadata": {
            "action": action,
            "risk": "supply_chain"
        }
    }
}

violations contains violation if {
    job := input.workflow.jobs[_]
    step := job.steps[_]
    step.type == "action"
    action := step.action
    
    # Check if action uses branch reference
    contains(action, "@main")
    
    violation := {
        "message": sprintf("Action pinned to branch instead of commit: %s", [action]),
        "context": sprintf("Job: %s, Step: %s", [job.id, step.id]),
        "job_id": job.id,
        "step_id": step.id,
        "metadata": {
            "action": action,
            "risk": "mutable_reference"
        }
    }
}

violations contains violation if {
    job := input.workflow.jobs[_]
    step := job.steps[_]
    step.type == "action"
    action := step.action
    
    # Check if action uses branch reference
    contains(action, "@master")
    
    violation := {
        "message": sprintf("Action pinned to branch instead of commit: %s", [action]),
        "context": sprintf("Job: %s, Step: %s", [job.id, step.id]),
        "job_id": job.id,
        "step_id": step.id,
        "metadata": {
            "action": action,
            "risk": "mutable_reference"
        }
    }
}
`

	if err := e.LoadPolicy(unpinnedPolicy, unpinnedRego); err != nil {
		return err
	}

	return nil
}

// ConvertToRulesFinding converts OPA Finding to rules.Finding
func (f Finding) ToRulesFinding() rules.Finding {
	return rules.Finding{
		RuleID:      f.RuleID,
		RuleName:    f.RuleName,
		Description: f.Description,
		Severity:    f.Severity,
		Category:    f.Category,
		FilePath:    f.FilePath,
		LineNumber:  f.LineNumber,
		Evidence:    f.Evidence,
		JobName:     f.JobID,  // Map to JobName
		StepName:    f.StepID, // Map to StepName
		Remediation: "Review and fix the detected security issue",
	}
}
