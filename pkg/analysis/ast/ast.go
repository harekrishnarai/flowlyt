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

package ast

import (
	"fmt"
	"go/token"

	"gopkg.in/yaml.v3"
)

// ASTAnalyzer provides AST-based analysis capabilities
type ASTAnalyzer struct {
	fileSet        *token.FileSet
	callGraph      *CallGraph
	dataFlow       *DataFlowAnalyzer
	reachability   *ReachabilityAnalyzer
	actionAnalyzer *ActionAnalyzer
	shellAnalyzer  *ShellAnalyzer
	config         *ASTConfig
}

// ASTConfig contains configuration for AST analysis
type ASTConfig struct {
	EnableActionAnalysis       bool
	EnableShellAnalysis        bool
	EnableAdvancedReachability bool
	TrustMarketplaceActions    bool
	MaxComplexityThreshold     int
	EnableContextAnalysis      bool
}

// WorkflowAST represents the parsed structure of a CI/CD workflow
type WorkflowAST struct {
	Jobs     map[string]*JobNode    `yaml:"jobs"`
	Triggers []*TriggerNode         `yaml:"on"`
	Env      map[string]*EnvNode    `yaml:"env"`
	Secrets  map[string]*SecretNode `yaml:"secrets"`
	Platform string                 // "github" or "gitlab"
}

// JobNode represents a job in the workflow with its dependencies
type JobNode struct {
	ID          string            `yaml:"-"`
	Name        string            `yaml:"name"`
	Steps       []*StepNode       `yaml:"steps"`
	Needs       []string          `yaml:"needs"`
	If          string            `yaml:"if"`
	Environment string            `yaml:"environment"`
	Permissions map[string]string `yaml:"permissions"`
	Secrets     []string          `yaml:"-"` // Extracted from steps
	Variables   map[string]string `yaml:"env"`
	RunsOn      string            `yaml:"runs-on"`
	Reachable   bool              `yaml:"-"` // Will be set by reachability analysis
}

// StepNode represents individual steps with data flow information
type StepNode struct {
	ID          string            `yaml:"id"`
	Name        string            `yaml:"name"`
	Uses        string            `yaml:"uses"`
	With        map[string]string `yaml:"with"`
	Run         string            `yaml:"run"`
	Env         map[string]string `yaml:"env"`
	If          string            `yaml:"if"`
	Shell       string            `yaml:"shell"`
	WorkingDir  string            `yaml:"working-directory"`
	Outputs     []string          `yaml:"-"` // Extracted from analysis
	Inputs      []string          `yaml:"-"` // Extracted from analysis
	Reachable   bool              `yaml:"-"`
	DataSources []string          `yaml:"-"` // Where data comes from
	DataSinks   []string          `yaml:"-"` // Where data goes to
}

// TriggerNode represents workflow triggers
type TriggerNode struct {
	Event     string                 `yaml:"-"`
	Config    map[string]interface{} `yaml:",inline"`
	Reachable bool                   `yaml:"-"`
}

// EnvNode represents environment variables
type EnvNode struct {
	Name    string `yaml:"-"`
	Value   string `yaml:",inline"`
	Tainted bool   `yaml:"-"`
	Source  string `yaml:"-"`
}

// SecretNode represents secrets
type SecretNode struct {
	Name        string `yaml:"-"`
	Value       string `yaml:",inline"`
	Required    bool   `yaml:"required"`
	Description string `yaml:"description"`
}

// NewASTAnalyzer creates a new AST analyzer with default configuration
func NewASTAnalyzer() *ASTAnalyzer {
	return NewASTAnalyzerWithConfig(DefaultASTConfig())
}

// NewASTAnalyzerWithConfig creates a new AST analyzer with custom configuration
func NewASTAnalyzerWithConfig(config *ASTConfig) *ASTAnalyzer {
	callGraph := NewCallGraph()
	dataFlow := NewDataFlowAnalyzer()
	reachability := NewReachabilityAnalyzer(callGraph)
	actionAnalyzer := NewActionAnalyzer()
	shellAnalyzer := NewShellAnalyzer()

	return &ASTAnalyzer{
		fileSet:        token.NewFileSet(),
		callGraph:      callGraph,
		dataFlow:       dataFlow,
		reachability:   reachability,
		actionAnalyzer: actionAnalyzer,
		shellAnalyzer:  shellAnalyzer,
		config:         config,
	}
}

// DefaultASTConfig returns default configuration for AST analysis
func DefaultASTConfig() *ASTConfig {
	return &ASTConfig{
		EnableActionAnalysis:       true,
		EnableShellAnalysis:        true,
		EnableAdvancedReachability: true,
		TrustMarketplaceActions:    true,
		MaxComplexityThreshold:     10,
		EnableContextAnalysis:      true,
	}
}

// Reset clears all analysis state for reuse between workflows
func (a *ASTAnalyzer) Reset() {
	a.callGraph.Reset()
	a.dataFlow.Reset()
	a.reachability.Reset()
}

// ParseWorkflow parses a workflow into AST representation
func (a *ASTAnalyzer) ParseWorkflow(workflow interface{}) (*WorkflowAST, error) {
	switch w := workflow.(type) {
	case map[string]interface{}:
		return a.parseWorkflowFromMap(w)
	case []byte:
		return a.parseWorkflowFromBytes(w)
	case string:
		return a.parseWorkflowFromString(w)
	default:
		return nil, fmt.Errorf("unsupported workflow type: %T", workflow)
	}
}

func (a *ASTAnalyzer) parseWorkflowFromBytes(data []byte) (*WorkflowAST, error) {
	var workflowMap map[string]interface{}
	if err := yaml.Unmarshal(data, &workflowMap); err != nil {
		return nil, fmt.Errorf("failed to parse workflow YAML: %w", err)
	}
	return a.parseWorkflowFromMap(workflowMap)
}

func (a *ASTAnalyzer) parseWorkflowFromString(data string) (*WorkflowAST, error) {
	return a.parseWorkflowFromBytes([]byte(data))
}

func (a *ASTAnalyzer) parseWorkflowFromMap(workflowMap map[string]interface{}) (*WorkflowAST, error) {
	workflow := &WorkflowAST{
		Jobs:     make(map[string]*JobNode),
		Triggers: []*TriggerNode{},
		Env:      make(map[string]*EnvNode),
		Secrets:  make(map[string]*SecretNode),
		Platform: "github", // Default, can be detected
	}

	// Parse triggers
	if onData, exists := workflowMap["on"]; exists {
		triggers, err := a.parseTriggers(onData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse triggers: %w", err)
		}
		workflow.Triggers = triggers
	}

	// Parse environment variables
	if envData, exists := workflowMap["env"]; exists {
		if envMap, ok := envData.(map[string]interface{}); ok {
			for name, value := range envMap {
				workflow.Env[name] = &EnvNode{
					Name:  name,
					Value: fmt.Sprintf("%v", value),
				}
			}
		}
	}

	// Parse jobs
	if jobsData, exists := workflowMap["jobs"]; exists {
		if jobsMap, ok := jobsData.(map[string]interface{}); ok {
			for jobID, jobData := range jobsMap {
				job, err := a.parseJob(jobID, jobData)
				if err != nil {
					return nil, fmt.Errorf("failed to parse job %s: %w", jobID, err)
				}
				workflow.Jobs[jobID] = job
			}
		}
	}

	return workflow, nil
}

func (a *ASTAnalyzer) parseTriggers(onData interface{}) ([]*TriggerNode, error) {
	var triggers []*TriggerNode

	switch data := onData.(type) {
	case string:
		// Simple string trigger like "push"
		triggers = append(triggers, &TriggerNode{
			Event:  data,
			Config: make(map[string]interface{}),
		})
	case []interface{}:
		// Array of trigger strings
		for _, item := range data {
			if str, ok := item.(string); ok {
				triggers = append(triggers, &TriggerNode{
					Event:  str,
					Config: make(map[string]interface{}),
				})
			}
		}
	case map[string]interface{}:
		// Complex trigger configuration
		for event, config := range data {
			triggerNode := &TriggerNode{
				Event:  event,
				Config: make(map[string]interface{}),
			}
			if configMap, ok := config.(map[string]interface{}); ok {
				triggerNode.Config = configMap
			}
			triggers = append(triggers, triggerNode)
		}
	}

	return triggers, nil
}

func (a *ASTAnalyzer) parseJob(jobID string, jobData interface{}) (*JobNode, error) {
	jobMap, ok := jobData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("job data is not a map")
	}

	job := &JobNode{
		ID:        jobID,
		Variables: make(map[string]string),
		Steps:     []*StepNode{},
		Needs:     []string{},
		Secrets:   []string{},
	}

	// Parse basic job fields
	if name, exists := jobMap["name"]; exists {
		job.Name = fmt.Sprintf("%v", name)
	}

	if runsOn, exists := jobMap["runs-on"]; exists {
		job.RunsOn = fmt.Sprintf("%v", runsOn)
	}

	if ifCond, exists := jobMap["if"]; exists {
		job.If = fmt.Sprintf("%v", ifCond)
	}

	if env, exists := jobMap["environment"]; exists {
		job.Environment = fmt.Sprintf("%v", env)
	}

	// Parse needs (dependencies)
	if needsData, exists := jobMap["needs"]; exists {
		switch needs := needsData.(type) {
		case string:
			job.Needs = []string{needs}
		case []interface{}:
			for _, need := range needs {
				if needStr, ok := need.(string); ok {
					job.Needs = append(job.Needs, needStr)
				}
			}
		}
	}

	// Parse permissions
	if permData, exists := jobMap["permissions"]; exists {
		if permMap, ok := permData.(map[string]interface{}); ok {
			job.Permissions = make(map[string]string)
			for perm, value := range permMap {
				job.Permissions[perm] = fmt.Sprintf("%v", value)
			}
		}
	}

	// Parse environment variables
	if envData, exists := jobMap["env"]; exists {
		if envMap, ok := envData.(map[string]interface{}); ok {
			for name, value := range envMap {
				job.Variables[name] = fmt.Sprintf("%v", value)
			}
		}
	}

	// Parse steps
	if stepsData, exists := jobMap["steps"]; exists {
		if stepsList, ok := stepsData.([]interface{}); ok {
			for i, stepData := range stepsList {
				step, err := a.parseStep(i, stepData)
				if err != nil {
					return nil, fmt.Errorf("failed to parse step %d: %w", i, err)
				}
				job.Steps = append(job.Steps, step)
			}
		}
	}

	return job, nil
}

func (a *ASTAnalyzer) parseStep(index int, stepData interface{}) (*StepNode, error) {
	stepMap, ok := stepData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("step data is not a map")
	}

	step := &StepNode{
		With:        make(map[string]string),
		Env:         make(map[string]string),
		Outputs:     []string{},
		Inputs:      []string{},
		DataSources: []string{},
		DataSinks:   []string{},
	}

	// Parse basic step fields
	if id, exists := stepMap["id"]; exists {
		step.ID = fmt.Sprintf("%v", id)
	} else {
		step.ID = fmt.Sprintf("step_%d", index)
	}

	if name, exists := stepMap["name"]; exists {
		step.Name = fmt.Sprintf("%v", name)
	}

	if uses, exists := stepMap["uses"]; exists {
		step.Uses = fmt.Sprintf("%v", uses)
	}

	if run, exists := stepMap["run"]; exists {
		step.Run = fmt.Sprintf("%v", run)
	}

	if ifCond, exists := stepMap["if"]; exists {
		step.If = fmt.Sprintf("%v", ifCond)
	}

	if shell, exists := stepMap["shell"]; exists {
		step.Shell = fmt.Sprintf("%v", shell)
	}

	if workingDir, exists := stepMap["working-directory"]; exists {
		step.WorkingDir = fmt.Sprintf("%v", workingDir)
	}

	// Parse 'with' parameters
	if withData, exists := stepMap["with"]; exists {
		if withMap, ok := withData.(map[string]interface{}); ok {
			for key, value := range withMap {
				step.With[key] = fmt.Sprintf("%v", value)
			}
		}
	}

	// Parse environment variables
	if envData, exists := stepMap["env"]; exists {
		if envMap, ok := envData.(map[string]interface{}); ok {
			for name, value := range envMap {
				step.Env[name] = fmt.Sprintf("%v", value)
			}
		}
	}

	return step, nil
}

// AnalyzeReachability performs reachability analysis on the workflow
func (a *ASTAnalyzer) AnalyzeReachability(workflow *WorkflowAST) map[string]bool {
	if workflow == nil {
		return make(map[string]bool)
	}

	// Build call graph first with error handling
	if err := a.callGraph.BuildCallGraph(workflow); err != nil {
		// Log error and return empty result rather than crashing
		fmt.Printf("Error building call graph: %v\n", err)
		return make(map[string]bool)
	}

	// Perform reachability analysis
	entryPoints := a.getEntryPoints(workflow)
	if len(entryPoints) == 0 {
		// No entry points found, return empty result
		return make(map[string]bool)
	}

	return a.reachability.AnalyzeReachability(workflow, entryPoints)
}

// AnalyzeDataFlow performs data flow analysis and returns tainted flows
func (a *ASTAnalyzer) AnalyzeDataFlow(workflow *WorkflowAST) ([]*DataFlow, error) {
	if workflow == nil {
		return nil, fmt.Errorf("workflow AST is nil")
	}

	if err := a.dataFlow.AnalyzeDataFlowWithCallGraph(workflow, a.callGraph); err != nil {
		return nil, fmt.Errorf("data flow analysis failed: %w", err)
	}

	flows := a.dataFlow.GetTaintedFlows()
	if flows == nil {
		return []*DataFlow{}, nil // Return empty slice instead of nil
	}

	return flows, nil
}

// AnalyzeWorkflowComprehensive performs comprehensive analysis including all P1 enhancements
func (a *ASTAnalyzer) AnalyzeWorkflowComprehensive(workflow *WorkflowAST) (*ComprehensiveAnalysisResult, error) {
	if workflow == nil {
		return nil, fmt.Errorf("workflow cannot be nil")
	}

	result := &ComprehensiveAnalysisResult{
		ReachabilityAnalysis: make(map[string]bool),
		DataFlows:            []*DataFlow{},
		ActionAnalyses:       []*ActionAnalysis{},
		ShellAnalyses:        []*ShellCommand{},
		SecurityRisks:        []string{},
		ComplexConditions:    []*ConditionAnalyzer{},
	}

	// Build call graph
	if err := a.callGraph.BuildCallGraph(workflow); err != nil {
		return nil, fmt.Errorf("failed to build call graph: %w", err)
	}

	// Enhanced reachability analysis
	if a.config.EnableAdvancedReachability {
		entryPoints := a.getEntryPoints(workflow)
		result.ReachabilityAnalysis = a.reachability.AnalyzeReachability(workflow, entryPoints)

		// Identify complex conditions
		for nodeID, condition := range a.reachability.conditions {
			if condition.Complexity > a.config.MaxComplexityThreshold {
				result.ComplexConditions = append(result.ComplexConditions, condition)
				result.SecurityRisks = append(result.SecurityRisks,
					fmt.Sprintf("complex_condition_%s", nodeID))
			}
		}
	}

	// Enhanced data flow analysis
	err := a.dataFlow.AnalyzeDataFlowWithCallGraph(workflow, a.callGraph)
	if err != nil {
		return nil, fmt.Errorf("data flow analysis failed: %w", err)
	}
	result.DataFlows = a.dataFlow.flows

	// Action analysis for all steps that use actions
	if a.config.EnableActionAnalysis {
		for _, job := range workflow.Jobs {
			for _, step := range job.Steps {
				if step.Uses != "" {
					actionAnalysis, err := a.actionAnalyzer.AnalyzeAction(step)
					if err != nil {
						// Log warning but continue
						result.SecurityRisks = append(result.SecurityRisks,
							fmt.Sprintf("action_analysis_failed_%s", step.Uses))
						continue
					}
					result.ActionAnalyses = append(result.ActionAnalyses, actionAnalysis)

					// Add action-specific risks
					result.SecurityRisks = append(result.SecurityRisks, actionAnalysis.Risks...)
				}
			}
		}
	}

	// Shell analysis for all steps with run commands
	if a.config.EnableShellAnalysis {
		for _, job := range workflow.Jobs {
			for _, step := range job.Steps {
				if step.Run != "" {
					// Build context for shell analysis
					context := make(map[string]string)
					for key, value := range step.Env {
						context[key] = value
					}
					for key, value := range job.Variables {
						context[key] = value
					}

					shellCmd, err := a.shellAnalyzer.AnalyzeShellCommand(step.Run, context)
					if err != nil {
						// Log warning but continue
						result.SecurityRisks = append(result.SecurityRisks,
							fmt.Sprintf("shell_analysis_failed_%s", step.Name))
						continue
					}
					result.ShellAnalyses = append(result.ShellAnalyses, shellCmd)

					// Add shell-specific risks
					result.SecurityRisks = append(result.SecurityRisks, shellCmd.SecurityRisks...)
					result.SecurityRisks = append(result.SecurityRisks, shellCmd.DataFlowRisks...)
				}
			}
		}
	}

	return result, nil
}

// ComprehensiveAnalysisResult contains all analysis results
type ComprehensiveAnalysisResult struct {
	ReachabilityAnalysis map[string]bool
	DataFlows            []*DataFlow
	ActionAnalyses       []*ActionAnalysis
	ShellAnalyses        []*ShellCommand
	SecurityRisks        []string
	ComplexConditions    []*ConditionAnalyzer
}

// GetSecurityMetrics returns security metrics from the analysis
func (car *ComprehensiveAnalysisResult) GetSecurityMetrics() *SecurityMetrics {
	metrics := &SecurityMetrics{
		TotalRisks:         len(car.SecurityRisks),
		HighRiskActions:    0,
		UntrustedActions:   0,
		DangerousCommands:  0,
		ComplexConditions:  len(car.ComplexConditions),
		SensitiveDataFlows: 0,
	}

	// Count action risks
	for _, actionAnalysis := range car.ActionAnalyses {
		if !actionAnalysis.Metadata.TrustedVendor {
			metrics.UntrustedActions++
		}
		for _, risk := range actionAnalysis.Risks {
			if risk == "privilege_escalation" || risk == "credential_exposure" {
				metrics.HighRiskActions++
			}
		}
	}

	// Count shell risks
	for _, shellCmd := range car.ShellAnalyses {
		for _, cmd := range shellCmd.ParsedCommands {
			if cmd.Dangerous {
				metrics.DangerousCommands++
			}
		}
	}

	// Count sensitive data flows
	for _, flow := range car.DataFlows {
		if flow.Tainted && (flow.Severity == "HIGH" || flow.Severity == "CRITICAL") {
			metrics.SensitiveDataFlows++
		}
	}

	return metrics
}

// SecurityMetrics contains security-related metrics
type SecurityMetrics struct {
	TotalRisks         int
	HighRiskActions    int
	UntrustedActions   int
	DangerousCommands  int
	ComplexConditions  int
	SensitiveDataFlows int
}

// GetTotalNodes returns the total number of nodes in the call graph
func (a *ASTAnalyzer) GetTotalNodes() int {
	return a.callGraph.GetNodeCount()
}

// GetReachabilityReport returns the reachability analysis report
func (a *ASTAnalyzer) GetReachabilityReport() *ReachabilityReport {
	return a.reachability.GetReachabilityReport()
}

func (a *ASTAnalyzer) getEntryPoints(workflow *WorkflowAST) []string {
	var entryPoints []string
	for _, trigger := range workflow.Triggers {
		entryPoints = append(entryPoints, fmt.Sprintf("trigger_%s", trigger.Event))
	}
	return entryPoints
}
