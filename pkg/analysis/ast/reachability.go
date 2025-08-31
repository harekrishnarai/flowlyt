package ast

import (
	"fmt"
	"regexp"
	"strings"
)

// ReachabilityAnalyzer determines which parts of the workflow are reachable
type ReachabilityAnalyzer struct {
	callGraph      *CallGraph
	reachableNodes map[string]bool
	conditions     map[string]*ConditionAnalyzer
}

// ConditionAnalyzer analyzes conditional expressions in workflows
type ConditionAnalyzer struct {
	Expression        string
	Variables         []string
	Secrets           []string
	Github            []string // github.* context
	Inputs            []string // inputs.* context
	Env               []string // env.* context
	Vars              []string // vars.* context
	Steps             []string // steps.* context
	Jobs              []string // jobs.* context
	Needs             []string // needs.* context
	Matrix            []string // matrix.* context
	Always            bool     // always() function used
	Failure           bool     // failure() function used
	Success           bool     // success() function used
	Cancelled         bool     // cancelled() function used
	StaticEval        *bool    // static evaluation result if determinable
	ContextDependency bool     // depends on runtime context
	Complexity        int      // complexity score for the condition
	Operators         []string // logical operators used
	Functions         []string // functions called in condition
}

// NewReachabilityAnalyzer creates a new reachability analyzer
func NewReachabilityAnalyzer(cg *CallGraph) *ReachabilityAnalyzer {
	return &ReachabilityAnalyzer{
		callGraph:      cg,
		reachableNodes: make(map[string]bool),
		conditions:     make(map[string]*ConditionAnalyzer),
	}
}

// Reset clears all analysis data for reuse
func (ra *ReachabilityAnalyzer) Reset() {
	// Clear maps efficiently
	for k := range ra.reachableNodes {
		delete(ra.reachableNodes, k)
	}
	for k := range ra.conditions {
		delete(ra.conditions, k)
	}
}

// AnalyzeReachability performs reachability analysis on the workflow
func (ra *ReachabilityAnalyzer) AnalyzeReachability(workflow *WorkflowAST, entryPoints []string) map[string]bool {
	// Reset state
	ra.reachableNodes = make(map[string]bool)
	ra.conditions = make(map[string]*ConditionAnalyzer)

	// Mark all trigger nodes as reachable (entry points)
	for _, trigger := range workflow.Triggers {
		triggerID := fmt.Sprintf("trigger_%s", trigger.Event)
		ra.markReachable(triggerID)
	}

	// Add any additional entry points
	for _, entryPoint := range entryPoints {
		ra.markReachable(entryPoint)
	}

	// Perform DFS from entry points to mark reachable nodes
	for nodeID := range ra.reachableNodes {
		ra.dfs(nodeID)
	}

	// Analyze conditional reachability
	ra.analyzeConditionalReachability(workflow)

	// Mark job and step reachability in the workflow AST
	ra.updateWorkflowReachability(workflow)

	return ra.reachableNodes
}

func (ra *ReachabilityAnalyzer) dfs(nodeID string) {
	// Get all connected nodes and visit them
	if edges := ra.callGraph.GetEdges(nodeID); edges != nil {
		for _, targetID := range edges {
			if !ra.reachableNodes[targetID] {
				ra.markReachable(targetID)
				ra.dfs(targetID)
			}
		}
	}
}

func (ra *ReachabilityAnalyzer) analyzeConditionalReachability(workflow *WorkflowAST) {
	// Analyze job-level conditions
	for jobID, job := range workflow.Jobs {
		jobNodeID := fmt.Sprintf("job_%s", jobID)

		if job.If != "" {
			condition := ra.parseCondition(job.If)
			ra.conditions[jobNodeID] = condition

			// If condition is statically false, mark as unreachable
			if condition.StaticEval != nil && !*condition.StaticEval {
				ra.markUnreachable(jobNodeID)
				// Remove all steps in this job too
				for stepIdx := range job.Steps {
					stepNodeID := fmt.Sprintf("step_%s_%d", jobID, stepIdx)
					ra.markUnreachable(stepNodeID)
				}
			}
		}

		// Check job dependencies - if no needed jobs are reachable, job is unreachable
		if len(job.Needs) > 0 {
			hasReachableDependency := false
			for _, needsJob := range job.Needs {
				needsJobID := fmt.Sprintf("job_%s", needsJob)
				if ra.reachableNodes[needsJobID] {
					hasReachableDependency = true
					break
				}
			}
			if !hasReachableDependency {
				ra.markUnreachable(jobNodeID)
				// Remove all steps in this job too
				for stepIdx := range job.Steps {
					stepNodeID := fmt.Sprintf("step_%s_%d", jobID, stepIdx)
					ra.markUnreachable(stepNodeID)
				}
			}
		}

		// Analyze step-level conditions
		for stepIdx, step := range job.Steps {
			stepNodeID := fmt.Sprintf("step_%s_%d", jobID, stepIdx)

			// Skip if parent job is unreachable
			if !ra.reachableNodes[jobNodeID] {
				ra.markUnreachable(stepNodeID)
				continue
			}

			if step.If != "" {
				condition := ra.parseCondition(step.If)
				ra.conditions[stepNodeID] = condition

				if condition.StaticEval != nil && !*condition.StaticEval {
					ra.markUnreachable(stepNodeID)
				}
			}
		}
	}
}

func (ra *ReachabilityAnalyzer) parseCondition(expr string) *ConditionAnalyzer {
	condition := &ConditionAnalyzer{
		Expression: expr,
		Variables:  []string{},
		Secrets:    []string{},
		Github:     []string{},
		Inputs:     []string{},
		Env:        []string{},
		Vars:       []string{},
		Steps:      []string{},
		Jobs:       []string{},
		Needs:      []string{},
		Matrix:     []string{},
		Operators:  []string{},
		Functions:  []string{},
	}

	// Clean the expression for analysis
	cleanExpr := strings.TrimSpace(expr)

	// Check for GitHub Actions functions
	condition.Always = strings.Contains(cleanExpr, "always()")
	condition.Failure = strings.Contains(cleanExpr, "failure()")
	condition.Success = strings.Contains(cleanExpr, "success()")
	condition.Cancelled = strings.Contains(cleanExpr, "cancelled()")

	// Extract logical operators
	operators := []string{"&&", "||", "!", "==", "!=", "<", ">", "<=", ">=", "contains", "startsWith", "endsWith"}
	for _, op := range operators {
		if strings.Contains(cleanExpr, op) {
			condition.Operators = append(condition.Operators, op)
		}
	}

	// Extract functions
	functionRegex := regexp.MustCompile(`(\w+)\s*\(`)
	functionMatches := functionRegex.FindAllStringSubmatch(cleanExpr, -1)
	for _, match := range functionMatches {
		if len(match) > 1 {
			condition.Functions = append(condition.Functions, match[1])
		}
	}

	// Extract variable references using regex
	varRegex := regexp.MustCompile(`\$\{\{\s*([^}]+)\s*\}\}`)
	matches := varRegex.FindAllStringSubmatch(cleanExpr, -1)

	for _, match := range matches {
		if len(match) > 1 {
			ref := strings.TrimSpace(match[1])
			switch {
			case strings.HasPrefix(ref, "secrets."):
				condition.Secrets = append(condition.Secrets, ref)
			case strings.HasPrefix(ref, "github."):
				condition.Github = append(condition.Github, ref)
			case strings.HasPrefix(ref, "env."):
				condition.Env = append(condition.Env, ref)
			case strings.HasPrefix(ref, "inputs."):
				condition.Inputs = append(condition.Inputs, ref)
			case strings.HasPrefix(ref, "vars."):
				condition.Vars = append(condition.Vars, ref)
			case strings.HasPrefix(ref, "steps."):
				condition.Steps = append(condition.Steps, ref)
			case strings.HasPrefix(ref, "jobs."):
				condition.Jobs = append(condition.Jobs, ref)
			case strings.HasPrefix(ref, "needs."):
				condition.Needs = append(condition.Needs, ref)
			case strings.HasPrefix(ref, "matrix."):
				condition.Matrix = append(condition.Matrix, ref)
			default:
				condition.Variables = append(condition.Variables, ref)
			}
		}
	}

	// Attempt static evaluation with enhanced context understanding
	condition.StaticEval = ra.evaluateStatically(cleanExpr, condition)

	// Calculate complexity score
	condition.Complexity = ra.calculateComplexity(condition)

	// Determine if condition depends on runtime context
	condition.ContextDependency = ra.hasContextDependency(condition)

	return condition
}

// calculateComplexity assigns a complexity score to the condition
func (ra *ReachabilityAnalyzer) calculateComplexity(condition *ConditionAnalyzer) int {
	complexity := 0

	// Base complexity from operators
	complexity += len(condition.Operators)

	// Add complexity for different context types
	complexity += len(condition.Github) * 2 // GitHub context adds more complexity
	complexity += len(condition.Secrets)    // Secrets add complexity
	complexity += len(condition.Steps) * 2  // Step dependencies are complex
	complexity += len(condition.Jobs) * 2   // Job dependencies are complex
	complexity += len(condition.Matrix)     // Matrix builds add complexity
	complexity += len(condition.Functions)  // Functions add complexity

	// Special function complexity
	if condition.Always || condition.Failure || condition.Success || condition.Cancelled {
		complexity += 3 // Status functions add significant complexity
	}

	return complexity
}

// hasContextDependency checks if condition depends on runtime context
func (ra *ReachabilityAnalyzer) hasContextDependency(condition *ConditionAnalyzer) bool {
	// These contexts are only available at runtime
	runtimeContexts := []string{
		"github.event", "github.run_", "github.job", "github.step_summary",
		"runner.", "job.", "steps.", "needs.",
	}

	// Check all context references
	allRefs := append(condition.Github, condition.Steps...)
	allRefs = append(allRefs, condition.Jobs...)
	allRefs = append(allRefs, condition.Needs...)

	for _, ref := range allRefs {
		for _, runtimeCtx := range runtimeContexts {
			if strings.Contains(ref, runtimeCtx) {
				return true
			}
		}
	}

	// Status functions depend on runtime context
	return condition.Always || condition.Failure || condition.Success || condition.Cancelled
}

func (ra *ReachabilityAnalyzer) evaluateStatically(expr string, condition *ConditionAnalyzer) *bool {
	// Remove GitHub Actions expression syntax for easier parsing
	cleanExpr := strings.TrimSpace(expr)
	if strings.HasPrefix(cleanExpr, "${{") && strings.HasSuffix(cleanExpr, "}}") {
		cleanExpr = strings.TrimSpace(cleanExpr[3 : len(cleanExpr)-2])
	}

	// If condition has runtime dependencies, cannot evaluate statically
	if condition.ContextDependency {
		return nil
	}

	// Enhanced static evaluation patterns
	staticPatterns := map[string]bool{
		"true":                    true,
		"false":                   false,
		"1":                       true,
		"0":                       false,
		"'true'":                  true,
		"'false'":                 false,
		"\"true\"":                true,
		"\"false\"":               false,
		"github.repository == ''": false, // Repository is never empty
		"github.ref == ''":        false, // Ref is never empty
		"env.CI == 'true'":        true,  // Always true in GitHub Actions
		"always()":                true,  // Always evaluates to true
	}

	// Check for direct static patterns
	if result, exists := staticPatterns[cleanExpr]; exists {
		return &result
	}

	// Enhanced pattern matching for more complex expressions
	return ra.evaluateComplexStatic(cleanExpr, condition)
}

// evaluateComplexStatic handles more complex static evaluation
func (ra *ReachabilityAnalyzer) evaluateComplexStatic(expr string, condition *ConditionAnalyzer) *bool {
	// Handle negation
	if strings.HasPrefix(expr, "!") {
		innerExpr := strings.TrimSpace(expr[1:])
		if innerResult := ra.evaluateStatically(innerExpr, condition); innerResult != nil {
			result := !*innerResult
			return &result
		}
	}

	// Handle simple boolean logic
	if strings.Contains(expr, "&&") {
		parts := strings.Split(expr, "&&")
		allTrue := true
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if result := ra.evaluateStatically(part, condition); result != nil {
				if !*result {
					allTrue = false
					break
				}
			} else {
				return nil // Cannot evaluate statically
			}
		}
		return &allTrue
	}

	if strings.Contains(expr, "||") {
		parts := strings.Split(expr, "||")
		anyTrue := false
		allEvaluable := true
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if result := ra.evaluateStatically(part, condition); result != nil {
				if *result {
					anyTrue = true
					break
				}
			} else {
				allEvaluable = false
			}
		}
		if anyTrue {
			return &anyTrue
		}
		if !allEvaluable {
			return nil
		}
		return &anyTrue
	}

	// Handle string comparisons with known values
	if ra.isKnownStringComparison(expr) {
		result := ra.evaluateStringComparison(expr)
		return result
	}

	// Handle contains/startsWith/endsWith functions
	if ra.isStringFunction(expr) {
		result := ra.evaluateStringFunction(expr)
		return result
	}

	return nil
}

// isKnownStringComparison checks if expression is a comparison with known values
func (ra *ReachabilityAnalyzer) isKnownStringComparison(expr string) bool {
	comparisonOps := []string{"==", "!=", "=", "<>"}
	for _, op := range comparisonOps {
		if strings.Contains(expr, op) {
			return true
		}
	}
	return false
}

// evaluateStringComparison evaluates string comparison expressions
func (ra *ReachabilityAnalyzer) evaluateStringComparison(expr string) *bool {
	// This is a simplified implementation - could be enhanced further
	knownComparisons := map[string]bool{
		"github.event_name == 'push'":         true,  // Often true
		"github.event_name == 'pull_request'": true,  // Often true
		"github.event_name == 'schedule'":     false, // Usually false
		"github.ref == 'refs/heads/main'":     true,  // Often true for main branch
		"github.ref == 'refs/heads/master'":   true,  // Often true for master branch
		"github.actor == 'dependabot[bot]'":   false, // Usually false
		"github.base_ref == ''":               false, // Usually not empty
		"runner.os == 'Linux'":                true,  // Most common
		"runner.os == 'Windows'":              false, // Less common
		"runner.os == 'macOS'":                false, // Less common
	}

	normalizedExpr := strings.ReplaceAll(expr, " ", "")
	normalizedExpr = strings.ReplaceAll(normalizedExpr, "'", "\"")

	for pattern, result := range knownComparisons {
		normalizedPattern := strings.ReplaceAll(pattern, " ", "")
		normalizedPattern = strings.ReplaceAll(normalizedPattern, "'", "\"")

		if normalizedExpr == normalizedPattern {
			return &result
		}
	}

	return nil
}

// isStringFunction checks if expression uses string functions
func (ra *ReachabilityAnalyzer) isStringFunction(expr string) bool {
	stringFunctions := []string{"contains(", "startsWith(", "endsWith("}
	for _, fn := range stringFunctions {
		if strings.Contains(expr, fn) {
			return true
		}
	}
	return false
}

// evaluateStringFunction evaluates string function expressions
func (ra *ReachabilityAnalyzer) evaluateStringFunction(expr string) *bool {
	// Simplified evaluation for string functions
	// In a real implementation, this would parse the function calls properly

	// Common patterns that are often true
	truePatterns := []string{
		"contains(github.ref, 'refs/heads')",  // refs usually contain refs/heads
		"startsWith(github.ref, 'refs/')",     // refs always start with refs/
		"contains(github.event_name, 'pull')", // pull_request contains pull
		"startsWith(runner.os, 'Lin')",        // Linux starts with Lin
	}

	// Common patterns that are often false
	falsePatterns := []string{
		"contains(github.actor, 'bot')",       // Usually not a bot
		"contains(github.ref, 'release')",     // Usually not a release branch
		"startsWith(github.ref, 'refs/tags')", // Usually not a tag
	}

	for _, pattern := range truePatterns {
		if strings.Contains(expr, pattern) {
			result := true
			return &result
		}
	}

	for _, pattern := range falsePatterns {
		if strings.Contains(expr, pattern) {
			result := false
			return &result
		}
	}

	return nil
}

func (ra *ReachabilityAnalyzer) updateWorkflowReachability(workflow *WorkflowAST) {
	// Update job reachability
	for jobID, job := range workflow.Jobs {
		jobNodeID := fmt.Sprintf("job_%s", jobID)
		job.Reachable = ra.reachableNodes[jobNodeID]

		// Update step reachability
		for stepIdx, step := range job.Steps {
			stepNodeID := fmt.Sprintf("step_%s_%d", jobID, stepIdx)
			step.Reachable = ra.reachableNodes[stepNodeID]
		}
	}

	// Update trigger reachability
	for _, trigger := range workflow.Triggers {
		triggerID := fmt.Sprintf("trigger_%s", trigger.Event)
		trigger.Reachable = ra.reachableNodes[triggerID]
	}
}

func (ra *ReachabilityAnalyzer) markReachable(nodeID string) {
	ra.reachableNodes[nodeID] = true
}

func (ra *ReachabilityAnalyzer) markUnreachable(nodeID string) {
	delete(ra.reachableNodes, nodeID)
}

// GetReachableNodes returns all reachable nodes
func (ra *ReachabilityAnalyzer) GetReachableNodes() map[string]bool {
	return ra.reachableNodes
}

// GetUnreachableNodes returns nodes that are defined but not reachable
func (ra *ReachabilityAnalyzer) GetUnreachableNodes() []string {
	var unreachable []string

	allNodes := ra.callGraph.GetNodes()
	for nodeID := range allNodes {
		if !ra.reachableNodes[nodeID] {
			unreachable = append(unreachable, nodeID)
		}
	}

	return unreachable
}

// IsReachable checks if a specific node is reachable
func (ra *ReachabilityAnalyzer) IsReachable(nodeID string) bool {
	return ra.reachableNodes[nodeID]
}

// GetConditionAnalysis returns the condition analysis for a node
func (ra *ReachabilityAnalyzer) GetConditionAnalysis(nodeID string) *ConditionAnalyzer {
	return ra.conditions[nodeID]
}

// GetReachabilityReport generates a detailed reachability report
func (ra *ReachabilityAnalyzer) GetReachabilityReport() *ReachabilityReport {
	report := &ReachabilityReport{
		TotalNodes:       len(ra.callGraph.GetNodes()),
		ReachableNodes:   len(ra.reachableNodes),
		UnreachableNodes: ra.GetUnreachableNodes(),
		ConditionalNodes: make(map[string]*ConditionAnalyzer),
	}

	// Add condition analysis to report
	for nodeID, condition := range ra.conditions {
		report.ConditionalNodes[nodeID] = condition
	}

	return report
}

// ReachabilityReport contains detailed reachability analysis results
type ReachabilityReport struct {
	TotalNodes       int
	ReachableNodes   int
	UnreachableNodes []string
	ConditionalNodes map[string]*ConditionAnalyzer
}

// GetReachabilityPercentage calculates the percentage of reachable nodes
func (rr *ReachabilityReport) GetReachabilityPercentage() float64 {
	if rr.TotalNodes == 0 {
		return 0.0
	}
	return float64(rr.ReachableNodes) / float64(rr.TotalNodes) * 100.0
}

// HasUnreachableCode returns true if there are unreachable nodes
func (rr *ReachabilityReport) HasUnreachableCode() bool {
	return len(rr.UnreachableNodes) > 0
}

// GetConditionalNodesCount returns the number of nodes with conditions
func (rr *ReachabilityReport) GetConditionalNodesCount() int {
	return len(rr.ConditionalNodes)
}

// GetStaticallyFalseConditions returns nodes with statically false conditions
func (rr *ReachabilityReport) GetStaticallyFalseConditions() []string {
	var falseConditions []string

	for nodeID, condition := range rr.ConditionalNodes {
		if condition.StaticEval != nil && !*condition.StaticEval {
			falseConditions = append(falseConditions, nodeID)
		}
	}

	return falseConditions
}

// AnalyzeConditionComplexity analyzes the complexity of conditional expressions
func (ca *ConditionAnalyzer) AnalyzeConditionComplexity() map[string]interface{} {
	complexity := map[string]interface{}{
		"has_functions":    ca.Always || ca.Failure || ca.Success || ca.Cancelled,
		"function_count":   0,
		"variable_count":   len(ca.Variables),
		"secret_count":     len(ca.Secrets),
		"github_count":     len(ca.Github),
		"total_references": len(ca.Variables) + len(ca.Secrets) + len(ca.Github),
		"is_static":        ca.StaticEval != nil,
		"static_result":    ca.StaticEval,
	}

	functionCount := 0
	if ca.Always {
		functionCount++
	}
	if ca.Failure {
		functionCount++
	}
	if ca.Success {
		functionCount++
	}
	if ca.Cancelled {
		functionCount++
	}
	complexity["function_count"] = functionCount

	return complexity
}
