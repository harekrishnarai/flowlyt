package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/harekrishnarai/flowlyt/pkg/analysis/ast"
	"github.com/harekrishnarai/flowlyt/pkg/constants"
	"github.com/harekrishnarai/flowlyt/pkg/parser"
	"github.com/harekrishnarai/flowlyt/pkg/platform"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

// ASTEnhancedEngine extends the hybrid engine with AST-based analysis
type ASTEnhancedEngine struct {
	*HybridEngine
	astAnalyzer *ast.ASTAnalyzer
	config      ASTEnhancedConfig
}

// ASTEnhancedConfig extends the base config with AST-specific settings
type ASTEnhancedConfig struct {
	Config                                        // Embed base config
	EnableReachabilityAnalysis bool               `json:"enable_reachability_analysis"`
	EnableDataFlowAnalysis     bool               `json:"enable_data_flow_analysis"`
	EnableCallGraphAnalysis    bool               `json:"enable_call_graph_analysis"`
	FilterUnreachableFindings  bool               `json:"filter_unreachable_findings"`
	MinDataFlowSeverity        string             `json:"min_data_flow_severity"`
	ReachabilityConfig         ReachabilityConfig `json:"reachability_config"`
}

// ReachabilityConfig configures reachability analysis behavior
type ReachabilityConfig struct {
	AnalyzeConditionals     bool `json:"analyze_conditionals"`
	StaticEvaluation        bool `json:"static_evaluation"`
	MarkUnreachableFindings bool `json:"mark_unreachable_findings"`
	ReportUnreachableCode   bool `json:"report_unreachable_code"`
}

// EnhancedAnalysisResult extends AnalysisResult with AST analysis data
type EnhancedAnalysisResult struct {
	*AnalysisResult
	ReachabilityReport *ast.ReachabilityReport `json:"reachability_report"`
	DataFlowFindings   []DataFlowFinding       `json:"data_flow_findings"`
	CallGraphMetrics   CallGraphMetrics        `json:"call_graph_metrics"`
	FilteredFindings   int                     `json:"filtered_findings_count"`
}

// DataFlowFinding represents a finding from data flow analysis
type DataFlowFinding struct {
	rules.Finding
	SourceID   string   `json:"source_id"`
	SinkID     string   `json:"sink_id"`
	FlowPath   []string `json:"flow_path"`
	TaintLevel string   `json:"taint_level"`
	RiskLevel  string   `json:"risk_level"`
}

// CallGraphMetrics provides metrics about the call graph
type CallGraphMetrics struct {
	TotalNodes    int            `json:"total_nodes"`
	NodesByType   map[string]int `json:"nodes_by_type"`
	TotalEdges    int            `json:"total_edges"`
	MaxDepth      int            `json:"max_depth"`
	ExternalCalls int            `json:"external_calls"`
	ActionCalls   int            `json:"action_calls"`
}

// NewASTEnhancedEngine creates a new AST-enhanced analysis engine
func NewASTEnhancedEngine(config ASTEnhancedConfig) (*ASTEnhancedEngine, error) {
	// Create base hybrid engine
	hybridEngine, err := NewHybridEngine(config.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to create hybrid engine: %w", err)
	}

	return &ASTEnhancedEngine{
		HybridEngine: hybridEngine,
		astAnalyzer:  ast.NewASTAnalyzer(),
		config:       config,
	}, nil
}

// AnalyzeWithAST performs enhanced analysis with AST-based reachability and data flow
func (e *ASTEnhancedEngine) AnalyzeWithAST(ctx context.Context, workflowFiles []parser.WorkflowFile) (*EnhancedAnalysisResult, error) {
	startTime := time.Now()

	// Create a basic analysis result structure
	standardResult := &AnalysisResult{
		Workflows:        []*platform.Workflow{},
		CombinedFindings: []rules.Finding{},
		Statistics: Statistics{
			PlatformBreakdown:  make(map[string]int),
			FindingsByCategory: make(map[rules.Category]int),
			FindingsBySeverity: make(map[rules.Severity]int),
		},
		Performance: PerformanceMetrics{},
	}

	// Analyze each workflow with the hybrid engine first
	for _, workflowFile := range workflowFiles {
		result, err := e.HybridEngine.AnalyzeWorkflow(workflowFile.Path)
		if err != nil {
			fmt.Printf("Warning: Standard analysis failed for %s: %v\n", workflowFile.Path, err)
			continue
		}

		// Merge results
		standardResult.Workflows = append(standardResult.Workflows, result.Workflows...)
		standardResult.CombinedFindings = append(standardResult.CombinedFindings, result.CombinedFindings...)

		// Update statistics
		for platform, count := range result.Statistics.PlatformBreakdown {
			standardResult.Statistics.PlatformBreakdown[platform] += count
		}
		for category, count := range result.Statistics.FindingsByCategory {
			standardResult.Statistics.FindingsByCategory[category] += count
		}
		for severity, count := range result.Statistics.FindingsBySeverity {
			standardResult.Statistics.FindingsBySeverity[severity] += count
		}
	}

	// Create enhanced result
	enhancedResult := &EnhancedAnalysisResult{
		AnalysisResult: standardResult,
	}

	// Perform AST analysis on each workflow
	var allDataFlowFindings []DataFlowFinding
	var aggregatedCallGraphMetrics CallGraphMetrics
	filteredCount := 0

	for _, workflowFile := range workflowFiles {
		// Reset analyzer state for each workflow to prevent memory leaks
		e.astAnalyzer.Reset()

		// Parse workflow into AST
		workflowAST, err := e.astAnalyzer.ParseWorkflow(workflowFile.Content)
		if err != nil {
			// Return detailed error instead of just logging
			return nil, fmt.Errorf("failed to parse workflow %s for AST analysis: %w", workflowFile.Path, err)
		}

		// Set platform information
		workflowAST.Platform = e.detectPlatform(workflowFile.Path)

		// Perform reachability analysis
		var reachableNodes map[string]bool
		if e.config.EnableReachabilityAnalysis {
			reachableNodes = e.astAnalyzer.AnalyzeReachability(workflowAST)
			if len(reachableNodes) == 0 {
				return nil, fmt.Errorf("reachability analysis failed for workflow %s: no reachable nodes found", workflowFile.Path)
			}
		}

		// Perform data flow analysis
		var dataFlows []*ast.DataFlow
		if e.config.EnableDataFlowAnalysis {
			dataFlows, err = e.astAnalyzer.AnalyzeDataFlow(workflowAST)
			if err != nil {
				return nil, fmt.Errorf("data flow analysis failed for %s: %w", workflowFile.Path, err)
			}

			// Convert data flows to findings
			dataFlowFindings := e.convertDataFlowsToFindings(dataFlows, workflowFile.Path)
			allDataFlowFindings = append(allDataFlowFindings, dataFlowFindings...)
		}

		// Filter existing findings by reachability
		if e.config.FilterUnreachableFindings && reachableNodes != nil {
			originalCount := len(enhancedResult.CombinedFindings)
			enhancedResult.CombinedFindings = e.filterFindingsByReachability(
				enhancedResult.CombinedFindings,
				reachableNodes,
				workflowAST,
				workflowFile.Path,
			)
			filteredCount += originalCount - len(enhancedResult.CombinedFindings)
		}

		// Collect call graph metrics
		if e.config.EnableCallGraphAnalysis {
			metrics := e.calculateCallGraphMetrics(workflowAST)
			aggregatedCallGraphMetrics.TotalNodes += metrics.TotalNodes
			aggregatedCallGraphMetrics.TotalEdges += metrics.TotalEdges
			aggregatedCallGraphMetrics.ExternalCalls += metrics.ExternalCalls
			aggregatedCallGraphMetrics.ActionCalls += metrics.ActionCalls

			if metrics.MaxDepth > aggregatedCallGraphMetrics.MaxDepth {
				aggregatedCallGraphMetrics.MaxDepth = metrics.MaxDepth
			}
		}
	}

	// Generate reachability report
	if e.config.EnableReachabilityAnalysis {
		enhancedResult.ReachabilityReport = e.astAnalyzer.GetReachabilityReport()
	}

	// Add data flow findings
	enhancedResult.DataFlowFindings = allDataFlowFindings
	enhancedResult.CallGraphMetrics = aggregatedCallGraphMetrics
	enhancedResult.FilteredFindings = filteredCount

	// Update performance metrics
	enhancedResult.Performance.TotalExecutionTimeMs = time.Since(startTime).Milliseconds()

	return enhancedResult, nil
}

func (e *ASTEnhancedEngine) detectPlatform(filePath string) string {
	if strings.Contains(filePath, ".github/workflows") {
		return constants.PlatformGitHub
	}
	if strings.Contains(filePath, ".gitlab-ci.yml") || strings.Contains(filePath, ".gitlab-ci.yaml") {
		return constants.PlatformGitLab
	}
	return constants.DefaultPlatform
}

func (e *ASTEnhancedEngine) convertDataFlowsToFindings(dataFlows []*ast.DataFlow, filePath string) []DataFlowFinding {
	var findings []DataFlowFinding

	for _, flow := range dataFlows {
		// Skip flows below minimum severity threshold
		if !e.meetsSeverityThreshold(flow.Severity) {
			continue
		}

		finding := DataFlowFinding{
			Finding: rules.Finding{
				RuleID:      fmt.Sprintf("DATAFLOW_%s", flow.SourceID),
				RuleName:    "Sensitive Data Flow",
				Description: fmt.Sprintf("Sensitive data flows from %s to %s: %s", flow.SourceID, flow.SinkID, flow.Risk),
				Severity:    e.convertSeverity(flow.Severity),
				Category:    rules.DataExposure,
				FilePath:    filePath,
				Evidence:    fmt.Sprintf("Data flow: %s → %s", flow.SourceID, flow.SinkID),
				Remediation: e.generateDataFlowRemediation(flow),
			},
			SourceID:   flow.SourceID,
			SinkID:     flow.SinkID,
			FlowPath:   flow.Path,
			TaintLevel: e.getTaintLevel(flow),
			RiskLevel:  flow.Risk,
		}

		findings = append(findings, finding)
	}

	return findings
}

func (e *ASTEnhancedEngine) filterFindingsByReachability(
	findings []rules.Finding,
	reachableNodes map[string]bool,
	workflow *ast.WorkflowAST,
	filePath string,
) []rules.Finding {
	var reachableFindings []rules.Finding

	for _, finding := range findings {
		if e.isFindingReachable(finding, reachableNodes, workflow) {
			reachableFindings = append(reachableFindings, finding)
		} else if e.config.ReachabilityConfig.MarkUnreachableFindings {
			// Mark as suppressed but keep for reporting
			finding.Evidence += " [UNREACHABLE: Code path not reachable]"
			reachableFindings = append(reachableFindings, finding)
		}
		// If MarkUnreachableFindings is false, we simply don't include unreachable findings
	}

	return reachableFindings
}

func (e *ASTEnhancedEngine) isFindingReachable(
	finding rules.Finding,
	reachableNodes map[string]bool,
	workflow *ast.WorkflowAST,
) bool {
	// Map finding to AST nodes based on job/step information
	if finding.JobName != "" {
		jobNodeID := fmt.Sprintf("job_%s", finding.JobName)
		if !reachableNodes[jobNodeID] {
			return false
		}

		if finding.StepName != "" {
			// Find step index and check reachability
			if job, exists := workflow.Jobs[finding.JobName]; exists {
				for stepIdx, step := range job.Steps {
					if step.Name == finding.StepName || step.ID == finding.StepName {
						stepNodeID := fmt.Sprintf("step_%s_%d", finding.JobName, stepIdx)
						return reachableNodes[stepNodeID]
					}
				}
			}
		}
	}

	return true // Default to reachable if we can't determine
}

func (e *ASTEnhancedEngine) calculateCallGraphMetrics(workflow *ast.WorkflowAST) CallGraphMetrics {
	callGraph := ast.NewCallGraph()
	callGraph.BuildCallGraph(workflow)

	nodes := callGraph.GetNodes()
	edges := callGraph.GetAllEdges()

	metrics := CallGraphMetrics{
		TotalNodes:  len(nodes),
		NodesByType: make(map[string]int),
		TotalEdges:  0,
	}

	// Count nodes by type
	for _, node := range nodes {
		metrics.NodesByType[node.Type]++
		if node.Type == "external_call" {
			metrics.ExternalCalls++
		}
		if node.Type == "action" {
			metrics.ActionCalls++
		}
	}

	// Count total edges
	for _, edgeList := range edges {
		metrics.TotalEdges += len(edgeList)
	}

	// Calculate max depth (simplified)
	metrics.MaxDepth = e.calculateMaxDepth(callGraph)

	return metrics
}

func (e *ASTEnhancedEngine) calculateMaxDepth(callGraph *ast.CallGraph) int {
	// Simplified depth calculation
	// In a real implementation, this would do proper graph traversal
	return 5 // Placeholder
}

func (e *ASTEnhancedEngine) meetsSeverityThreshold(severity string) bool {
	if e.config.MinDataFlowSeverity == "" {
		return true
	}

	severityLevels := map[string]int{
		"INFO":     0,
		"LOW":      1,
		"MEDIUM":   2,
		"HIGH":     3,
		"CRITICAL": 4,
	}

	minLevel := severityLevels[e.config.MinDataFlowSeverity]
	currentLevel := severityLevels[severity]

	return currentLevel >= minLevel
}

func (e *ASTEnhancedEngine) convertSeverity(astSeverity string) rules.Severity {
	switch astSeverity {
	case "CRITICAL":
		return rules.Critical
	case "HIGH":
		return rules.High
	case "MEDIUM":
		return rules.Medium
	case "LOW":
		return rules.Low
	default:
		return rules.Info
	}
}

func (e *ASTEnhancedEngine) getTaintLevel(flow *ast.DataFlow) string {
	if flow.Tainted {
		return "HIGH"
	}
	return "LOW"
}

func (e *ASTEnhancedEngine) generateDataFlowRemediation(flow *ast.DataFlow) string {
	switch {
	case strings.Contains(flow.Risk, "Secret exposure"):
		return "Avoid logging or transmitting secrets. Use secure secret management practices."
	case strings.Contains(flow.Risk, "network"):
		return "Validate and sanitize data before network transmission. Use secure protocols."
	case strings.Contains(flow.Risk, "GitHub token"):
		return "Limit GitHub token permissions to minimum required. Avoid exposing tokens in logs."
	default:
		return "Review data flow to ensure sensitive information is properly protected."
	}
}

// GetReachabilityReport returns the latest reachability analysis report
func (e *ASTEnhancedEngine) GetReachabilityReport() *ast.ReachabilityReport {
	return e.astAnalyzer.GetReachabilityReport()
}

// AnalyzeWorkflowReachability performs reachability analysis on a single workflow
func (e *ASTEnhancedEngine) AnalyzeWorkflowReachability(workflowContent interface{}) (map[string]bool, error) {
	workflowAST, err := e.astAnalyzer.ParseWorkflow(workflowContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse workflow: %w", err)
	}

	return e.astAnalyzer.AnalyzeReachability(workflowAST), nil
}

// AnalyzeWorkflowDataFlow performs data flow analysis on a single workflow
func (e *ASTEnhancedEngine) AnalyzeWorkflowDataFlow(workflowContent interface{}) ([]*ast.DataFlow, error) {
	workflowAST, err := e.astAnalyzer.ParseWorkflow(workflowContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse workflow: %w", err)
	}

	return e.astAnalyzer.AnalyzeDataFlow(workflowAST)
}

// DefaultASTEnhancedConfig returns a default configuration for AST-enhanced analysis
func DefaultASTEnhancedConfig() ASTEnhancedConfig {
	return ASTEnhancedConfig{
		Config:                     Config{}, // Use default base config
		EnableReachabilityAnalysis: true,
		EnableDataFlowAnalysis:     true,
		EnableCallGraphAnalysis:    true,
		FilterUnreachableFindings:  true,
		MinDataFlowSeverity:        constants.SeverityLow,
		ReachabilityConfig: ReachabilityConfig{
			AnalyzeConditionals:     true,
			StaticEvaluation:        true,
			MarkUnreachableFindings: true,
			ReportUnreachableCode:   true,
		},
	}
}
