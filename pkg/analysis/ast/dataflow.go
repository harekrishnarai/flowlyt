package ast

import (
	"fmt"
	"regexp"
	"strings"
)

// DataFlowAnalyzer tracks data flow through the workflow
type DataFlowAnalyzer struct {
	sources   map[string]*DataSource
	sinks     map[string]*DataSink
	flows     []*DataFlow
	flowGraph *DataFlowGraph // Add graph for efficient analysis
}

// DataFlowGraph represents the workflow structure as a directed graph
type DataFlowGraph struct {
	adjacencyList map[string][]string
	nodeToSource  map[string]*DataSource
	nodeToSink    map[string]*DataSink
}

// DataSource represents a source of data in the workflow
type DataSource struct {
	ID      string
	Type    string // "input", "secret", "env", "output", "artifact", "github_context"
	Name    string
	NodeID  string
	Tainted bool   // Whether this source contains sensitive data
	Origin  string // Where the data originally comes from
	Value   string // The actual value or reference
}

// DataSink represents a destination for data in the workflow
type DataSink struct {
	ID        string
	Type      string // "output", "log", "network", "file", "env", "action_input"
	Name      string
	NodeID    string
	Sensitive bool   // Whether this sink could leak sensitive data
	Command   string // The command or action that creates this sink
}

// DataFlow represents a flow of data from source to sink
type DataFlow struct {
	SourceID string
	SinkID   string
	Path     []string // Nodes the data flows through
	Tainted  bool
	Severity string // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	Risk     string // Description of the risk
}

// NewDataFlowAnalyzer creates a new data flow analyzer
func NewDataFlowAnalyzer() *DataFlowAnalyzer {
	return &DataFlowAnalyzer{
		sources:   make(map[string]*DataSource),
		sinks:     make(map[string]*DataSink),
		flows:     []*DataFlow{},
		flowGraph: nil,
	}
}

// Reset clears all analysis data for reuse
func (dfa *DataFlowAnalyzer) Reset() {
	// Clear maps efficiently
	for k := range dfa.sources {
		delete(dfa.sources, k)
	}
	for k := range dfa.sinks {
		delete(dfa.sinks, k)
	}

	// Reset slices
	dfa.flows = dfa.flows[:0]
	dfa.flowGraph = nil
}

// AnalyzeDataFlow performs data flow analysis on the workflow
func (dfa *DataFlowAnalyzer) AnalyzeDataFlow(workflow *WorkflowAST) error {
	// Reset previous analysis
	dfa.Reset()

	// Identify all data sources and sinks
	dfa.identifyDataSources(workflow)
	dfa.identifyDataSinks(workflow)

	// Trace data flows using graph analysis
	dfa.traceDataFlows(workflow)

	return nil
}

// AnalyzeDataFlowWithCallGraph performs analysis using call graph for accuracy
func (dfa *DataFlowAnalyzer) AnalyzeDataFlowWithCallGraph(workflow *WorkflowAST, callGraph *CallGraph) error {
	// Reset previous analysis
	dfa.Reset()

	// Identify all data sources and sinks
	dfa.identifyDataSources(workflow)
	dfa.identifyDataSinks(workflow)

	// Use call graph for more accurate flow analysis
	dfa.traceDataFlowsWithCallGraph(workflow, callGraph)

	return nil
}

// traceDataFlowsWithCallGraph uses call graph for more accurate analysis
func (dfa *DataFlowAnalyzer) traceDataFlowsWithCallGraph(workflow *WorkflowAST, callGraph *CallGraph) {
	// 🚀 PERFORMANCE FIX: Use efficient O(V+E) graph traversal instead of O(n²)
	for sourceID, source := range dfa.sources {
		// Find only reachable sinks for this source using BFS (O(V+E) per source)
		reachableSinks := dfa.findReachableSinksForSource(source, callGraph)

		for _, sinkInfo := range reachableSinks {
			// Only create flows for sinks that have actual data dependencies
			if dfa.hasActualDataFlow(source, sinkInfo.sink, sinkInfo.path) {
				severity := dfa.calculateFlowSeverity(source, sinkInfo.sink)
				risk := dfa.calculateFlowRisk(source, sinkInfo.sink)

				flow := &DataFlow{
					SourceID: sourceID,
					SinkID:   sinkInfo.sink.ID,
					Path:     sinkInfo.path,
					Tainted:  source.Tainted,
					Severity: severity,
					Risk:     risk,
				}
				dfa.flows = append(dfa.flows, flow)
			}
		}
	}
}

// SinkInfo contains sink and path information
type SinkInfo struct {
	sink *DataSink
	path []string
}

// findReachableSinksForSource efficiently finds all reachable sinks for a source
func (dfa *DataFlowAnalyzer) findReachableSinksForSource(source *DataSource, callGraph *CallGraph) []SinkInfo {
	var result []SinkInfo
	visited := make(map[string]bool)
	queue := []string{source.NodeID}
	parent := make(map[string]string)

	for len(queue) > 0 {
		currentNode := queue[0]
		queue = queue[1:]

		if visited[currentNode] {
			continue
		}
		visited[currentNode] = true

		// Check if this node has sinks
		for _, sink := range dfa.sinks {
			if sink.NodeID == currentNode {
				// Reconstruct path from source to this sink
				path := dfa.reconstructPath(source.NodeID, currentNode, parent)
				result = append(result, SinkInfo{
					sink: sink,
					path: path,
				})
			}
		}

		// Add connected nodes to queue
		edges := callGraph.GetEdges(currentNode)
		for _, nextNode := range edges {
			if !visited[nextNode] {
				parent[nextNode] = currentNode
				queue = append(queue, nextNode)
			}
		}
	}

	return result
}

// reconstructPath builds the path from source to sink
func (dfa *DataFlowAnalyzer) reconstructPath(start, end string, parent map[string]string) []string {
	if start == end {
		return []string{start}
	}

	path := []string{}
	current := end

	for current != "" && current != start {
		path = append([]string{current}, path...)
		current = parent[current]
	}

	if current == start {
		path = append([]string{start}, path...)
	}

	return path
}

// hasActualDataFlow checks if there's a real data dependency between source and sink
func (dfa *DataFlowAnalyzer) hasActualDataFlow(source *DataSource, sink *DataSink, path []string) bool {
	// 🎯 ACCURACY FIX: Filter out unrelated data flows

	// 1. Check if source and sink are data-type compatible
	if !dfa.areDataTypesCompatible(source, sink) {
		return false
	}

	// 2. Check if the path involves actual data usage (not just reachability)
	if !dfa.pathInvolvesSameData(source, sink, path) {
		return false
	}

	// 3. Check if it's within the same logical workflow context
	if !dfa.withinSameContext(source, sink) {
		return false
	}

	// 4. Filter out obvious false positives
	if dfa.isObviousFalsePositive(source, sink) {
		return false
	}

	return true
}

// areDataTypesCompatible checks if source and sink can actually exchange data
func (dfa *DataFlowAnalyzer) areDataTypesCompatible(source *DataSource, sink *DataSink) bool {
	// Environment variables can flow to environment assignments or command execution
	if source.Type == "env" {
		return sink.Type == "env" || sink.Type == "log" || sink.Type == "action_input"
	}

	// Secrets should only flow to specific secure contexts
	if source.Type == "secret" {
		return sink.Type == "action_input" || sink.Type == "env" ||
			(sink.Type == "network" && sink.Sensitive) ||
			(sink.Type == "log" && sink.Sensitive)
	}

	// Outputs can flow to most places
	if source.Type == "output" {
		return true
	}

	// GitHub context has specific usage patterns
	if source.Type == "github_context" {
		return sink.Type == "action_input" || sink.Type == "env" || sink.Type == "log"
	}

	return true
}

// pathInvolvesSameData checks if the path actually involves the same data
func (dfa *DataFlowAnalyzer) pathInvolvesSameData(source *DataSource, sink *DataSink, path []string) bool {
	// For now, implement basic heuristics
	// In production, this would analyze variable usage along the path

	// If source and sink have similar names, likely related
	if strings.Contains(strings.ToLower(sink.Name), strings.ToLower(source.Name)) ||
		strings.Contains(strings.ToLower(source.Name), strings.ToLower(sink.Name)) {
		return true
	}

	// If both involve secrets/tokens, likely related
	sourceHasSecret := strings.Contains(strings.ToLower(source.Name), "secret") ||
		strings.Contains(strings.ToLower(source.Name), "token")
	sinkHasSecret := strings.Contains(strings.ToLower(sink.Name), "secret") ||
		strings.Contains(strings.ToLower(sink.Name), "token")

	if sourceHasSecret && sinkHasSecret {
		return true
	}

	// If path is very short (direct connection), more likely to be real
	return len(path) <= 3
}

// withinSameContext checks if source and sink are in related contexts
func (dfa *DataFlowAnalyzer) withinSameContext(source *DataSource, sink *DataSink) bool {
	// Global sources can reach anywhere
	if source.NodeID == "global" {
		return true
	}

	// Same step - definitely related
	if source.NodeID == sink.NodeID {
		return true
	}

	// Same job - likely related
	sourceJob := dfa.extractJobFromNodeID(source.NodeID)
	sinkJob := dfa.extractJobFromNodeID(sink.NodeID)

	return sourceJob == sinkJob || sourceJob == "" || sinkJob == ""
}

// extractJobFromNodeID extracts job name from node ID
func (dfa *DataFlowAnalyzer) extractJobFromNodeID(nodeID string) string {
	if strings.HasPrefix(nodeID, "job_") {
		return strings.TrimPrefix(nodeID, "job_")
	}
	if strings.HasPrefix(nodeID, "step_") {
		parts := strings.Split(nodeID, "_")
		if len(parts) >= 2 {
			return parts[1]
		}
	}
	return ""
}

// isObviousFalsePositive filters out clearly unrelated flows
func (dfa *DataFlowAnalyzer) isObviousFalsePositive(source *DataSource, sink *DataSink) bool {
	// Don't create flows between different unrelated environment variables
	if source.Type == "env" && sink.Type == "env" &&
		source.NodeID != sink.NodeID &&
		!strings.Contains(strings.ToLower(sink.Name), strings.ToLower(source.Name)) {
		return true
	}

	// Don't create flows between unrelated secrets
	if source.Type == "secret" && sink.Type == "action_input" &&
		!strings.Contains(strings.ToLower(sink.Command), strings.ToLower(source.Name)) {
		return true
	}

	return false
}

func (dfa *DataFlowAnalyzer) identifyDataSources(workflow *WorkflowAST) {
	// Global environment variables as sources
	for envName, envNode := range workflow.Env {
		source := &DataSource{
			ID:      fmt.Sprintf("global_env_%s", envName),
			Type:    "env",
			Name:    envName,
			NodeID:  "global",
			Tainted: dfa.isSensitiveValue(envNode.Value),
			Origin:  "global_env",
			Value:   envNode.Value,
		}
		dfa.sources[source.ID] = source
	}

	// Global secrets as sources
	for secretName := range workflow.Secrets {
		source := &DataSource{
			ID:      fmt.Sprintf("global_secret_%s", secretName),
			Type:    "secret",
			Name:    secretName,
			NodeID:  "global",
			Tainted: true, // All secrets are tainted
			Origin:  "global_secrets",
		}
		dfa.sources[source.ID] = source
	}

	// Job-level sources
	for jobID, job := range workflow.Jobs {
		jobNodeID := fmt.Sprintf("job_%s", jobID)

		// Job environment variables
		for envName, envValue := range job.Variables {
			source := &DataSource{
				ID:      fmt.Sprintf("job_env_%s_%s", jobID, envName),
				Type:    "env",
				Name:    envName,
				NodeID:  jobNodeID,
				Tainted: dfa.isSensitiveValue(envValue),
				Origin:  "job_env",
				Value:   envValue,
			}
			dfa.sources[source.ID] = source
		}

		// Step-level sources
		for stepIdx, step := range job.Steps {
			stepNodeID := fmt.Sprintf("step_%s_%d", jobID, stepIdx)

			// Step environment variables
			for envName, envValue := range step.Env {
				source := &DataSource{
					ID:      fmt.Sprintf("step_env_%s_%s", stepNodeID, envName),
					Type:    "env",
					Name:    envName,
					NodeID:  stepNodeID,
					Tainted: dfa.isSensitiveValue(envValue),
					Origin:  "step_env",
					Value:   envValue,
				}
				dfa.sources[source.ID] = source
			}

			// Action outputs become sources
			if step.Uses != "" {
				outputs := dfa.extractActionOutputs(step.Uses)
				for _, output := range outputs {
					source := &DataSource{
						ID:      fmt.Sprintf("action_output_%s_%s", stepNodeID, output),
						Type:    "output",
						Name:    output,
						NodeID:  stepNodeID,
						Tainted: dfa.isActionOutputTainted(step.Uses, output),
						Origin:  "action_output",
					}
					dfa.sources[source.ID] = source
				}
			}

			// GitHub context variables as sources
			dfa.extractGitHubContextSources(stepNodeID, step)
		}
	}
}

func (dfa *DataFlowAnalyzer) identifyDataSinks(workflow *WorkflowAST) {
	for jobID, job := range workflow.Jobs {
		for stepIdx, step := range job.Steps {
			stepNodeID := fmt.Sprintf("step_%s_%d", jobID, stepIdx)

			// Shell commands are potential sinks
			if step.Run != "" {
				dfa.analyzeShellCommandSinks(stepNodeID, step.Run)
			}

			// Action inputs are sinks
			for inputName, inputValue := range step.With {
				sink := &DataSink{
					ID:        fmt.Sprintf("action_input_%s_%s", stepNodeID, inputName),
					Type:      "action_input",
					Name:      inputName,
					NodeID:    stepNodeID,
					Sensitive: dfa.isSensitiveActionInput(step.Uses, inputName),
					Command:   fmt.Sprintf("%s with %s=%s", step.Uses, inputName, inputValue),
				}
				dfa.sinks[sink.ID] = sink
			}

			// Environment variable assignments are sinks
			for envName, envValue := range step.Env {
				sink := &DataSink{
					ID:        fmt.Sprintf("env_assignment_%s_%s", stepNodeID, envName),
					Type:      "env",
					Name:      envName,
					NodeID:    stepNodeID,
					Sensitive: dfa.isSensitiveValue(envValue),
					Command:   fmt.Sprintf("env: %s=%s", envName, envValue),
				}
				dfa.sinks[sink.ID] = sink
			}
		}
	}
}

func (dfa *DataFlowAnalyzer) analyzeShellCommandSinks(nodeID, command string) {
	// Network-based sinks (potential data exfiltration)
	networkPatterns := map[string]string{
		`curl\s+[^|\s]*\$\{[^}]+\}`:  "network_exfiltration",
		`wget\s+[^|\s]*\$\{[^}]+\}`:  "network_exfiltration",
		`nc\s+[^|\s]*\$\{[^}]+\}`:    "network_exfiltration",
		`ssh\s+[^|\s]*\$\{[^}]+\}`:   "ssh_exfiltration",
		`scp\s+[^|\s]*\$\{[^}]+\}`:   "file_transfer",
		`rsync\s+[^|\s]*\$\{[^}]+\}`: "file_transfer",
	}

	// File-based sinks
	filePatterns := map[string]string{
		`echo\s+[^|]*\$\{[^}]+\}[^|]*>\s*[^|\s]+`:   "file_write",
		`cat\s+[^|]*\$\{[^}]+\}[^|]*>\s*[^|\s]+`:    "file_write",
		`printf\s+[^|]*\$\{[^}]+\}[^|]*>\s*[^|\s]+`: "file_write",
	}

	// Logging sinks (might expose sensitive data)
	loggingPatterns := map[string]string{
		`echo\s+[^|>]*\$\{[^}]+\}`:   "console_log",
		`printf\s+[^|>]*\$\{[^}]+\}`: "console_log",
		`logger\s+[^|>]*\$\{[^}]+\}`: "system_log",
	}

	allPatterns := []map[string]string{networkPatterns, filePatterns, loggingPatterns}
	sinkTypes := []string{"network", "file", "log"}

	for i, patterns := range allPatterns {
		for pattern, riskType := range patterns {
			if matched, _ := regexp.MatchString(pattern, command); matched {
				sink := &DataSink{
					ID:        fmt.Sprintf("shell_%s_%s_%d", nodeID, riskType, len(dfa.sinks)),
					Type:      sinkTypes[i],
					Name:      riskType,
					NodeID:    nodeID,
					Sensitive: true, // Shell commands with variables are considered sensitive
					Command:   command,
				}
				dfa.sinks[sink.ID] = sink
			}
		}
	}
}

func (dfa *DataFlowAnalyzer) extractActionOutputs(actionName string) []string {
	// Known outputs for popular actions
	knownOutputs := map[string][]string{
		"actions/checkout":                      {"ref", "commit"},
		"actions/setup-node":                    {"node-version", "cache-hit"},
		"actions/cache":                         {"cache-hit"},
		"docker/build-push-action":              {"digest", "metadata"},
		"aws-actions/configure-aws-credentials": {"aws-account-id"},
	}

	if outputs, exists := knownOutputs[actionName]; exists {
		return outputs
	}

	return []string{} // Unknown action, assume no outputs for now
}

func (dfa *DataFlowAnalyzer) extractGitHubContextSources(stepNodeID string, step *StepNode) {
	// Extract GitHub context references from step
	contexts := []string{
		"github.token", "github.actor", "github.repository", "github.ref",
		"github.sha", "github.run_id", "github.run_number", "github.event",
	}

	// Check in various fields for GitHub context usage
	fields := []string{step.Run}
	for _, value := range step.With {
		fields = append(fields, value)
	}
	for _, value := range step.Env {
		fields = append(fields, value)
	}

	for _, field := range fields {
		for _, context := range contexts {
			pattern := fmt.Sprintf(`\$\{\{\s*%s\s*\}\}`, regexp.QuoteMeta(context))
			if matched, _ := regexp.MatchString(pattern, field); matched {
				source := &DataSource{
					ID:      fmt.Sprintf("github_context_%s_%s", stepNodeID, strings.ReplaceAll(context, ".", "_")),
					Type:    "github_context",
					Name:    context,
					NodeID:  stepNodeID,
					Tainted: context == "github.token", // GitHub token is always sensitive
					Origin:  "github_context",
					Value:   context,
				}
				dfa.sources[source.ID] = source
			}
		}
	}
}

func (dfa *DataFlowAnalyzer) isSensitiveValue(value string) bool {
	sensitivePatterns := []string{
		`\$\{\{\s*secrets\.`,     // References to secrets
		`\$\{\{\s*github\.token`, // GitHub token
		`(?i)password`,           // Password-like values
		`(?i)secret`,             // Secret-like values
		`(?i)key`,                // Key-like values
		`(?i)token`,              // Token-like values
		`(?i)credential`,         // Credential-like values
		`(?i)api[_-]?key`,        // API keys
		`(?i)private[_-]?key`,    // Private keys
	}

	for _, pattern := range sensitivePatterns {
		if matched, _ := regexp.MatchString(pattern, value); matched {
			return true
		}
	}
	return false
}

func (dfa *DataFlowAnalyzer) isSensitiveActionInput(actionName, inputName string) bool {
	// Known sensitive inputs for popular actions
	sensitiveInputs := map[string][]string{
		"actions/checkout":                      {"token"},
		"docker/login-action":                   {"username", "password"},
		"aws-actions/configure-aws-credentials": {"aws-access-key-id", "aws-secret-access-key", "role-to-assume"},
		"azure/login":                           {"creds"},
		"google-github-actions/auth":            {"credentials_json", "service_account_key"},
	}

	if inputs, exists := sensitiveInputs[actionName]; exists {
		for _, sensitiveInput := range inputs {
			if strings.EqualFold(inputName, sensitiveInput) {
				return true
			}
		}
	}

	// General patterns for sensitive input names
	sensitiveNames := []string{"password", "secret", "key", "token", "credential", "auth"}
	inputLower := strings.ToLower(inputName)
	for _, sensitiveName := range sensitiveNames {
		if strings.Contains(inputLower, sensitiveName) {
			return true
		}
	}

	return false
}

func (dfa *DataFlowAnalyzer) isActionOutputTainted(actionName, outputName string) bool {
	// Some action outputs might contain sensitive data
	taintedOutputs := map[string][]string{
		"aws-actions/configure-aws-credentials": {"aws-account-id"},
		"azure/login":                           {"subscription-id", "tenant-id"},
	}

	if outputs, exists := taintedOutputs[actionName]; exists {
		for _, taintedOutput := range outputs {
			if strings.EqualFold(outputName, taintedOutput) {
				return true
			}
		}
	}

	return false
}

func (dfa *DataFlowAnalyzer) traceDataFlows(workflow *WorkflowAST) {
	// Use graph-based analysis instead of O(n²) comparison
	dfa.buildDataFlowGraph(workflow)
	dfa.findReachableFlows()
}

// buildDataFlowGraph creates a directed graph of data flows
func (dfa *DataFlowAnalyzer) buildDataFlowGraph(workflow *WorkflowAST) {
	// Create adjacency list for efficient graph traversal
	adjacencyList := make(map[string][]string)
	nodeToSource := make(map[string]*DataSource)
	nodeToSink := make(map[string]*DataSink)

	// Index sources and sinks by their nodes
	for _, source := range dfa.sources {
		nodeToSource[source.NodeID] = source
		if adjacencyList[source.NodeID] == nil {
			adjacencyList[source.NodeID] = []string{}
		}
	}

	for _, sink := range dfa.sinks {
		nodeToSink[sink.NodeID] = sink
		if adjacencyList[sink.NodeID] == nil {
			adjacencyList[sink.NodeID] = []string{}
		}
	}

	// Build edges based on workflow structure (jobs, steps, dependencies)
	for jobID, job := range workflow.Jobs {
		jobNodeID := fmt.Sprintf("job_%s", jobID)

		// Connect job dependencies
		for _, neededJob := range job.Needs {
			neededJobID := fmt.Sprintf("job_%s", neededJob)
			adjacencyList[neededJobID] = append(adjacencyList[neededJobID], jobNodeID)
		}

		// Connect steps in sequence
		var prevStepID string
		for stepIdx := range job.Steps {
			stepNodeID := fmt.Sprintf("step_%s_%d", jobID, stepIdx)

			// Connect job to first step
			if stepIdx == 0 {
				adjacencyList[jobNodeID] = append(adjacencyList[jobNodeID], stepNodeID)
			}

			// Connect steps in sequence
			if prevStepID != "" {
				adjacencyList[prevStepID] = append(adjacencyList[prevStepID], stepNodeID)
			}
			prevStepID = stepNodeID
		}
	}

	// Store graph for flow finding
	dfa.flowGraph = &DataFlowGraph{
		adjacencyList: adjacencyList,
		nodeToSource:  nodeToSource,
		nodeToSink:    nodeToSink,
	}
}

// findReachableFlows uses BFS to find actual reachable data flows
func (dfa *DataFlowAnalyzer) findReachableFlows() {
	if dfa.flowGraph == nil {
		return
	}

	// For each source, find all reachable sinks using BFS
	for sourceID, source := range dfa.sources {
		reachableSinks := dfa.findReachableSinks(source.NodeID)

		for _, sinkNodeID := range reachableSinks {
			// Find all sinks in this node
			for sinkID, sink := range dfa.sinks {
				if sink.NodeID == sinkNodeID {
					// Calculate path and create flow
					path := dfa.findShortestPath(source.NodeID, sink.NodeID)
					if len(path) > 0 {
						severity := dfa.calculateFlowSeverity(source, sink)
						risk := dfa.calculateFlowRisk(source, sink)

						flow := &DataFlow{
							SourceID: sourceID,
							SinkID:   sinkID,
							Path:     path,
							Tainted:  source.Tainted,
							Severity: severity,
							Risk:     risk,
						}
						dfa.flows = append(dfa.flows, flow)
					}
				}
			}
		}
	}
}

// findReachableSinks uses BFS to find all nodes reachable from source
func (dfa *DataFlowAnalyzer) findReachableSinks(sourceNodeID string) []string {
	if dfa.flowGraph == nil {
		return []string{}
	}

	visited := make(map[string]bool)
	queue := []string{sourceNodeID}
	reachable := []string{}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if visited[current] {
			continue
		}
		visited[current] = true

		// Check if this node has sinks
		if _, hasSink := dfa.flowGraph.nodeToSink[current]; hasSink {
			reachable = append(reachable, current)
		}

		// Add neighbors to queue
		for _, neighbor := range dfa.flowGraph.adjacencyList[current] {
			if !visited[neighbor] {
				queue = append(queue, neighbor)
			}
		}
	}

	return reachable
}

// findShortestPath finds the shortest path between two nodes
func (dfa *DataFlowAnalyzer) findShortestPath(start, end string) []string {
	if dfa.flowGraph == nil || start == end {
		return []string{start}
	}

	visited := make(map[string]bool)
	parent := make(map[string]string)
	queue := []string{start}

	visited[start] = true

	// BFS to find shortest path
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if current == end {
			// Reconstruct path
			path := []string{}
			for node := end; node != ""; node = parent[node] {
				path = append([]string{node}, path...)
				if node == start {
					break
				}
			}
			return path
		}

		for _, neighbor := range dfa.flowGraph.adjacencyList[current] {
			if !visited[neighbor] {
				visited[neighbor] = true
				parent[neighbor] = current
				queue = append(queue, neighbor)
			}
		}
	}

	return []string{} // No path found
}

func (dfa *DataFlowAnalyzer) canDataFlow(source *DataSource, sink *DataSink, workflow *WorkflowAST) bool {
	// Data can flow if:
	// 1. Source and sink are in the same step
	// 2. Source is in an earlier step in the same job
	// 3. Source is global and sink is anywhere
	// 4. Source is job-level and sink is in the same job

	if source.NodeID == "global" {
		return true // Global sources can reach any sink
	}

	if source.NodeID == sink.NodeID {
		return true // Same step
	}

	// Extract job and step information
	sourceJob, sourceStep := dfa.parseNodeID(source.NodeID)
	sinkJob, sinkStep := dfa.parseNodeID(sink.NodeID)

	if sourceJob == sinkJob {
		// Same job - check step ordering
		if sourceStep == -1 {
			return true // Job-level source can reach any step in the job
		}
		if sinkStep > sourceStep {
			return true // Source step comes before sink step
		}
	}

	// Check job dependencies
	if sinkJob != "" && sourceJob != "" {
		if job, exists := workflow.Jobs[sinkJob]; exists {
			for _, neededJob := range job.Needs {
				if neededJob == sourceJob {
					return true // Sink job depends on source job
				}
			}
		}
	}

	return false
}

func (dfa *DataFlowAnalyzer) parseNodeID(nodeID string) (job string, step int) {
	if nodeID == "global" {
		return "", -1
	}

	if strings.HasPrefix(nodeID, "job_") {
		return strings.TrimPrefix(nodeID, "job_"), -1
	}

	if strings.HasPrefix(nodeID, "step_") {
		parts := strings.Split(nodeID, "_")
		if len(parts) >= 3 {
			jobName := strings.Join(parts[1:len(parts)-1], "_")
			stepIdx := -1
			fmt.Sscanf(parts[len(parts)-1], "%d", &stepIdx)
			return jobName, stepIdx
		}
	}

	return "", -1
}

func (dfa *DataFlowAnalyzer) calculateFlowSeverity(source *DataSource, sink *DataSink) string {
	if source.Tainted && sink.Sensitive {
		if sink.Type == "network" {
			return "CRITICAL" // Tainted data going to network
		}
		if sink.Type == "log" && source.Type == "secret" {
			return "HIGH" // Secret going to logs
		}
		return "MEDIUM"
	}

	if source.Tainted || sink.Sensitive {
		return "LOW"
	}

	return "INFO"
}

func (dfa *DataFlowAnalyzer) calculateFlowRisk(source *DataSource, sink *DataSink) string {
	if source.Type == "secret" && sink.Type == "network" {
		return "Secret exposure via network call"
	}
	if source.Type == "secret" && sink.Type == "log" {
		return "Secret exposure in logs"
	}
	if source.Tainted && sink.Type == "file" {
		return "Sensitive data written to file"
	}
	if source.Type == "github_context" && source.Name == "github.token" && sink.Sensitive {
		return "GitHub token misuse"
	}

	return "Potential sensitive data flow"
}

// GetTaintedFlows returns all data flows involving tainted data
func (dfa *DataFlowAnalyzer) GetTaintedFlows() []*DataFlow {
	var taintedFlows []*DataFlow
	for _, flow := range dfa.flows {
		if flow.Tainted {
			taintedFlows = append(taintedFlows, flow)
		}
	}
	return taintedFlows
}

// GetAllFlows returns all detected data flows
func (dfa *DataFlowAnalyzer) GetAllFlows() []*DataFlow {
	return dfa.flows
}

// GetFlowsBySeverity returns flows filtered by minimum severity
func (dfa *DataFlowAnalyzer) GetFlowsBySeverity(minSeverity string) []*DataFlow {
	severityLevels := map[string]int{
		"INFO":     0,
		"LOW":      1,
		"MEDIUM":   2,
		"HIGH":     3,
		"CRITICAL": 4,
	}

	minLevel := severityLevels[minSeverity]
	var filteredFlows []*DataFlow

	for _, flow := range dfa.flows {
		if severityLevels[flow.Severity] >= minLevel {
			filteredFlows = append(filteredFlows, flow)
		}
	}

	return filteredFlows
}
