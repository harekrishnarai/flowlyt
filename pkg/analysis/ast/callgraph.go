package ast

import (
	"fmt"
	"regexp"
	"strings"
)

// CallGraph tracks relationships between workflow components
type CallGraph struct {
	nodes map[string]*CallNode
	edges map[string][]string
}

// CallNode represents a node in the call graph
type CallNode struct {
	ID       string
	Type     string // "job", "step", "action", "workflow", "trigger"
	Name     string
	Platform string
	Metadata map[string]interface{}
}

// NewCallGraph creates a new call graph analyzer
func NewCallGraph() *CallGraph {
	return &CallGraph{
		nodes: make(map[string]*CallNode),
		edges: make(map[string][]string),
	}
}

// Reset clears all graph data for reuse
func (cg *CallGraph) Reset() {
	// Clear maps efficiently
	for k := range cg.nodes {
		delete(cg.nodes, k)
	}
	for k := range cg.edges {
		delete(cg.edges, k)
	}
}

// BuildCallGraph constructs the call graph from workflow AST
func (cg *CallGraph) BuildCallGraph(workflow *WorkflowAST) error {
	// Add workflow triggers as entry points
	for _, trigger := range workflow.Triggers {
		triggerNode := &CallNode{
			ID:   fmt.Sprintf("trigger_%s", trigger.Event),
			Type: "trigger",
			Name: trigger.Event,
			Metadata: map[string]interface{}{
				"config": trigger.Config,
			},
		}
		cg.addNode(triggerNode)
	}

	// Process jobs and their dependencies
	for jobID, job := range workflow.Jobs {
		jobNode := &CallNode{
			ID:   fmt.Sprintf("job_%s", jobID),
			Type: "job",
			Name: job.Name,
			Metadata: map[string]interface{}{
				"permissions": job.Permissions,
				"environment": job.Environment,
				"condition":   job.If,
				"runs_on":     job.RunsOn,
			},
		}
		cg.addNode(jobNode)

		// Connect triggers to jobs (triggers can start any job)
		for _, trigger := range workflow.Triggers {
			triggerID := fmt.Sprintf("trigger_%s", trigger.Event)
			cg.addEdge(triggerID, jobNode.ID)
		}

		// Add job dependencies
		for _, needsJob := range job.Needs {
			cg.addEdge(fmt.Sprintf("job_%s", needsJob), jobNode.ID)
		}

		// Process steps within job
		for stepIdx, step := range job.Steps {
			stepNode := &CallNode{
				ID:   fmt.Sprintf("step_%s_%d", jobID, stepIdx),
				Type: "step",
				Name: step.Name,
				Metadata: map[string]interface{}{
					"uses":        step.Uses,
					"run":         step.Run,
					"condition":   step.If,
					"shell":       step.Shell,
					"working_dir": step.WorkingDir,
				},
			}
			cg.addNode(stepNode)
			cg.addEdge(jobNode.ID, stepNode.ID)

			// Link steps in sequence (each step depends on previous)
			if stepIdx > 0 {
				prevStepID := fmt.Sprintf("step_%s_%d", jobID, stepIdx-1)
				cg.addEdge(prevStepID, stepNode.ID)
			}

			// Analyze action calls
			if step.Uses != "" {
				actionNode := cg.analyzeActionCall(step.Uses)
				if actionNode != nil {
					cg.addNode(actionNode)
					cg.addEdge(stepNode.ID, actionNode.ID)
				}
			}

			// Analyze shell commands for external calls
			if step.Run != "" {
				externalCalls := cg.analyzeShellCommands(step.Run)
				for _, externalCall := range externalCalls {
					cg.addNode(externalCall)
					cg.addEdge(stepNode.ID, externalCall.ID)
				}
			}
		}
	}

	return nil
}

func (cg *CallGraph) analyzeActionCall(actionRef string) *CallNode {
	// Parse action reference (e.g., "actions/checkout@v4")
	parts := strings.Split(actionRef, "@")
	if len(parts) != 2 {
		return nil
	}

	actionName := parts[0]
	version := parts[1]

	return &CallNode{
		ID:   fmt.Sprintf("action_%s", strings.ReplaceAll(actionName, "/", "_")),
		Type: "action",
		Name: actionName,
		Metadata: map[string]interface{}{
			"version": version,
			"source":  actionRef,
		},
	}
}

func (cg *CallGraph) analyzeShellCommands(command string) []*CallNode {
	var externalCalls []*CallNode

	// Patterns for external calls that could be security-relevant
	patterns := map[string]string{
		`curl\s+[^\s]+`:                   "network_call",
		`wget\s+[^\s]+`:                   "network_call",
		`ssh\s+[^\s]+`:                    "ssh_call",
		`scp\s+[^\s]+`:                    "file_transfer",
		`docker\s+(?:run|exec|pull|push)`: "docker_call",
		`git\s+(?:clone|pull|push|fetch)`: "git_call",
		`npm\s+(?:install|publish)`:       "npm_call",
		`pip\s+install`:                   "pip_call",
		`go\s+(?:get|install)`:            "go_call",
	}

	for pattern, callType := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllString(command, -1)

		for i, match := range matches {
			externalCall := &CallNode{
				ID:   fmt.Sprintf("external_%s_%d", callType, i),
				Type: "external_call",
				Name: callType,
				Metadata: map[string]interface{}{
					"command": match,
					"type":    callType,
				},
			}
			externalCalls = append(externalCalls, externalCall)
		}
	}

	return externalCalls
}

func (cg *CallGraph) addNode(node *CallNode) {
	cg.nodes[node.ID] = node
}

func (cg *CallGraph) addEdge(fromID, toID string) {
	if cg.edges[fromID] == nil {
		cg.edges[fromID] = []string{}
	}
	cg.edges[fromID] = append(cg.edges[fromID], toID)
}

// GetNode returns a node by ID
func (cg *CallGraph) GetNode(id string) (*CallNode, bool) {
	node, exists := cg.nodes[id]
	return node, exists
}

// GetEdges returns all edges from a node
func (cg *CallGraph) GetEdges(fromID string) []string {
	return cg.edges[fromID]
}

// GetNodeCount returns the total number of nodes
func (cg *CallGraph) GetNodeCount() int {
	return len(cg.nodes)
}

// GetNodes returns all nodes
func (cg *CallGraph) GetNodes() map[string]*CallNode {
	return cg.nodes
}

// GetAllEdges returns all edges
func (cg *CallGraph) GetAllEdges() map[string][]string {
	return cg.edges
}

// FindPaths finds all paths between two nodes
func (cg *CallGraph) FindPaths(fromID, toID string, maxDepth int) [][]string {
	var paths [][]string
	visited := make(map[string]bool)

	var dfs func(currentID string, path []string, depth int)
	dfs = func(currentID string, path []string, depth int) {
		if depth > maxDepth {
			return
		}

		if currentID == toID {
			// Found a path
			paths = append(paths, append([]string{}, path...))
			return
		}

		if visited[currentID] {
			return
		}

		visited[currentID] = true
		path = append(path, currentID)

		for _, nextID := range cg.edges[currentID] {
			dfs(nextID, path, depth+1)
		}

		// Backtrack
		visited[currentID] = false
		path = path[:len(path)-1]
	}

	dfs(fromID, []string{}, 0)
	return paths
}

// GetReverseDependencies returns all nodes that depend on the given node
func (cg *CallGraph) GetReverseDependencies(nodeID string) []string {
	var dependencies []string

	for fromID, edges := range cg.edges {
		for _, toID := range edges {
			if toID == nodeID {
				dependencies = append(dependencies, fromID)
				break
			}
		}
	}

	return dependencies
}

// IsReachable checks if there's a path from one node to another
func (cg *CallGraph) IsReachable(fromID, toID string) bool {
	if fromID == toID {
		return true
	}

	visited := make(map[string]bool)
	queue := []string{fromID}

	for len(queue) > 0 {
		currentID := queue[0]
		queue = queue[1:]

		if visited[currentID] {
			continue
		}
		visited[currentID] = true

		for _, nextID := range cg.edges[currentID] {
			if nextID == toID {
				return true
			}
			if !visited[nextID] {
				queue = append(queue, nextID)
			}
		}
	}

	return false
}
