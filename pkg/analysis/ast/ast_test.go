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
	"testing"
)

func TestASTAnalyzer(t *testing.T) {
	analyzer := NewASTAnalyzer()

	if analyzer == nil {
		t.Fatal("Failed to create AST analyzer")
	}

	// Test workflow parsing
	workflowYAML := `
name: Test Workflow
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Run tests
        run: |
          echo "Running tests"
          curl -H "Authorization: Bearer ${{ secrets.API_TOKEN }}" https://api.example.com/data
        env:
          API_TOKEN: ${{ secrets.API_TOKEN }}
      
      - name: Conditional step
        if: github.event_name == 'push'
        run: echo "This only runs on push"

  build:
    needs: test
    runs-on: ubuntu-latest
    if: success()
    steps:
      - name: Build
        run: echo "Building..."
`

	workflowAST, err := analyzer.ParseWorkflow(workflowYAML)
	if err != nil {
		t.Fatalf("Failed to parse workflow: %v", err)
	}

	if workflowAST == nil {
		t.Fatal("Workflow AST is nil")
	}

	// Test that we have the expected structure
	if len(workflowAST.Jobs) != 2 {
		t.Errorf("Expected 2 jobs, got %d", len(workflowAST.Jobs))
	}

	if len(workflowAST.Triggers) != 2 {
		t.Errorf("Expected 2 triggers, got %d", len(workflowAST.Triggers))
	}

	// Test reachability analysis
	reachableNodes := analyzer.AnalyzeReachability(workflowAST)
	if len(reachableNodes) == 0 {
		t.Error("No reachable nodes found")
	}

	// Test data flow analysis
	dataFlows, err := analyzer.AnalyzeDataFlow(workflowAST)
	if err != nil {
		t.Errorf("Data flow analysis failed: %v", err)
	}

	// Should detect flows involving secrets
	foundSecretFlow := false
	for _, flow := range dataFlows {
		if flow.Tainted {
			foundSecretFlow = true
			break
		}
	}

	if !foundSecretFlow {
		t.Error("Expected to find tainted data flows involving secrets")
	}
}

func TestCallGraph(t *testing.T) {
	callGraph := NewCallGraph()

	if callGraph == nil {
		t.Fatal("Failed to create call graph")
	}

	// Test basic functionality
	node := &CallNode{
		ID:   "test_node",
		Type: "test",
		Name: "Test Node",
	}

	callGraph.addNode(node)

	retrievedNode, exists := callGraph.GetNode("test_node")
	if !exists {
		t.Error("Failed to retrieve added node")
	}

	if retrievedNode.Name != "Test Node" {
		t.Errorf("Expected node name 'Test Node', got '%s'", retrievedNode.Name)
	}
}

func TestDataFlowAnalyzer(t *testing.T) {
	analyzer := NewDataFlowAnalyzer()

	if analyzer == nil {
		t.Fatal("Failed to create data flow analyzer")
	}

	// Test sensitive value detection
	testCases := []struct {
		value    string
		expected bool
	}{
		{"${{ secrets.API_TOKEN }}", true},
		{"${{ github.token }}", true},
		{"password123", true},
		{"my_secret_key", true},
		{"regular_value", false},
		{"normal text", false},
	}

	for _, tc := range testCases {
		result := analyzer.isSensitiveValue(tc.value)
		if result != tc.expected {
			t.Errorf("isSensitiveValue(%q) = %v, expected %v", tc.value, result, tc.expected)
		}
	}
}

func TestReachabilityAnalyzer(t *testing.T) {
	callGraph := NewCallGraph()
	analyzer := NewReachabilityAnalyzer(callGraph)

	if analyzer == nil {
		t.Fatal("Failed to create reachability analyzer")
	}

	// Test condition parsing
	testCases := []struct {
		expression string
		expectFunc bool
	}{
		{"always()", true},
		{"failure()", true},
		{"success()", true},
		{"github.event_name == 'push'", false},
		{"${{ always() }}", true},
	}

	for _, tc := range testCases {
		condition := analyzer.parseCondition(tc.expression)
		hasFunc := condition.Always || condition.Failure || condition.Success || condition.Cancelled

		if hasFunc != tc.expectFunc {
			t.Errorf("parseCondition(%q) function detection = %v, expected %v", tc.expression, hasFunc, tc.expectFunc)
		}
	}
}
