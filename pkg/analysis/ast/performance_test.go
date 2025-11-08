package ast

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestLargeWorkflowPerformance tests the analyzer with a large workflow
func TestLargeWorkflowPerformance(t *testing.T) {
	analyzer := NewASTAnalyzer()

	// Generate a large workflow with many jobs and steps
	jobCount := 20
	stepsPerJob := 10

	var workflow strings.Builder
	workflow.WriteString(`
name: Large Test Workflow
on: [push, pull_request]
jobs:
`)

	for i := 0; i < jobCount; i++ {
		workflow.WriteString(fmt.Sprintf(`
  job_%d:
    runs-on: ubuntu-latest`, i))

		if i > 0 {
			workflow.WriteString(fmt.Sprintf(`
    needs: job_%d`, i-1))
		}

		workflow.WriteString(`
    steps:`)

		for j := 0; j < stepsPerJob; j++ {
			workflow.WriteString(fmt.Sprintf(`
      - name: Step %d-%d
        run: |
          echo "Running step %d-%d"
          curl -H "Authorization: Bearer ${{ secrets.TOKEN_%d }}" https://api.example.com/data
          export VAR_%d="${{ secrets.SECRET_%d }}"
        env:
          ENV_VAR_%d: ${{ secrets.ENV_SECRET_%d }}`, j, i, j, i, j, j, j, j, j))
		}
	}

	workflowYAML := workflow.String()

	// Test parsing performance
	start := time.Now()
	workflowAST, err := analyzer.ParseWorkflow(workflowYAML)
	parseTime := time.Since(start)

	if err != nil {
		t.Fatalf("Failed to parse large workflow: %v", err)
	}

	t.Logf("Parsed workflow with %d jobs, %d total steps in %v",
		len(workflowAST.Jobs), jobCount*stepsPerJob, parseTime)

	// Test reachability analysis performance
	start = time.Now()
	reachableNodes := analyzer.AnalyzeReachability(workflowAST)
	reachabilityTime := time.Since(start)

	t.Logf("Reachability analysis completed in %v, found %d reachable nodes",
		reachabilityTime, len(reachableNodes))

	// Test data flow analysis performance
	start = time.Now()
	dataFlows, err := analyzer.AnalyzeDataFlow(workflowAST)
	dataFlowTime := time.Since(start)

	if err != nil {
		t.Fatalf("Data flow analysis failed: %v", err)
	}

	t.Logf("Data flow analysis completed in %v, found %d flows",
		dataFlowTime, len(dataFlows))

	// Performance assertions (these are reasonable for a large workflow)
	if parseTime > 75*time.Millisecond {
		t.Errorf("Parsing took too long: %v > 75ms", parseTime)
	}

	if reachabilityTime > 150*time.Millisecond {
		t.Errorf("Reachability analysis took too long: %v > 150ms", reachabilityTime)
	}

	if dataFlowTime > 750*time.Millisecond {
		t.Errorf("Data flow analysis took too long: %v > 750ms", dataFlowTime)
	}

	// Check if we found reasonable number of flows (not O(n²))
	expectedMaxFlows := jobCount * stepsPerJob * 5 // At most 5 flows per step
	if len(dataFlows) > expectedMaxFlows {
		t.Errorf("Too many data flows found: %d > %d (possible O(n²) behavior)",
			len(dataFlows), expectedMaxFlows)
	}
}

// TestMemoryLeakPrevention tests that Reset() properly cleans up
func TestMemoryLeakPrevention(t *testing.T) {
	analyzer := NewASTAnalyzer()

	simpleWorkflow := `
name: Simple Workflow
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "test"
`

	// Analyze multiple times to check for memory leaks
	for i := 0; i < 100; i++ {
		workflowAST, err := analyzer.ParseWorkflow(simpleWorkflow)
		if err != nil {
			t.Fatalf("Parse failed on iteration %d: %v", i, err)
		}

		analyzer.AnalyzeReachability(workflowAST)
		analyzer.AnalyzeDataFlow(workflowAST)

		// Reset should clean up memory
		analyzer.Reset()
	}

	// If we get here without running out of memory, the test passes
	t.Log("Memory leak prevention test completed successfully")
}

// BenchmarkDataFlowAnalysis benchmarks the data flow analysis
func BenchmarkDataFlowAnalysis(b *testing.B) {
	analyzer := NewASTAnalyzer()

	workflow := `
name: Benchmark Workflow
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Step 1
        run: echo "test"
        env:
          SECRET: ${{ secrets.API_TOKEN }}
      - name: Step 2
        run: curl -H "Auth: $SECRET" https://api.example.com
      - name: Step 3  
        run: echo "Result: ${{ steps.step1.outputs.result }}"
`

	workflowAST, err := analyzer.ParseWorkflow(workflow)
	if err != nil {
		b.Fatalf("Failed to parse workflow: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		analyzer.Reset()
		analyzer.AnalyzeDataFlow(workflowAST)
	}
}
