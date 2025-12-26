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

package main

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/harekrishnarai/flowlyt/pkg/analysis/ast"
)

// generateLargeWorkflow creates a workflow with many jobs and steps for performance testing
func generateLargeWorkflow(numJobs, stepsPerJob int) string {
	var workflow strings.Builder
	
	workflow.WriteString("name: Large Performance Test Workflow\n")
	workflow.WriteString("on: [push, pull_request]\n\n")
	workflow.WriteString("jobs:\n")
	
	for i := 0; i < numJobs; i++ {
		jobName := fmt.Sprintf("job%d", i)
		workflow.WriteString(fmt.Sprintf("  %s:\n", jobName))
		workflow.WriteString("    runs-on: ubuntu-latest\n")
		
		// Add some dependencies to create a more complex call graph
		if i > 0 && rand.Float32() < 0.3 {
			depJob := fmt.Sprintf("job%d", rand.Intn(i))
			workflow.WriteString(fmt.Sprintf("    needs: %s\n", depJob))
		}
		
		workflow.WriteString("    steps:\n")
		
		for j := 0; j < stepsPerJob; j++ {
			stepName := fmt.Sprintf("step%d", j)
			workflow.WriteString(fmt.Sprintf("      - name: %s\n", stepName))
			
			if j%3 == 0 {
				// Checkout action
				workflow.WriteString("        uses: actions/checkout@v3\n")
			} else if j%3 == 1 {
				// Shell command with environment variables
				workflow.WriteString("        run: |\n")
				workflow.WriteString(fmt.Sprintf("          echo \"Processing in job %s step %s\"\n", jobName, stepName))
				workflow.WriteString("          echo $SECRET_TOKEN\n")
				workflow.WriteString("          curl -H \"Authorization: Bearer $API_KEY\" https://api.example.com/data\n")
				workflow.WriteString("        env:\n")
				workflow.WriteString(fmt.Sprintf("          SECRET_TOKEN: ${{ secrets.SECRET_TOKEN_%d }}\n", i))
				workflow.WriteString("          API_KEY: ${{ secrets.API_KEY }}\n")
			} else {
				// Custom action
				workflow.WriteString(fmt.Sprintf("        uses: custom/action@v1\n"))
				workflow.WriteString("        with:\n")
				workflow.WriteString(fmt.Sprintf("          token: ${{ secrets.TOKEN_%d_%d }}\n", i, j))
			}
		}
		workflow.WriteString("\n")
	}
	
	return workflow.String()
}

func runPerformanceTest(numJobs, stepsPerJob int) {
	fmt.Printf("\n=== Performance Test: %d jobs, %d steps per job ===\n", numJobs, stepsPerJob)
	
	// Generate large workflow
	workflowContent := generateLargeWorkflow(numJobs, stepsPerJob)
	fmt.Printf("Generated workflow with %d characters\n", len(workflowContent))
	
	// Create analyzer
	analyzer := ast.NewASTAnalyzer()
	
	// Measure parsing time
	start := time.Now()
	workflowAST, err := analyzer.ParseWorkflow(workflowContent)
	parseTime := time.Since(start)
	
	if err != nil {
		fmt.Printf("ERROR: Failed to parse workflow: %v\n", err)
		return
	}
	
	fmt.Printf("Parse time: %v\n", parseTime)
	fmt.Printf("AST nodes: %d\n", len(workflowAST.Jobs))
	
	// Measure reachability analysis time
	start = time.Now()
	reachableNodes := analyzer.AnalyzeReachability(workflowAST)
	reachabilityTime := time.Since(start)
	
	fmt.Printf("Reachability analysis time: %v\n", reachabilityTime)
	fmt.Printf("Reachable nodes: %d\n", len(reachableNodes))
	
	// Measure data flow analysis time
	start = time.Now()
	dataFlows, err := analyzer.AnalyzeDataFlow(workflowAST)
	dataFlowTime := time.Since(start)
	
	if err != nil {
		fmt.Printf("ERROR: Data flow analysis failed: %v\n", err)
		return
	}
	
	fmt.Printf("Data flow analysis time: %v\n", dataFlowTime)
	fmt.Printf("Data flows found: %d\n", len(dataFlows))
	
	totalTime := parseTime + reachabilityTime + dataFlowTime
	fmt.Printf("Total analysis time: %v\n", totalTime)
	
	// Calculate complexity metrics
	totalNodes := numJobs * (stepsPerJob + 1) // +1 for job node
	fmt.Printf("Expected nodes: %d\n", totalNodes)
	fmt.Printf("Time per node: %v\n", totalTime/time.Duration(totalNodes))
	
	// Reset analyzer to test memory cleanup
	analyzer.Reset()
	fmt.Printf("Memory reset completed\n")
}

func main() {
	fmt.Println("=== Flowlyt AST Performance Test ===")
	
	// Seed random number generator
	rand.Seed(time.Now().UnixNano())
	
	// Test different scales
	testCases := []struct {
		jobs        int
		stepsPerJob int
	}{
		{5, 3},    // Small: 5 jobs, 15 steps
		{10, 5},   // Medium: 10 jobs, 50 steps
		{20, 5},   // Large: 20 jobs, 100 steps
		{50, 3},   // Very Large: 50 jobs, 150 steps
		{100, 2},  // Huge: 100 jobs, 200 steps
	}
	
	for _, tc := range testCases {
		runPerformanceTest(tc.jobs, tc.stepsPerJob)
		
		// Add a small delay between tests
		time.Sleep(100 * time.Millisecond)
	}
	
	fmt.Println("\n=== Performance Test Complete ===")
	fmt.Println("Note: Times may vary based on system performance.")
	fmt.Println("The graph-based algorithm should scale as O(V+E) rather than O(n²).")
}
