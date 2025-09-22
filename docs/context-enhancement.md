# Context Enhancement for AI Analysis

## Overview

The Flowlyt security scanner has been enhanced to provide better context information to AI providers for more accurate false positive detection. Three new fields have been added to the `Finding` struct to provide crucial context about the execution environment.

## New Fields

### 1. `Trigger` (string)
- **Purpose**: Identifies how the workflow was triggered
- **Examples**: "push", "pull_request", "workflow_dispatch", "schedule", "release"
- **AI Impact**: Helps AI understand the execution context and assess risk levels
- **Security Relevance**: Some triggers (like `workflow_dispatch`) are higher risk than others

### 2. `RunnerType` (string) 
- **Purpose**: Identifies where the job is running
- **Examples**: "ubuntu-latest", "windows-latest", "self-hosted", "matrix"
- **AI Impact**: Critical for assessing attack surface and security implications
- **Security Relevance**: Self-hosted runners have significantly different security models

### 3. `FileContext` (string)
- **Purpose**: Determines the purpose/environment of the workflow file
- **Examples**: "production", "test", "example", "template", "development", "staging"
- **AI Impact**: Helps differentiate between legitimate test code and production risks
- **Security Relevance**: Issues in test/example files may be less critical than production

## Context Extraction Logic

### Trigger Detection
```go
func extractTriggerInfo(workflow parser.WorkflowFile) string {
    // Handles various YAML formats:
    // - Simple string: on: push
    // - Array: on: [push, pull_request]  
    // - Complex object: on: { push: { branches: [main] } }
    // Returns the primary trigger or "complex"/"multiple" for advanced configs
}
```

### Runner Type Detection
```go
func extractRunnerType(job parser.Job) string {
    // Handles:
    // - Simple: runs-on: ubuntu-latest
    // - Array: runs-on: [self-hosted, linux]
    // - Matrix: runs-on: ${{ matrix.os }}
    // Returns primary runner or "matrix" for complex configurations
}
```

### File Context Detection
```go
func extractFileContext(workflow parser.WorkflowFile) string {
    // Analyzes file path and workflow name for context clues:
    // - Paths containing "test", "example", "demo" → respective contexts
    // - Workflow names with "ci", "deploy", "release" → respective contexts
    // - Default: "production" (conservative approach)
}
```

## AI Prompt Enhancement

All AI providers now receive enhanced context in their prompts:

```
IMPORTANT CONTEXT:
- **Workflow Trigger:** The workflow was triggered by a 'push' event. This is crucial for understanding the context of the execution.
- **Runner Type:** The job is running on a 'self-hosted' runner. Pay special attention to self-hosted runners as they have different security implications.
- **File Context:** The finding was found in a file that appears to be part of 'production'. This can help differentiate between production code, tests, and examples.
```

## Usage in Rule Functions

Rules can now enhance findings with context information:

```go
func checkSomeRule(workflow parser.WorkflowFile) []Finding {
    var findings []Finding
    
    for jobName, job := range workflow.Workflow.Jobs {
        // ... rule logic ...
        
        finding := Finding{
            RuleID: "SOME_RULE",
            // ... other fields ...
        }
        
        // Enhance with context information
        finding = enhanceFindingWithContext(finding, workflow, job)
        findings = append(findings, finding)
    }
    
    return findings
}
```

## Benefits for AI Analysis

1. **Improved Accuracy**: AI can better assess whether findings are legitimate based on context
2. **Risk Prioritization**: Self-hosted runners and production contexts get higher scrutiny
3. **False Positive Reduction**: Test/example files receive more lenient analysis
4. **Context-Aware Reasoning**: AI explanations can reference specific trigger and runner implications

## Security Implications by Context

### Trigger Types
- **High Risk**: `workflow_dispatch`, `repository_dispatch` (user-controlled)
- **Medium Risk**: `pull_request` (external contributions)  
- **Lower Risk**: `push` to protected branches, `schedule`

### Runner Types
- **High Risk**: `self-hosted` (customer infrastructure)
- **Medium Risk**: `ubuntu-latest`, `windows-latest` (shared GitHub runners)
- **Variable Risk**: Matrix builds (depends on configuration)

### File Contexts
- **High Priority**: `production`, `deployment`, `release`
- **Medium Priority**: `ci`, `staging`, `development`
- **Lower Priority**: `test`, `example`, `template`

## Example Enhanced Finding

```json
{
  "rule_id": "MALICIOUS_CURL_PIPE_BASH",
  "rule_name": "Curl Pipe to Shell", 
  "severity": "HIGH",
  "trigger": "pull_request",
  "runner_type": "self-hosted",
  "file_context": "production",
  "evidence": "curl https://example.com/script.sh | bash",
  "job_name": "deploy",
  "ai_reasoning": "This is likely a true positive because: 1) Running on self-hosted runner increases attack surface, 2) Triggered by pull_request allows external input, 3) Production context makes this high-priority, 4) Direct shell execution without verification is dangerous"
}
```

This enhancement significantly improves AI analysis quality by providing the contextual information needed for accurate security assessment.