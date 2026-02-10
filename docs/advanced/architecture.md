# Architecture

This document provides a comprehensive overview of Flowlyt's architecture, design principles, and internal components.

## System Overview

Flowlyt is designed as a modular, extensible CI/CD security analyzer built in Go. The architecture follows clean architecture principles with clear separation of concerns and dependency injection.

```
┌─────────────────────────────────────────────────────────────┐
│                        User Interface                      │
├─────────────────────────────────────────────────────────────┤
│  CLI  │  HTTP API  │  GitHub Action  │  GitLab Component   │
├─────────────────────────────────────────────────────────────┤
│                    Application Layer                        │
├─────────────────────────────────────────────────────────────┤
│ Config │ Analysis │ Reporting │ Policy │ Rule Engine        │
├─────────────────────────────────────────────────────────────┤
│                      Core Domain                            │
├─────────────────────────────────────────────────────────────┤
│ Parser │ Platform │ Rules   │ Shell   │ Policies           │
├─────────────────────────────────────────────────────────────┤
│                   Infrastructure Layer                      │
├─────────────────────────────────────────────────────────────┤
│  File I/O  │  Git  │  GitHub API  │  GitLab API  │  OPA    │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Parser Engine

The parser engine is responsible for understanding different CI/CD workflow formats.

**Location:** `pkg/parser/`

**Components:**
- **YAML Parser:** Handles GitHub Actions and GitLab CI YAML files
- **Syntax Analyzer:** Understands workflow structure and semantics
- **AST Builder:** Creates abstract syntax trees for analysis
- **Context Extractor:** Extracts relevant security contexts

**Key Interfaces:**
```go
type Parser interface {
    Parse(content []byte) (*Workflow, error)
    ParseFile(path string) (*Workflow, error)
    Validate(workflow *Workflow) error
}

type Workflow struct {
    Platform     string
    Name         string
    Triggers     []Trigger
    Jobs         []Job
    Environment  map[string]string
    Permissions  Permissions
}
```

**Parser Architecture:**
```
Input YAML → Lexer → Parser → AST → Workflow Model
     ↑                                      ↓
Configuration                      Security Analysis
```

### 2. Platform Support

Multi-platform support with pluggable platform implementations.

**Location:** `pkg/platform/`

**Supported Platforms:**
- GitHub Actions
- GitLab CI/CD
- Jenkins (planned)
- Azure DevOps (planned)

**Platform Interface:**
```go
type Platform interface {
    Name() string
    DetectWorkflows(rootPath string) ([]string, error)
    ParseWorkflow(path string) (*Workflow, error)
    GetSecurityContext(workflow *Workflow) *SecurityContext
    ValidateWorkflow(workflow *Workflow) error
}
```

**Platform-Specific Features:**
- **GitHub Actions:** Supports reusable workflows, environment protection, OIDC
- **GitLab CI:** Supports includes, extends, parallel jobs, DAG pipelines

### 3. Rule Engine

Flexible, extensible rule engine for security analysis.

**Location:** `pkg/rules/`

**Rule Types:**
- **Pattern Rules:** Regex-based pattern matching
- **Semantic Rules:** Understanding workflow logic and flow
- **Policy Rules:** Open Policy Agent (OPA) integration
- **Custom Rules:** User-defined rules via configuration

**Rule Engine Architecture:**
```go
type RuleEngine interface {
    LoadRules(config *Config) error
    EvaluateWorkflow(workflow *Workflow) ([]Finding, error)
    AddCustomRule(rule *CustomRule) error
    GetRuleMetadata(ruleID string) *RuleMetadata
}

type Rule interface {
    ID() string
    Name() string
    Description() string
    Severity() Severity
    Category() Category
    Evaluate(context *SecurityContext) (*Finding, error)
}
```

**Built-in Rule Categories:**
- **SECRET_EXPOSURE:** Hardcoded secrets, token leakage
- **COMMAND_INJECTION:** Shell injection, dangerous commands
- **PRIVILEGE_ESCALATION:** Excessive permissions, sudo usage
- **MALICIOUS_PATTERN:** Suspicious commands, known attack patterns
- **COMPLIANCE:** Regulatory and policy compliance

### 4. Security Context Analysis

Contextual analysis engine that understands workflow security implications.

**Location:** `pkg/security/`

**Context Components:**
- **Permission Analysis:** Evaluates GITHUB_TOKEN and other permissions
- **Environment Analysis:** Checks environment variables and secrets usage
- **Flow Analysis:** Understands data flow and control flow
- **Dependency Analysis:** Analyzes action and image dependencies

**Security Context Structure:**
```go
type SecurityContext struct {
    Workflow     *Workflow
    Permissions  PermissionSet
    Secrets      []SecretUsage
    Environment  EnvironmentContext
    Dependencies []Dependency
    ShellCommands []ShellCommand
}
```

### 5. Policy Framework

Comprehensive policy framework for compliance and governance.

**Location:** `pkg/policies/`

**Policy Engine Features:**
- **OPA Integration:** Uses Open Policy Agent for policy evaluation
- **Policy as Code:** Version-controlled policy definitions
- **Hierarchical Policies:** Organization → Team → Repository → Workflow
- **Compliance Frameworks:** SOC 2, PCI DSS, HIPAA, ISO 27001

**Policy Architecture:**
```go
type PolicyEngine interface {
    LoadPolicies(paths []string) error
    EvaluateCompliance(workflow *Workflow) (*ComplianceResult, error)
    ValidatePolicy(policy *Policy) error
    GetPolicyMetadata() []*PolicyMetadata
}
```

### 6. Report Generation

Multi-format reporting system with extensible output formats.

**Location:** `pkg/report/`

**Supported Formats:**
- **CLI:** Human-readable terminal output with colors
- **JSON:** Machine-readable structured data
- **Markdown:** Documentation-friendly format
- **SARIF:** Static Analysis Results Interchange Format
- **HTML:** Rich web-based reports (planned)

**Report Architecture:**
```go
type Reporter interface {
    Generate(findings []Finding, options *ReportOptions) ([]byte, error)
    Format() string
    ContentType() string
}
```

## Data Flow

### Analysis Pipeline

```
1. Input Discovery
   ├── Scan repository for workflow files
   ├── Detect platform (GitHub Actions, GitLab CI, etc.)
   └── Validate file accessibility

2. Parsing Phase
   ├── Parse YAML syntax
   ├── Build workflow AST
   ├── Extract security-relevant elements
   └── Create security context

3. Rule Evaluation
   ├── Load applicable rules
   ├── Filter rules by configuration
   ├── Execute rules against security context
   └── Collect findings

4. Policy Evaluation
   ├── Load policy framework
   ├── Apply organizational policies
   ├── Check compliance requirements
   └── Generate compliance report

5. Report Generation
   ├── Aggregate findings
   ├── Apply filtering and sorting
   ├── Format output
   └── Generate final report
```

### Configuration Resolution

```
Configuration Priority (highest to lowest):
1. Command-line flags
2. Environment variables
3. Repository .flowlyt.yml
4. Team configuration
5. Organization configuration
6. Global defaults
```

## Extensibility

### Custom Rules

Flowlyt supports multiple ways to add custom rules:

#### 1. YAML-Based Rules
```yaml
# custom-rules.yml
rules:
  - id: "COMPANY_SECRETS"
    name: "Company Secret Detection"
    description: "Detects company-specific secret patterns"
    severity: "HIGH"
    category: "SECRET_EXPOSURE"
    patterns:
      - "COMPANY_API_KEY_[A-Za-z0-9]{32}"
      - "INTERNAL_TOKEN_[A-Fa-f0-9]{40}"
    remediation: "Use GitHub secrets for company API keys"
```

#### 2. Go Plugin Rules
```go
// custom_rule.go
package main

import "github.com/harekrishnarai/flowlyt/pkg/rules"

type CompanySecretRule struct{}

func (r *CompanySecretRule) ID() string { return "COMPANY_SECRETS" }
func (r *CompanySecretRule) Name() string { return "Company Secret Detection" }
func (r *CompanySecretRule) Severity() rules.Severity { return rules.HIGH }

func (r *CompanySecretRule) Evaluate(ctx *rules.SecurityContext) (*rules.Finding, error) {
    // Custom rule logic
    return nil, nil
}

// Export the rule
var Rule = &CompanySecretRule{}
```

#### 3. OPA Policy Rules
```rego
# company_policies.rego
package flowlyt.company

import rego.v1

deny contains msg if {
    input.workflow.jobs[_].steps[_].env[key]
    startswith(key, "COMPANY_SECRET_")
    msg := "Company secrets must use GitHub secrets"
}
```

### Platform Extensions

Add support for new CI/CD platforms:

```go
// platform/jenkins/jenkins.go
package jenkins

import "github.com/harekrishnarai/flowlyt/pkg/platform"

type JenkinsPlatform struct{}

func (p *JenkinsPlatform) Name() string {
    return "jenkins"
}

func (p *JenkinsPlatform) DetectWorkflows(rootPath string) ([]string, error) {
    // Detect Jenkinsfiles
}

func (p *JenkinsPlatform) ParseWorkflow(path string) (*platform.Workflow, error) {
    // Parse Jenkinsfile
}

// Register the platform
func init() {
    platform.Register("jenkins", &JenkinsPlatform{})
}
```

### Output Format Extensions

Add custom output formats:

```go
// report/custom_formatter.go
package report

type CustomFormatter struct{}

func (f *CustomFormatter) Generate(findings []Finding, options *ReportOptions) ([]byte, error) {
    // Custom formatting logic
}

func (f *CustomFormatter) Format() string {
    return "custom"
}

func (f *CustomFormatter) ContentType() string {
    return "application/custom"
}

// Register the formatter
func init() {
    RegisterFormatter("custom", &CustomFormatter{})
}
```

## Performance Considerations

### Scalability

**Repository Size:**
- Efficient file discovery using gitignore patterns
- Parallel processing of multiple workflow files
- Memory-efficient streaming for large repositories

**Analysis Performance:**
- Rule evaluation optimization with early exit conditions
- Caching of parsed workflows and rule metadata
- Incremental analysis for changed files only

**Concurrent Processing:**
```go
// Parallel workflow analysis
func (a *Analyzer) AnalyzeRepositories(repos []string) error {
    semaphore := make(chan struct{}, a.config.MaxConcurrency)
    var wg sync.WaitGroup
    
    for _, repo := range repos {
        wg.Add(1)
        go func(repo string) {
            defer wg.Done()
            semaphore <- struct{}{}
            defer func() { <-semaphore }()
            
            a.analyzeRepository(repo)
        }(repo)
    }
    
    wg.Wait()
    return nil
}
```

### Memory Management

**Efficient Data Structures:**
- Use of sync.Pool for reusable objects
- Streaming processing for large files
- Garbage collection optimization

**Resource Cleanup:**
```go
// Proper resource management
func (p *Parser) ParseWorkflow(path string) (*Workflow, error) {
    file, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer file.Close()
    
    // Use limited reader to prevent memory exhaustion
    reader := &io.LimitedReader{R: file, N: maxFileSize}
    return p.parse(reader)
}
```

## Security Architecture

### Input Validation

All inputs are validated and sanitized:

```go
// Secure file path handling
func (s *Scanner) validatePath(path string) error {
    // Prevent path traversal
    if strings.Contains(path, "..") {
        return ErrInvalidPath
    }
    
    // Ensure within repository bounds
    absPath, err := filepath.Abs(path)
    if err != nil {
        return err
    }
    
    if !strings.HasPrefix(absPath, s.repositoryRoot) {
        return ErrPathOutsideRepository
    }
    
    return nil
}
```

### Sandboxing

External integrations are sandboxed:

```go
// Secure external command execution
func (e *Executor) executeRule(rule *ExternalRule) error {
    ctx, cancel := context.WithTimeout(context.Background(), ruleTimeout)
    defer cancel()
    
    cmd := exec.CommandContext(ctx, rule.Command, rule.Args...)
    cmd.Dir = e.sandboxDir
    cmd.Env = e.sanitizedEnv()
    
    return cmd.Run()
}
```

### Secrets Handling

Secure handling of sensitive data:

```go
// Redact sensitive information
func (r *Reporter) redactSecrets(content string) string {
    for _, pattern := range secretPatterns {
        content = pattern.ReplaceAllStringFunc(content, func(match string) string {
            return secretMask
        })
    }
    return content
}
```

## Testing Architecture

### Test Structure

```
tests/
├── unit/              # Unit tests for individual components
├── integration/       # Integration tests for component interaction
├── e2e/              # End-to-end tests with real repositories
├── fixtures/         # Test data and sample workflows
└── performance/      # Performance and load tests
```

### Test Categories

**Unit Tests:**
- Parser functionality
- Rule evaluation logic
- Configuration handling
- Report generation

**Integration Tests:**
- Platform detection and parsing
- Rule engine integration
- Policy evaluation
- CLI command integration

**End-to-End Tests:**
- Full workflow analysis
- Real repository scanning
- Output format validation
- Error handling scenarios

### Test Utilities

```go
// Test helpers for workflow creation
func CreateTestWorkflow(platform string, jobs ...Job) *Workflow {
    return &Workflow{
        Platform: platform,
        Name:     "test-workflow",
        Jobs:     jobs,
    }
}

// Mock platform for testing
type MockPlatform struct {
    workflows []string
    errors    map[string]error
}

func (m *MockPlatform) DetectWorkflows(path string) ([]string, error) {
    if err, exists := m.errors[path]; exists {
        return nil, err
    }
    return m.workflows, nil
}
```

## Deployment Architecture

### Distribution Methods

**Single Binary:**
- Cross-platform compilation
- Minimal dependencies
- Easy installation

**Container Image:**
- Lightweight Alpine-based image
- Security scanning integrated
- Multi-architecture support

**GitHub Action:**
- Pre-built action for GitHub workflows
- Automatic updates
- Integration with GitHub Security tab

**Package Managers:**
- Homebrew for macOS
- APT for Ubuntu/Debian
- Chocolatey for Windows
- Go modules for development

### Configuration Management

**Hierarchical Configuration:**
```
Global Config → Organization → Team → Repository → CLI Args
```

**Configuration Sources:**
- Command-line flags
- Environment variables
- Configuration files (.flowlyt.yml)
- Remote configuration (via API)

## Monitoring and Observability

### Metrics Collection

```go
// Performance metrics
type Metrics struct {
    AnalysisDuration    time.Duration
    FilesProcessed      int
    RulesEvaluated      int
    FindingsGenerated   int
    MemoryUsage         int64
}
```

### Logging

Structured logging with configurable levels:

```go
// Structured logging
logger.Info("workflow analysis completed",
    zap.String("repository", repo),
    zap.Duration("duration", duration),
    zap.Int("findings", len(findings)),
    zap.String("platform", platform),
)
```

### Health Checks

```go
// Health check endpoints
func (s *Server) healthCheck(w http.ResponseWriter, r *http.Request) {
    health := &HealthStatus{
        Status:    "healthy",
        Version:   version.Version,
        Uptime:    time.Since(s.startTime),
        RulesLoaded: s.ruleEngine.RuleCount(),
    }
    
    json.NewEncoder(w).Encode(health)
}
```

---

**Next:** [Troubleshooting](troubleshooting.md)
