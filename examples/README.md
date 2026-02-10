# Flowlyt Examples

This directory contains examples demonstrating various Flowlyt features and usage patterns.

## Directory Structure

```
examples/
├── workflows/              # GitHub Actions workflow examples
│   ├── basic-security-scan.yml
│   ├── enterprise-pipeline.yml
│   └── README.md
├── enhanced/               # Enhanced analysis examples
│   └── enhanced_ast_analysis.go
├── performance/            # Performance benchmarking
│   └── ast_performance_benchmark.go
├── cli-output-example.sh   # CLI output format demonstration
└── sarif-github-advanced-security-example.json  # SARIF output example
```

## Examples Overview

### 📋 Workflow Examples

**Location**: `workflows/`

GitHub Actions workflow examples showing how to integrate Flowlyt into your CI/CD pipelines.

- **Basic Security Scan**: Simple workflow for quick security checks
- **Enterprise Pipeline**: Advanced workflow with policy enforcement and compliance

[View workflow examples →](workflows/README.md)

### 🔍 Enhanced Analysis

**Location**: `enhanced/enhanced_ast_analysis.go`

Demonstrates enhanced AST (Abstract Syntax Tree) analysis capabilities for complex workflow patterns.

**Run example**:
```bash
go run examples/enhanced/enhanced_ast_analysis.go
```

### ⚡ Performance Benchmarking

**Location**: `performance/ast_performance_benchmark.go`

Performance benchmark for AST analysis with large workflows.

**Run benchmark**:
```bash
go run examples/performance/ast_performance_benchmark.go
```

### 🖥️ CLI Output Example

**Location**: `cli-output-example.sh`

Demonstrates the enhanced CLI output format with colored output, progress indicators, and visual representations of findings.

**View example**:
```bash
./examples/cli-output-example.sh
```

### 📄 SARIF Output Example

**Location**: `sarif-github-advanced-security-example.json`

Example SARIF (Static Analysis Results Interchange Format) output for GitHub Security tab integration.

This shows how Flowlyt findings appear in GitHub's Security tab with:
- Detailed rule descriptions
- Remediation guidance
- Severity levels
- Line-level annotations

**View example**:
```bash
cat examples/sarif-github-advanced-security-example.json | jq '.'
```

## Usage

### For Users

Browse the `workflows/` directory to find pre-built GitHub Actions workflows you can use directly in your projects.

### For Contributors

The Go examples demonstrate:
- How to use Flowlyt's AST analysis APIs
- Performance characteristics of different analysis methods
- Integration patterns for custom tooling

## Documentation

For complete documentation, see:
- [Installation Guide](../docs/guides/installation.md)
- [Quick Start](../docs/guides/quick-start.md)
- [CLI Reference](../docs/reference/cli-reference.md)
- [GitHub Actions Integration](../docs/integrations/github-actions-integration.md)

## Contributing

Have a useful example? We'd love to include it!

1. Create your example following the existing patterns
2. Add documentation explaining the use case
3. Submit a pull request

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

---

**Questions?** Open an issue at https://github.com/harekrishnarai/flowlyt/issues
