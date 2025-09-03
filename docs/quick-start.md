# Quick Start Guide

## Installation

### Option 1: Download Pre-built Binary
```bash
# Download the latest release for your platform
curl -L https://github.com/harekrishnarai/flowlyt/releases/latest/download/flowlyt-linux-amd64 -o flowlyt
chmod +x flowlyt
sudo mv flowlyt /usr/local/bin/
```

### Option 2: Install via Go
```bash
# Recommended method (bypasses proxy cache issues)
GOPRIVATE=github.com/harekrishnarai/flowlyt go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest

# Alternative: install specific version
go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@v0.0.6
```

> **Note**: Due to Go module proxy cache issues, `go install @latest` may install an incorrect version (v1.0.0). Use the `GOPRIVATE` method above to ensure you get the correct latest version.

### Option 3: Build from Source
```bash
git clone https://github.com/harekrishnarai/flowlyt.git
cd flowlyt
go build -o flowlyt cmd/flowlyt/main.go
```

## Basic Usage

### Analyze a Single Workflow
```bash
# Analyze a single workflow file (no config required)
flowlyt scan --workflow .github/workflows/ci.yml

# If .flowlyt.yml exists in the directory, it will be automatically used
# Configuration is completely optional

# Enable vulnerability intelligence
flowlyt scan --workflow .github/workflows/ci.yml --enable-vuln-intel
```

### Analyze Entire Repository
```bash
# Scan all workflows in repository (no config required)
flowlyt scan --repo ./my-repo

# GitHub repository analysis
flowlyt analyze-org --organization myorg --token $GITHUB_TOKEN

# GitLab repository analysis  
flowlyt scan --platform gitlab --repo ./my-repo
```

### Output Formats
```bash
# JSON output
flowlyt analyze workflow.yml --output-format json

# SARIF output for GitHub Security tab
flowlyt analyze workflow.yml --output-format sarif --output-file results.sarif

# Markdown report
flowlyt analyze workflow.yml --output-format markdown --output-file report.md
```

## GitHub Actions Integration

Create `.github/workflows/security-scan.yml`:

```yaml
name: Flowlyt Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Flowlyt Security Scan
        uses: harekrishnarai/flowlyt@v1
        with:
          config-file: '.flowlyt.yml'
          output-format: 'sarif'
          output-file: 'flowlyt-results.sarif'
          
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: flowlyt-results.sarif
```

## Configuration (Optional)

Flowlyt works out-of-the-box without any configuration. However, you can optionally create a `.flowlyt.yml` file in your repository root for advanced customization:

```yaml
# Basic configuration (all settings are optional)
version: "1"

rules:
  # Disable specific rules
  disabled: ["UNPINNED_ACTION"]
  
  # Enable only specific rules (if omitted, all rules are enabled)
  enabled: ["HARDCODED_SECRET", "DANGEROUS_COMMAND"]

# Output settings
output:
  format: "cli"               # cli, json, sarif, markdown
  min_severity: "MEDIUM"      # CRITICAL, HIGH, MEDIUM, LOW, INFO
  include_line_numbers: true
  show_rule_description: true

# False positive management
ignore:
  files:
    - "test/**/*"
    - "docs/**/*"
  global:
    strings: ["example", "test"]

# Platform-specific settings
platforms:
  github_actions:
    enforce_pinned_actions: true
    check_dangerous_permissions: true
  gitlab_ci:
    enforce_image_pinning: true
    check_script_injection: true
```

> **Note**: Configuration files are completely optional. Flowlyt provides sensible defaults and works immediately without any setup.

## Next Steps

- [Configuration Guide](configuration.md) - Detailed configuration options
- [AST Analysis](ast-analysis.md) - Advanced static analysis features
- [Custom Rules](custom-rules.md) - Creating your own security rules
- [Security Rules](security-rules.md) - Complete list of built-in rules
- [CLI Reference](cli-reference.md) - Complete command reference
