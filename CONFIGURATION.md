# Flowlyt Configuration Guide

## Overview

Flowlyt now supports comprehensive configuration for scalable security scanning with user-configurable false positives and custom rule authoring.

## Configuration File

Create a `.flowlyt.yml` file in your project root or specify a custom path with `--config`.

### Example Configuration

```yaml
# Flowlyt Configuration File
version: "1"

# Rule configuration
rules:
  # Enable specific rules only (if empty, all rules are enabled)
  enabled: []
  
  # Disable specific rules
  disabled: ["UNPINNED_ACTION", "CONTINUE_ON_ERROR_CRITICAL_JOB"]
  
  # Custom user-defined rules
  custom_rules:
    # Example: Detect suspicious Docker commands
    - id: "CUSTOM_DOCKER_RISK"
      name: "Suspicious Docker Command"
      description: "Detects potentially risky Docker commands in workflows"
      severity: "HIGH"
      category: "MALICIOUS_PATTERN"
      type: "regex"
      patterns:
        - "docker run.*--privileged"
        - "docker.*--cap-add.*SYS_ADMIN"
        - "docker.*--security-opt.*seccomp=unconfined"
      target:
        commands: true      # Check run commands
        actions: false      # Check uses actions
        environment: false  # Check env vars
        permissions: false  # Check permissions
        events: false       # Check workflow events
      remediation: "Avoid running Docker containers with elevated privileges."
    
    # Example: Detect environment variable secrets
    - id: "CUSTOM_ENV_SECRETS"
      name: "Environment Variable Secrets"
      description: "Detects potential secrets in environment variable names"
      severity: "CRITICAL"
      category: "SECRET_EXPOSURE"
      type: "regex"
      pattern: "(?i)(password|secret|token|key|credential).*=.*[A-Za-z0-9]{8,}"
      target:
        commands: true
        environment: true
      remediation: "Use GitHub secrets instead of hardcoded values."
  
  # False positive configuration
  false_positives:
    # Global ignore patterns (applied to all rules)
    global:
      patterns:
        - ".*example.*"
        - ".*test.*"
      strings:
        - "placeholder"
        - "dummy"
        - "sample"
    
    # Secret-specific ignores
    secrets:
      patterns:
        - ".*_test$"
        - ".*_example$"
      strings:
        - "YOUR_SECRET_HERE"
        - "changeme"
        - "fake-token"
      contexts:
        - "uses:.*@[a-f0-9]{40}"  # Action SHAs
        - "uses:.*@v\\d+"         # Version tags
        - "\\$\\{\\{ secrets\\."  # Secret references
        - "\\$\\{\\{ env\\."      # Env references
    
    # Action-specific ignores
    actions:
      actions: []  # Specific actions to ignore
      orgs:        # Trusted organizations
        - "actions"
        - "github"
    
    # File patterns to ignore globally
    files:
      - "test/**"
      - "tests/**"
      - "examples/**"
      - "docs/**"
      - "*.md"
    
    # Rule-specific ignore patterns
    rules:
      HARDCODED_SECRET:
        patterns:
          - ".*_test\\.yml$"
        strings:
          - "fake-token"
        files:
          - "test/**"
      UNPINNED_ACTION:
        actions:
          - "actions/checkout@v4"  # Allow specific version tags

# Output configuration
output:
  format: "cli"  # cli, json, sarif, junit
  file: ""       # Output file (empty for stdout)
  min_severity: "LOW"  # Minimum severity to report
  show_remediation: true
  fields:
    line_number: true
    evidence: true
    remediation: true
    category: true
```

## Command Line Options

### Configuration
- `--config`, `-c`: Path to configuration file
- `--enable-rules`: Enable only specific rules (comma-separated)
- `--disable-rules`: Disable specific rules (comma-separated)
- `--min-severity`: Minimum severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)

### Examples

```bash
# Use custom configuration file
flowlyt --config my-config.yml --repo /path/to/repo

# Enable only specific rules
flowlyt --enable-rules HARDCODED_SECRET,BROAD_PERMISSIONS --repo .

# Disable problematic rules
flowlyt --disable-rules UNPINNED_ACTION,CONTINUE_ON_ERROR --repo .

# Show only high-severity issues
flowlyt --min-severity HIGH --repo .

# Combine options
flowlyt --config .flowlyt.yml --disable-rules UNPINNED_ACTION --min-severity MEDIUM --repo .
```

## Custom Rule Types

### Regex Rules
Simple pattern-based rules for text matching:

```yaml
custom_rules:
  - id: "MY_PATTERN_RULE"
    name: "Custom Pattern Detection"
    type: "regex"
    pattern: "dangerous.*command"
    # OR multiple patterns:
    patterns:
      - "pattern1"
      - "pattern2"
    target:
      commands: true
    severity: "HIGH"
    category: "MALICIOUS_PATTERN"
    remediation: "Avoid using dangerous commands"
```

### Rule Targets
Specify what the rule should examine:

- `commands: true` - Check `run:` commands in workflow steps
- `actions: true` - Check `uses:` actions in workflow steps
- `environment: true` - Check environment variables
- `permissions: true` - Check workflow permissions
- `events: true` - Check workflow trigger events

### Severity Levels
- `CRITICAL` - Critical security vulnerabilities
- `HIGH` - High-risk security issues
- `MEDIUM` - Medium-risk security concerns
- `LOW` - Low-risk security observations
- `INFO` - Informational findings

### Categories
- `MALICIOUS_PATTERN` - Potentially malicious code patterns
- `MISCONFIGURATION` - Security misconfigurations
- `SECRET_EXPOSURE` - Exposed secrets or credentials
- `SHELL_OBFUSCATION` - Obfuscated shell commands
- `POLICY_VIOLATION` - Policy compliance violations

## False Positive Management

### Global Ignores
Apply to all rules:

```yaml
false_positives:
  global:
    patterns: [".*test.*", ".*example.*"]
    strings: ["placeholder", "dummy"]
```

### Rule-Specific Ignores
Override for specific rules:

```yaml
false_positives:
  rules:
    HARDCODED_SECRET:
      strings: ["fake-api-key", "test-token"]
      files: ["test/**", "examples/**"]
```

### File Pattern Ignores
Ignore entire file patterns:

```yaml
false_positives:
  files:
    - "test/**"
    - "docs/**"
    - "*.md"
```

## Migration from Hard-coded Rules

### Before (Not Scalable)
```go
// Hard-coded in source code
commonFalsePositives := []string{"example", "test"}
```

### After (Scalable)
```yaml
# User-configurable in .flowlyt.yml
false_positives:
  global:
    strings: ["example", "test", "my-custom-ignore"]
```

## Best Practices

1. **Start with defaults**: Use the default configuration and gradually customize
2. **Use file patterns**: Ignore test directories and documentation files
3. **Rule-specific ignores**: Be specific about which rules to ignore for which patterns
4. **Version control**: Include `.flowlyt.yml` in your repository
5. **Team configuration**: Share configuration across team members
6. **Regular review**: Periodically review and update ignore patterns

## Advanced Usage

### Project-specific Configuration
Place `.flowlyt.yml` in each project:

```
my-project/
├── .flowlyt.yml      # Project-specific config
├── .github/
│   └── workflows/
└── src/
```

### CI/CD Integration
```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    flowlyt --config .flowlyt.yml \
            --min-severity HIGH \
            --output json \
            --output-file security-report.json \
            --repo .
```

### Multiple Environments
```bash
# Development (all rules, low threshold)
flowlyt --config .flowlyt.dev.yml --min-severity LOW

# Production (critical only)
flowlyt --config .flowlyt.prod.yml --min-severity CRITICAL
```

This configuration system makes Flowlyt highly scalable and flexible for different teams, projects, and security requirements.
