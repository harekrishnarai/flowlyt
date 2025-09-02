# Configuration Management

Flowlyt provides a comprehensive configuration system that allows you to customize security rules, manage false positives, and adapt the tool to your organization's specific requirements.

## Configuration File Overview

The primary configuration file is `.flowlyt.yml`, which should be placed in your repository root or specified via the `--config` flag.

### Basic Configuration Structure

```yaml
# .flowlyt.yml
version: "1"

# Rule configuration
rules:
  enabled: []           # Specific rules to enable
  disabled: []          # Specific rules to disable
  custom_rules: []      # User-defined custom rules

# False positive management
ignore:
  global: []            # Global ignore patterns
  secrets: {}           # Secret-specific ignores
  files: []             # File-based ignores
  rules: {}             # Rule-specific ignores

# Output configuration
output:
  format: "cli"         # Output format (cli, json, markdown)
  file: ""              # Output file path
  min_severity: "LOW"   # Minimum severity to report
```

## Rule Configuration

### Enabling and Disabling Rules

#### Enable Specific Rules Only
```yaml
rules:
  enabled:
    - "HARDCODED_SECRET"
    - "MALICIOUS_BASE64_DECODE"
    - "INSECURE_PULL_REQUEST_TARGET"
    - "BROAD_PERMISSIONS"
```

#### Disable Specific Rules
```yaml
rules:
  disabled:
    - "UNPINNED_ACTION"                    # Using Dependabot for updates
    - "CONTINUE_ON_ERROR_CRITICAL_JOB"     # Needed for specific workflows
```

#### Combine Enable and Disable
```yaml
rules:
  # Start with these base rules
  enabled:
    - "HARDCODED_SECRET"
    - "DANGEROUS_COMMAND"
    - "BROAD_PERMISSIONS"
  
  # But disable these specific ones
  disabled:
    - "UNPINNED_ACTION"    # Managed separately
```

### Custom Rules

Define organization-specific security rules:

```yaml
rules:
  custom_rules:
    # Docker security rule
    - id: "COMPANY_DOCKER_POLICY"
      name: "Company Docker Image Policy"
      description: "Ensures only approved Docker images are used"
      severity: "HIGH"
      category: "POLICY_VIOLATION"
      type: "regex"
      pattern: "image:\\s*(?!company-registry\\.com/)"
      target:
        commands: true
      remediation: "Use only approved Docker images from company-registry.com"
    
    # API key pattern
    - id: "COMPANY_API_KEY"
      name: "Company API Key Detection"
      description: "Detects company-specific API key patterns"
      severity: "CRITICAL"
      type: "regex"
      pattern: "corp_key_[A-Za-z0-9]{32}"
      target:
        environment: true
        commands: true
      remediation: "Use GitHub secrets for company API keys"
```

## False Positive Management

### Global Ignores

Apply ignores across all rules:

```yaml
ignore:
  global:
    # Ignore specific strings
    strings:
      - "example.com"
      - "localhost"
      - "127.0.0.1"
      - "test-secret"
    
    # Ignore patterns (regex)
    patterns:
      - ".*\\.example\\.com$"
      - "^test[_-].*"
      - ".*[_-]test$"
```

### Secret-Specific Ignores

Configure ignores specifically for secret detection:

```yaml
ignore:
  secrets:
    # Ignore specific secret strings
    strings:
      - "fake-api-key"
      - "test-token-12345"
      - "example-secret"
      - "your-api-key-here"
    
    # Ignore secret patterns
    patterns:
      - "^sk-test-.*"        # Test Stripe keys
      - ".*_test$"           # Test suffixes
      - "^example_.*"        # Example prefixes
      - "^AKIA[0-9A-Z]{16}$" # AWS test keys (if using test accounts)
    
    # Context-based ignores
    contexts:
      - "\\$\\{\\{ secrets\\."     # GitHub secret references
      - "\\$\\{[A-Z_]+\\}"         # Environment variable references
      - "# .*"                     # Comments
      - "\\*\\*\\*"                # Masked values
```

### File-Based Ignores

Ignore entire files or directories:

```yaml
ignore:
  files:
    - "test/**/*"              # All test files
    - "tests/**/*"             # Test directory
    - "examples/**/*"          # Example files
    - "docs/**/*"              # Documentation
    - "*.md"                   # Markdown files
    - ".github/workflows/test-*"  # Test workflows
    - "scripts/dev/*"          # Development scripts
```

### Rule-Specific Ignores

Configure ignores for specific rules:

```yaml
ignore:
  rules:
    # Ignores for hardcoded secret rule
    HARDCODED_SECRET:
      strings:
        - "TODO: add real secret here"
        - "placeholder-secret"
        - "fake-token"
      patterns:
        - "^EXAMPLE_.*"
        - ".*_PLACEHOLDER$"
      files:
        - "test/fixtures/**"
        - "examples/**"
    
    # Ignores for unpinned action rule
    UNPINNED_ACTION:
      strings:
        - "actions/checkout@v4"      # Trust official actions
        - "actions/setup-node@v4"
      patterns:
        - "actions/.*@v[0-9]+"       # Allow version tags for official actions
    
    # Ignores for dangerous command rule
    DANGEROUS_COMMAND:
      strings:
        - "curl -s https://trusted-domain.com/install.sh | bash"
      contexts:
        - "# This is safe because"   # When explicitly documented
```

## Environment-Specific Configuration

### Development Environment

```yaml
# .flowlyt.dev.yml
version: "1"

rules:
  disabled:
    - "CONTINUE_ON_ERROR_CRITICAL_JOB"  # Allow in development
    - "UNPINNED_ACTION"                 # More lenient in dev

ignore:
  global:
    strings:
      - "dev-api-key"
      - "localhost"
    patterns:
      - ".*-dev$"
      - ".*-local$"

output:
  min_severity: "MEDIUM"    # Show fewer issues in development
```

### Production Environment

```yaml
# .flowlyt.prod.yml
version: "1"

rules:
  enabled:
    - "HARDCODED_SECRET"
    - "MALICIOUS_BASE64_DECODE"
    - "INSECURE_PULL_REQUEST_TARGET"
    - "BROAD_PERMISSIONS"
    - "DANGEROUS_COMMAND"

output:
  min_severity: "HIGH"      # Only show critical issues in production
  format: "json"            # Machine-readable output for automation
```

### Team-Specific Configuration

```yaml
# .flowlyt.frontend.yml - Frontend team configuration
version: "1"

rules:
  custom_rules:
    - id: "NPM_SECURITY"
      name: "NPM Security Check"
      pattern: "npm\\s+install\\s+.*--unsafe-perm"
      severity: "HIGH"
      target:
        commands: true
      remediation: "Avoid --unsafe-perm flag"

ignore:
  files:
    - "backend/**/*"        # Frontend team ignores backend files
```

```yaml
# .flowlyt.backend.yml - Backend team configuration
version: "1"

rules:
  custom_rules:
    - id: "GO_SECURITY"
      name: "Go Security Check"
      pattern: "go\\s+get\\s+.*@master"
      severity: "MEDIUM"
      target:
        commands: true
      remediation: "Use specific version tags"

ignore:
  files:
    - "frontend/**/*"       # Backend team ignores frontend files
```

## Output Configuration

### Format Options

```yaml
output:
  format: "cli"             # cli, json, markdown
  file: ""                  # Output file (empty for stdout)
  min_severity: "LOW"       # CRITICAL, HIGH, MEDIUM, LOW, INFO
  
  # CLI-specific options
  show_remediation: true    # Show remediation advice
  show_evidence: true       # Show evidence snippets
  color: true               # Enable colored output
  
  # Additional fields to include
  fields:
    line_number: true       # Show line numbers
    file_path: true         # Show file paths
    rule_id: true           # Show rule IDs
    category: true          # Show rule categories
```

### Report Customization

```yaml
output:
  # Custom report template (for future use)
  template: "custom-report.tmpl"
  
  # Include/exclude specific information
  include:
    - "summary"             # Include summary section
    - "findings"            # Include detailed findings
    - "remediation"         # Include remediation advice
  
  exclude:
    - "scan_metadata"       # Exclude scan timing info
```

## Advanced Configuration

### Conditional Configuration

```yaml
# Environment-based configuration
environments:
  development:
    rules:
      disabled: ["UNPINNED_ACTION"]
    output:
      min_severity: "MEDIUM"
  
  staging:
    rules:
      disabled: ["CONTINUE_ON_ERROR_CRITICAL_JOB"]
    output:
      min_severity: "HIGH"
  
  production:
    rules:
      enabled: ["HARDCODED_SECRET", "DANGEROUS_COMMAND"]
    output:
      min_severity: "CRITICAL"

# Platform-specific configuration
platforms:
  github:
    rules:
      enabled: ["INSECURE_PULL_REQUEST_TARGET", "BROAD_PERMISSIONS"]
  
  gitlab:
    rules:
      enabled: ["GITLAB_DANGEROUS_ARTIFACTS"]
    custom_rules:
      - id: "GITLAB_RUNNER_SECURITY"
        pattern: "tags:\\s*\\[.*shell.*\\]"
        severity: "HIGH"
```

### Inheritance and Overrides

```yaml
# Base configuration
base: ".flowlyt.base.yml"

# Override specific settings
rules:
  disabled:
    - "UNPINNED_ACTION"     # Add to base disabled rules

ignore:
  global:
    strings:
      - "project-specific-ignore"  # Add to base ignores

# Completely override output settings
output:
  format: "json"
  min_severity: "HIGH"
```

## Configuration Validation

### Schema Validation

Flowlyt validates configuration files against a schema:

```bash
# Validate configuration
flowlyt --config .flowlyt.yml --validate-config

# Check for configuration errors
flowlyt --config .flowlyt.yml --repo . --dry-run
```

### Common Configuration Errors

**Invalid rule ID:**
```yaml
rules:
  enabled:
    - "INVALID_RULE_NAME"    # ❌ Rule doesn't exist
```

**Invalid severity level:**
```yaml
rules:
  custom_rules:
    - id: "CUSTOM_RULE"
      severity: "SUPER_HIGH"  # ❌ Invalid severity
```

**Invalid regex pattern:**
```yaml
rules:
  custom_rules:
    - id: "BAD_REGEX"
      pattern: "[invalid regex("  # ❌ Invalid regex
```

## Configuration Best Practices

### 1. Version Control Configuration

```yaml
# Always specify version for compatibility
version: "1"

# Add comments for complex configurations
rules:
  disabled:
    - "UNPINNED_ACTION"  # Disabled because we use Dependabot
    - "CONTINUE_ON_ERROR_CRITICAL_JOB"  # Needed for flaky test suite
```

### 2. Team Collaboration

```yaml
# Use descriptive names for custom rules
rules:
  custom_rules:
    - id: "COMPANY_DOCKER_REGISTRY_POLICY_2024"
      name: "Company Docker Registry Policy (2024 Edition)"
      description: |
        Enforces company policy requiring all Docker images to come from
        our approved internal registry. Updated in 2024 to include new
        registry domain.
```

### 3. Documentation

Document your configuration decisions:

```yaml
# .flowlyt.yml
# 
# Flowlyt Configuration for Project XYZ
# 
# Security Requirements:
# - All secrets must use GitHub secrets
# - Docker images must come from company registry
# - No privileged containers allowed
# 
# Exceptions:
# - UNPINNED_ACTION disabled (managed by Dependabot)
# - Test files ignored for secret detection
# 
# Last Updated: 2024-01-15
# Owner: Security Team <security@company.com>

version: "1"

rules:
  # Core security rules (never disable these)
  enabled:
    - "HARDCODED_SECRET"
    - "DANGEROUS_COMMAND"
    - "MALICIOUS_BASE64_DECODE"
  
  # Disabled rules with justification
  disabled:
    - "UNPINNED_ACTION"  # Managed by Dependabot
```

### 4. Testing Configuration

```bash
# Test configuration against known good/bad workflows
flowlyt --config .flowlyt.yml --workflow test/good-workflow.yml
flowlyt --config .flowlyt.yml --workflow test/bad-workflow.yml

# Validate that configuration changes work as expected
diff old-report.json new-report.json
```

## Integration Examples

### CI/CD Integration

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Flowlyt
        run: GOPRIVATE=github.com/harekrishnarai/flowlyt go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
      - name: Security Scan (Development)
        if: github.ref != 'refs/heads/main'
        run: flowlyt --config .flowlyt.dev.yml --repo .
      - name: Security Scan (Production)
        if: github.ref == 'refs/heads/main'
        run: flowlyt --config .flowlyt.prod.yml --repo . --min-severity HIGH
```

### Multi-Project Configuration

```yaml
# .flowlyt.global.yml - Organization-wide defaults
version: "1"

rules:
  custom_rules:
    - id: "ORG_DOCKER_POLICY"
      name: "Organization Docker Policy"
      pattern: "image:\\s*(?!registry\\.company\\.com/)"
      severity: "HIGH"
      target:
        commands: true

ignore:
  global:
    strings:
      - "company.com"
      - "internal.example"
```

```yaml
# project/.flowlyt.yml - Project-specific overrides
base: "../.flowlyt.global.yml"

rules:
  disabled:
    - "CONTINUE_ON_ERROR_CRITICAL_JOB"  # Project-specific exception

ignore:
  files:
    - "legacy/**/*"  # Legacy code exemption
```

## Migration and Upgrades

### Configuration Migration

When upgrading Flowlyt versions:

```bash
# Check for configuration compatibility
flowlyt --config .flowlyt.yml --check-compatibility

# Migrate configuration to new format
flowlyt --config .flowlyt.yml --migrate-config --output .flowlyt.v2.yml
```

### Gradual Rollout

```yaml
# Gradual introduction of new rules
rules:
  enabled:
    - "HARDCODED_SECRET"      # Always enabled
    
  # New rules (warning level initially)
  experimental:
    - id: "NEW_SECURITY_RULE"
      severity: "INFO"        # Start with low severity
      remediation: "This will become HIGH severity next month"
```

---

**Next:** [Report Generation](reporting.md)
