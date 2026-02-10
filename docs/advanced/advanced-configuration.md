# Advanced Configuration System

Flowlyt provides a comprehensive **enterprise-grade configuration system** that supports:

- **Organization-wide Policy Enforcement**
- **Custom Rule Templates**
- **Compliance Framework Integration**
- **Advanced Ignore Patterns**
- **Policy Inheritance**

## Configuration Files

### Basic Configuration (`.flowlyt.yml`)
```yaml
version: "1"
rules:
  enabled: []
  disabled: []
  custom_rules: []
  false_positives: {}
output:
  format: "cli"
  min_severity: "LOW"
```

### Enterprise Configuration (`.flowlyt-enterprise.yml`)
```yaml
version: "1"

# Organization-wide settings
organization:
  name: "Enterprise Corp"
  policy_repo: "enterprise-corp/security-policies"
  default_policies: ["enterprise-baseline", "pci-dss-compliance"]
  
# Compliance integration
compliance:
  enabled: true
  frameworks: ["pci-dss", "sox", "nist-800-53"]
  
# Security policies
policies:
  - id: "enterprise-baseline"
    enforcement: "block"
    rules:
      - rule_id: "UNPINNED_ACTION"
        enforcement: "block"
      - rule_id: "HARDCODED_SECRET"
        enforcement: "block"
```

## Organization-Wide Policy Enforcement

### Policy Definition
```yaml
policies:
  - id: "production-security"
    name: "Production Security Policy"
    version: "1.0"
    enabled: true
    enforcement: "block"  # block, error, warn, disabled
    
    # Define where this policy applies
    scope:
      organizations: ["enterprise-corp"]
      repositories: ["*/production-*", "*/api-*"]
      environments: ["production", "staging"]
      branches: ["main", "master", "release/*"]
      file_patterns: [".github/workflows/**"]
      
    # Rules enforced by this policy
    rules:
      - rule_id: "UNPINNED_ACTION"
        enforcement: "block"
        severity: "HIGH"
      - rule_id: "HARDCODED_SECRET"
        enforcement: "block"
        severity: "CRITICAL"
      - rule_id: "BROAD_PERMISSIONS"
        enforcement: "error"
        severity: "HIGH"
        
    # Policy exceptions
    exceptions:
      - id: "demo-exception"
        description: "Demo repositories can use unpinned actions"
        rule_id: "UNPINNED_ACTION"
        scope:
          repositories: ["*/demo-*", "*/example-*"]
        justification: "Demo repositories are not production critical"
        approver: "security-team"
        expiry_date: "2026-01-01T00:00:00Z"
        ticket_url: "https://jira.enterprise.com/SEC-123"
        
    # Compliance mapping
    compliance: ["pci-dss", "sox"]
    
    # Metadata
    metadata:
      owner: "Security Team"
      contact: "security@enterprise.com"
      created: "2025-01-01T00:00:00Z"
      updated: "2025-08-30T00:00:00Z"
      tags: ["baseline", "required"]
```

### Enforcement Levels

| Level | Description | Action |
|-------|-------------|---------|
| **block** | Blocks CI/CD pipeline | ❌ Fails build/deployment |
| **error** | Treated as error | ⚠️ Flags for immediate attention |
| **warn** | Warning only | ⚠️ Shows warning but continues |
| **disabled** | Policy disabled | ➖ No enforcement |

## Custom Rule Templates

### Template Definition
```yaml
templates:
  - id: "custom-secret-detection"
    name: "Custom Secret Detection Template"
    description: "Template for detecting organization-specific secrets"
    category: "SECRET_EXPOSURE"
    severity: "CRITICAL"
    
    # Configurable parameters
    parameters:
      secret_pattern:
        type: "string"
        description: "Regex pattern for detecting secrets"
        required: true
        validation: "^[\\w\\-\\[\\]\\(\\)\\|\\\\\\^\\$\\.\\*\\+\\?\\{\\}]+$"
      secret_name:
        type: "string"
        description: "Human-readable name for the secret type"
        required: true
      remediation_url:
        type: "string"
        description: "URL to remediation documentation"
        default: "https://security.enterprise.com/secrets"
        
    # Base rule with parameter placeholders
    base_rule:
      id: "CUSTOM_SECRET_{{secret_name}}"
      name: "{{secret_name}} Detection"
      description: "Detects {{secret_name}} in workflow files"
      severity: "CRITICAL"
      category: "SECRET_EXPOSURE"
      type: "regex"
      pattern: "{{secret_pattern}}"
      target:
        commands: true
        environment: true
      remediation: "Remove {{secret_name}} and use GitHub secrets. See: {{remediation_url}}"
      
    # Usage examples
    examples:
      - name: "AWS Access Key Detection"
        description: "Detect AWS access keys in workflows"
        parameters:
          secret_pattern: "AKIA[0-9A-Z]{16}"
          secret_name: "AWS Access Key"
          remediation_url: "https://docs.aws.amazon.com/security/"
```

### Using Templates
```yaml
custom_rules:
  # Instantiate template with specific parameters
  - template: "custom-secret-detection"
    parameters:
      secret_pattern: "(?i)(aws[_-]?access[_-]?key|aws[_-]?secret)[\\s]*[=:][\\s]*['\"]?AKIA[0-9A-Z]{16}['\"]?"
      secret_name: "Enterprise AWS Key"
      remediation_url: "https://security.enterprise.com/aws-secrets"
```

## Compliance Framework Integration

### Supported Frameworks

#### PCI DSS (Payment Card Industry)
```yaml
compliance:
  frameworks:
    - "pci-dss"
  custom_frameworks:
    pci-dss:
      id: "pci-dss"
      name: "PCI DSS v4.0"
      version: "4.0"
      controls:
        - id: "PCI-6.5.1"
          title: "Injection Flaws"
          required_rules: ["SHELL_INJECTION", "SQL_INJECTION"]
          severity: "HIGH"
        - id: "PCI-8.2.3"
          title: "Strong Authentication"
          required_rules: ["HARDCODED_SECRET", "WEAK_CREDENTIALS"]
          severity: "CRITICAL"
```

#### SOX (Sarbanes-Oxley)
```yaml
compliance:
  frameworks:
    - "sox"
  custom_frameworks:
    sox:
      id: "sox"
      name: "Sarbanes-Oxley Act"
      version: "2002"
      controls:
        - id: "SOX-404"
          title: "Internal Controls Over Financial Reporting"
          required_rules: ["BROAD_PERMISSIONS", "CHANGE_CONTROL"]
          severity: "HIGH"
```

#### NIST 800-53
```yaml
compliance:
  frameworks:
    - "nist-800-53"
  custom_frameworks:
    nist-800-53:
      id: "nist-800-53"
      name: "NIST Special Publication 800-53"
      version: "Rev. 5"
      controls:
        - id: "AC-6"
          title: "Least Privilege"
          required_rules: ["BROAD_PERMISSIONS", "EXCESSIVE_SCOPE"]
          severity: "MEDIUM"
        - id: "SC-28"
          title: "Protection of Information at Rest"
          required_rules: ["HARDCODED_SECRET", "UNENCRYPTED_DATA"]
          severity: "HIGH"
```

## Advanced Ignore Patterns

### Context-Aware Ignoring
```yaml
false_positives:
  # Global patterns applied to all rules
  global:
    patterns:
      - ".*example.*"
      - ".*test.*"
      - ".*demo.*"
      - ".*/templates/.*"
    strings:
      - "placeholder"
      - "dummy"
      - "sample"
      - "TODO"
      - "FIXME"
      
  # Secret-specific ignores with context awareness
  secrets:
    patterns:
      - ".*_test$"
      - ".*_example$"
      - ".*/test/.*"
    strings:
      - "YOUR_SECRET_HERE"
      - "changeme"
      - "example.com"
    contexts:
      - "uses:.*@[a-f0-9]{40}"   # Action SHAs
      - "\\$\\{\\{ secrets\\."   # Secret references
      - "\\$\\{\\{ env\\."       # Env references
      - "echo ['\"]\\$\\{"       # Echo with variables
      - "#.*"                    # Comments
      
  # Rule-specific exceptions
  rules:
    HARDCODED_SECRET:
      patterns:
        - ".*_test\\.yml$"
        - ".*/test/.*"
      strings:
        - "fake-token"
        - "test-secret"
      files:
        - "test/**"
        - "examples/**"
    UNPINNED_ACTION:
      actions:
        - "actions/checkout@v4"   # Allow trusted versions
        - "actions/setup-node@v4"
      patterns:
        - ".*/demo/.*"            # Demo workflows
        - ".*/examples/.*"        # Examples
```

### Environment-Specific Configuration
```yaml
false_positives:
  # Different rules for different environments
  environments:
    development:
      rules:
        UNPINNED_ACTION:
          enforcement: "warn"     # More lenient in dev
    staging:
      rules:
        HARDCODED_SECRET:
          enforcement: "error"    # Stricter in staging
    production:
      rules:
        UNPINNED_ACTION:
          enforcement: "block"    # Strictest in production
        HARDCODED_SECRET:
          enforcement: "block"
```

## Policy Inheritance

### Hierarchical Configuration
```yaml
organization:
  inheritance:
    enabled: true
    parent_configs:
      - "https://raw.githubusercontent.com/enterprise-corp/policies/main/base.yml"
      - "https://raw.githubusercontent.com/enterprise-corp/policies/main/industry.yml"
    merge_strategy: "merge"  # "override", "merge", "append"
```

### Merge Strategies

#### Override Strategy
```yaml
merge_strategy: "override"
# Child config completely replaces parent config
```

#### Merge Strategy
```yaml
merge_strategy: "merge"
# Child config merges with parent, child takes precedence
```

#### Append Strategy
```yaml
merge_strategy: "append"
# Child config appends to parent config
```

## CLI Usage

### Basic Usage
```bash
# Use enterprise configuration
flowlyt scan --repo . --config .flowlyt-enterprise.yml

# Enable policy enforcement
flowlyt scan --repo . --enable-policy-enforcement

# Generate policy compliance report
flowlyt scan --repo . --policy-report --output json
```

### Advanced Usage
```bash
# Scan with specific compliance frameworks
flowlyt scan --repo . \
  --config .flowlyt-enterprise.yml \
  --enable-policy-enforcement \
  --compliance-frameworks "pci-dss,sox" \
  --policy-report

# Organization-wide policy scanning
flowlyt analyze-org --organization enterprise-corp \
  --enable-policy-enforcement \
  --policy-config enterprise-policies.yml

# Custom policy configuration
flowlyt scan --repo . \
  --policy-config custom-policies.yml \
  --enable-policy-enforcement \
  --output sarif \
  --output-file compliance-report.sarif
```

## Configuration Validation

### Schema Validation
The configuration system includes built-in validation:

```bash
# Validate configuration file
flowlyt validate-config --config .flowlyt-enterprise.yml

# Test policy rules
flowlyt test-policies --policy-config policies.yml --test-repo test-repo/
```

### Common Validation Errors

#### Invalid Policy Scope
```yaml
# ❌ Invalid
scope:
  organizations: "enterprise-corp"  # Should be array

# ✅ Valid  
scope:
  organizations: ["enterprise-corp"]
```

#### Missing Required Fields
```yaml
# ❌ Invalid
policies:
  - name: "Test Policy"  # Missing required 'id' field

# ✅ Valid
policies:
  - id: "test-policy"
    name: "Test Policy"
```

## Best Practices

### 1. **Start Simple, Scale Up**
```yaml
# Begin with basic rules
rules:
  enabled: ["UNPINNED_ACTION", "HARDCODED_SECRET"]
  
# Gradually add custom rules and policies
```

### 2. **Use Policy Templates**
```yaml
# Create reusable templates for common patterns
templates:
  - id: "org-secret-template"
    # Template definition
    
# Instantiate multiple times with different parameters
custom_rules:
  - template: "org-secret-template"
    parameters: { secret_type: "api_key" }
  - template: "org-secret-template"
    parameters: { secret_type: "database_password" }
```

### 3. **Implement Gradual Enforcement**
```yaml
# Phase 1: Warnings only
policies:
  - id: "new-policy"
    enforcement: "warn"
    
# Phase 2: Errors (after team awareness)
# enforcement: "error"

# Phase 3: Blocking (after fixes implemented)  
# enforcement: "block"
```

### 4. **Document Exceptions**
```yaml
exceptions:
  - id: "legacy-system-exception"
    description: "Legacy system requires special handling"
    justification: "Documented technical debt, tracked in JIRA-123"
    approver: "security-architect"
    expiry_date: "2025-12-31T00:00:00Z"
    ticket_url: "https://jira.enterprise.com/TECH-123"
```

### 5. **Monitor and Iterate**
```bash
# Regular compliance reporting
flowlyt analyze-org --organization enterprise-corp \
  --enable-policy-enforcement \
  --output json \
  --output-file monthly-compliance-$(date +%Y-%m).json

# Review and adjust policies based on findings
```

## Troubleshooting

### Common Issues

#### Policy Not Applied
```bash
# Check policy scope matches your repository
flowlyt scan --repo . --config policy.yml --verbose

# Verify organization/repository naming
```

#### Template Parameter Errors
```yaml
# Ensure all required parameters are provided
parameters:
  secret_pattern: "AKIA[0-9A-Z]{16}"  # ✅ Required parameter
  # secret_name: missing              # ❌ Will cause error
```

#### Compliance Framework Issues
```bash
# Verify framework configuration
flowlyt scan --repo . \
  --compliance-frameworks "invalid-framework" # ❌ Will warn about unknown framework
```

### Debug Mode
```bash
# Enable verbose output for troubleshooting
flowlyt scan --repo . \
  --config .flowlyt-enterprise.yml \
  --enable-policy-enforcement \
  --verbose
```

## Integration Examples

### GitHub Actions
```yaml
name: Security Compliance Check
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Enterprise Security Scan
      run: |
        flowlyt scan --repo . \
          --config .flowlyt-enterprise.yml \
          --enable-policy-enforcement \
          --policy-report \
          --output sarif \
          --output-file security-compliance.sarif
          
    - name: Upload SARIF
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: security-compliance.sarif
        category: enterprise-security
```

### GitLab CI
```yaml
security_compliance:
  stage: test
  script:
    - flowlyt scan --repo . 
        --config .flowlyt-enterprise.yml 
        --enable-policy-enforcement
        --output json 
        --output-file compliance-report.json
  artifacts:
    reports:
      security: compliance-report.json
    expire_in: 1 week
```

## Resources

- **Configuration Schema**: [config-schema.json](./config-schema.json)
- **Policy Templates**: [templates/](./templates/)
- **Compliance Frameworks**: [compliance/](./compliance/)
- **Examples**: [examples/advanced-config/](./examples/advanced-config/)

## Contributing

To contribute to the advanced configuration system:

1. **Add New Templates**: Create templates in `templates/`
2. **Add Compliance Frameworks**: Define frameworks in `compliance/`
3. **Enhance Validation**: Update validation rules in `pkg/config/validation.go`
4. **Document Examples**: Add real-world examples in `examples/`
