# Custom Rules

Flowlyt's custom rules feature allows you to create organization-specific security rules tailored to your unique requirements and security policies.

## Why Custom Rules?

Custom rules enable you to:
- **Enforce organizational policies** specific to your company
- **Detect proprietary patterns** unique to your infrastructure
- **Extend built-in rules** with additional security checks
- **Customize security standards** for different teams or projects
- **Implement compliance requirements** specific to your industry

## Rule Types

### 1. Regex-Based Rules

The most common type of custom rule uses regular expressions to match patterns.

**Basic Structure:**
```yaml
# .flowlyt.yml
rules:
  custom_rules:
    - id: "RULE_ID"                    # Unique identifier
      name: "Human Readable Name"      # Display name
      description: "Detailed description of what this rule detects"
      severity: "HIGH"                 # CRITICAL, HIGH, MEDIUM, LOW, INFO
      category: "POLICY_VIOLATION"     # Categorization
      type: "regex"                    # Rule type
      pattern: "regex_pattern_here"    # Single pattern
      # OR
      patterns:                        # Multiple patterns
        - "pattern1"
        - "pattern2"
      target:                          # What to analyze
        commands: true                 # Shell commands
        actions: true                  # Action references  
        environment: true              # Environment variables
        permissions: true              # Workflow permissions
        events: true                   # Trigger events
      remediation: "How to fix this issue"
```

### 2. Script-Based Rules

For complex logic that can't be expressed with regex.

```yaml
rules:
  custom_rules:
    - id: "COMPLEX_SECURITY_CHECK"
      name: "Complex Security Validation"
      type: "script"
      script: |
        #!/bin/bash
        # Custom validation script
        # Return 0 for pass, 1 for fail
        if grep -q "dangerous_pattern" "$1"; then
          echo "Dangerous pattern detected"
          exit 1
        fi
        exit 0
      severity: "HIGH"
      remediation: "Remove dangerous patterns"
```

## Practical Examples

### Example 1: Docker Security Policy

Enforce your organization's Docker image policy.

```yaml
rules:
  custom_rules:
    - id: "COMPANY_DOCKER_POLICY"
      name: "Company Docker Image Policy"
      description: "Ensures only approved Docker images from company registry are used"
      severity: "HIGH"
      category: "POLICY_VIOLATION"
      type: "regex"
      pattern: "image:\\s*(?!company-registry\\.com/)"
      target:
        commands: true
      remediation: "Use only approved Docker images from company-registry.com"

    - id: "PROHIBITED_BASE_IMAGES"
      name: "Prohibited Base Images"
      description: "Detects usage of prohibited base images"
      severity: "CRITICAL"
      type: "regex"
      patterns:
        - "FROM\\s+ubuntu:latest"
        - "FROM\\s+alpine:latest"
        - "FROM\\s+.*:latest"
      target:
        commands: true
      remediation: "Use specific version tags instead of 'latest'"

    - id: "DOCKER_PRIVILEGED_MODE"
      name: "Docker Privileged Mode"
      description: "Detects Docker containers running in privileged mode"
      severity: "CRITICAL"
      type: "regex"
      pattern: "docker\\s+run\\s+.*--privileged"
      target:
        commands: true
      remediation: "Avoid privileged containers; use specific capabilities instead"
```

**Example workflow that would trigger these rules:**
```yaml
# ❌ This would trigger COMPANY_DOCKER_POLICY
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: nginx:latest              # ❌ Not from company registry + latest tag
    steps:
      - run: |
          docker run --privileged ubuntu:latest  # ❌ Multiple violations
```

**Compliant workflow:**
```yaml
# ✅ This passes all rules
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: company-registry.com/nginx:1.21.6@sha256:abc123...
    steps:
      - run: |
          docker run --cap-add=NET_ADMIN company-registry.com/app:v1.2.3
```

### Example 2: Cloud Provider Restrictions

Restrict which cloud providers can be used.

```yaml
rules:
  custom_rules:
    - id: "APPROVED_CLOUD_PROVIDERS"
      name: "Approved Cloud Providers Only"
      description: "Ensures only approved cloud providers are used"
      severity: "HIGH"
      type: "regex"
      patterns:
        - "aws\\s+(?!configure)"        # AWS CLI (except configure)
        - "gcloud\\s+"                  # Google Cloud CLI
        - "az\\s+"                      # Azure CLI (if not approved)
      target:
        commands: true
      remediation: "Use only approved cloud providers: AWS and GCP"

    - id: "CLOUD_CREDENTIALS_CHECK"
      name: "Cloud Credentials Security"
      description: "Detects hardcoded cloud credentials"
      severity: "CRITICAL"
      type: "regex"
      patterns:
        - "AWS_ACCESS_KEY_ID\\s*=\\s*['\"]?AKIA[A-Z0-9]{16}['\"]?"
        - "GOOGLE_APPLICATION_CREDENTIALS\\s*=.*\\.json"
      target:
        environment: true
        commands: true
      remediation: "Use secure credential management (GitHub Secrets, OIDC)"
```

### Example 3: Security Tool Compliance

Mandate specific security scanning tools.

```yaml
rules:
  custom_rules:
    - id: "REQUIRED_SECURITY_SCAN"
      name: "Required Security Scanning"
      description: "Ensures security scanning is performed in deployment workflows"
      severity: "HIGH"
      type: "regex"
      pattern: "(snyk|semgrep|codeql|trivy)\\s+"
      target:
        commands: true
        actions: true
      remediation: "Add required security scanning step"

    - id: "PROHIBITED_SECURITY_TOOLS"
      name: "Prohibited Security Tools"
      description: "Detects usage of prohibited security tools"
      severity: "MEDIUM"
      type: "regex"
      patterns:
        - "nmap\\s+"                    # Network scanning
        - "sqlmap\\s+"                  # SQL injection testing
        - "metasploit"                  # Penetration testing
      target:
        commands: true
      remediation: "Use approved security scanning tools only"
```

### Example 4: Deployment Approval Process

Ensure proper approval process for production deployments.

```yaml
rules:
  custom_rules:
    - id: "PRODUCTION_DEPLOYMENT_APPROVAL"
      name: "Production Deployment Requires Approval"
      description: "Production deployments must require manual approval"
      severity: "HIGH"
      type: "regex"
      pattern: "environment:\\s*production"
      target:
        environment: true
      remediation: "Add 'required_reviewers' or 'wait_timer' to production environment"

    - id: "DEPLOYMENT_BRANCHES"
      name: "Deployment Branch Restrictions"
      description: "Deployments should only occur from specific branches"
      severity: "MEDIUM"
      type: "regex"
      pattern: "if:\\s*github\\.ref\\s*==\\s*['\"]refs/heads/(?!main|release/)"
      target:
        commands: true
      remediation: "Deploy only from main or release branches"
```

## Advanced Rule Features

### Multi-Pattern Rules

Combine multiple patterns for comprehensive detection:

```yaml
rules:
  custom_rules:
    - id: "COMPREHENSIVE_SECRET_CHECK"
      name: "Comprehensive Secret Detection"
      description: "Detects multiple types of secrets and credentials"
      severity: "CRITICAL"
      type: "regex"
      patterns:
        - "password\\s*[=:]\\s*['\"][^'\"]{8,}['\"]"       # Password assignments
        - "secret\\s*[=:]\\s*['\"][^'\"]{16,}['\"]"        # Secret assignments
        - "token\\s*[=:]\\s*['\"][^'\"]{20,}['\"]"         # Token assignments
        - "key\\s*[=:]\\s*['\"][A-Za-z0-9+/=]{24,}['\"]"   # Base64-like keys
      target:
        environment: true
        commands: true
      remediation: "Use proper secret management instead of hardcoded values"
```

### Context-Aware Rules

Rules that consider the context of the match:

```yaml
rules:
  custom_rules:
    - id: "CONTEXT_AWARE_SECRET"
      name: "Context-Aware Secret Detection"
      description: "Detects secrets while considering context"
      severity: "HIGH"
      type: "regex"
      pattern: "(?<!#\\s*)(?<!example[_-])(?<!test[_-])api[_-]?key\\s*[=:]\\s*['\"][^'\"]{16,}['\"]"
      target:
        environment: true
        commands: true
      remediation: "Use GitHub secrets for API keys"
      # This pattern excludes:
      # - Comments (# api_key=...)
      # - Example values (example_api_key=...)
      # - Test values (test_api_key=...)
```

### File-Specific Rules

Apply rules only to specific file types or paths:

```yaml
rules:
  custom_rules:
    - id: "DOCKERFILE_SECURITY"
      name: "Dockerfile Security Checks"
      description: "Security checks specific to Dockerfiles"
      severity: "MEDIUM"
      type: "regex"
      patterns:
        - "ADD\\s+https?://"            # Remote ADD commands
        - "RUN\\s+.*\\|\\s*bash"        # Piped bash commands
        - "USER\\s+root"                # Running as root
      target:
        commands: true
      file_patterns:
        - "**/Dockerfile*"
        - "**/*.dockerfile"
      remediation: "Follow Docker security best practices"
```

## Testing Custom Rules

### Local Testing

Test your custom rules before deployment:

```bash
# Test specific rule file
flowlyt --config custom-rules.yml --workflow test-workflow.yml

# Test against sample repository
flowlyt --config custom-rules.yml --repo ./test-repo
```

### Rule Development Workflow

1. **Create test cases:**
```yaml
# test-workflow.yml
name: Test Workflow
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: nginx:latest              # Should trigger rule
    steps:
      - run: docker run --privileged ubuntu  # Should trigger rule
```

2. **Define the rule:**
```yaml
# custom-rules.yml
rules:
  custom_rules:
    - id: "TEST_RULE"
      # ... rule definition
```

3. **Test and iterate:**
```bash
flowlyt --config custom-rules.yml --workflow test-workflow.yml
```

### Validation Script

Create a validation script to test all your custom rules:

```bash
#!/bin/bash
# validate-rules.sh

echo "Testing custom rules..."

# Test positive cases (should trigger)
for test_file in tests/positive/*.yml; do
  echo "Testing $test_file (should find issues)..."
  if ! flowlyt --config custom-rules.yml --workflow "$test_file" | grep -q "CRITICAL\|HIGH"; then
    echo "❌ Expected to find issues in $test_file"
    exit 1
  fi
done

# Test negative cases (should pass)
for test_file in tests/negative/*.yml; do
  echo "Testing $test_file (should pass)..."
  if flowlyt --config custom-rules.yml --workflow "$test_file" | grep -q "CRITICAL\|HIGH"; then
    echo "❌ Unexpected issues found in $test_file"
    exit 1
  fi
done

echo "✅ All tests passed!"
```

## Rule Organization

### Team-Specific Rules

Organize rules by team or project:

```yaml
# .flowlyt.frontend.yml
rules:
  custom_rules:
    - id: "FRONTEND_SECURITY"
      name: "Frontend Security Checks"
      patterns:
        - "npm\\s+install\\s+.*--unsafe-perm"
        - "yarn\\s+add\\s+.*@latest"
      target:
        commands: true
      remediation: "Use specific versions and avoid unsafe permissions"

# .flowlyt.backend.yml  
rules:
  custom_rules:
    - id: "BACKEND_SECURITY"
      name: "Backend Security Checks"
      patterns:
        - "go\\s+get\\s+.*@master"
        - "pip\\s+install\\s+.*--trusted-host"
      target:
        commands: true
      remediation: "Use pinned versions and trusted repositories"
```

### Environment-Specific Rules

Different rules for different environments:

```yaml
# .flowlyt.production.yml
rules:
  custom_rules:
    - id: "PROD_DEPLOYMENT_SECURITY"
      name: "Production Deployment Security"
      severity: "CRITICAL"
      patterns:
        - "kubectl\\s+apply\\s+.*--validate=false"
        - "helm\\s+install\\s+.*--skip-tls-verify"
      target:
        commands: true
      remediation: "Never skip validation or TLS verification in production"

# .flowlyt.development.yml
rules:
  custom_rules:
    - id: "DEV_BEST_PRACTICES"
      name: "Development Best Practices"
      severity: "LOW"
      patterns:
        - "console\\.log\\("          # Debug statements
        - "debugger;"                 # Debug breakpoints
      target:
        commands: true
      remediation: "Remove debug statements before merging"
```

## Integration with CI/CD

### GitHub Actions Integration

```yaml
name: Custom Security Rules
on: [push, pull_request]

jobs:
  custom-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Flowlyt
        run: GOPRIVATE=github.com/harekrishnarai/flowlyt go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
      - name: Run Custom Security Rules
        run: |
          flowlyt --config .flowlyt.custom.yml \
                  --repo . \
                  --min-severity HIGH \
                  --output json \
                  --output-file custom-security-report.json
      - name: Check Results
        run: |
          if [ -s custom-security-report.json ]; then
            echo "Custom security violations found!"
            cat custom-security-report.json
            exit 1
          fi
```

### GitLab CI Integration

```yaml
# .gitlab-ci.yml
custom_security_scan:
  stage: test
  image: golang:latest
  script:
    - GOPRIVATE=github.com/harekrishnarai/flowlyt go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
    - flowlyt --config .flowlyt.custom.yml --platform gitlab --repo . --output json --output-file custom-report.json
  artifacts:
    reports:
      junit: custom-report.json
    when: always
  rules:
    - if: $CI_MERGE_REQUEST_ID
    - if: $CI_COMMIT_BRANCH == "main"
```

## Best Practices

### 1. Rule Design Principles

**Be Specific:**
```yaml
# ❌ Too broad
pattern: "password"

# ✅ More specific
pattern: "password\\s*[=:]\\s*['\"][^'\"]{8,}['\"]"
```

**Minimize False Positives:**
```yaml
# Include context to reduce false positives
pattern: "(?<!#\\s*)(?<!example[_-])api[_-]?key\\s*[=:]\\s*['\"][^'\"]{16,}['\"]"
```

**Provide Clear Remediation:**
```yaml
remediation: |
  Replace hardcoded API keys with GitHub secrets:
  1. Add the key to repository secrets
  2. Reference it as ${{ secrets.API_KEY }}
  3. Remove the hardcoded value
```

### 2. Rule Maintenance

**Version Control:**
- Keep custom rules in version control
- Use meaningful commit messages for rule changes
- Tag rule versions for rollback capability

**Documentation:**
```yaml
# Document complex rules
- id: "COMPLEX_RULE"
  name: "Complex Security Pattern"
  description: |
    This rule detects a specific security anti-pattern where:
    1. Docker containers are run with elevated privileges
    2. Network access is unrestricted  
    3. Volume mounts include sensitive paths
    
    This combination creates a significant security risk because...
```

**Testing:**
- Create comprehensive test cases
- Test against real workflows
- Validate before deploying organization-wide

### 3. Performance Considerations

**Optimize Patterns:**
```yaml
# ❌ Inefficient pattern
pattern: ".*password.*=.*"

# ✅ More efficient pattern  
pattern: "password\\s*[=:]\\s*['\"][^'\"]+['\"]"
```

**Target Appropriately:**
```yaml
# Only target relevant sections
target:
  commands: true        # Enable if checking shell commands
  actions: false        # Disable if not checking actions
  environment: true     # Enable if checking env vars
```

## Troubleshooting

### Common Issues

**Rule Not Triggering:**
1. Check pattern syntax with online regex testers
2. Verify target configuration
3. Test with simple test cases
4. Enable debug output

**Too Many False Positives:**
1. Add negative lookaheads for common false positives
2. Be more specific with patterns
3. Use context-aware matching
4. Add appropriate ignore patterns

**Performance Issues:**
1. Optimize regex patterns
2. Limit target scope
3. Use more specific file patterns
4. Consider rule complexity

---

**Next:** [Configuration Management](configuration.md)
