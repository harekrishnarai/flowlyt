# Shell Analysis

Flowlyt includes comprehensive shell command analysis capabilities to detect dangerous command patterns, command injection vulnerabilities, and insecure scripting practices in CI/CD workflows.

## Overview

Shell analysis is critical for CI/CD security because workflows often execute shell commands that can be exploited by attackers. Flowlyt analyzes shell commands in various contexts:

- Direct `run` commands in workflows
- Shell scripts referenced in workflows
- Environment variable usage in commands
- Command substitution and piping patterns
- Dynamic command construction

## Dangerous Command Patterns

### 1. Remote Script Execution

**Direct Pipe to Shell:**
```yaml
# ❌ DANGEROUS: Pipes remote content directly to shell
- name: Install dependencies
  run: curl -s https://get.example.com/install.sh | bash

# ❌ DANGEROUS: Alternative piping methods
- name: Setup environment
  run: wget -O- https://setup.example.com/install | sh

# ❌ DANGEROUS: Using eval with remote content
- name: Configure system
  run: eval "$(curl -s https://config.example.com/setup)"
```

**Why this is dangerous:**
- No verification of script content
- Susceptible to man-in-the-middle attacks
- Allows arbitrary code execution
- No integrity checking

**Secure alternatives:**
```yaml
# ✅ SECURE: Download, verify, then execute
- name: Install dependencies securely
  run: |
    curl -s https://get.example.com/install.sh > install.sh
    echo "expected_sha256_hash install.sh" | sha256sum -c
    bash install.sh

# ✅ SECURE: Use official actions when available
- name: Setup Node.js
  uses: actions/setup-node@v4
  with:
    node-version: '18'

# ✅ SECURE: Pin to specific versions
- name: Install using package manager
  run: |
    npm install -g some-package@1.2.3
```

### 2. Command Injection Vulnerabilities

**Dynamic Command Construction:**
```yaml
# ❌ DANGEROUS: Unvalidated input in commands
- name: Process user input
  run: |
    USER_INPUT="${{ github.event.inputs.command }}"
    eval "$USER_INPUT"

# ❌ DANGEROUS: Environment variable in command
- name: Deploy to environment
  run: |
    ENVIRONMENT="${{ github.event.inputs.environment }}"
    ssh deploy@server "cd /app && git checkout $ENVIRONMENT"

# ❌ DANGEROUS: Filename injection
- name: Process files
  run: |
    FILE_NAME="${{ github.event.inputs.filename }}"
    cat "$FILE_NAME" | grep "pattern"
```

**Why this is dangerous:**
- Allows injection of arbitrary commands
- Can bypass access controls
- Enables privilege escalation
- Can access sensitive data

**Secure alternatives:**
```yaml
# ✅ SECURE: Input validation and sanitization
- name: Process validated input
  run: |
    USER_INPUT="${{ github.event.inputs.command }}"
    # Validate input against whitelist
    case "$USER_INPUT" in
      "deploy"|"test"|"build")
        echo "Valid command: $USER_INPUT"
        ;;
      *)
        echo "Invalid command" >&2
        exit 1
        ;;
    esac

# ✅ SECURE: Use parameterized commands
- name: Deploy securely
  run: |
    if [[ "${{ github.event.inputs.environment }}" =~ ^[a-zA-Z0-9_-]+$ ]]; then
      ssh deploy@server "./deploy.sh '${{ github.event.inputs.environment }}'"
    else
      echo "Invalid environment name" >&2
      exit 1
    fi

# ✅ SECURE: Proper quoting and validation
- name: Process files securely
  run: |
    FILE_NAME="${{ github.event.inputs.filename }}"
    # Validate filename
    if [[ "$FILE_NAME" =~ ^[a-zA-Z0-9._/-]+$ ]] && [[ -f "$FILE_NAME" ]]; then
      grep "pattern" "$FILE_NAME"
    else
      echo "Invalid or non-existent file" >&2
      exit 1
    fi
```

### 3. Privilege Escalation Patterns

**Dangerous Privilege Usage:**
```yaml
# ❌ DANGEROUS: Running as root unnecessarily
- name: Install packages
  run: |
    sudo apt-get update
    sudo apt-get install -y some-package
    sudo chmod 777 /tmp/app-data

# ❌ DANGEROUS: Modifying system files
- name: Configure system
  run: |
    echo "dangerous setting" | sudo tee -a /etc/hosts
    sudo chown -R root:root /app

# ❌ DANGEROUS: Disabling security features
- name: Setup environment
  run: |
    sudo setenforce 0  # Disable SELinux
    sudo ufw disable   # Disable firewall
```

**Secure alternatives:**
```yaml
# ✅ SECURE: Use non-root installation methods
- name: Install packages securely
  run: |
    # Use package manager without sudo when possible
    npm install some-package
    # Or use containerized approach

# ✅ SECURE: Minimal privilege usage
- name: Configure application
  run: |
    # Work in user space
    mkdir -p ~/.local/app-config
    echo "setting=value" > ~/.local/app-config/config

# ✅ SECURE: Explicit permission management
- name: Setup with minimal privileges
  run: |
    # Only modify what's necessary
    chmod 755 ./scripts/deploy.sh
    # Use application-specific directories
```

## Shell Analysis Rules

### Built-in Rules

#### DANGEROUS_COMMAND
**Description:** Detects potentially dangerous shell command patterns

**Patterns detected:**
- `curl ... | bash`
- `wget ... | sh`
- `eval "$(curl ...)"`
- `rm -rf /`
- `chmod 777`
- `> /dev/null 2>&1` (suspicious output hiding)

**Example detection:**
```yaml
# This will trigger DANGEROUS_COMMAND
- name: Quick setup
  run: curl -s setup.sh | bash  # Flagged as dangerous
```

#### COMMAND_INJECTION
**Description:** Identifies potential command injection vulnerabilities

**Patterns detected:**
- Unquoted variables in commands
- Dynamic command construction
- User input in `eval` statements
- Unsafe environment variable usage

**Example detection:**
```yaml
# This will trigger COMMAND_INJECTION
- name: Deploy
  run: |
    ENV=${{ github.event.inputs.environment }}
    ssh server "cd /app && deploy.sh $ENV"  # Unquoted variable
```

#### PRIVILEGE_ESCALATION
**Description:** Flags unnecessary privilege escalation

**Patterns detected:**
- Unnecessary `sudo` usage
- Running as root
- Modifying system files
- Disabling security features

**Example detection:**
```yaml
# This will trigger PRIVILEGE_ESCALATION
- name: Install
  run: sudo chmod 777 /app  # Excessive permissions
```

### Custom Shell Analysis Rules

Create custom rules for organization-specific patterns:

```yaml
# .flowlyt.yml
custom_rules:
  - id: "COMPANY_DANGEROUS_COMMANDS"
    name: "Company-specific dangerous commands"
    description: "Commands banned by company security policy"
    category: "SHELL_ANALYSIS"
    severity: "HIGH"
    patterns:
      - "internal-tool --unsafe-mode"
      - "legacy-script.sh"
      - "debug-enable-all"
    remediation: "Use approved alternatives from security documentation"
    
  - id: "PRODUCTION_SHELL_RESTRICTIONS"
    name: "Production shell restrictions"
    description: "Shell patterns not allowed in production workflows"
    category: "SHELL_ANALYSIS"
    severity: "CRITICAL"
    apply_to:
      environments: ["production"]
    patterns:
      - "rm -f .*"
      - "dd if=/dev/.*"
      - "mkfs\\..*"
    remediation: "Production deployments should not use destructive commands"
```

## Advanced Shell Analysis

### 1. Context-Aware Analysis

Flowlyt analyzes shell commands in context:

**Environment-Specific Analysis:**
```yaml
# Development environment - more lenient
name: Development Build
on:
  push:
    branches: [develop]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # This might be allowed in development
      - run: curl -s dev-tools.internal/setup.sh | bash
```

```yaml
# Production environment - strict analysis
name: Production Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      # This would be flagged as critical in production
      - run: curl -s setup.sh | bash  # CRITICAL in production context
```

### 2. Multi-Step Command Analysis

Analyze complex multi-step shell operations:

```yaml
- name: Complex deployment script
  run: |
    # Flowlyt analyzes the entire script block
    
    # Step 1: Download (analyzed for dangerous patterns)
    curl -L https://releases.example.com/v1.0.0/app.tar.gz > app.tar.gz
    
    # Step 2: Verify (security best practice - good)
    echo "expected_hash app.tar.gz" | sha256sum -c
    
    # Step 3: Extract (analyzed for path traversal)
    tar -xzf app.tar.gz --strip-components=1
    
    # Step 4: Execute (analyzed for dangerous execution)
    chmod +x ./install.sh && ./install.sh  # Potential issue flagged
```

### 3. Variable Tracking

Track variable usage through shell scripts:

```yaml
- name: Variable tracking example
  env:
    USER_INPUT: ${{ github.event.inputs.command }}
    SAFE_VAR: "predefined-value"
  run: |
    # Flowlyt tracks variable origins and usage
    
    DANGEROUS_VAR="$USER_INPUT"  # Marked as potentially dangerous
    SAFE_COMMAND="echo"
    
    # This would be flagged as dangerous due to variable tracking
    $DANGEROUS_VAR  # User input executed as command
    
    # This would be considered safer
    $SAFE_COMMAND "$DANGEROUS_VAR"  # User input as argument, not command
```

## Shell Security Best Practices

### 1. Input Validation

Always validate and sanitize input:

```bash
#!/bin/bash
# validate-input.sh

validate_environment() {
    local env="$1"
    case "$env" in
        "development"|"staging"|"production")
            echo "Valid environment: $env"
            return 0
            ;;
        *)
            echo "Invalid environment: $env" >&2
            return 1
            ;;
    esac
}

validate_filename() {
    local filename="$1"
    # Only allow alphanumeric, dots, hyphens, underscores
    if [[ "$filename" =~ ^[a-zA-Z0-9._-]+$ ]]; then
        return 0
    else
        echo "Invalid filename: $filename" >&2
        return 1
    fi
}

# Usage
ENVIRONMENT="${{ github.event.inputs.environment }}"
if validate_environment "$ENVIRONMENT"; then
    echo "Deploying to $ENVIRONMENT"
else
    exit 1
fi
```

### 2. Secure Command Construction

Build commands safely:

```bash
#!/bin/bash
# secure-commands.sh

# ❌ DANGEROUS: Dynamic command construction
user_command="${{ github.event.inputs.command }}"
eval "$user_command"

# ✅ SECURE: Predefined command with validated parameters
case "${{ github.event.inputs.action }}" in
    "deploy")
        ./deploy.sh "${{ github.event.inputs.environment }}"
        ;;
    "test")
        ./run-tests.sh "${{ github.event.inputs.test_suite }}"
        ;;
    "build")
        ./build.sh "${{ github.event.inputs.build_type }}"
        ;;
    *)
        echo "Unknown action" >&2
        exit 1
        ;;
esac
```

### 3. Proper Quoting

Use proper quoting to prevent injection:

```bash
#!/bin/bash
# proper-quoting.sh

# ❌ DANGEROUS: Unquoted variables
file_name=${{ github.event.inputs.filename }}
grep pattern $file_name  # Vulnerable to injection

# ✅ SECURE: Properly quoted variables
file_name="${{ github.event.inputs.filename }}"
grep pattern "$file_name"  # Safe from injection

# ✅ SECURE: Array usage for complex commands
declare -a safe_args=(
    "--config"
    "${CONFIG_FILE}"
    "--environment"
    "${ENVIRONMENT}"
)
./app "${safe_args[@]}"
```

### 4. Error Handling

Implement proper error handling:

```bash
#!/bin/bash
# error-handling.sh

set -euo pipefail  # Exit on error, undefined vars, pipe failures

cleanup() {
    echo "Cleaning up temporary files..."
    rm -f /tmp/deployment-*
}

trap cleanup EXIT

download_and_verify() {
    local url="$1"
    local expected_hash="$2"
    local output_file="$3"
    
    # Download
    if ! curl -L "$url" -o "$output_file"; then
        echo "Failed to download from $url" >&2
        return 1
    fi
    
    # Verify
    if ! echo "$expected_hash $output_file" | sha256sum -c; then
        echo "Hash verification failed" >&2
        return 1
    fi
    
    echo "Successfully downloaded and verified $output_file"
}
```

## Configuration Examples

### Environment-Specific Shell Analysis

```yaml
# .flowlyt.yml
shell_analysis:
  environments:
    development:
      rules:
        - "DANGEROUS_COMMAND"      # Warn but don't fail
        - "COMMAND_INJECTION"
      severity_override:
        "DANGEROUS_COMMAND": "MEDIUM"  # Reduce severity in dev
        
    staging:
      rules:
        - "DANGEROUS_COMMAND"
        - "COMMAND_INJECTION"
        - "PRIVILEGE_ESCALATION"
      severity_override:
        "DANGEROUS_COMMAND": "HIGH"
        
    production:
      rules:
        - "DANGEROUS_COMMAND"
        - "COMMAND_INJECTION"
        - "PRIVILEGE_ESCALATION"
        - "PRODUCTION_SHELL_RESTRICTIONS"
      severity_override:
        "DANGEROUS_COMMAND": "CRITICAL"  # Maximum severity in prod
```

### Custom Shell Patterns

```yaml
# .flowlyt.yml
custom_shell_patterns:
  organization_patterns:
    - id: "INTERNAL_TOOL_MISUSE"
      name: "Internal tool misuse"
      patterns:
        - "internal-cli --debug.*--production"
        - "admin-tool --bypass-security"
      severity: "HIGH"
      
    - id: "DEPRECATED_COMMANDS"
      name: "Deprecated command usage"
      patterns:
        - "legacy-deploy\\.sh"
        - "old-backup-script"
      severity: "MEDIUM"
      remediation: "Use new deployment system: docs/new-deployment.md"
      
  security_patterns:
    - id: "CRYPTO_MISUSE"
      name: "Cryptographic operation misuse"
      patterns:
        - "openssl.*-noout.*-verify"
        - "gpg.*--trust-model.*always"
      severity: "HIGH"
      remediation: "Use secure cryptographic practices"
```

### Shell Analysis Reporting

Generate shell-specific security reports:

```bash
#!/bin/bash
# shell-security-report.sh

echo "Shell Security Analysis Report"
echo "============================="

# Analyze shell patterns in workflows
flowlyt --repo . \
        --output json \
        --filter-category "SHELL_ANALYSIS" > shell-findings.json

# Extract shell-specific statistics
echo "Shell Security Summary:"
echo "- Dangerous Commands: $(jq '[.findings[] | select(.rule_id == "DANGEROUS_COMMAND")] | length' shell-findings.json)"
echo "- Command Injections: $(jq '[.findings[] | select(.rule_id == "COMMAND_INJECTION")] | length' shell-findings.json)"
echo "- Privilege Escalations: $(jq '[.findings[] | select(.rule_id == "PRIVILEGE_ESCALATION")] | length' shell-findings.json)"

# Generate remediation summary
echo -e "\nTop Shell Security Issues:"
jq -r '.findings[] | 
       select(.category == "SHELL_ANALYSIS") | 
       "\(.severity): \(.rule_name) in \(.file_path):\(.line_number)"' \
   shell-findings.json | sort | uniq -c | sort -nr | head -10
```

---

**Next:** [Policy Enforcement](policy-enforcement.md)
