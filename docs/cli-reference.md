# Command Line Interface Reference

Complete reference for Flowlyt's command-line interface, including all commands, flags, and usage examples.

## Commands Overview

| Command | Description | Example |
|---------|-------------|---------|
| `scan` | Scan repository or workflow files | `flowlyt scan ./my-repo` |
| `analyze-org` | Analyze all repositories in an organization | `flowlyt analyze-org --organization mycompany` |

## analyze-org Command

Analyze all repositories in a GitHub organization for security issues.

### Usage
```bash
flowlyt analyze-org --organization ORGNAME [options]
```

### Required Flags
- `--organization`, `-o` - GitHub organization name to analyze

### Optional Flags
- `--token`, `-t` - GitHub personal access token (optional - will auto-detect from gh CLI or GITHUB_TOKEN)
- `--output-format`, `-f` - Output format: cli, json, markdown (default: "cli")
- `--output-file`, `--out` - Output file path (default: stdout)
- `--config`, `--cfg` - Configuration file path
- `--min-severity` - Minimum severity level: INFO, LOW, MEDIUM, HIGH, CRITICAL (default: "LOW")
- `--max-repos` - Maximum number of repositories to analyze (default: 100)
- `--repo-filter` - Regular expression to filter repository names
- `--include-forks` - Include forked repositories (default: false)
- `--include-archived` - Include archived repositories (default: false)
- `--include-private` - Include private repositories (default: true)
- `--include-public` - Include public repositories (default: true)
- `--max-workers` - Maximum concurrent workers (default: CPU count)
- `--no-progress` - Disable progress reporting
- `--summary-only` - Show only organization summary

### Examples

```bash
# Basic organization analysis
flowlyt analyze-org --organization mycompany

# Analysis with custom filtering
flowlyt analyze-org --organization mycompany --repo-filter "^api-.*" --include-forks

# Output to SARIF file
flowlyt analyze-org --organization mycompany --output-format sarif --output-file results.sarif

# High severity findings only
flowlyt analyze-org --organization mycompany --min-severity HIGH --summary-only

# Using short flags
flowlyt analyze-org -o mycompany -f json

# With explicit token (optional if gh CLI is authenticated)
flowlyt analyze-org -o mycompany --token YOUR_GITHUB_TOKEN
```

## scan Command

Scan repository or workflow files for security issues.

### Usage

```bash
# GitHub repository
flowlyt --url https://github.com/user/repository

# GitLab repository
flowlyt --url https://gitlab.com/user/repository

# GitHub repository with specific branch
flowlyt --url https://github.com/user/repository/tree/main
```

#### `--workflow`, `-w`
Scan a specific workflow file instead of the entire repository.

```bash
# GitHub Actions workflow
flowlyt --workflow .github/workflows/ci.yml

# GitLab CI pipeline
flowlyt --workflow .gitlab-ci.yml

# Custom named workflow
flowlyt --workflow .github/workflows/custom-security.yml
```

### Platform Options

#### `--platform`, `--pl`
Specify the CI/CD platform (default: `github`).

**Supported values:** `github`, `gitlab`, `jenkins` (planned), `azure` (planned)

```bash
# GitHub Actions (default)
flowlyt --platform github --repo .

# GitLab CI/CD
flowlyt --platform gitlab --repo .

# Auto-detect from repository structure
flowlyt --repo .  # Detects platform automatically
```

#### `--gitlab-instance`
Specify GitLab instance URL for on-premise GitLab installations.

```bash
# On-premise GitLab
flowlyt --platform gitlab \
        --gitlab-instance https://gitlab.company.com \
        --repo ./project

# GitLab.com (default, no need to specify)
flowlyt --platform gitlab --repo ./project
```

### Output Options

#### `--output`, `-o`
Specify output format.

**Supported values:** `cli` (default), `json`, `markdown`

```bash
# CLI output (default, human-readable)
flowlyt --output cli --repo .

# JSON output (machine-readable)
flowlyt --output json --repo .

# Markdown output (for documentation)
flowlyt --output markdown --repo .
```

#### `--output-file`, `-f`
Specify output file path. If not provided, outputs to stdout.

```bash
# Save to file
flowlyt --output json --output-file security-report.json --repo .

# Save markdown report
flowlyt --output markdown --output-file security-report.md --repo .

# Output to stdout (default)
flowlyt --output json --repo .
```

### Configuration Options

#### `--config`, `--cfg`
Specify path to configuration file (default: `.flowlyt.yml`).

```bash
# Use default configuration
flowlyt --repo .

# Use custom configuration file
flowlyt --config custom-config.yml --repo .

# Use configuration from different directory
flowlyt --config /path/to/.flowlyt.yml --repo .
```

#### `--policy`, `-p`
Specify custom policy file or directory for OPA policies.

```bash
# Single policy file
flowlyt --policy ./policies/custom.rego --repo .

# Policy directory
flowlyt --policy ./policies/ --repo .

# Multiple policy paths
flowlyt --policy policy1.rego --policy policy2.rego --repo .
```

### Rule Management Options

#### `--enable-rules`, `--enable`
Enable specific rules (comma-separated). Can be used multiple times.

```bash
# Enable specific rules
flowlyt --enable-rules HARDCODED_SECRET,MALICIOUS_BASE64_DECODE --repo .

# Enable single rule
flowlyt --enable-rules INSECURE_PULL_REQUEST_TARGET --repo .

# Multiple --enable-rules flags
flowlyt --enable-rules HARDCODED_SECRET \
        --enable-rules DANGEROUS_COMMAND \
        --repo .
```

#### `--disable-rules`, `--disable`
Disable specific rules (comma-separated). Can be used multiple times.

```bash
# Disable specific rules
flowlyt --disable-rules UNPINNED_ACTION,CONTINUE_ON_ERROR_CRITICAL_JOB --repo .

# Disable single rule
flowlyt --disable-rules UNPINNED_ACTION --repo .

# Multiple --disable-rules flags
flowlyt --disable-rules UNPINNED_ACTION \
        --disable-rules CONTINUE_ON_ERROR_CRITICAL_JOB \
        --repo .
```

#### `--no-default-rules`
Disable all default security rules. Use with `--enable-rules` to run only specific rules.

```bash
# Run only specific rules
flowlyt --no-default-rules \
        --enable-rules HARDCODED_SECRET,DANGEROUS_COMMAND \
        --repo .

# Custom rules only (with configuration file)
flowlyt --no-default-rules --config custom-rules-only.yml --repo .
```

### Filtering Options

#### `--min-severity`
Specify minimum severity level to report.

**Supported values:** `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` (default: `LOW`)

```bash
# Show only critical issues
flowlyt --min-severity CRITICAL --repo .

# Show high and critical issues
flowlyt --min-severity HIGH --repo .

# Show all issues (default)
flowlyt --min-severity LOW --repo .
```

#### `--entropy-threshold`
Set entropy threshold for secret detection (default: `4.5`).

```bash
# More sensitive (more potential false positives)
flowlyt --entropy-threshold 3.5 --repo .

# Less sensitive (fewer false positives)
flowlyt --entropy-threshold 6.0 --repo .

# Default threshold
flowlyt --entropy-threshold 4.5 --repo .
```

### AI Integration Options

Flowlyt can integrate with AI providers to analyze security findings and help distinguish between false positives and true positives.

#### `--ai`
Specify AI provider for finding verification.

**Supported providers:** `openai`, `gemini`, `claude`, `grok`

```bash
# Use OpenAI for analysis
flowlyt --ai openai --ai-key your-openai-key --repo .

# Use Google Gemini
flowlyt --ai gemini --ai-key your-gemini-key --repo .

# Use Anthropic Claude
flowlyt --ai claude --ai-key your-claude-key --repo .

# Use xAI Grok
flowlyt --ai grok --ai-key your-grok-key --repo .
```

#### `--ai-key`
API key for the AI provider. Can also be set via `AI_API_KEY` environment variable.

```bash
# Using CLI flag
flowlyt --ai openai --ai-key sk-1234567890abcdef --repo .

# Using environment variable
export AI_API_KEY=sk-1234567890abcdef
flowlyt --ai openai --repo .
```

#### `--ai-model`
Specify a specific AI model to use (optional, uses provider default).

```bash
# OpenAI specific model
flowlyt --ai openai --ai-key your-key --ai-model gpt-4 --repo .

# Gemini specific model
flowlyt --ai gemini --ai-key your-key --ai-model gemini-1.5-pro --repo .

# Claude specific model
flowlyt --ai claude --ai-key your-key --ai-model claude-3-opus-20240229 --repo .
```

#### `--ai-base-url`
Custom base URL for AI provider (useful for self-hosted models).

```bash
# Self-hosted OpenAI-compatible endpoint
flowlyt --ai openai --ai-key your-key \
        --ai-base-url https://your-server.com/v1 \
        --repo .

# Azure OpenAI endpoint
flowlyt --ai openai --ai-key your-key \
        --ai-base-url https://your-resource.openai.azure.com/openai/deployments/your-deployment \
        --repo .
```

#### `--ai-timeout`
Timeout for AI analysis in seconds (default: 30).

```bash
# Faster timeout for quick analysis
flowlyt --ai openai --ai-key your-key --ai-timeout 10 --repo .

# Longer timeout for complex analysis
flowlyt --ai openai --ai-key your-key --ai-timeout 60 --repo .
```

#### `--ai-workers`
Number of concurrent AI analysis workers (default: 5).

```bash
# More concurrent workers for faster analysis
flowlyt --ai openai --ai-key your-key --ai-workers 10 --repo .

# Fewer workers to respect rate limits
flowlyt --ai openai --ai-key your-key --ai-workers 2 --repo .
```

### Utility Options

#### `--temp-dir`
Specify temporary directory for repository clones when using `--url`.

```bash
# Custom temp directory
flowlyt --url https://github.com/user/repo --temp-dir /tmp/flowlyt-scans

# Default temp directory (system temp)
flowlyt --url https://github.com/user/repo
```

#### `--help`, `-h`
Show help information.

```bash
# General help
flowlyt --help

# Command-specific help
flowlyt init-policy --help
```

#### `--version`, `-v`
Show version information.

```bash
flowlyt --version
# Output: flowlyt version 0.0.1
```

## Commands

### `init-policy`
Create an example OPA policy file.

**Usage:**
```bash
flowlyt init-policy [output-path]
```

**Examples:**
```bash
# Create in default location
flowlyt init-policy

# Create at specific path
flowlyt init-policy ./policies/example.rego

# Create in policies directory
flowlyt init-policy ./policies/custom-policy.rego
```

**Generated policy example:**
```rego
# Example policy file
package flowlyt

# Allow workflow if it meets security requirements
allow {
    input.workflow.name
    not dangerous_commands
    proper_permissions
}

# Check for dangerous commands
dangerous_commands {
    input.workflow.jobs[_].steps[_].run
    contains(input.workflow.jobs[_].steps[_].run, "curl | bash")
}

# Check for proper permissions
proper_permissions {
    not input.workflow.permissions.write-all
}
```

## Usage Examples

### Basic Scanning

```bash
# Scan current directory (auto-detect platform)
flowlyt --repo .

# Scan specific repository
flowlyt --repo /path/to/project

# Scan remote GitHub repository
flowlyt --url https://github.com/user/repository

# Scan specific workflow file
flowlyt --workflow .github/workflows/ci.yml
```

### Platform-Specific Scanning

```bash
# GitHub Actions (default)
flowlyt --platform github --repo .

# GitLab CI/CD
flowlyt --platform gitlab --repo .

# On-premise GitLab
flowlyt --platform gitlab \
        --gitlab-instance https://gitlab.company.com \
        --repo .
```

### Configuration and Customization

```bash
# Use custom configuration
flowlyt --config .flowlyt.custom.yml --repo .

# Disable specific rules
flowlyt --disable-rules UNPINNED_ACTION,CONTINUE_ON_ERROR_CRITICAL_JOB --repo .

# Enable only critical security rules
flowlyt --no-default-rules \
        --enable-rules HARDCODED_SECRET,MALICIOUS_BASE64_DECODE \
        --repo .

# Filter by severity
flowlyt --min-severity HIGH --repo .
```

### Output and Reporting

```bash
# JSON output for automation
flowlyt --output json --output-file report.json --repo .

# Markdown report for documentation
flowlyt --output markdown --output-file security-report.md --repo .

# CLI output with specific severity
flowlyt --output cli --min-severity CRITICAL --repo .
```

### Advanced Usage

```bash
# Complete scan with custom settings
flowlyt --platform github \
        --repo . \
        --config .flowlyt.prod.yml \
        --min-severity HIGH \
        --entropy-threshold 5.0 \
        --output json \
        --output-file security-scan.json

# Security-focused scan
flowlyt --enable-rules HARDCODED_SECRET,DANGEROUS_COMMAND,MALICIOUS_BASE64_DECODE \
        --min-severity CRITICAL \
        --output json \
        --repo .

# Development environment scan (more lenient)
flowlyt --config .flowlyt.dev.yml \
        --min-severity MEDIUM \
        --disable-rules UNPINNED_ACTION \
        --repo .
```

### AI-Enhanced Analysis

```bash
# Basic AI analysis with OpenAI
flowlyt --repo . --ai openai --ai-key your-openai-key

# AI analysis with custom model
flowlyt --repo . \
        --ai openai \
        --ai-key your-key \
        --ai-model gpt-4

# AI analysis with Google Gemini
flowlyt --repo . --ai gemini --ai-key your-gemini-key

# High-performance AI analysis
flowlyt --repo . \
        --ai openai \
        --ai-key your-key \
        --ai-workers 10 \
        --ai-timeout 60

# AI analysis with JSON output for automation
flowlyt --repo . \
        --ai claude \
        --ai-key your-claude-key \
        --output json \
        --output-file scan-with-ai.json

# AI analysis using environment variable for API key
export AI_API_KEY=your-openai-key
flowlyt --repo . --ai openai

# Self-hosted AI model
flowlyt --repo . \
        --ai openai \
        --ai-key your-key \
        --ai-base-url https://your-llm-server.com/v1

# Focus on high-severity findings with AI verification
flowlyt --repo . \
        --min-severity HIGH \
        --ai gemini \
        --ai-key your-key \
        --ai-workers 3
```

## Exit Codes

Flowlyt returns different exit codes based on scan results:

| Exit Code | Description |
|-----------|-------------|
| `0` | Success - no security issues found |
| `1` | Security issues found |
| `2` | Configuration error |
| `3` | Runtime error (file not found, permission denied, etc.) |
| `4` | Invalid arguments or usage |

**Examples:**
```bash
# Check exit code
flowlyt --repo .
echo "Exit code: $?"

# Use in scripts
if flowlyt --repo . --min-severity HIGH; then
    echo "No high-severity issues found"
    deploy.sh
else
    echo "Security issues found, blocking deployment"
    exit 1
fi
```

## Environment Variables

Flowlyt recognizes several environment variables:

### `FLOWLYT_CONFIG`
Default configuration file path.

```bash
export FLOWLYT_CONFIG="/path/to/global-config.yml"
flowlyt --repo .  # Uses global config
```

### `FLOWLYT_OUTPUT_FORMAT`
Default output format.

```bash
export FLOWLYT_OUTPUT_FORMAT="json"
flowlyt --repo .  # Outputs JSON by default
```

### `FLOWLYT_MIN_SEVERITY`
Default minimum severity level.

```bash
export FLOWLYT_MIN_SEVERITY="HIGH"
flowlyt --repo .  # Shows only HIGH and CRITICAL by default
```

### `GITHUB_TOKEN`
GitHub API token for accessing private repositories.

```bash
export GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxx"
flowlyt --url https://github.com/private/repository
```

### `GITLAB_TOKEN`
GitLab API token for accessing private repositories.

```bash
export GITLAB_TOKEN="glpat-xxxxxxxxxxxxxxxxxxxx"
flowlyt --platform gitlab --url https://gitlab.com/private/repository
```

## Integration Examples

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "Running Flowlyt security scan..."
if ! flowlyt --repo . --min-severity HIGH --output cli; then
    echo "❌ Security issues found. Fix them before committing."
    exit 1
fi
echo "✅ No security issues found."
```

### CI/CD Integration

```bash
# GitHub Actions
- name: Security Scan
  run: |
    flowlyt --repo . \
            --config .flowlyt.yml \
            --min-severity HIGH \
            --output json \
            --output-file security-report.json
    
    # Fail if critical issues found
    if jq -e '.findings[] | select(.severity == "CRITICAL")' security-report.json > /dev/null; then
      echo "Critical security issues found!"
      exit 1
    fi
```

### Makefile Integration

```makefile
# Makefile
.PHONY: security-scan security-scan-strict

security-scan:
	@echo "Running security scan..."
	@flowlyt --repo . --min-severity MEDIUM

security-scan-strict:
	@echo "Running strict security scan..."
	@flowlyt --repo . --min-severity HIGH --config .flowlyt.strict.yml

security-report:
	@echo "Generating security report..."
	@flowlyt --repo . \
		--output markdown \
		--output-file security-report.md \
		--min-severity LOW
	@echo "Report saved to security-report.md"
```

## Troubleshooting

### Common Issues

**Command not found:**
```bash
# Check if flowlyt is in PATH
which flowlyt

# If installed with go install, add Go bin to PATH
export PATH=$PATH:$(go env GOPATH)/bin
```

**Permission denied on repository:**
```bash
# Ensure read access to repository
ls -la /path/to/repository

# For remote repositories, check token permissions
flowlyt --url https://github.com/private/repo  # Requires GITHUB_TOKEN
```

**Configuration file not found:**
```bash
# Check if config file exists
ls -la .flowlyt.yml

# Use explicit config path
flowlyt --config /full/path/to/.flowlyt.yml --repo .
```

**No workflows found:**
```bash
# Check for workflow files
find . -name "*.yml" -path "*/.github/workflows/*"
find . -name ".gitlab-ci.yml"

# Specify platform explicitly
flowlyt --platform gitlab --repo .
```

### Debugging

**Verbose output:**
```bash
# Enable debug logging (if available)
FLOWLYT_DEBUG=1 flowlyt --repo .

# Use JSON output for detailed information
flowlyt --output json --repo . | jq '.'
```

**Validate configuration:**
```bash
# Test configuration file
flowlyt --config .flowlyt.yml --workflow test-workflow.yml

# Check rule IDs
flowlyt --help | grep -A 20 "Available rules"
```

---

**Next:** [CI/CD Integration](cicd-integration.md)
