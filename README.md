<img width="945" height="299" alt="flowlytgh" src="https://github.com/user-attachments/assets/a994d9b6-be4c-41d0-a3e8-adda9d72caaa" />

<div align="center">
  <strong>🔒 Secure your CI/CD pipelines with Flowlyt</strong>
  <br>
  <a href="https://github.com/harekrishnarai/flowlyt">⭐ Star us on GitHub</a>
</div>

# Flowlyt - Multi-Platform CI/CD Security Analyzer

Flowlyt is a comprehensive security analyzer that scans CI/CD workflows to detect malicious patterns, misconfigurations, and secrets exposure. It provides a scalable and flexible approach to enforcing secure CI/CD practices across multiple platforms including GitHub Actions and GitLab CI/CD, with user-configurable rules, custom policies, and intelligent false positive management.

![flowlyt](https://github.com/user-attachments/assets/38b4eaac-3a6e-44eb-a1f4-78b9183d5eaf)

## ✨ Key Features

### 🔍 **Advanced Static Analysis**
- **Multi-Platform Support**: Analyze GitHub Actions and GitLab CI/CD workflows with platform-specific rules
- **Workflow Parsing**: Deep analysis of CI/CD YAML files across different platforms
- **Malicious Pattern Detection**: Identify unsafe patterns like `curl | bash`, base64-encoded payloads, and shell obfuscation
- **Supply Chain Security**: Detect unpinned actions and risky trigger contexts
- **Data Exfiltration Detection**: Identify suspicious data transmission patterns

### ⚙️ **Configuration-Driven Security**
- **YAML Configuration**: Comprehensive `.flowlyt.yml` configuration file support
- **User-Configurable Rules**: Enable/disable specific rules based on your needs
- **Custom Rule Authoring**: Create regex-based custom rules for organization-specific security requirements
- **False Positive Management**: Sophisticated ignore patterns (strings, regex, file-based, rule-specific)
- **Severity Filtering**: Configure minimum severity levels for reporting

### 🛡️ **Multi-Layer Detection**
- **Misconfiguration Detection**: Scan for insecure `permissions:` settings, `continue-on-error: true` in critical jobs
- **Secret Detection**: Advanced entropy-based and regex-based scanning for hardcoded secrets, tokens, and credentials
- **Shell Command Analysis**: Parse `run:` blocks to detect shell obfuscation, `eval` usage, and subshell tricks
- **Policy Enforcement**: Define custom policies in Rego (Open Policy Agent)

### 📊 **Flexible Output & Reporting**
- **Multiple Output Formats**: CLI, JSON, Markdown, and SARIF reporting
- **SARIF Integration**: Industry-standard format for GitHub Security Tab, IDEs, and enterprise tools
- **Severity-Based Filtering**: Filter results by minimum severity level
- **Detailed Findings**: Comprehensive information including file paths, line numbers, and remediation advice
- **Integration-Ready**: Perfect for CI/CD pipelines and security workflows

## Installation

### Option 1: Using pre-built binaries

Download the latest release from the [GitHub Releases page](https://github.com/harekrishnarai/flowlyt/releases).

### Option 2: Using Go package manager

```bash
# Install directly using Go
go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
```

This will download, compile, and install the `flowlyt` binary to your `$GOPATH/bin` directory. Make sure your `$GOPATH/bin` is in your system's `PATH` to run the tool from anywhere.

### Option 3: Building from source

```bash
# Clone the repository
git clone https://github.com/harekrishnarai/flowlyt.git
cd flowlyt

# Build the binary
go build -o flowlyt ./cmd/flowlyt
```

### Option 4: Using Docker

```bash
docker pull harekrishnarai/flowlyt:latest
docker run --rm -v $(pwd):/repo harekrishnarai/flowlyt --repo /repo
```

## ⚠️ Known Issues

### Go Module Proxy Cache Issue

**Issue**: `go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest` may install an incorrect version (v1.0.0) due to a Go module proxy cache issue.

**Symptoms**:
- Installing with `@latest` downloads v1.0.0 instead of the actual latest version (v0.0.4)
- Tool may not function correctly or detect security issues properly

**Workaround**: Use the `GOPRIVATE` environment variable to bypass the proxy cache:

```bash
# Recommended installation method (bypasses proxy cache)
GOPRIVATE=github.com/harekrishnarai/flowlyt go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
```

**Alternative**: Install specific version directly:
```bash
# Install specific latest version
go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@v0.0.3
```

**Verification**: Check that you have the correct version:
```bash
flowlyt --version
# Should output: flowlyt version 0.0.4
```

This issue has been reported to GitHub support and should be resolved server-side in the future.

## Usage

## 🚀 Quick Start

### Multi-Platform Support

**GitHub Actions (default):**
```bash
flowlyt --repo ./myrepo
flowlyt --platform=github --repo ./myrepo
```

**GitLab CI/CD:**
```bash
flowlyt --platform=gitlab --repo ./myrepo
flowlyt --platform=gitlab --workflow .gitlab-ci.yml
```

### CLI Examples

**Basic repository scan:**
```bash
flowlyt --repo ./myrepo
```

**Scan with configuration file:**
```bash
flowlyt --repo ./myrepo --config .flowlyt.yml
```

**Filter by severity:**
```bash
flowlyt --repo ./myrepo --min-severity HIGH
```

**Custom rule management:**
```bash
# Disable specific rules
flowlyt --repo ./myrepo --disable-rules UNPINNED_ACTION,HARDCODED_SECRET

# Enable only specific rules
flowlyt --repo ./myrepo --enable-rules MALICIOUS_BASE64_DECODE,BROAD_PERMISSIONS
```

**Generate reports:**
```bash
# JSON output
flowlyt --repo ./myrepo --output json --output-file security-report.json

# Markdown report
flowlyt --repo ./myrepo --output markdown --output-file security-report.md
```

**Scan remote repository:**
```bash
flowlyt --url https://github.com/user/repo
```

**Single workflow file:**
```bash
flowlyt --workflow .github/workflows/ci.yml
```

### Configuration File

Create a `.flowlyt.yml` file in your repository root:

```yaml
# Flowlyt Configuration
rules:
  enabled:
    - "MALICIOUS_BASE64_DECODE"
    - "INSECURE_PULL_REQUEST_TARGET"
    - "BROAD_PERMISSIONS"
  disabled:
    - "UNPINNED_ACTION"  # Disable if using dependabot
  
  # Custom rules
  custom:
    - id: "CUSTOM_FORBIDDEN_COMMAND"
      name: "Forbidden Command Usage"
      description: "Detects usage of forbidden commands"
      severity: "HIGH"
      pattern: "(?i)(wget|curl)\\s+.*\\|\\s*(sh|bash)"
      target: "commands"
      remediation: "Use secure alternatives to downloading and executing scripts"

# False positive management
ignore:
  global:
    - "example.com"  # Ignore example domains
    - "test-secret"  # Ignore test secrets
  
  secrets:
    - pattern: "^sk-test-"  # Ignore test API keys
      regex: true
  
  files:
    - "test/**/*"  # Ignore test files
    - "docs/examples/**/*"
  
  rules:
    HARDCODED_SECRET:
      - "TODO: add real secret here"
      - pattern: "^EXAMPLE_.*"
        regex: true

# Output configuration
output:
  format: "cli"
  min_severity: "MEDIUM"
  file: ""
```

**For detailed configuration options, see [CONFIGURATION.md](./CONFIGURATION.md).**

## 📋 Command Line Options

```bash
USAGE:
   flowlyt [global options] command [command options]

GLOBAL OPTIONS:
   --repo value, -r value                                                             Local repository path to scan
   --url value, -u value                                                              GitHub repository URL to scan
   --workflow value, -w value                                                         Path to a single workflow file to scan
   --output value, -o value                                                           Output format (cli, json, markdown) (default: "cli")
   --output-file value, -f value                                                      Output file path (if not specified, prints to stdout)
   --config value, -c value                                                           Configuration file path (.flowlyt.yml)
   --policy value, -p value                                                           Custom policy file or directory
   --no-default-rules                                                                 Disable default security rules (default: false)
   --enable-rules value, --enable value [ --enable-rules value, --enable value ]      Enable specific rules (comma-separated)
   --disable-rules value, --disable value [ --disable-rules value, --disable value ]  Disable specific rules (comma-separated)
   --min-severity value                                                               Minimum severity level to report (CRITICAL, HIGH, MEDIUM, LOW, INFO) (default: "LOW")
   --entropy-threshold value                                                          Entropy threshold for secret detection (default: 4.5)
   --temp-dir value                                                                   Temporary directory for repository clone
   --help, -h                                                                         show help
   --version, -v                                                                      print the version

COMMANDS:
   init-policy  Create an example policy file
   help, h      Shows a list of commands or help for one command
```

## 🎯 Security Rules

Flowlyt includes comprehensive built-in security rules:

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| `MALICIOUS_BASE64_DECODE` | Base64 Decode Execution | CRITICAL | Detects base64 decode and execution patterns |
| `INSECURE_PULL_REQUEST_TARGET` | Insecure pull_request_target | CRITICAL | Identifies risky pull_request_target usage |
| `MALICIOUS_DATA_EXFILTRATION` | Data Exfiltration | CRITICAL | Detects suspicious data transmission patterns |
| `BROAD_PERMISSIONS` | Broad Permissions | CRITICAL | Identifies overly permissive workflow permissions |
| `SHELL_OBFUSCATION` | Shell Obfuscation | CRITICAL | Detects obfuscated shell commands |
| `MALICIOUS_CURL_PIPE_BASH` | Curl Pipe to Shell | HIGH | Identifies curl pipe to shell patterns |
| `HARDCODED_SECRET` | Hardcoded Secret | HIGH | Detects hardcoded secrets and credentials |
| `DANGEROUS_COMMAND` | Dangerous Command | HIGH | Identifies potentially dangerous commands |
| `SHELL_EVAL_USAGE` | Eval Usage | HIGH | Detects dangerous eval usage |
| `UNPINNED_ACTION` | Unpinned Action | MEDIUM | Identifies unpinned GitHub Actions |
| `CONTINUE_ON_ERROR_CRITICAL_JOB` | Continue on Error | MEDIUM | Detects continue-on-error in critical jobs |

*All rules can be enabled/disabled through configuration or CLI flags.*

## 🔧 GitHub Action Integration

To use Flowlyt in your GitHub Actions workflow:

```yaml
name: Flowlyt Security Check
on: [pull_request, push]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Scan workflows with Flowlyt
        uses: harekrishnarai/flowlyt@v1.0.2
        with:
          # Optional: Configuration file path
          config: '.flowlyt.yml'
          
          # Optional: Output format (cli, json, markdown)
          output-format: markdown
          
          # Optional: Output file path
          output-file: flowlyt-security-report.md
          
          # Optional: Minimum severity level
          min-severity: 'HIGH'
          
          # Optional: Disable specific rules
          disable-rules: 'UNPINNED_ACTION,HARDCODED_SECRET'
          
          # Optional: Enable only specific rules
          # enable-rules: 'MALICIOUS_BASE64_DECODE,BROAD_PERMISSIONS'
          
          # Optional: Set to 'true' to comment results on PRs
          comment-on-pr: 'true'
          
          # Optional: Path to custom policies
          # policy-path: './policies'
          
          # Optional: Set to 'true' to disable default rules
          # no-default-rules: 'false'
          
          # Optional: Fail on severity level
          fail-on-severity: 'CRITICAL'
      
      - name: Upload security report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: flowlyt-security-report
          path: flowlyt-security-report.md
```

#### Action Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `repository` | Repository to scan | No | Current workspace |
| `config` | Path to configuration file | No | `.flowlyt.yml` |
| `output-format` | Output format (cli, json, markdown) | No | `markdown` |
| `output-file` | Path to output file | No | `flowlyt-results.md` |
| `min-severity` | Minimum severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO) | No | `LOW` |
| `enable-rules` | Comma-separated list of rules to enable | No | |
| `disable-rules` | Comma-separated list of rules to disable | No | |
| `policy-path` | Path to custom policy files | No | |
| `no-default-rules` | Disable default security rules | No | `false` |
| `entropy-threshold` | Entropy threshold for secret detection | No | `4.5` |
| `comment-on-pr` | Whether to comment results on PRs | No | `true` |
| `fail-on-severity` | Fail if findings with this severity or higher are found | No | |

#### Action Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total number of findings |
| `critical-count` | Number of critical findings |
| `high-count` | Number of high severity findings |
| `results-file` | Path to the results file |

### Using the Action with a Self-Hosted Runner

If you're using a self-hosted runner, make sure Docker is installed and you have sufficient permissions:

```yaml
jobs:
  security:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v3
      - name: Scan workflows
        uses: harekrishnarai/flowlyt@v1.0.2
        with:
          output-format: markdown
          output-file: flowlyt-results.md
```

## 📝 Custom Policies & Rules

### OPA Policies

Flowlyt supports custom policies written in Rego (Open Policy Agent language):

```rego
package flowlyt

# Detect workflows with write-all permissions
deny[violation] {
    input.workflow.permissions == "write-all"
    
    violation := {
        "id": "POLICY_BROAD_PERMISSIONS",
        "name": "Workflow Has Broad Permissions",
        "description": "Workflow has 'write-all' permissions, which grants excessive access",
        "severity": "HIGH",
        "evidence": "permissions: write-all",
        "remediation": "Use more specific permissions instead of 'write-all'"
    }
}
```

### Custom Rules

Define custom regex-based rules in your configuration:

```yaml
rules:
  custom:
    - id: "CUSTOM_DOCKER_PRIVILEGED"
      name: "Privileged Docker Container"
      description: "Detects usage of privileged Docker containers"
      severity: "HIGH"
      pattern: "docker\\s+run\\s+.*--privileged"
      target: "commands"
      remediation: "Avoid using privileged containers; use specific capabilities instead"
    
    - id: "CUSTOM_SUDO_USAGE"
      name: "Sudo Usage in Workflows"
      description: "Detects sudo usage which may indicate privilege escalation"
      severity: "MEDIUM"
      pattern: "\\bsudo\\b"
      target: "commands"
      remediation: "Use least-privilege principles; avoid sudo when possible"
```

### Initialize Example Policy

Generate an example policy file:

```bash
flowlyt init-policy ./policies/custom.rego
```

## 🎛️ Advanced Configuration

### False Positive Management

Flowlyt provides sophisticated false positive management:

```yaml
ignore:
  # Global ignore patterns
  global:
    - "example.com"
    - "localhost"
    - "127.0.0.1"
  
  # Secret-specific ignores
  secrets:
    - "test-api-key"
    - pattern: "^sk-test-"
      regex: true
  
  # File-based ignores
  files:
    - "test/**/*"
    - "docs/examples/**/*"
    - "*.md"
  
  # Rule-specific ignores
  rules:
    HARDCODED_SECRET:
      - "TODO: replace with real secret"
      - pattern: "^EXAMPLE_.*"
        regex: true
    
    UNPINNED_ACTION:
      - "actions/checkout@v4"  # If you trust official actions
```

### Multi-Environment Configuration

Use different configurations for different environments:

```bash
# Development environment
flowlyt --config .flowlyt.dev.yml --min-severity LOW

# Production environment
flowlyt --config .flowlyt.prod.yml --min-severity CRITICAL
```

### Integration with Security Tools

Flowlyt integrates well with other security tools:

```bash
# Combine with other scanners
flowlyt --output json --output-file flowlyt.json --repo .
semgrep --config=auto --json --output=semgrep.json .
# Merge results with your security dashboard
```

## 🏗️ Architecture

Flowlyt is designed with a modular architecture for scalability and extensibility:

```
flowlyt/
├── cmd/flowlyt/           # CLI application entry point
├── pkg/
│   ├── config/            # Configuration management & custom rules
│   ├── parser/            # GitHub Actions workflow parser
│   ├── rules/             # Built-in security rules engine
│   ├── shell/             # Shell command analyzer
│   ├── secrets/           # Secret detection engine
│   ├── policies/          # OPA policy engine
│   ├── report/            # Report generation (CLI, JSON, Markdown)
│   └── github/            # GitHub repository handling
└── test/                  # Test workflows and policies
```

### Key Components

- **Configuration Engine**: YAML-based configuration with CLI flag overrides
- **Rule Engine**: Pluggable rule system with enable/disable capabilities
- **Custom Rule Engine**: Regex-based custom rule support
- **False Positive Engine**: Sophisticated ignore pattern matching
- **Multi-Format Reporter**: CLI, JSON, and Markdown output support

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/harekrishnarai/flowlyt.git
cd flowlyt

# Install dependencies
go mod download

# Run tests
go test ./...

# Build
go build -o flowlyt ./cmd/flowlyt

# Run
./flowlyt --help
```

## 📚 Documentation

- [Configuration Guide](./CONFIGURATION.md) - Comprehensive configuration options
- [Contributing Guide](./CONTRIBUTING.md) - How to contribute to Flowlyt
- [Security Policy](./SECURITY.md) - Security reporting and policies
- [Code of Conduct](./CODE_OF_CONDUCT.md) - Community guidelines

## 🆘 Support

- 💭 Want to lookup deeply the code? [![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/harekrishnarai/flowlyt)
- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/harekrishnarai/flowlyt/issues)
- 💡 **Feature Requests**: [GitHub Discussions](https://github.com/harekrishnarai/flowlyt/discussions)
- 📚 **Documentation**: [Wiki](https://github.com/harekrishnarai/flowlyt/wiki)

## 📊 Example Output

```bash
🔍 Flowlyt - GitHub Actions Security Analyzer
=======================================

► SCAN INFORMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Repository:          ./example-repo
Scan Time:           Thu, 10 Jul 2025 16:00:00 IST
Duration:            45ms
Workflows Analyzed:  3
Rules Applied:       12

► SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SEVERITY | COUNT | INDICATOR       
-----------+-------+-----------------
  CRITICAL |   2   | ██████████████  
  HIGH     |   3   | ██████████████  
  MEDIUM   |   1   | ████            
  LOW      |   0   |                 
  INFO     |   0   |                 
  TOTAL    |   6   |                 

► FINDINGS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

■ CRITICAL SEVERITY FINDINGS
─────────────────────────────────────────────────

✗ [1] Base64 Decode Execution (MALICIOUS_BASE64_DECODE)
  File:        .github/workflows/ci.yml
  Line:        42
  Job:         build
  Step:        Deploy
  Description: Command decodes and executes base64 encoded data

✗ [2] Overly Broad Permissions (BROAD_PERMISSIONS)
  File:        .github/workflows/release.yml
  Line:        8
  Description: Workflow uses 'write-all' permissions

✅ Scan completed in 45ms
Found 6 issues (2 Critical, 3 High, 1 Medium, 0 Low, 0 Info)
```

## 🚀 Roadmap


- [x] **SARIF Output**: Support for SARIF format for better tool integration
- [ ] **Workflow Visualization**: Visual workflow security analysis
- [ ] **Plugin System**: Extensible plugin architecture
- [ ] **IDE Integration**: VS Code extension for real-time analysis
- [ ] **Advanced Analytics**: Security trend analysis and reporting
- [ ] **Multi-Language Support**: Support for other CI/CD platforms

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

---

## Contributors
Thanks to all the people who already contributed!   
[Prashant Venkatesh](https://www.linkedin.com/in/prashant-venkatesh-99018999/)    
[Nandan Gupta](https://www.linkedin.com/in/nandan-gupta-698aa11b)  
[Mohd. Arif](https://www.linkedin.com/in/mohd--arif/) 
[Hare Krishna Rai](https://www.linkedin.com/in/harekrishnarai/)  
[Gaurav Joshi](https://www.linkedin.com/in/gauravjoshii/)  
[Chanchal Kalnarayan](https://www.linkedin.com/in/ckalnarayan) 

<a href="https://github.com/harekrishnarai/flowlyt/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=harekrishnarai/flowlyt" />
</a>
