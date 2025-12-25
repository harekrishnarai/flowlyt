# Flowlyt Security Action

🛡️ **Enterprise-grade GitHub Actions workflow security scanner** with policy enforcement and vulnerability intelligence.

## Quick Start

Add Flowlyt to your workflow to automatically scan for security vulnerabilities:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Flowlyt Security Scan
        uses: harekrishnarai/flowlyt@v1.0.1
        with:
          fail-on-severity: 'CRITICAL'
          upload-sarif: 'true'
          comment-on-pr: 'true'
```

## Manual Scan (workflow_dispatch)

Trigger a manual scan and upload SARIF to GitHub Security. This example uses the v1.0.0 release tag and sets the required permissions.

```yaml
name: Flowlyt manual scan

on:
  workflow_dispatch: {}

permissions:
  contents: read
  security-events: write

jobs:
  analyze:
    name: Flowlyt security scan
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Run Flowlyt Security Scan
        uses: harekrishnarai/flowlyt@v1.0.1
        with:
          # Do not pass config-file or enable-ast-analysis here
          repository: .
          output-format: sarif
          output-file: flowlyt-results.sarif
          min-severity: LOW
          fail-on-severity: CRITICAL
          max-critical: 0
          max-high: 0
          comment-on-pr: true
          upload-sarif: 'true'
          sarif-category: flowlyt
          create-issue: 'false'
          issue-labels: security,flowlyt
          continue-on-error: 'false'
          verbose: 'false'

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: flowlyt-results.sarif
```

Optional: Pin to a specific commit for maximum supply-chain security.

```yaml
      - name: Run Flowlyt Security Scan (pinned)
        uses: harekrishnarai/flowlyt@f9c1041af4ffe2a45adbe374c8d9d40fb07d3d6d
        with:
          repository: .
          output-format: sarif
          output-file: flowlyt-results.sarif
          min-severity: LOW
          fail-on-severity: CRITICAL
          max-critical: 0
          max-high: 0
          comment-on-pr: true
          upload-sarif: 'true'
          sarif-category: flowlyt
          create-issue: 'false'
          issue-labels: security,flowlyt
          continue-on-error: 'false'
          verbose: 'false'
```

Notes:
- `security-events: write` is required to upload SARIF to the GitHub Security tab.
- `repository: .` scans the current repository’s workflows.
- Avoid passing `config-file` or enabling AST analysis via Action inputs unless documented; they are not required for standard scans.

## Features

### 🔍 **Comprehensive Security Analysis**
- **46+ Security Rules**: Cache poisoning, secrets exposure, privilege escalation, supply chain attacks
- **Multi-Platform Support**: GitHub Actions, GitLab CI/CD (coming soon)
- **Vulnerability Intelligence**: Real-time threat data from OSV.dev
- **SARIF Integration**: Automatic upload to GitHub Security tab

### 🏛️ **Enterprise Policy Enforcement**
- **Custom Security Policies**: Organization-wide security standards
- **Compliance Frameworks**: PCI-DSS, SOX, NIST-800-53 support
- **Security Gates**: Block deployments on critical violations
- **Trend Analysis**: Track security posture over time

### 🚀 **CI/CD Integration**
- **Zero Configuration**: Works out-of-the-box
- **Smart Caching**: Optimized for fast CI/CD pipelines
- **Multi-Output Formats**: CLI, JSON, Markdown, SARIF
- **Pull Request Comments**: Contextual security feedback

## Configuration

### Basic Usage

```yaml
- name: Security Scan
  uses: harekrishnarai/flowlyt@v1.0.1
  with:
    # Minimum severity to report (INFO, LOW, MEDIUM, HIGH, CRITICAL)
    min-severity: 'MEDIUM'
    
    # Fail the action on findings of this severity or higher
    fail-on-severity: 'CRITICAL'
    
    # Upload SARIF results to GitHub Security tab
    upload-sarif: 'true'
```

### Enterprise Configuration

```yaml
- name: Enterprise Security Scan
  uses: harekrishnarai/flowlyt@v1.0.1
  with:
    # Path to configuration file
    config-file: '.flowlyt-enterprise.yml'
    
    # Enable policy enforcement
    enable-policy-enforcement: 'true'
    
    # Enable vulnerability intelligence
    enable-vuln-intel: 'true'
    
    # Compliance frameworks to evaluate
    compliance-frameworks: 'pci-dss,sox,nist-800-53'
    
    # Maximum allowed findings
    max-critical: '0'
    max-high: '5'
    
    # Create GitHub issues for critical violations
    create-issue: 'true'
    issue-labels: 'security,critical,flowlyt'
```

### Advanced Security Pipeline

```yaml
name: Advanced Security Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'  # Daily security scan

permissions:
  contents: read
  security-events: write
  issues: write
  pull-requests: write

jobs:
  security-scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        config: [basic, enterprise, compliance]
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Security Scan - ${{ matrix.config }}
        uses: harekrishnarai/flowlyt@v1.0.1
        with:
          config-file: '.flowlyt-${{ matrix.config }}.yml'
          output-format: 'sarif'
          output-file: 'security-${{ matrix.config }}.sarif'
          enable-policy-enforcement: 'true'
          enable-vuln-intel: 'true'
          sarif-category: 'flowlyt-${{ matrix.config }}'
          verbose: 'true'
      
      - name: Upload Security Results
        uses: actions/upload-artifact@v4
        with:
          name: security-results-${{ matrix.config }}
          path: security-${{ matrix.config }}.sarif
        if: always()

  security-gate:
    needs: security-scan
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
      - name: Download Security Results
        uses: actions/download-artifact@v4
        with:
          pattern: security-results-*
          merge-multiple: true
      
      - name: Security Gate Decision
        run: |
          echo "🔒 Evaluating security gate..."
          # Custom logic to evaluate multiple scan results
          # Block deployment if critical issues found
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `repository` | Repository to scan | No | `.` |
| `config-file` | Path to configuration file | No | `.flowlyt.yml` |
| `output-format` | Output format (cli, json, markdown, sarif) | No | `sarif` |
| `output-file` | Output file path | No | `flowlyt-results.sarif` |
| `min-severity` | Minimum severity to report | No | `LOW` |
| `fail-on-severity` | Fail on this severity or higher | No | `CRITICAL` |
| `max-critical` | Maximum critical findings allowed | No | `0` |
| `max-high` | Maximum high findings allowed | No | `0` |
| `enable-policy-enforcement` | Enable enterprise policies | No | `false` |
| `enable-vuln-intel` | Enable vulnerability intelligence | No | `false` |
| `policy-config` | Path to policy configuration | No | `` |
| `compliance-frameworks` | Compliance frameworks to check | No | `` |
| `comment-on-pr` | Comment results on PRs | No | `true` |
| `upload-sarif` | Upload SARIF to GitHub Security | No | `true` |
| `sarif-category` | SARIF upload category | No | `flowlyt` |
| `create-issue` | Create issues for critical violations | No | `false` |
| `issue-labels` | Labels for created issues | No | `security,flowlyt` |
| `continue-on-error` | Continue on security failures | No | `false` |
| `verbose` | Enable verbose output | No | `false` |

## Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total number of findings |
| `critical-count` | Number of critical findings |
| `high-count` | Number of high severity findings |
| `medium-count` | Number of medium severity findings |
| `low-count` | Number of low severity findings |
| `policy-violations` | Number of policy violations |
| `blocking-violations` | Number of blocking violations |
| `compliance-status` | Overall compliance status |
| `results-file` | Path to results file |
| `sarif-file` | Path to SARIF file |
| `exit-code` | Scan exit code (0=success, 1=findings, 2=error) |
| `summary` | Markdown summary of findings |

## Security Rules

Flowlyt includes **46+ comprehensive security rules** covering:

### 🔐 **Secrets & Credentials**
- Hardcoded secrets detection
- Over-provisioned secrets
- Unredacted secrets in logs
- Secrets inheritance vulnerabilities

### 🛡️ **Permissions & Access**
- Broad workflow permissions
- Privilege escalation detection
- Self-hosted runner security
- Container escape attempts

### 🔗 **Supply Chain Security**
- Unpinned action versions
- Typosquatting detection
- Malicious base64 patterns
- Artifact poisoning attacks

### 💉 **Injection Attacks**
- Shell injection vulnerabilities
- Expression injection
- Command injection
- Environment variable injection

### 🎯 **Advanced Threats**
- Cache poisoning attacks
- Git reference confusion
- Impostor commit detection
- Stale action references

## Configuration Files

### Basic Configuration (`.flowlyt.yml`)

```yaml
version: "1"

rules:
  # Enable specific rules
  enabled: []
  
  # Disable specific rules
  disabled: ["LOW_SEVERITY_RULE"]
  
  # Custom rules
  custom_rules:
    - id: "CUSTOM_DOCKER_RISK"
      name: "Suspicious Docker Command"
      severity: "HIGH"
      patterns:
        - "docker run.*--privileged"
        - "docker.*--cap-add.*SYS_ADMIN"

# Output configuration
output:
  include_remediation: true
  include_compliance: false
  grouping: "severity"

# Filtering
filtering:
  min_severity: "MEDIUM"
  exclude_files: []
  exclude_rules: []
```

### Enterprise Configuration (`.flowlyt-enterprise.yml`)

```yaml
version: "1"

# Organization-wide settings
organization:
  name: "Enterprise Corp"
  policy_repo: "enterprise-corp/security-policies"
  default_policies: ["enterprise-baseline", "pci-dss-compliance"]

# Compliance frameworks
compliance:
  enabled: true
  frameworks: ["pci-dss", "sox", "nist-800-53"]
  report_path: "./compliance-reports/"

# Policy enforcement
policy_enforcement:
  enabled: true
  strict_mode: true
  blocking_rules: ["CRITICAL_VIOLATION", "COMPLIANCE_FAILURE"]
  
# Vulnerability intelligence
vulnerability_intelligence:
  enabled: true
  osv_api_key: "${{ secrets.OSV_API_KEY }}"
  cache_duration: "24h"
  sources: ["osv.dev", "github-advisory"]

# Notifications
notifications:
  slack:
    webhook_url: "${{ secrets.SLACK_WEBHOOK }}"
    channel: "#security-alerts"
  email:
    recipients: ["security@company.com"]
    smtp_server: "smtp.company.com"
```

## Security Gate Examples

### Block on Critical Issues

```yaml
- name: Security Gate
  uses: harekrishnarai/flowlyt@v1.0.1
  with:
    fail-on-severity: 'CRITICAL'
    max-critical: '0'
    continue-on-error: 'false'
```

### Warning on High Issues

```yaml
- name: Security Check
  uses: harekrishnarai/flowlyt@v1.0.1
  with:
    fail-on-severity: 'HIGH'
    max-high: '3'
    continue-on-error: 'true'
    comment-on-pr: 'true'
```

### Enterprise Compliance Gate

```yaml
- name: Compliance Check
  uses: harekrishnarai/flowlyt@v1.0.1
  with:
    enable-policy-enforcement: 'true'
    compliance-frameworks: 'pci-dss,sox'
    create-issue: 'true'
    issue-labels: 'compliance,security,urgent'
```

## Troubleshooting

### Common Issues

**Binary Download Failed**
```
❌ Failed to download binary from releases
```
- **Solution**: Check internet connectivity or use source build fallback
- **Workaround**: Pre-install binary in workflow

**SARIF Upload Failed**
```
❌ SARIF upload failed
```
- **Solution**: Ensure `security-events: write` permission is set
- **Check**: Verify SARIF file format is valid

**Configuration Not Found**
```
⚠️ Configuration file .flowlyt.yml not found
```
- **Solution**: Create configuration file or use default settings
- **Alternative**: Specify different config path with `config-file` input

### Verbose Debugging

Enable verbose output for troubleshooting:

```yaml
- name: Debug Security Scan
  uses: harekrishnarai/flowlyt@v1
  with:
    verbose: 'true'
    min-severity: 'INFO'
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [docs.flowlyt.dev](https://docs.flowlyt.dev)
- **Issues**: [GitHub Issues](https://github.com/harekrishnarai/flowlyt/issues)
- **Security**: [security@flowlyt.dev](mailto:security@flowlyt.dev)
- **Community**: [GitHub Discussions](https://github.com/harekrishnarai/flowlyt/discussions)

---

🛡️ **Secure your CI/CD pipelines with Flowlyt** - The enterprise security scanner for GitHub Actions workflows.
