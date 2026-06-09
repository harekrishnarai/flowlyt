# Report Generation

Flowlyt provides multiple output formats and comprehensive reporting capabilities to suit different use cases, from command-line usage to automated CI/CD integration.

## Output Formats

### CLI Output (Default)

The CLI output format provides a human-readable, colorized report perfect for terminal usage.

**Example CLI Output:**
```
🔍 Flowlyt - Multi-Platform CI/CD Security Analyzer
Platform: GITHUB
=======================================

► SCAN INFORMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Repository:          ./my-repo
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
[CRITICAL] Hardcoded Secret
┌────────────────────────────────────────────────────────────
│ File: .github/workflows/deploy.yml (Line 25)
│ Rule: HARDCODED_SECRET
│ 
│ Evidence:
│   GITHUB_TOKEN: "ghp_xxxxxxxxxxxxxxxxxxxx"
│ 
│ Remediation:
│   Use GitHub secrets instead of hardcoded tokens:
│   env:
│     GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
└────────────────────────────────────────────────────────────

[HIGH] Dangerous Command Pattern
┌────────────────────────────────────────────────────────────
│ File: .github/workflows/ci.yml (Line 42)
│ Rule: DANGEROUS_COMMAND
│ 
│ Evidence:
│   run: curl -s https://install.sh | bash
│ 
│ Remediation:
│   Download and verify scripts before execution:
│   run: |
│     curl -s https://install.sh > install.sh
│     sha256sum install.sh | grep expected_hash
│     bash install.sh
└────────────────────────────────────────────────────────────
```

**Usage:**
```bash
# Basic CLI output
flowlyt --repo . --output cli

# CLI output with specific severity
flowlyt --repo . --output cli --min-severity HIGH

# Save CLI output to file
flowlyt --repo . --output cli --output-file security-report.txt
```

### JSON Output

Machine-readable JSON format ideal for automation, CI/CD integration, and programmatic processing.

**Example JSON Output:**
```json
{
  "repository": "./my-repo",
  "scan_time": "2025-07-10T16:00:00Z",
  "duration": "45ms",
  "workflows_count": 3,
  "rules_count": 12,
  "findings": [
    {
      "rule_id": "HARDCODED_SECRET",
      "rule_name": "Hardcoded Secret",
      "severity": "CRITICAL",
      "category": "SECRET_EXPOSURE",
      "file_path": ".github/workflows/deploy.yml",
      "line_number": 25,
      "column_number": 5,
      "evidence": "GITHUB_TOKEN: \"ghp_xxxxxxxxxxxxxxxxxxxx\"",
      "description": "Hardcoded secret detected in workflow file",
      "remediation": "Use GitHub secrets instead of hardcoded tokens",
      "references": [
        "https://docs.github.com/en/actions/security-guides/encrypted-secrets"
      ]
    },
    {
      "rule_id": "DANGEROUS_COMMAND",
      "rule_name": "Dangerous Command Pattern",
      "severity": "HIGH",
      "category": "COMMAND_INJECTION",
      "file_path": ".github/workflows/ci.yml",
      "line_number": 42,
      "column_number": 8,
      "evidence": "run: curl -s https://install.sh | bash",
      "description": "Potentially dangerous command that pipes remote content to shell",
      "remediation": "Download and verify scripts before execution",
      "references": [
        "https://security.stackexchange.com/questions/213401/why-is-curl-pipe-bash-a-security-risk"
      ]
    }
  ],
  "summary": {
    "critical": 1,
    "high": 1,
    "medium": 0,
    "low": 0,
    "info": 0,
    "total": 2
  }
}
```

**Usage:**
```bash
# JSON output
flowlyt --repo . --output json

# JSON output to file
flowlyt --repo . --output json --output-file security-report.json

# Process JSON with jq
flowlyt --repo . --output json | jq '.findings[] | select(.severity == "CRITICAL")'
```

### Markdown Output

Documentation-friendly Markdown format perfect for reports, documentation, and integration with platforms that support Markdown.

**Example Markdown Output:**
```markdown
# Security Scan Report

## 📋 Scan Information

| Item | Value |
|------|-------|
| **Repository** | ./my-repo |
| **Scan Time** | Thu, 10 Jul 2025 16:00:00 IST |
| **Duration** | 45ms |
| **Workflows Analyzed** | 3 |
| **Rules Applied** | 12 |

## 📊 Summary

| Severity | Count |
|----------|-------|
| 🔴 **Critical** | 1 |
| 🟠 **High** | 1 |
| 🟡 **Medium** | 0 |
| 🔵 **Low** | 0 |
| ⚪ **Info** | 0 |
| **Total** | **2** |

## 🔍 Findings

### 🔴 CRITICAL: Hardcoded Secret

**File:** `.github/workflows/deploy.yml` (Line 25)  
**Rule:** `HARDCODED_SECRET`  
**Category:** `SECRET_EXPOSURE`

**Evidence:**
```yaml
GITHUB_TOKEN: "ghp_xxxxxxxxxxxxxxxxxxxx"
```

**Description:**
Hardcoded secret detected in workflow file

**Remediation:**
Use GitHub secrets instead of hardcoded tokens:
```yaml
env:
  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**References:**
- [GitHub Encrypted Secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)

---

### 🟠 HIGH: Dangerous Command Pattern

**File:** `.github/workflows/ci.yml` (Line 42)  
**Rule:** `DANGEROUS_COMMAND`  
**Category:** `COMMAND_INJECTION`

**Evidence:**
```bash
run: curl -s https://install.sh | bash
```

**Description:**
Potentially dangerous command that pipes remote content to shell

**Remediation:**
Download and verify scripts before execution:
```bash
run: |
  curl -s https://install.sh > install.sh
  sha256sum install.sh | grep expected_hash
  bash install.sh
```

**References:**
- [Security Risk of curl | bash](https://security.stackexchange.com/questions/213401/why-is-curl-pipe-bash-a-security-risk)

---

## ✅ Recommendations

1. **Address Critical Issues First**: Start by fixing the 1 critical security issue(s)
2. **Review High-Priority Items**: Examine the 1 high-severity finding(s)
3. **Implement Security Best Practices**: Consider using security-focused workflow templates
4. **Regular Scanning**: Integrate Flowlyt into your CI/CD pipeline for continuous monitoring

*Report generated by Flowlyt v0.0.1 on 2025-07-10*
```

**Usage:**
```bash
# Markdown output
flowlyt --repo . --output markdown

# Markdown output to file
flowlyt --repo . --output markdown --output-file SECURITY-REPORT.md

# Include in documentation
flowlyt --repo . --output markdown --output-file docs/security-analysis.md
```

## Report Customization

### Filtering Reports

#### By Severity Level
```bash
# Only critical and high severity issues
flowlyt --repo . --min-severity HIGH --output json

# Only critical issues
flowlyt --repo . --min-severity CRITICAL --output markdown

# All issues including info level
flowlyt --repo . --min-severity INFO --output cli
```

#### By Rule Categories
```bash
# Using configuration file to filter by categories
# .flowlyt.yml
rules:
  enabled:
    - "HARDCODED_SECRET"      # SECRET_EXPOSURE category
    - "DANGEROUS_COMMAND"     # COMMAND_INJECTION category
    - "MALICIOUS_BASE64_DECODE"  # MALICIOUS_PATTERN category

flowlyt --config .flowlyt.yml --repo . --output json
```

#### By File Patterns
```bash
# Using configuration file to focus on specific files
# .flowlyt.yml
ignore:
  files:
    - "test/**/*"      # Ignore test files
    - "docs/**/*"      # Ignore documentation
    - "examples/**/*"  # Ignore examples

flowlyt --config .flowlyt.yml --repo . --output markdown
```

### Custom Report Templates

#### Environment-Specific Reports

**Development Environment Report:**
```bash
# .flowlyt.dev.yml
output:
  format: "cli"
  min_severity: "MEDIUM"
  show_remediation: true
  include_context: true

flowlyt --config .flowlyt.dev.yml --repo .
```

**Production Environment Report:**
```bash
# .flowlyt.prod.yml
output:
  format: "json"
  min_severity: "HIGH"
  fields:
    - "summary"
    - "critical_findings_only"

flowlyt --config .flowlyt.prod.yml --repo .
```

## Advanced Reporting Features

### Report Aggregation

Combine multiple scans into a single report:

```bash
#!/bin/bash
# aggregate-reports.sh

# Scan different environments
flowlyt --config .flowlyt.dev.yml --repo . --output json > dev-report.json
flowlyt --config .flowlyt.staging.yml --repo . --output json > staging-report.json
flowlyt --config .flowlyt.prod.yml --repo . --output json > prod-report.json

# Combine reports
jq -n '
{
  "scan_time": now | strftime("%Y-%m-%dT%H:%M:%SZ"),
  "environments": {
    "development": input,
    "staging": input,
    "production": input
  }
}' dev-report.json staging-report.json prod-report.json > combined-report.json
```

### Trend Analysis

Track security improvements over time:

```bash
#!/bin/bash
# trend-analysis.sh

DATE=$(date +%Y-%m-%d)
REPORT_DIR="security-reports"

mkdir -p "$REPORT_DIR"

# Generate daily report
flowlyt --repo . --output json --output-file "$REPORT_DIR/security-$DATE.json"

# Generate trend summary
jq -r '
["Date", "Critical", "High", "Medium", "Low", "Total"],
(
  inputs | 
  [
    (input_filename | split("/")[-1] | split(".")[0] | split("-")[-1]),
    .summary.critical,
    .summary.high,
    .summary.medium,
    .summary.low,
    .summary.total
  ]
) | @csv
' "$REPORT_DIR"/security-*.json > "$REPORT_DIR/trend-analysis.csv"
```

### Compliance Reports

Generate compliance-focused reports:

```bash
# SOC 2 focused configuration
# .flowlyt.soc2.yml
rules:
  enabled:
    - "HARDCODED_SECRET"
    - "BROAD_PERMISSIONS"
    - "INSECURE_PULL_REQUEST_TARGET"
  custom_rules:
    - id: "SOC2_ACCESS_CONTROL"
      name: "SOC 2 Access Control"
      description: "Ensures proper access controls per SOC 2 requirements"
      severity: "HIGH"
      pattern: "permissions:\\s*write-all"
      remediation: "Use principle of least privilege"

flowlyt --config .flowlyt.soc2.yml --repo . --output markdown --output-file SOC2-COMPLIANCE-REPORT.md
```

## Integration with External Tools

### GitHub Security Tab

Convert Flowlyt output to SARIF format for GitHub Security tab:

```bash
#!/bin/bash
# convert-to-sarif.sh

# Generate Flowlyt report
flowlyt --repo . --output json > flowlyt-report.json

# Convert to SARIF format (requires custom converter)
python3 scripts/flowlyt-to-sarif.py flowlyt-report.json > flowlyt-results.sarif

# Upload to GitHub (in CI/CD)
# Uses github/codeql-action/upload-sarif action
```

### Slack Integration

Send report summaries to Slack:

```bash
#!/bin/bash
# slack-notification.sh

# Generate report
flowlyt --repo . --output json > security-report.json

# Extract summary
CRITICAL=$(jq '.summary.critical' security-report.json)
HIGH=$(jq '.summary.high' security-report.json)
MEDIUM=$(jq '.summary.medium' security-report.json)

# Send to Slack
curl -X POST -H 'Content-type: application/json' \
  --data "{
    \"text\": \"🔍 Security Scan Results\",
    \"attachments\": [{
      \"color\": \"$([ $CRITICAL -gt 0 ] && echo danger || echo good)\",
      \"fields\": [
        {\"title\": \"Critical\", \"value\": \"$CRITICAL\", \"short\": true},
        {\"title\": \"High\", \"value\": \"$HIGH\", \"short\": true},
        {\"title\": \"Medium\", \"value\": \"$MEDIUM\", \"short\": true}
      ]
    }]
  }" \
  "$SLACK_WEBHOOK_URL"
```

### Email Reports

Generate and email security reports:

```bash
#!/bin/bash
# email-report.sh

# Generate markdown report
flowlyt --repo . --output markdown --output-file security-report.md

# Convert to HTML (requires pandoc)
pandoc security-report.md -o security-report.html

# Send email (requires mailutils)
mail -s "Security Scan Report - $(date)" \
     -a "Content-Type: text/html" \
     security-team@company.com < security-report.html
```

## Report Automation

### Scheduled Reports

```yaml
# .github/workflows/scheduled-security-report.yml
name: Scheduled Security Report
on:
  schedule:
    - cron: '0 6 * * 1'  # Every Monday at 6 AM

jobs:
  security-report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Flowlyt
        run: GOPRIVATE=github.com/harekrishnarai/flowlyt go install github.com/harekrishnarai/flowlyt/v2/cmd/flowlyt@latest
      
      - name: Generate Weekly Report
        run: |
          flowlyt --repo . \
                  --output markdown \
                  --output-file weekly-security-report.md
      
      - name: Create Issue with Report
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('weekly-security-report.md', 'utf8');
            
            github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: `Weekly Security Report - ${new Date().toISOString().split('T')[0]}`,
              body: report,
              labels: ['security', 'report']
            });
```

### Progressive Reports

Track security improvement over time:

```bash
#!/bin/bash
# progressive-report.sh

CURRENT_REPORT="current-security.json"
PREVIOUS_REPORT="previous-security.json"

# Generate current report
flowlyt --repo . --output json > "$CURRENT_REPORT"

if [ -f "$PREVIOUS_REPORT" ]; then
  # Compare with previous scan
  CURRENT_CRITICAL=$(jq '.summary.critical' "$CURRENT_REPORT")
  PREVIOUS_CRITICAL=$(jq '.summary.critical' "$PREVIOUS_REPORT")
  
  CURRENT_HIGH=$(jq '.summary.high' "$CURRENT_REPORT")
  PREVIOUS_HIGH=$(jq '.summary.high' "$PREVIOUS_REPORT")
  
  echo "Security Trend Analysis:"
  echo "Critical: $PREVIOUS_CRITICAL → $CURRENT_CRITICAL ($(($CURRENT_CRITICAL - $PREVIOUS_CRITICAL)))"
  echo "High: $PREVIOUS_HIGH → $CURRENT_HIGH ($(($CURRENT_HIGH - $PREVIOUS_HIGH)))"
  
  if [ $CURRENT_CRITICAL -lt $PREVIOUS_CRITICAL ] || [ $CURRENT_HIGH -lt $PREVIOUS_HIGH ]; then
    echo "✅ Security posture improved!"
  elif [ $CURRENT_CRITICAL -gt $PREVIOUS_CRITICAL ] || [ $CURRENT_HIGH -gt $PREVIOUS_HIGH ]; then
    echo "⚠️ Security posture declined!"
  else
    echo "📊 Security posture unchanged"
  fi
fi

# Archive current report as previous
cp "$CURRENT_REPORT" "$PREVIOUS_REPORT"
```

## Best Practices for Reporting

### 1. Choose the Right Format

**CLI Format:**
- ✅ Interactive terminal use
- ✅ Quick manual reviews
- ✅ Developer-friendly output
- ❌ Not suitable for automation

**JSON Format:**
- ✅ CI/CD automation
- ✅ Integration with other tools
- ✅ Programmatic processing
- ❌ Not human-readable

**Markdown Format:**
- ✅ Documentation and reports
- ✅ GitHub/GitLab integration
- ✅ Human-readable and processable
- ❌ Limited automation capabilities

### 2. Report Storage and Retention

```bash
# Organize reports by date and environment
reports/
├── 2025-01-15/
│   ├── dev-security-report.json
│   ├── staging-security-report.json
│   └── prod-security-report.json
├── 2025-01-16/
│   └── ...
└── archives/
    └── 2024/
```

### 3. Report Distribution

**Development Team:**
- CLI output for immediate feedback
- JSON reports for automation
- Weekly summary reports

**Security Team:**
- Comprehensive markdown reports
- Trend analysis reports
- Compliance-focused reports

**Management:**
- Executive summary reports
- Trend dashboards
- KPI tracking

### 4. Report Security

**Sensitive Information:**
- Mask actual secret values in reports
- Sanitize file paths if needed
- Control report access and distribution

**Example sanitized output:**
```json
{
  "evidence": "API_KEY: \"***REDACTED***\"",
  "description": "Hardcoded secret detected (value masked for security)"
}
```

---

**Next:** [Troubleshooting](troubleshooting.md)
