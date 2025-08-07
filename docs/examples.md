# Examples

This document provides comprehensive examples of using Flowlyt in various scenarios, from basic usage to advanced enterprise deployments.

## Table of Contents

1. [Basic Usage Examples](#basic-usage-examples)
2. [Configuration Examples](#configuration-examples)
3. [Custom Rules Examples](#custom-rules-examples)
4. [CI/CD Integration Examples](#cicd-integration-examples)
5. [Enterprise Deployment Examples](#enterprise-deployment-examples)
6. [Compliance Examples](#compliance-examples)
7. [Real-World Scenarios](#real-world-scenarios)

## Basic Usage Examples

### Example 1: First Security Scan

Perform your first security scan on a GitHub repository:

```bash
# Clone a sample repository
git clone https://github.com/example/sample-repo.git
cd sample-repo

# Run basic security scan
flowlyt --repo .
```

**Expected Output:**
```
🔍 Flowlyt - Multi-Platform CI/CD Security Analyzer
Platform: GITHUB
=======================================

► SCAN INFORMATION
Repository:          ./sample-repo
Scan Time:           Thu, 10 Jul 2025 16:00:00 IST
Workflows Analyzed:  2
Rules Applied:       8

► SUMMARY
  SEVERITY | COUNT | INDICATOR       
-----------+-------+-----------------
  HIGH     |   1   | ██████████████  
  MEDIUM   |   2   | ████████        
  LOW      |   0   |                 
  TOTAL    |   3   |                 

► FINDINGS
[HIGH] Hardcoded Secret
└─ File: .github/workflows/deploy.yml (Line 15)
   Evidence: GITHUB_TOKEN: "ghp_xxxxxxxxxxxxxxxxxxxx"
   Remediation: Use GitHub secrets instead of hardcoded tokens
```

### Example 2: JSON Output for Automation

Generate machine-readable output for CI/CD integration:

```bash
# Generate JSON report
flowlyt --repo . --output json --output-file security-report.json

# View specific findings
cat security-report.json | jq '.findings[] | select(.severity == "HIGH")'

# Count issues by severity
cat security-report.json | jq '.summary'
```

### Example 3: Filtering by Severity

Focus on critical and high-severity issues only:

```bash
# Show only high and critical issues
flowlyt --repo . --min-severity HIGH

# Show all issues including informational
flowlyt --repo . --min-severity INFO

# Custom severity filtering via config
cat > .flowlyt.yml << 'EOF'
output:
  min_severity: "MEDIUM"
  show_remediation: true
EOF

flowlyt --repo . --config .flowlyt.yml
```

## Configuration Examples

### Example 1: Basic Configuration

**.flowlyt.yml** - Simple configuration for a development team:

```yaml
# Basic Flowlyt configuration for development team
output:
  format: "cli"
  min_severity: "MEDIUM"
  show_remediation: true

rules:
  enabled:
    - "HARDCODED_SECRET"
    - "DANGEROUS_COMMAND"
    - "BROAD_PERMISSIONS"
    - "INSECURE_PULL_REQUEST_TARGET"

ignore:
  files:
    - "test/**/*"
    - "docs/**/*"
    - "examples/**/*"
  
  patterns:
    - "**/*-test.yml"
    - "**/example-*.yml"

# Team-specific settings
team:
  name: "backend-team"
  notification_channel: "#backend-security"
```

### Example 2: Environment-Specific Configuration

Different configurations for different environments:

**.flowlyt.dev.yml** - Development environment:
```yaml
# Development environment - more permissive
output:
  format: "cli"
  min_severity: "HIGH"

rules:
  enabled:
    - "HARDCODED_SECRET"
    - "DANGEROUS_COMMAND"
  
  # Allow some risky patterns in development
  disabled:
    - "BROAD_PERMISSIONS"

ignore:
  files:
    - "test/**/*"
    - "dev-scripts/**/*"
    - "local-testing/**/*"
```

**.flowlyt.prod.yml** - Production environment:
```yaml
# Production environment - strict security
output:
  format: "json"
  min_severity: "MEDIUM"
  fail_on_violation: true

rules:
  enabled:
    - "HARDCODED_SECRET"
    - "DANGEROUS_COMMAND"
    - "BROAD_PERMISSIONS"
    - "INSECURE_PULL_REQUEST_TARGET"
    - "MALICIOUS_BASE64_DECODE"

ignore:
  files:
    - "test/**/*"  # Only ignore test files

# Strict compliance requirements
compliance:
  frameworks:
    - "SOC2"
    - "PCI-DSS"
  fail_on_non_compliance: true
```

### Example 3: Organization-Wide Configuration

**.flowlyt.yml** - Enterprise organization configuration:

```yaml
# Organization-wide security policy
policy:
  version: "2.0"
  name: "Acme Corp Security Policy"
  owner: "security-team@acme.com"

# Global security baseline
rules:
  enabled:
    - "HARDCODED_SECRET"
    - "DANGEROUS_COMMAND"
    - "BROAD_PERMISSIONS"
    - "INSECURE_PULL_REQUEST_TARGET"
    - "MALICIOUS_BASE64_DECODE"
    - "SUPPLY_CHAIN_ATTACK"

# Organization-specific custom rules
custom_rules:
  - id: "ACME_INTERNAL_SECRETS"
    name: "Acme Internal Secret Detection"
    description: "Detects Acme-specific secret patterns"
    severity: "CRITICAL"
    patterns:
      - "ACME_API_KEY_[A-Za-z0-9]{32}"
      - "ACME_INTERNAL_TOKEN_[A-Fa-f0-9]{40}"
    remediation: "Use Acme Vault for secret management"

# Compliance frameworks
compliance:
  frameworks:
    - "SOC2"
    - "PCI-DSS"
    - "ISO27001"
  
  reporting:
    generate_compliance_report: true
    include_evidence: true

# Organization-wide ignore patterns
ignore:
  files:
    - "test/**/*"
    - "tests/**/*"
    - "spec/**/*"
    - "docs/**/*"
    - "examples/**/*"
    - "vendor/**/*"
    - "node_modules/**/*"

# Notification settings
notifications:
  slack:
    webhook_url: "https://hooks.slack.com/services/..."
    channel: "#security-alerts"
    mention_on_critical: true
  
  email:
    smtp_server: "smtp.acme.com"
    recipients:
      - "security-team@acme.com"
      - "compliance@acme.com"
```

## Custom Rules Examples

### Example 1: Company-Specific Secret Detection

Create custom rules for organization-specific secrets:

**custom-rules.yml:**
```yaml
custom_rules:
  # Company API key detection
  - id: "COMPANY_API_KEYS"
    name: "Company API Key Detection"
    description: "Detects company-specific API key patterns"
    severity: "CRITICAL"
    category: "SECRET_EXPOSURE"
    patterns:
      - "COMPANY_API_KEY_[A-Za-z0-9]{32}"
      - "COMP_SECRET_[A-Fa-f0-9]{64}"
      - "INTERNAL_TOKEN_[0-9a-f]{40}"
    remediation: |
      Company secrets detected. Please:
      1. Remove the hardcoded secret
      2. Use GitHub secrets: ${{ secrets.COMPANY_API_KEY }}
      3. Report to security@company.com
    references:
      - "https://docs.company.com/security/secrets"

  # Internal service authentication
  - id: "INTERNAL_SERVICE_AUTH"
    name: "Internal Service Authentication"
    description: "Detects internal service authentication patterns"
    severity: "HIGH"
    category: "ACCESS_CONTROL"
    patterns:
      - "service_account_[a-z_]+@company\\.internal"
      - "INTERNAL_SERVICE_[A-Z_]+_KEY"
    remediation: "Use service account authentication via Workload Identity"

  # Deprecated security patterns
  - id: "DEPRECATED_SECURITY_PATTERNS"
    name: "Deprecated Security Patterns"
    description: "Identifies usage of deprecated security patterns"
    severity: "MEDIUM"
    category: "DEPRECATED"
    patterns:
      - "md5sum"
      - "sha1sum"
      - "--insecure"
      - "--disable-ssl"
    remediation: "Use approved security practices: docs/security-standards.md"
```

### Example 2: Infrastructure-Specific Rules

Rules for infrastructure and DevOps teams:

**infra-rules.yml:**
```yaml
custom_rules:
  # Cloud provider credentials
  - id: "CLOUD_CREDENTIALS"
    name: "Cloud Provider Credential Detection"
    description: "Detects cloud provider credentials"
    severity: "CRITICAL"
    category: "CLOUD_SECURITY"
    patterns:
      - "AWS_ACCESS_KEY_ID\\s*[:=]\\s*[A-Z0-9]{20}"
      - "AZURE_CLIENT_SECRET\\s*[:=]\\s*[A-Za-z0-9+/]{44}"
      - "GOOGLE_APPLICATION_CREDENTIALS"
    remediation: "Use cloud-native authentication (IAM roles, Workload Identity)"

  # Kubernetes security
  - id: "KUBERNETES_SECURITY"
    name: "Kubernetes Security Issues"
    description: "Identifies Kubernetes security anti-patterns"
    severity: "HIGH"
    category: "CONTAINER_SECURITY"
    patterns:
      - "privileged:\\s*true"
      - "runAsRoot:\\s*true"
      - "allowPrivilegeEscalation:\\s*true"
    remediation: "Follow Kubernetes security best practices"

  # Infrastructure exposure
  - id: "INFRASTRUCTURE_EXPOSURE"
    name: "Infrastructure Information Exposure"
    description: "Detects exposure of infrastructure information"
    severity: "MEDIUM"
    category: "INFORMATION_DISCLOSURE"
    patterns:
      - "\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b"  # IP addresses
      - "\\w+\\.internal\\b"  # Internal hostnames
      - "password\\s*[:=]\\s*[^\\s\"']+"  # Plain passwords
    remediation: "Avoid hardcoding infrastructure details"
```

### Example 3: Application-Specific Rules

Rules for specific application types:

**app-specific-rules.yml:**
```yaml
custom_rules:
  # Database connection strings
  - id: "DATABASE_CONNECTIONS"
    name: "Database Connection String Detection"
    description: "Detects hardcoded database connections"
    severity: "HIGH"
    category: "DATABASE_SECURITY"
    patterns:
      - "mysql://[^\\s\"']+:[^\\s\"']+@"
      - "postgresql://[^\\s\"']+:[^\\s\"']+@"
      - "mongodb://[^\\s\"']+:[^\\s\"']+@"
    remediation: "Use environment variables for database connections"

  # API endpoints exposure
  - id: "API_ENDPOINT_EXPOSURE"
    name: "API Endpoint Exposure"
    description: "Detects hardcoded API endpoints"
    severity: "MEDIUM"
    category: "INFORMATION_DISCLOSURE"
    patterns:
      - "https://api\\.[a-z0-9-]+\\.[a-z]{2,}/[^\\s\"']+"
      - "https://[a-z0-9-]+\\.amazonaws\\.com/[^\\s\"']+"
    remediation: "Use configuration management for API endpoints"

  # License and legal compliance
  - id: "LICENSE_COMPLIANCE"
    name: "License Compliance Check"
    description: "Ensures proper license compliance"
    severity: "LOW"
    category: "COMPLIANCE"
    patterns:
      - "uses:.*@master"  # Should pin to specific versions
      - "uses:.*@main"    # Should pin to specific versions
    remediation: "Pin action versions for security and compliance"
```

## CI/CD Integration Examples

### Example 1: GitHub Actions Integration

**.github/workflows/security-scan.yml:**
```yaml
name: Security Scan with Flowlyt

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # Weekly scan on Mondays

jobs:
  security-analysis:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write  # For SARIF upload
      
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        
      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
          
      - name: Install Flowlyt
        run: go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
        
      - name: Run security analysis
        run: |
          flowlyt --repo . \
                  --output json \
                  --output-file security-report.json \
                  --config .flowlyt.yml
                  
      - name: Upload security report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.json
          retention-days: 30
          
      - name: Check for critical issues
        run: |
          CRITICAL_COUNT=$(jq '.summary.critical' security-report.json)
          HIGH_COUNT=$(jq '.summary.high' security-report.json)
          
          echo "Critical issues: $CRITICAL_COUNT"
          echo "High severity issues: $HIGH_COUNT"
          
          if [ "$CRITICAL_COUNT" -gt 0 ]; then
            echo "❌ Critical security issues found!"
            jq -r '.findings[] | select(.severity == "CRITICAL") | "- \(.rule_name) in \(.file_path):\(.line_number)"' security-report.json
            exit 1
          fi
          
          if [ "$HIGH_COUNT" -gt 5 ]; then
            echo "⚠️ Too many high-severity issues found!"
            exit 1
          fi
          
          echo "✅ Security scan passed"
          
      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = JSON.parse(fs.readFileSync('security-report.json'));
            
            const summary = `## 🔍 Security Analysis Results
            
            | Severity | Count |
            |----------|-------|
            | Critical | ${report.summary.critical} |
            | High     | ${report.summary.high} |
            | Medium   | ${report.summary.medium} |
            | Low      | ${report.summary.low} |
            
            ${report.summary.critical > 0 ? '❌ Critical issues found - please review' : '✅ No critical issues found'}
            `;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: summary
            });
```

### Example 2: GitLab CI Integration

**.gitlab-ci.yml:**
```yaml
stages:
  - security
  - deploy

variables:
  FLOWLYT_VERSION: "latest"

security_scan:
  stage: security
  image: golang:1.21-alpine
  before_script:
    - apk add --no-cache git
    - go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@${FLOWLYT_VERSION}
    - export PATH=$PATH:$(go env GOPATH)/bin
  script:
    - |
      echo "Running Flowlyt security analysis..."
      flowlyt --repo . \
              --output json \
              --output-file security-report.json \
              --config .flowlyt.yml
      
      # Check for critical issues
      CRITICAL_COUNT=$(jq '.summary.critical' security-report.json)
      if [ "$CRITICAL_COUNT" -gt 0 ]; then
        echo "❌ Critical security issues found!"
        jq -r '.findings[] | select(.severity == "CRITICAL")' security-report.json
        exit 1
      fi
      
      echo "✅ Security scan completed successfully"
  artifacts:
    reports:
      junit: security-report.json
    paths:
      - security-report.json
    expire_in: 1 week
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
    - if: $CI_PIPELINE_SOURCE == "schedule"

security_notifications:
  stage: security
  image: alpine:latest
  dependencies:
    - security_scan
  before_script:
    - apk add --no-cache curl jq
  script:
    - |
      if [ -f security-report.json ]; then
        TOTAL_ISSUES=$(jq '.summary.total' security-report.json)
        CRITICAL_ISSUES=$(jq '.summary.critical' security-report.json)
        
        if [ "$TOTAL_ISSUES" -gt 0 ]; then
          # Send to Slack
          curl -X POST -H 'Content-type: application/json' \
            --data "{
              \"text\": \"🔍 Security Scan Results for $CI_PROJECT_NAME\",
              \"attachments\": [{
                \"color\": \"$([ $CRITICAL_ISSUES -gt 0 ] && echo danger || echo warning)\",
                \"fields\": [
                  {\"title\": \"Critical\", \"value\": \"$CRITICAL_ISSUES\", \"short\": true},
                  {\"title\": \"Total\", \"value\": \"$TOTAL_ISSUES\", \"short\": true},
                  {\"title\": \"Pipeline\", \"value\": \"$CI_PIPELINE_URL\", \"short\": false}
                ]
              }]
            }" \
            "$SLACK_WEBHOOK_URL"
        fi
      fi
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  when: always
```

### Example 3: Jenkins Pipeline Integration

**Jenkinsfile:**
```groovy
pipeline {
    agent any
    
    environment {
        FLOWLYT_VERSION = 'latest'
        SLACK_CHANNEL = '#security-alerts'
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Setup Flowlyt') {
            steps {
                script {
                    // Install Go if not available
                    sh '''
                        if ! command -v go &> /dev/null; then
                            echo "Installing Go..."
                            wget -q https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
                            sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
                            export PATH=$PATH:/usr/local/go/bin
                        fi
                        
                        # Install Flowlyt
                        go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@${FLOWLYT_VERSION}
                    '''
                }
            }
        }
        
        stage('Security Analysis') {
            steps {
                script {
                    sh '''
                        export PATH=$PATH:$(go env GOPATH)/bin
                        
                        echo "Running Flowlyt security analysis..."
                        flowlyt --repo . \
                                --output json \
                                --output-file security-report.json \
                                --config .flowlyt.yml
                        
                        # Generate human-readable report
                        flowlyt --repo . \
                                --output markdown \
                                --output-file security-report.md \
                                --config .flowlyt.yml
                    '''
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'security-report.*', fingerprint: true
                    
                    script {
                        // Parse results
                        def report = readJSON file: 'security-report.json'
                        def criticalCount = report.summary.critical
                        def highCount = report.summary.high
                        
                        if (criticalCount > 0) {
                            currentBuild.result = 'FAILURE'
                            error("Critical security issues found: ${criticalCount}")
                        } else if (highCount > 5) {
                            currentBuild.result = 'UNSTABLE'
                            echo "Warning: High number of security issues: ${highCount}"
                        }
                        
                        // Send notification
                        if (report.summary.total > 0) {
                            slackSend(
                                channel: SLACK_CHANNEL,
                                color: criticalCount > 0 ? 'danger' : 'warning',
                                message: """
Security Scan Results for ${env.JOB_NAME} #${env.BUILD_NUMBER}:
Critical: ${criticalCount}
High: ${highCount}
Total: ${report.summary.total}
Build: ${env.BUILD_URL}
                                """.stripIndent()
                            )
                        }
                    }
                }
            }
        }
    }
}
```

## Enterprise Deployment Examples

### Example 1: Multi-Repository Scanning

**scripts/scan-all-repos.sh:**
```bash
#!/bin/bash
# Enterprise script to scan multiple repositories

set -euo pipefail

# Configuration
ORG_NAME="acme-corp"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
OUTPUT_DIR="security-reports"
CONFIG_FILE=".flowlyt-enterprise.yml"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Function to scan a repository
scan_repository() {
    local repo="$1"
    local repo_name=$(basename "$repo")
    local report_file="$OUTPUT_DIR/${repo_name}-security-report.json"
    
    echo "🔍 Scanning repository: $repo"
    
    # Clone repository
    local temp_dir=$(mktemp -d)
    git clone "$repo" "$temp_dir" 2>/dev/null || {
        echo "❌ Failed to clone $repo"
        return 1
    }
    
    cd "$temp_dir"
    
    # Run security scan
    if flowlyt --repo . \
               --output json \
               --output-file "$report_file" \
               --config "$CONFIG_FILE" 2>/dev/null; then
        echo "✅ Scan completed for $repo_name"
        
        # Check for critical issues
        local critical_count=$(jq '.summary.critical' "$report_file" 2>/dev/null || echo "0")
        if [ "$critical_count" -gt 0 ]; then
            echo "🚨 CRITICAL: $critical_count critical issues found in $repo_name"
        fi
    else
        echo "❌ Scan failed for $repo_name"
    fi
    
    # Cleanup
    cd - > /dev/null
    rm -rf "$temp_dir"
}

# Get list of repositories
echo "📋 Fetching repository list for organization: $ORG_NAME"

if [ -n "$GITHUB_TOKEN" ]; then
    # Use GitHub API to get repositories
    repos=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
                 "https://api.github.com/orgs/$ORG_NAME/repos?per_page=100" | \
            jq -r '.[].clone_url')
else
    # Manual list of repositories
    repos=(
        "https://github.com/$ORG_NAME/repo1.git"
        "https://github.com/$ORG_NAME/repo2.git"
        "https://github.com/$ORG_NAME/repo3.git"
    )
fi

# Scan repositories in parallel
echo "🚀 Starting parallel repository scans..."
export -f scan_repository
echo "$repos" | xargs -n 1 -P 5 -I {} bash -c 'scan_repository "{}"'

# Generate summary report
echo "📊 Generating summary report..."
python3 << 'EOF'
import json
import glob
from collections import defaultdict

# Collect all reports
reports = []
for report_file in glob.glob("security-reports/*-security-report.json"):
    try:
        with open(report_file, 'r') as f:
            report = json.load(f)
            report['repository'] = report_file.replace('security-reports/', '').replace('-security-report.json', '')
            reports.append(report)
    except Exception as e:
        print(f"Error reading {report_file}: {e}")

# Generate summary
summary = {
    'total_repositories': len(reports),
    'repositories_with_issues': sum(1 for r in reports if r['summary']['total'] > 0),
    'total_critical': sum(r['summary']['critical'] for r in reports),
    'total_high': sum(r['summary']['high'] for r in reports),
    'total_medium': sum(r['summary']['medium'] for r in reports),
    'total_low': sum(r['summary']['low'] for r in reports),
    'by_repository': [
        {
            'name': r['repository'],
            'critical': r['summary']['critical'],
            'high': r['summary']['high'],
            'total': r['summary']['total']
        }
        for r in reports
    ]
}

# Save summary
with open('security-reports/summary.json', 'w') as f:
    json.dump(summary, f, indent=2)

print(f"📈 Summary:")
print(f"  Total repositories scanned: {summary['total_repositories']}")
print(f"  Repositories with issues: {summary['repositories_with_issues']}")
print(f"  Critical issues: {summary['total_critical']}")
print(f"  High severity issues: {summary['total_high']}")
print(f"  Total issues: {summary['total_critical'] + summary['total_high'] + summary['total_medium'] + summary['total_low']}")
EOF

echo "✅ Enterprise security scan completed. Reports available in: $OUTPUT_DIR"
```

### Example 2: Automated Compliance Reporting

**scripts/compliance-report.sh:**
```bash
#!/bin/bash
# Generate compliance reports for enterprise

# Configuration
REPORT_DATE=$(date +%Y-%m-%d)
COMPLIANCE_DIR="compliance-reports/$REPORT_DATE"
FRAMEWORKS=("SOC2" "PCI-DSS" "HIPAA")

mkdir -p "$COMPLIANCE_DIR"

echo "🏢 Generating Enterprise Compliance Report - $REPORT_DATE"

# Function to generate framework-specific report
generate_compliance_report() {
    local framework="$1"
    local config_file=".flowlyt-${framework,,}.yml"
    local output_file="$COMPLIANCE_DIR/${framework,,}-compliance-report.json"
    
    echo "📋 Generating $framework compliance report..."
    
    # Scan with framework-specific configuration
    flowlyt --repo . \
            --config "$config_file" \
            --output json \
            --output-file "$output_file" \
            --compliance-framework "$framework"
    
    # Generate compliance summary
    python3 << EOF
import json

with open('$output_file', 'r') as f:
    report = json.load(f)

compliance_score = 100 - (
    report['summary']['critical'] * 20 +
    report['summary']['high'] * 10 +
    report['summary']['medium'] * 5 +
    report['summary']['low'] * 1
)

compliance_status = {
    'framework': '$framework',
    'scan_date': '$REPORT_DATE',
    'compliance_score': max(0, compliance_score),
    'status': 'COMPLIANT' if compliance_score >= 95 else 'NON_COMPLIANT',
    'critical_issues': report['summary']['critical'],
    'total_issues': report['summary']['total'],
    'recommendations': []
}

if report['summary']['critical'] > 0:
    compliance_status['recommendations'].append('Address all critical security issues immediately')

if report['summary']['high'] > 5:
    compliance_status['recommendations'].append('Reduce high-severity issues to improve compliance score')

with open('$COMPLIANCE_DIR/${framework,,}-status.json', 'w') as f:
    json.dump(compliance_status, f, indent=2)

print(f"$framework Compliance Score: {compliance_score}%")
print(f"Status: {compliance_status['status']}")
EOF
}

# Generate reports for each framework
for framework in "${FRAMEWORKS[@]}"; do
    generate_compliance_report "$framework"
done

# Generate executive summary
python3 << 'EOF'
import json
import glob
from datetime import datetime

# Collect all compliance statuses
statuses = []
for status_file in glob.glob(f"compliance-reports/{os.environ['REPORT_DATE']}/*-status.json"):
    with open(status_file, 'r') as f:
        status = json.load(f)
        statuses.append(status)

# Generate executive summary
executive_summary = {
    'report_date': os.environ['REPORT_DATE'],
    'organization': 'Acme Corporation',
    'overall_status': 'COMPLIANT' if all(s['status'] == 'COMPLIANT' for s in statuses) else 'NON_COMPLIANT',
    'frameworks': statuses,
    'recommendations': [
        'Implement automated security scanning in all CI/CD pipelines',
        'Establish regular security training for development teams',
        'Review and update security policies quarterly'
    ],
    'next_review_date': (datetime.now() + timedelta(days=90)).strftime('%Y-%m-%d')
}

with open(f"compliance-reports/{os.environ['REPORT_DATE']}/executive-summary.json", 'w') as f:
    json.dump(executive_summary, f, indent=2)

print("📊 Executive Summary Generated")
print(f"Overall Status: {executive_summary['overall_status']}")
for status in statuses:
    print(f"  {status['framework']}: {status['compliance_score']}% ({status['status']})")
EOF

echo "✅ Compliance reporting completed. Reports available in: $COMPLIANCE_DIR"
```

### Example 3: Policy Management System

**scripts/policy-management.sh:**
```bash
#!/bin/bash
# Enterprise policy management system

POLICY_REPO="git@github.com:acme-corp/security-policies.git"
POLICY_DIR="security-policies"
ROLLOUT_CONFIG="rollout-config.yml"

# Function to deploy policies
deploy_policies() {
    local environment="$1"
    local scope="$2"
    
    echo "🚀 Deploying policies to $environment (scope: $scope)"
    
    case "$scope" in
        "pilot")
            # Deploy to pilot repositories only
            repositories=("acme-corp/pilot-app1" "acme-corp/pilot-app2")
            ;;
        "gradual")
            # Deploy to 50% of repositories
            repositories=$(get_repository_list | head -n $(($(get_repository_list | wc -l) / 2)))
            ;;
        "full")
            # Deploy to all repositories
            repositories=$(get_repository_list)
            ;;
    esac
    
    for repo in "${repositories[@]}"; do
        echo "  📦 Deploying to $repo"
        deploy_to_repository "$repo" "$environment"
    done
}

# Function to get repository list
get_repository_list() {
    # Implementation depends on your repository management system
    curl -s -H "Authorization: token $GITHUB_TOKEN" \
         "https://api.github.com/orgs/acme-corp/repos?per_page=100" | \
    jq -r '.[].full_name'
}

# Function to deploy to specific repository
deploy_to_repository() {
    local repo="$1"
    local environment="$2"
    local policy_file="policies/${environment}.flowlyt.yml"
    
    # Clone repository
    local temp_dir=$(mktemp -d)
    git clone "https://github.com/$repo.git" "$temp_dir"
    cd "$temp_dir"
    
    # Copy policy file
    cp "$POLICY_DIR/$policy_file" ".flowlyt.yml"
    
    # Create PR with policy update
    git checkout -b "security/update-policy-$(date +%Y%m%d)"
    git add .flowlyt.yml
    git commit -m "Update security policy for $environment environment"
    git push origin "security/update-policy-$(date +%Y%m%d)"
    
    # Create pull request (using GitHub CLI)
    gh pr create \
        --title "Security Policy Update - $environment" \
        --body "Automated policy update for $environment environment" \
        --label "security,automated"
    
    # Cleanup
    cd - > /dev/null
    rm -rf "$temp_dir"
}

# Main execution
case "${1:-}" in
    "deploy")
        deploy_policies "${2:-production}" "${3:-full}"
        ;;
    "validate")
        echo "🔍 Validating policies..."
        flowlyt validate-policies --directory "$POLICY_DIR"
        ;;
    "test")
        echo "🧪 Testing policies..."
        flowlyt test-policies \
                --policies "$POLICY_DIR" \
                --test-cases "test-cases/" \
                --output "policy-test-results.json"
        ;;
    *)
        echo "Usage: $0 {deploy|validate|test} [environment] [scope]"
        echo "  deploy: Deploy policies to repositories"
        echo "  validate: Validate policy syntax and structure"
        echo "  test: Test policies against known test cases"
        exit 1
        ;;
esac
```

## Compliance Examples

### Example 1: SOC 2 Type II Compliance

**Configuration for SOC 2 compliance:**

**.flowlyt-soc2.yml:**
```yaml
# SOC 2 Type II Compliance Configuration
policy:
  name: "SOC 2 Type II Security Policy"
  framework: "SOC2"
  type: "Type II"
  
compliance_controls:
  # CC6.1 - Logical and Physical Access Controls
  access_controls:
    rules:
      - "MULTI_FACTOR_AUTHENTICATION"
      - "PRINCIPLE_LEAST_PRIVILEGE"
      - "ACCESS_REVIEW_QUARTERLY"
    implementation:
      - check: "GitHub branch protection enabled"
      - check: "Required reviewers for production changes"
      - check: "Admin access logged and monitored"
      
  # CC6.7 - System Operations
  system_operations:
    rules:
      - "CHANGE_MANAGEMENT_DOCUMENTED"
      - "DEPLOYMENT_APPROVAL_REQUIRED"
      - "ROLLBACK_PROCEDURES_TESTED"
    implementation:
      - check: "Pull request workflow enforced"
      - check: "Production deployments require approval"
      - check: "Automated rollback capabilities verified"

# SOC 2 specific rules
rules:
  enabled:
    - "HARDCODED_SECRET"           # Security principle
    - "BROAD_PERMISSIONS"          # Access control
    - "INSECURE_PULL_REQUEST_TARGET"  # Code review process
    - "DANGEROUS_COMMAND"          # System operations
    - "CHANGE_TRACKING_REQUIRED"   # Change management
    
custom_rules:
  - id: "SOC2_AUDIT_LOGGING"
    name: "SOC 2 Audit Logging Requirements"
    description: "Ensures audit logging is implemented"
    severity: "HIGH"
    patterns:
      - "audit.*log.*disabled"
      - "logging.*level.*off"
    remediation: "Enable comprehensive audit logging per SOC 2 requirements"
    
  - id: "SOC2_DATA_ENCRYPTION"
    name: "SOC 2 Data Encryption Requirements"  
    description: "Verifies data encryption in transit and at rest"
    severity: "CRITICAL"
    patterns:
      - "http://"  # Should use HTTPS
      - "ssl.*false"
      - "tls.*disabled"
    remediation: "Use encryption for all data transmission and storage"

# Compliance reporting
reporting:
  include_evidence: true
  generate_attestation: true
  auditor_review_required: true
```

**SOC 2 Compliance Check Script:**

```bash
#!/bin/bash
# soc2-compliance-check.sh

echo "🏛️ SOC 2 Type II Compliance Check"
echo "================================="

# Run SOC 2 specific scan
flowlyt --repo . \
        --config .flowlyt-soc2.yml \
        --output json \
        --output-file soc2-compliance-report.json

# Parse results for SOC 2 specific findings
python3 << 'EOF'
import json

with open('soc2-compliance-report.json', 'r') as f:
    report = json.load(f)

# SOC 2 Control Assessment
controls = {
    'CC6.1': {'critical': 0, 'high': 0, 'medium': 0},  # Access Controls
    'CC6.7': {'critical': 0, 'high': 0, 'medium': 0},  # System Operations
    'CC7.2': {'critical': 0, 'high': 0, 'medium': 0},  # System Monitoring
}

# Map findings to SOC 2 controls
for finding in report.get('findings', []):
    rule_id = finding.get('rule_id', '')
    severity = finding.get('severity', '').lower()
    
    # Map rules to controls (simplified mapping)
    if rule_id in ['HARDCODED_SECRET', 'BROAD_PERMISSIONS']:
        controls['CC6.1'][severity] += 1
    elif rule_id in ['DANGEROUS_COMMAND', 'CHANGE_TRACKING_REQUIRED']:
        controls['CC6.7'][severity] += 1
    elif rule_id in ['SOC2_AUDIT_LOGGING', 'MONITORING_DISABLED']:
        controls['CC7.2'][severity] += 1

# Calculate compliance scores
compliance_scores = {}
for control, findings in controls.items():
    # Simple scoring: Critical = -20, High = -10, Medium = -5
    score = 100 - (findings['critical'] * 20 + findings['high'] * 10 + findings['medium'] * 5)
    compliance_scores[control] = max(0, score)
    
    print(f"Control {control}: {score}% compliant")
    if findings['critical'] > 0:
        print(f"  ❌ Critical issues: {findings['critical']}")
    if findings['high'] > 0:
        print(f"  ⚠️  High issues: {findings['high']}")

# Overall compliance
overall_score = sum(compliance_scores.values()) / len(compliance_scores)
print(f"\n📊 Overall SOC 2 Compliance Score: {overall_score:.1f}%")

if overall_score >= 95:
    print("✅ SOC 2 COMPLIANT")
elif overall_score >= 80:
    print("⚠️ PARTIALLY COMPLIANT - Remediation required")
else:
    print("❌ NON-COMPLIANT - Immediate action required")
EOF
```

### Example 2: PCI DSS Compliance

**.flowlyt-pci.yml:**
```yaml
# PCI DSS Compliance Configuration
policy:
  name: "PCI DSS Security Policy"
  framework: "PCI-DSS"
  version: "4.0"
  scope: "cardholder_data_environment"

# PCI DSS Requirements mapping
pci_requirements:
  # Requirement 2: Do not use vendor-supplied defaults
  req_2:
    rules:
      - "NO_DEFAULT_CREDENTIALS"
      - "SECURE_CONFIGURATION"
    tests:
      - "No default passwords in workflows"
      - "Security settings properly configured"
      
  # Requirement 4: Encrypt transmission of cardholder data
  req_4:
    rules:
      - "ENCRYPTED_COMMUNICATIONS"
      - "STRONG_CRYPTOGRAPHY"
    tests:
      - "TLS 1.2+ required"
      - "No unencrypted sensitive data"
      
  # Requirement 6: Develop secure systems
  req_6:
    rules:
      - "SECURE_DEVELOPMENT"
      - "VULNERABILITY_MANAGEMENT"
    tests:
      - "Security testing in pipeline"
      - "Regular security updates"

rules:
  enabled:
    - "HARDCODED_SECRET"
    - "WEAK_CRYPTOGRAPHY"
    - "INSECURE_PROTOCOLS"
    - "DEFAULT_CREDENTIALS"
    - "UNENCRYPTED_COMMUNICATION"
    
custom_rules:
  - id: "PCI_CARDHOLDER_DATA"
    name: "Cardholder Data Protection"
    description: "Detects potential cardholder data exposure"
    severity: "CRITICAL"
    patterns:
      - "\\b4[0-9]{3}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}\\b"  # Visa
      - "\\b5[1-5][0-9]{2}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}\\b"  # MasterCard
    remediation: "Never store cardholder data in workflows or code"
    
  - id: "PCI_NETWORK_SECURITY"
    name: "Network Security Requirements"
    description: "Ensures network security controls"
    severity: "HIGH"
    patterns:
      - "firewall.*disabled"
      - "iptables.*flush"
      - "ufw.*disable"
    remediation: "Maintain secure network configurations"
```

## Real-World Scenarios

### Example 1: Startup Security Implementation

A growing startup implementing security practices:

```yaml
# .flowlyt-startup.yml
# Progressive security implementation for startup

# Phase 1: Basic security (Month 1-2)
phase_1:
  rules:
    enabled:
      - "HARDCODED_SECRET"      # Critical: prevent credential leaks
      - "DANGEROUS_COMMAND"     # High: prevent command injection
    
  enforcement:
    mode: "advisory"            # Start with warnings
    
  team_training:
    - "Security awareness workshop"
    - "Secure coding practices"

# Phase 2: Enhanced security (Month 3-4)  
phase_2:
  rules:
    enabled:
      - "HARDCODED_SECRET"
      - "DANGEROUS_COMMAND"
      - "BROAD_PERMISSIONS"     # Add permission management
      - "INSECURE_PULL_REQUEST_TARGET"
    
  enforcement:
    mode: "permissive"          # Allow overrides with justification
    
  processes:
    - "Code review process"
    - "Security champion program"

# Phase 3: Mature security (Month 5+)
phase_3:
  rules:
    enabled:
      - "HARDCODED_SECRET"
      - "DANGEROUS_COMMAND"
      - "BROAD_PERMISSIONS"
      - "INSECURE_PULL_REQUEST_TARGET"
      - "SUPPLY_CHAIN_ATTACK"  # Add supply chain security
      - "MALICIOUS_BASE64_DECODE"
    
  enforcement:
    mode: "strict"              # Full enforcement
    
  compliance:
    frameworks: ["SOC2"]        # Start compliance journey
```

### Example 2: Financial Services Implementation

High-security financial services environment:

```yaml
# .flowlyt-finserv.yml
# Financial services security configuration

policy:
  name: "Financial Services Security Policy"
  industry: "financial_services"
  regulatory_requirements:
    - "SOX"          # Sarbanes-Oxley
    - "PCI-DSS"      # Payment Card Industry
    - "FFIEC"        # Federal Financial Institutions Examination Council

# Strict security rules
rules:
  enabled:
    - "HARDCODED_SECRET"
    - "DANGEROUS_COMMAND"
    - "BROAD_PERMISSIONS"
    - "INSECURE_PULL_REQUEST_TARGET"
    - "SUPPLY_CHAIN_ATTACK"
    - "MALICIOUS_BASE64_DECODE"
    - "FINANCIAL_DATA_EXPOSURE"
    - "AUDIT_TRAIL_REQUIRED"
    
# Financial services specific rules
custom_rules:
  - id: "FINANCIAL_DATA_PROTECTION"
    name: "Financial Data Protection"
    description: "Prevents exposure of financial data"
    severity: "CRITICAL"
    patterns:
      - "account[_-]?number"
      - "routing[_-]?number"
      - "swift[_-]?code"
      - "iban[_-]?number"
    remediation: "Use tokenization for financial data"
    
  - id: "REGULATORY_COMPLIANCE"
    name: "Regulatory Compliance Check"
    description: "Ensures regulatory compliance"
    severity: "HIGH"
    patterns:
      - "audit.*disabled"
      - "logging.*off"
      - "encryption.*false"
    remediation: "Maintain audit trails and encryption"

# Strict enforcement
enforcement:
  mode: "strict"
  fail_on_critical: true
  require_security_approval: ["CRITICAL", "HIGH"]
  audit_all_changes: true

# Compliance reporting
reporting:
  generate_compliance_reports: true
  include_audit_trail: true
  notify_regulators: true
```

### Example 3: Healthcare/HIPAA Implementation

Healthcare organization with HIPAA requirements:

```yaml
# .flowlyt-healthcare.yml
# Healthcare/HIPAA security configuration

policy:
  name: "Healthcare Security Policy"
  industry: "healthcare"
  regulatory_requirements:
    - "HIPAA"        # Health Insurance Portability and Accountability Act
    - "HITECH"       # Health Information Technology for Economic and Clinical Health

# HIPAA-focused security rules
rules:
  enabled:
    - "HARDCODED_SECRET"
    - "PHI_EXPOSURE"             # Protected Health Information
    - "ENCRYPTION_REQUIRED"
    - "ACCESS_LOGGING_MANDATORY"
    - "AUDIT_TRAIL_COMPLETE"
    
# Healthcare specific rules
custom_rules:
  - id: "PHI_DETECTION"
    name: "Protected Health Information Detection"
    description: "Detects potential PHI in workflows"
    severity: "CRITICAL"
    patterns:
      - "ssn[_-]?\\d{3}[_-]?\\d{2}[_-]?\\d{4}"
      - "medical[_-]?record[_-]?number"
      - "patient[_-]?id"
      - "diagnosis[_-]?code"
    remediation: "Remove PHI from workflows, use de-identified data"
    
  - id: "HIPAA_ENCRYPTION"
    name: "HIPAA Encryption Requirements"
    description: "Ensures encryption meets HIPAA standards"
    severity: "HIGH"
    patterns:
      - "encryption.*aes128"      # Require AES-256
      - "ssl.*v[12]"              # Require TLS 1.2+
      - "md5|sha1"                # Weak hashing
    remediation: "Use HIPAA-compliant encryption standards"

# Business Associate Agreements
business_associates:
  - "GitHub"
  - "AWS"
  - "Azure"
  - "Google Cloud"

# HIPAA compliance checks
hipaa_safeguards:
  administrative:
    - "security_officer_assigned"
    - "workforce_training_completed"
    - "access_management_documented"
    
  physical:
    - "facility_access_controls"
    - "workstation_security"
    - "media_controls"
    
  technical:
    - "unique_user_identification"
    - "audit_controls"
    - "encryption_decryption"
```

---

**Next:** [Best Practices](best-practices.md)
