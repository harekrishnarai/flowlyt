# CI/CD Integration

Learn how to integrate Flowlyt into your CI/CD pipelines for automated security scanning across different platforms.

## GitHub Actions Integration

### Basic Integration

```yaml
name: Security Scan
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Install Flowlyt
        run: go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
      
      - name: Run security scan
        run: |
          flowlyt --repo . \
                  --min-severity HIGH \
                  --output json \
                  --output-file security-report.json
      
      - name: Upload security report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: security-report.json
        if: always()
```

### Advanced GitHub Actions Integration

```yaml
name: Comprehensive Security Pipeline
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  security-scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        config: [dev, staging, prod]
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Install Flowlyt
        run: go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
      
      - name: Run environment-specific scan
        run: |
          flowlyt --repo . \
                  --config .flowlyt.${{ matrix.config }}.yml \
                  --output json \
                  --output-file security-${{ matrix.config }}.json
      
      - name: Check for critical issues
        run: |
          if jq -e '.findings[] | select(.severity == "CRITICAL")' security-${{ matrix.config }}.json > /dev/null; then
            echo "❌ Critical security issues found in ${{ matrix.config }} environment!"
            jq '.findings[] | select(.severity == "CRITICAL")' security-${{ matrix.config }}.json
            exit 1
          fi
          echo "✅ No critical issues found in ${{ matrix.config }} environment"
      
      - name: Generate markdown report
        run: |
          flowlyt --repo . \
                  --config .flowlyt.${{ matrix.config }}.yml \
                  --output markdown \
                  --output-file security-report-${{ matrix.config }}.md
      
      - name: Comment PR with security report
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('security-report-${{ matrix.config }}.md', 'utf8');
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## Security Scan Results (${{ matrix.config }})\n\n${report}`
            });
      
      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: security-reports-${{ matrix.config }}
          path: |
            security-${{ matrix.config }}.json
            security-report-${{ matrix.config }}.md
        if: always()

  security-gate:
    needs: security-scan
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
      - name: Download all artifacts
        uses: actions/download-artifact@v4
      
      - name: Aggregate security results
        run: |
          echo "Checking all security reports..."
          for report in security-reports-*/security-*.json; do
            if jq -e '.findings[] | select(.severity == "CRITICAL" or .severity == "HIGH")' "$report" > /dev/null; then
              echo "❌ High/Critical issues found in $report"
              exit 1
            fi
          done
          echo "✅ All security checks passed"
```

### Reusable Security Action

Create a reusable workflow for security scanning:

```yaml
# .github/workflows/security-scan.yml
name: Reusable Security Scan
on:
  workflow_call:
    inputs:
      config-file:
        description: 'Flowlyt configuration file'
        required: false
        type: string
        default: '.flowlyt.yml'
      min-severity:
        description: 'Minimum severity level'
        required: false
        type: string
        default: 'HIGH'
      fail-on-issues:
        description: 'Fail the workflow if issues are found'
        required: false
        type: boolean
        default: true
    outputs:
      issues-found:
        description: 'Whether security issues were found'
        value: ${{ jobs.security.outputs.issues-found }}

jobs:
  security:
    runs-on: ubuntu-latest
    outputs:
      issues-found: ${{ steps.scan.outputs.issues-found }}
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Flowlyt
        run: go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
      
      - name: Security scan
        id: scan
        run: |
          flowlyt --repo . \
                  --config ${{ inputs.config-file }} \
                  --min-severity ${{ inputs.min-severity }} \
                  --output json \
                  --output-file security-report.json
          
          # Check if any issues were found
          if [ -s security-report.json ] && jq -e '.findings | length > 0' security-report.json > /dev/null; then
            echo "issues-found=true" >> $GITHUB_OUTPUT
            if [ "${{ inputs.fail-on-issues }}" = "true" ]; then
              echo "❌ Security issues found!"
              exit 1
            fi
          else
            echo "issues-found=false" >> $GITHUB_OUTPUT
            echo "✅ No security issues found"
          fi
```

Use the reusable workflow:

```yaml
# .github/workflows/ci.yml
name: CI Pipeline
on: [push, pull_request]

jobs:
  security-dev:
    uses: ./.github/workflows/security-scan.yml
    with:
      config-file: '.flowlyt.dev.yml'
      min-severity: 'MEDIUM'
      fail-on-issues: false
  
  security-prod:
    uses: ./.github/workflows/security-scan.yml
    with:
      config-file: '.flowlyt.prod.yml'
      min-severity: 'HIGH'
      fail-on-issues: true
  
  deploy:
    needs: [security-dev, security-prod]
    if: needs.security-prod.outputs.issues-found == 'false'
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: echo "Deploying..."
```

## GitLab CI Integration

### Basic GitLab CI Integration

```yaml
# .gitlab-ci.yml
stages:
  - security
  - build
  - test
  - deploy

security_scan:
  stage: security
  image: golang:1.21
  script:
    - go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
    - flowlyt --platform gitlab --repo . --output json --output-file security-report.json
  artifacts:
    reports:
      junit: security-report.json
    paths:
      - security-report.json
    when: always
    expire_in: 1 week
  rules:
    - if: $CI_MERGE_REQUEST_ID
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### Advanced GitLab CI Integration

```yaml
# .gitlab-ci.yml
variables:
  FLOWLYT_VERSION: "latest"

stages:
  - security
  - build
  - test
  - deploy

.security_template: &security_template
  image: golang:1.21
  before_script:
    - go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@$FLOWLYT_VERSION
  artifacts:
    reports:
      junit: security-report-$ENVIRONMENT.json
    paths:
      - security-report-$ENVIRONMENT.json
      - security-report-$ENVIRONMENT.md
    when: always
    expire_in: 1 month

security_development:
  <<: *security_template
  stage: security
  variables:
    ENVIRONMENT: "dev"
  script:
    - |
      flowlyt --platform gitlab \
              --repo . \
              --config .flowlyt.dev.yml \
              --min-severity MEDIUM \
              --output json \
              --output-file security-report-$ENVIRONMENT.json
    - |
      flowlyt --platform gitlab \
              --repo . \
              --config .flowlyt.dev.yml \
              --min-severity MEDIUM \
              --output markdown \
              --output-file security-report-$ENVIRONMENT.md
  rules:
    - if: $CI_MERGE_REQUEST_ID
    - if: $CI_COMMIT_BRANCH != $CI_DEFAULT_BRANCH

security_production:
  <<: *security_template
  stage: security
  variables:
    ENVIRONMENT: "prod"
  script:
    - |
      flowlyt --platform gitlab \
              --repo . \
              --config .flowlyt.prod.yml \
              --min-severity HIGH \
              --output json \
              --output-file security-report-$ENVIRONMENT.json
    - |
      # Fail if critical issues are found
      if jq -e '.findings[] | select(.severity == "CRITICAL")' security-report-$ENVIRONMENT.json > /dev/null; then
        echo "❌ Critical security issues found!"
        jq '.findings[] | select(.severity == "CRITICAL")' security-report-$ENVIRONMENT.json
        exit 1
      fi
    - |
      flowlyt --platform gitlab \
              --repo . \
              --config .flowlyt.prod.yml \
              --min-severity HIGH \
              --output markdown \
              --output-file security-report-$ENVIRONMENT.md
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

security_scheduled:
  <<: *security_template
  stage: security
  variables:
    ENVIRONMENT: "comprehensive"
  script:
    - |
      # Comprehensive scan with all rules
      flowlyt --platform gitlab \
              --repo . \
              --min-severity LOW \
              --output json \
              --output-file security-report-$ENVIRONMENT.json
    - |
      # Generate detailed report
      flowlyt --platform gitlab \
              --repo . \
              --min-severity LOW \
              --output markdown \
              --output-file security-report-$ENVIRONMENT.md
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"

deploy:
  stage: deploy
  image: alpine:latest
  dependencies:
    - security_production
  script:
    - |
      # Check security report before deployment
      if [ -f security-report-prod.json ]; then
        echo "Checking security report..."
        # Add your deployment logic here
        echo "✅ Security checks passed, deploying..."
      else
        echo "❌ Security report not found, blocking deployment"
        exit 1
      fi
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### GitLab Security Dashboard Integration

```yaml
# Integration with GitLab Security Dashboard
security_scan_sast:
  stage: security
  image: golang:1.21
  script:
    - go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
    - |
      # Convert Flowlyt output to GitLab Security format
      flowlyt --platform gitlab --repo . --output json > flowlyt-report.json
      
      # Transform to GitLab SAST format (custom script)
      python3 scripts/convert-to-gitlab-sast.py flowlyt-report.json > gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

## Jenkins Integration

### Jenkins Pipeline Integration

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    environment {
        FLOWLYT_CONFIG = '.flowlyt.jenkins.yml'
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Install Flowlyt') {
            steps {
                script {
                    sh '''
                        # Install Go if not available
                        if ! command -v go &> /dev/null; then
                            wget -q https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
                            sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
                            export PATH=$PATH:/usr/local/go/bin
                        fi
                        
                        # Install Flowlyt
                        go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
                    '''
                }
            }
        }
        
        stage('Security Scan') {
            parallel {
                stage('Development Rules') {
                    when {
                        not { branch 'main' }
                    }
                    steps {
                        script {
                            sh '''
                                flowlyt --repo . \
                                        --config .flowlyt.dev.yml \
                                        --min-severity MEDIUM \
                                        --output json \
                                        --output-file security-dev.json
                            '''
                        }
                    }
                }
                
                stage('Production Rules') {
                    when {
                        branch 'main'
                    }
                    steps {
                        script {
                            sh '''
                                flowlyt --repo . \
                                        --config .flowlyt.prod.yml \
                                        --min-severity HIGH \
                                        --output json \
                                        --output-file security-prod.json
                                
                                # Check for critical issues
                                if jq -e '.findings[] | select(.severity == "CRITICAL")' security-prod.json > /dev/null; then
                                    echo "❌ Critical security issues found!"
                                    exit 1
                                fi
                            '''
                        }
                    }
                }
            }
        }
        
        stage('Generate Reports') {
            steps {
                script {
                    sh '''
                        # Generate human-readable report
                        if [ -f security-dev.json ]; then
                            flowlyt --repo . --config .flowlyt.dev.yml --output markdown --output-file security-report.md
                        elif [ -f security-prod.json ]; then
                            flowlyt --repo . --config .flowlyt.prod.yml --output markdown --output-file security-report.md
                        fi
                    '''
                }
            }
        }
    }
    
    post {
        always {
            // Archive security reports
            archiveArtifacts artifacts: 'security-*.json,security-*.md', fingerprint: true
            
            // Publish test results if using JSON format compatible with Jenkins
            publishTestResults testResultsPattern: 'security-*.json'
        }
        
        failure {
            // Send notification on security failures
            emailext (
                subject: "Security Scan Failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: "Security issues found in ${env.JOB_NAME} build ${env.BUILD_NUMBER}. Check the build logs for details.",
                to: "${env.CHANGE_AUTHOR_EMAIL}"
            )
        }
        
        success {
            echo "✅ Security scan passed successfully"
        }
    }
}
```

## Azure DevOps Integration

### Azure Pipelines Integration

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include:
      - main
      - develop

pr:
  branches:
    include:
      - main

variables:
  flowlytVersion: 'latest'

stages:
- stage: Security
  displayName: 'Security Scanning'
  jobs:
  - job: SecurityScan
    displayName: 'Flowlyt Security Scan'
    pool:
      vmImage: 'ubuntu-latest'
    
    strategy:
      matrix:
        Development:
          configFile: '.flowlyt.dev.yml'
          minSeverity: 'MEDIUM'
          failOnIssues: false
        Production:
          configFile: '.flowlyt.prod.yml'
          minSeverity: 'HIGH'
          failOnIssues: true
    
    steps:
    - checkout: self
    
    - task: GoTool@0
      displayName: 'Use Go 1.21'
      inputs:
        version: '1.21'
    
    - script: |
        go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@$(flowlytVersion)
      displayName: 'Install Flowlyt'
    
    - script: |
        flowlyt --repo . \
                --config $(configFile) \
                --min-severity $(minSeverity) \
                --output json \
                --output-file security-$(Agent.JobName).json
      displayName: 'Run Security Scan'
    
    - script: |
        if [ "$(failOnIssues)" = "true" ]; then
          if jq -e '.findings[] | select(.severity == "CRITICAL" or .severity == "HIGH")' security-$(Agent.JobName).json > /dev/null; then
            echo "❌ Critical/High security issues found!"
            exit 1
          fi
        fi
        echo "✅ Security scan completed"
      displayName: 'Check Security Results'
    
    - task: PublishTestResults@2
      displayName: 'Publish Security Results'
      inputs:
        testResultsFormat: 'JUnit'
        testResultsFiles: 'security-$(Agent.JobName).json'
        testRunTitle: 'Flowlyt Security Scan - $(Agent.JobName)'
      condition: always()
    
    - task: PublishBuildArtifacts@1
      displayName: 'Publish Security Reports'
      inputs:
        pathToPublish: 'security-$(Agent.JobName).json'
        artifactName: 'security-reports'
      condition: always()

- stage: Deploy
  displayName: 'Deploy'
  dependsOn: Security
  condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
  jobs:
  - deployment: DeployProduction
    displayName: 'Deploy to Production'
    environment: 'production'
    strategy:
      runOnce:
        deploy:
          steps:
          - download: current
            artifact: security-reports
          
          - script: |
              echo "Validating security before deployment..."
              # Add validation logic here
              echo "✅ Security validation passed, proceeding with deployment"
            displayName: 'Security Gate'
```

## Pre-commit Hook Integration

### Basic Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "Running Flowlyt security scan..."

# Run security scan
if ! flowlyt --repo . --min-severity HIGH --output cli; then
    echo ""
    echo "❌ Security issues found! Please fix them before committing."
    echo ""
    echo "To see detailed report:"
    echo "  flowlyt --repo . --output json"
    echo ""
    echo "To bypass this check (not recommended):"
    echo "  git commit --no-verify"
    echo ""
    exit 1
fi

echo "✅ No security issues found."
```

### Advanced Pre-commit Hook with Configuration

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Configuration
FLOWLYT_CONFIG=".flowlyt.precommit.yml"
MIN_SEVERITY="HIGH"
OUTPUT_FILE="/tmp/flowlyt-precommit.json"

echo "🔍 Running Flowlyt security scan..."

# Check if Flowlyt is installed
if ! command -v flowlyt &> /dev/null; then
    echo "❌ Flowlyt not found. Please install it:"
    echo "  go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest"
    exit 1
fi

# Run security scan
flowlyt --repo . \
        --config "$FLOWLYT_CONFIG" \
        --min-severity "$MIN_SEVERITY" \
        --output json \
        --output-file "$OUTPUT_FILE"

scan_result=$?

if [ $scan_result -ne 0 ]; then
    echo ""
    echo "❌ Security issues found!"
    echo ""
    
    # Show summary
    if [ -f "$OUTPUT_FILE" ]; then
        critical_count=$(jq '[.findings[] | select(.severity == "CRITICAL")] | length' "$OUTPUT_FILE" 2>/dev/null || echo "0")
        high_count=$(jq '[.findings[] | select(.severity == "HIGH")] | length' "$OUTPUT_FILE" 2>/dev/null || echo "0")
        
        echo "Summary:"
        echo "  Critical: $critical_count"
        echo "  High: $high_count"
        echo ""
        
        # Show top 3 issues
        echo "Top issues:"
        jq -r '.findings[:3] | .[] | "  [\(.severity)] \(.rule_name) - \(.file_path):\(.line_number)"' "$OUTPUT_FILE" 2>/dev/null
        echo ""
    fi
    
    echo "To see full report:"
    echo "  flowlyt --repo . --output cli"
    echo ""
    echo "To bypass this check (not recommended):"
    echo "  git commit --no-verify"
    echo ""
    
    # Cleanup
    rm -f "$OUTPUT_FILE"
    exit 1
fi

echo "✅ No security issues found."

# Cleanup
rm -f "$OUTPUT_FILE"
```

## Docker Integration

### Dockerfile for CI/CD

```dockerfile
# Dockerfile.flowlyt
FROM golang:1.21-alpine AS builder

WORKDIR /app
RUN go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest

FROM alpine:latest
RUN apk --no-cache add ca-certificates git
WORKDIR /root/

COPY --from=builder /go/bin/flowlyt /usr/local/bin/flowlyt

ENTRYPOINT ["flowlyt"]
```

### Docker Compose for Development

```yaml
# docker-compose.security.yml
version: '3.8'

services:
  flowlyt:
    build:
      context: .
      dockerfile: Dockerfile.flowlyt
    volumes:
      - .:/workspace
    working_dir: /workspace
    command: ["--repo", ".", "--output", "json", "--output-file", "/workspace/security-report.json"]

  security-dashboard:
    image: nginx:alpine
    ports:
      - "8080:80"
    volumes:
      - ./security-reports:/usr/share/nginx/html
    depends_on:
      - flowlyt
```

## Monitoring and Alerting

### GitHub Actions with Slack Notifications

```yaml
- name: Notify Slack on Security Issues
  if: failure()
  uses: 8398a7/action-slack@v3
  with:
    status: failure
    channel: '#security'
    text: |
      🚨 Security scan failed for ${{ github.repository }}
      
      Branch: ${{ github.ref }}
      Commit: ${{ github.sha }}
      
      Please check the security report in the artifacts.
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

### GitLab CI with Teams Notification

```yaml
notify_teams:
  stage: .post
  image: curlimages/curl:latest
  script:
    - |
      if [ "$CI_JOB_STATUS" = "failed" ]; then
        curl -H "Content-Type: application/json" \
             -d "{\"text\": \"🚨 Security scan failed for $CI_PROJECT_NAME on $CI_COMMIT_REF_NAME\"}" \
             "$TEAMS_WEBHOOK_URL"
      fi
  rules:
    - when: on_failure
```

## Best Practices for CI/CD Integration

### 1. Environment-Specific Configurations

Use different security configurations for different environments:

```bash
# Development: More lenient
flowlyt --config .flowlyt.dev.yml --min-severity MEDIUM

# Staging: Moderate strictness
flowlyt --config .flowlyt.staging.yml --min-severity HIGH

# Production: Strict security
flowlyt --config .flowlyt.prod.yml --min-severity CRITICAL
```

### 2. Fail Fast Strategy

Implement security gates early in the pipeline:

```yaml
stages:
  - security-gate    # First stage
  - build
  - test
  - deploy
```

### 3. Parallel Security Scans

Run different types of security scans in parallel:

```yaml
jobs:
  flowlyt-scan:
    # Flowlyt workflow security scan
    
  dependency-scan:
    # Dependency vulnerability scan
    
  static-analysis:
    # Static code analysis
```

### 4. Security Report Aggregation

Combine multiple security tools:

```bash
# Aggregate multiple security reports
jq -s '.[0] + .[1]' flowlyt-report.json dependency-report.json > combined-report.json
```

---

**Next:** [Report Generation](reporting.md)
