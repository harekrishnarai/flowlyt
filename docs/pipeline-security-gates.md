# CI/CD Security Gate Integration Guide

This comprehensive guide covers integrating Flowlyt as a security gate in your CI/CD pipelines with proper critical issue handling and pipeline failure logic.

## 🛡️ Security Gate Concepts

### Pipeline Failure Modes

Flowlyt supports multiple ways to fail pipelines based on security findings:

1. **Severity-Based Failure** - Fail when findings exceed a severity threshold
2. **Count-Based Failure** - Fail when finding counts exceed limits  
3. **Policy-Based Failure** - Fail on blocking policy violations
4. **Compliance-Based Failure** - Fail on compliance framework violations

### Exit Code Behavior

| Scenario | Exit Code | Pipeline Result | Use Case |
|----------|-----------|-----------------|----------|
| No issues found | 0 | ✅ Success | Clean code |
| Issues below threshold | 0 | ✅ Success | Acceptable risk |
| Issues above threshold | 1 | ❌ Failure | Security gate |
| Critical policy violations | 1 | ❌ Failure | Policy enforcement |
| Scanner error | 2 | ❌ Failure | Technical issue |

## 🔧 GitHub Actions Integration

### Enhanced Action Inputs

The Flowlyt GitHub Action provides comprehensive inputs for enterprise security gate functionality:

```yaml
- name: Enterprise Security Gate
  uses: harekrishnarai/flowlyt@v1
  with:
    # Basic Configuration
    repository: '.'                              # Repository to scan
    config-file: '.flowlyt-enterprise.yml'      # Configuration file
    output-format: 'sarif'                      # Output format (cli, json, sarif)
    output-file: 'security-results.sarif'       # Output file path
    
    # Security Gate Configuration
    fail-on-severity: 'CRITICAL'                # Minimum severity to fail pipeline
    max-critical: 0                             # Maximum critical issues allowed
    max-high: 5                                 # Maximum high severity issues allowed
    
    # Enterprise Features
    enable-policy-enforcement: true              # Enable policy enforcement
    enable-vuln-intel: true                     # Enable vulnerability intelligence
    policy-config: 'policies/enterprise.yml'    # Custom policy configuration
    compliance-frameworks: 'pci-dss,sox,nist'   # Compliance frameworks
    
    # Integration Options
    upload-sarif: true                          # Upload to GitHub Security tab
    sarif-category: 'flowlyt-security'          # SARIF category for organization
    comment-on-pr: true                         # Comment on pull requests
    create-issue: true                          # Create issues for critical findings
    issue-labels: 'security,critical,flowlyt'   # Labels for created issues
    
    # Pipeline Control
    continue-on-error: false                    # Fail pipeline on security issues
    verbose: false                              # Enable debug output
```

### Action Outputs

The action provides comprehensive outputs for pipeline decision making:

```yaml
# Use outputs in subsequent steps
- name: Security Gate Decision
  run: |
    echo "Total findings: ${{ steps.security.outputs.findings-count }}"
    echo "Critical issues: ${{ steps.security.outputs.critical-count }}"
    echo "Policy violations: ${{ steps.security.outputs.policy-violations }}"
    echo "Compliance status: ${{ steps.security.outputs.compliance-status }}"
    
    # Make deployment decisions based on security status
    if [ "${{ steps.security.outputs.blocking-violations }}" -gt 0 ]; then
      echo "🚨 Deployment blocked by policy violations"
      exit 1
    fi
```

## 🎯 Security Gate Patterns

### 1. Critical Issue Blocking Pattern

Block all deployments when critical security issues are found:

```yaml
name: Critical Security Gate

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      issues: write
      pull-requests: write
    
    steps:
    - name: Checkout Code
      uses: actions/checkout@v4
    
    - name: Critical Security Scan
      id: security
      uses: harekrishnarai/flowlyt@v1
      with:
        config-file: '.flowlyt-enterprise.yml'
        fail-on-severity: 'CRITICAL'       # Block on any critical issue
        max-critical: 0                    # Zero tolerance
        enable-policy-enforcement: true
        upload-sarif: true
        create-issue: true
    
    # This step only runs if no critical issues found
    - name: Deployment Approved
      run: |
        echo "✅ Security gate passed - deployment approved"
        echo "Critical issues: ${{ steps.security.outputs.critical-count }}"
    
    # Create blocking status check
    - name: Set Security Status
      run: |
        if [ "${{ steps.security.outputs.critical-count }}" -gt 0 ]; then
          echo "security-gate=BLOCKED" >> $GITHUB_ENV
          exit 1
        else
          echo "security-gate=PASSED" >> $GITHUB_ENV
        fi

  # Deployment only runs if security gate passes
  deploy:
    needs: security-gate
    if: success()
    runs-on: ubuntu-latest
    environment: production
    
    steps:
    - name: Deploy Secure Application
      run: |
        echo "🚀 Deploying application after security validation"
        # Your deployment commands here
```

### 2. Multi-Environment Security Pattern

Different security requirements for different environments:

```yaml
name: Multi-Environment Security Pipeline

on:
  push:
    branches: [develop, staging, main]

jobs:
  # Development: Warn on issues but don't block
  security-dev:
    if: github.ref_name == 'develop'
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Development Security Scan
      uses: harekrishnarai/flowlyt@v1
      with:
        fail-on-severity: ''              # Don't fail pipeline
        max-critical: 10                  # Allow some issues for dev
        comment-on-pr: true
        continue-on-error: true           # Always continue

  # Staging: Block on critical and high issues
  security-staging:
    if: github.ref_name == 'staging'
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Staging Security Scan
      uses: harekrishnarai/flowlyt@v1
      with:
        fail-on-severity: 'HIGH'         # Block on high or critical
        max-critical: 2                  # Allow few critical for staging
        enable-policy-enforcement: true
        upload-sarif: true

  # Production: Zero tolerance for critical issues
  security-production:
    if: github.ref_name == 'main'
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Production Security Scan
      uses: harekrishnarai/flowlyt@v1
      with:
        fail-on-severity: 'CRITICAL'     # Block only on critical
        max-critical: 0                  # Zero critical issues allowed
        max-high: 3                      # Limit high severity issues
        enable-policy-enforcement: true
        enable-vuln-intel: true
        compliance-frameworks: 'pci-dss,sox'
        upload-sarif: true
        create-issue: true
```

### 3. Policy Enforcement Pattern

Enterprise policy enforcement with exception handling:

```yaml
name: Enterprise Policy Enforcement

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  policy-enforcement:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      issues: write
      pull-requests: write
    
    steps:
    - name: Checkout
      uses: actions/checkout@v4
    
    - name: Enterprise Policy Scan
      id: policy
      uses: harekrishnarai/flowlyt@v1
      with:
        config-file: '.flowlyt-enterprise.yml'
        enable-policy-enforcement: true
        policy-config: 'policies/enterprise-policies.yml'
        compliance-frameworks: 'pci-dss,sox,nist-800-53'
        fail-on-severity: 'HIGH'
        upload-sarif: true
        comment-on-pr: true
        continue-on-error: true          # Handle failures manually
    
    - name: Policy Violation Analysis
      run: |
        echo "🏛️ Policy Enforcement Results:"
        echo "Policy violations: ${{ steps.policy.outputs.policy-violations }}"
        echo "Blocking violations: ${{ steps.policy.outputs.blocking-violations }}"
        echo "Compliance status: ${{ steps.policy.outputs.compliance-status }}"
        
        BLOCKING="${{ steps.policy.outputs.blocking-violations }}"
        COMPLIANCE="${{ steps.policy.outputs.compliance-status }}"
        
        if [ "$BLOCKING" -gt 0 ]; then
          echo "🚨 POLICY ENFORCEMENT: BLOCKED"
          echo "Found $BLOCKING blocking policy violations"
          echo "::error::Deployment blocked by enterprise security policy"
          exit 1
        elif [ "$COMPLIANCE" = "false" ]; then
          echo "⚠️ COMPLIANCE: NON-COMPLIANT"
          echo "Compliance frameworks are not satisfied"
          
          # For main branch, compliance is required
          if [ "${{ github.ref_name }}" = "main" ]; then
            echo "::error::Production deployment requires full compliance"
            exit 1
          else
            echo "::warning::Non-compliance noted for review"
          fi
        else
          echo "✅ POLICY ENFORCEMENT: APPROVED"
          echo "All policies satisfied, deployment approved"
        fi
    
    - name: Generate Policy Report
      if: always()
      run: |
        cat > policy-report.md << EOF
        # 🏛️ Enterprise Policy Enforcement Report
        
        **Repository:** \`${{ github.repository }}\`
        **Branch:** \`${{ github.ref_name }}\`
        **Scan Time:** $(date -u '+%Y-%m-%d %H:%M:%S UTC')
        
        ## Policy Status
        | Metric | Value |
        |--------|-------|
        | Policy Violations | ${{ steps.policy.outputs.policy-violations }} |
        | Blocking Violations | ${{ steps.policy.outputs.blocking-violations }} |
        | Compliance Status | ${{ steps.policy.outputs.compliance-status }} |
        
        ## Security Findings
        | Severity | Count |
        |----------|-------|
        | Critical | ${{ steps.policy.outputs.critical-count }} |
        | High | ${{ steps.policy.outputs.high-count }} |
        | Medium | ${{ steps.policy.outputs.medium-count }} |
        
        ## Enforcement Decision
        $([ "${{ steps.policy.outputs.blocking-violations }}" = "0" ] && echo "✅ **APPROVED** - No blocking violations" || echo "🚨 **BLOCKED** - Policy violations must be resolved")
        
        EOF
        
        cat policy-report.md >> $GITHUB_STEP_SUMMARY
```

### 4. Compliance Monitoring Pattern

Continuous compliance validation with reporting:

```yaml
name: Compliance Monitoring

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM UTC
  workflow_dispatch:

jobs:
  compliance-matrix:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        framework: [pci-dss, sox, nist-800-53, iso-27001]
        include:
          - framework: pci-dss
            severity: 'CRITICAL'
            max-critical: 0
          - framework: sox
            severity: 'HIGH'
            max-critical: 1
          - framework: nist-800-53
            severity: 'HIGH'
            max-critical: 2
          - framework: iso-27001
            severity: 'MEDIUM'
            max-critical: 3
    
    steps:
    - name: Checkout
      uses: actions/checkout@v4
    
    - name: ${{ matrix.framework }} Compliance Scan
      id: compliance
      uses: harekrishnarai/flowlyt@v1
      with:
        config-file: '.flowlyt-enterprise.yml'
        enable-policy-enforcement: true
        compliance-frameworks: ${{ matrix.framework }}
        fail-on-severity: ${{ matrix.severity }}
        max-critical: ${{ matrix.max-critical }}
        output-format: 'json'
        output-file: 'compliance-${{ matrix.framework }}.json'
        upload-sarif: true
        sarif-category: 'compliance-${{ matrix.framework }}'
        create-issue: true
        issue-labels: 'compliance,${{ matrix.framework }},monitoring'
    
    - name: Upload Compliance Report
      uses: actions/upload-artifact@v4
      with:
        name: compliance-${{ matrix.framework }}
        path: compliance-${{ matrix.framework }}.json
        retention-days: 365  # Keep for audit trail
    
    - name: Compliance Status
      run: |
        COMPLIANT="${{ steps.compliance.outputs.compliance-status }}"
        VIOLATIONS="${{ steps.compliance.outputs.policy-violations }}"
        
        if [ "$COMPLIANT" = "true" ]; then
          echo "✅ ${{ matrix.framework }}: COMPLIANT"
        else
          echo "❌ ${{ matrix.framework }}: NON-COMPLIANT ($VIOLATIONS violations)"
          
          # Create compliance incident
          echo "::error::${{ matrix.framework }} compliance violation detected"
        fi

  compliance-dashboard:
    needs: compliance-matrix
    if: always()
    runs-on: ubuntu-latest
    
    steps:
    - name: Download All Reports
      uses: actions/download-artifact@v4
      with:
        pattern: compliance-*
        merge-multiple: true
    
    - name: Generate Compliance Dashboard
      run: |
        echo "# 📋 Compliance Dashboard" > dashboard.md
        echo "" >> dashboard.md
        echo "**Generated:** $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> dashboard.md
        echo "**Repository:** ${{ github.repository }}" >> dashboard.md
        echo "" >> dashboard.md
        echo "## Compliance Status by Framework" >> dashboard.md
        echo "" >> dashboard.md
        echo "| Framework | Status | Violations | Critical | High |" >> dashboard.md
        echo "|-----------|--------|------------|----------|------|" >> dashboard.md
        
        for file in compliance-*.json; do
          if [ -f "$file" ]; then
            framework=$(echo "$file" | sed 's/compliance-\(.*\)\.json/\1/')
            violations=$(jq '.policy_evaluation.policy_violations // 0' "$file" 2>/dev/null || echo "0")
            critical=$(jq '[.findings[] | select(.Severity == "CRITICAL")] | length' "$file" 2>/dev/null || echo "0")
            high=$(jq '[.findings[] | select(.Severity == "HIGH")] | length' "$file" 2>/dev/null || echo "0")
            compliant=$(jq '.compliance_report.compliant // false' "$file" 2>/dev/null || echo "false")
            
            status=$([ "$compliant" = "true" ] && echo "✅ Compliant" || echo "❌ Non-Compliant")
            echo "| $framework | $status | $violations | $critical | $high |" >> dashboard.md
          fi
        done
        
        echo "" >> dashboard.md
        echo "## Action Items" >> dashboard.md
        echo "" >> dashboard.md
        
        # Check for non-compliance
        non_compliant_count=0
        for file in compliance-*.json; do
          if [ -f "$file" ]; then
            compliant=$(jq '.compliance_report.compliant // false' "$file" 2>/dev/null || echo "false")
            if [ "$compliant" = "false" ]; then
              framework=$(echo "$file" | sed 's/compliance-\(.*\)\.json/\1/')
              echo "- 🚨 **$framework**: Address compliance violations" >> dashboard.md
              non_compliant_count=$((non_compliant_count + 1))
            fi
          fi
        done
        
        if [ "$non_compliant_count" -eq 0 ]; then
          echo "- ✅ **All frameworks compliant** - No action required" >> dashboard.md
        fi
        
        cat dashboard.md >> $GITHUB_STEP_SUMMARY
    
    - name: Alert on Compliance Failures
      if: failure()
      uses: actions/github-script@v7
      with:
        script: |
          const title = '🚨 Compliance Monitoring Alert';
          const body = `## 📋 Compliance Violations Detected
          
          **Monitoring Run:** [${{ github.run_number }}](${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }})
          **Date:** ${new Date().toISOString().split('T')[0]}
          
          ### Status
          One or more compliance frameworks are showing violations that require immediate attention.
          
          ### Action Required
          1. Review the compliance dashboard in the workflow summary
          2. Address violations according to your compliance procedures
          3. Update security controls and policies as needed
          4. Re-run compliance validation to verify fixes
          
          **Priority:** High - Compliance violations may impact audit readiness
          
          ---
          *Auto-generated by Flowlyt Compliance Monitoring*`;
          
          await github.rest.issues.create({
            owner: context.repo.owner,
            repo: context.repo.repo,
            title: title,
            body: body,
            labels: ['compliance', 'security', 'urgent', 'monitoring']
          });
```

## 🔌 Other CI/CD Platform Integration

### GitLab CI with Security Gates

```yaml
stages:
  - security-gate
  - build
  - deploy

variables:
  FLOWLYT_IMAGE: "ghcr.io/harekrishnarai/flowlyt:latest"

security_scan:
  stage: security-gate
  image: $FLOWLYT_IMAGE
  script:
    - |
      echo "🔍 Running security gate scan..."
      flowlyt scan \
        --repo . \
        --config .flowlyt-enterprise.yml \
        --enable-policy-enforcement \
        --output json \
        --output-file security-results.json \
        --fail-on-severity CRITICAL \
        --max-critical 0
      
      # Extract metrics
      CRITICAL_COUNT=$(jq '[.findings[] | select(.Severity == "CRITICAL")] | length' security-results.json)
      echo "Critical issues found: $CRITICAL_COUNT"
      
      # Fail if critical issues found
      if [ "$CRITICAL_COUNT" -gt 0 ]; then
        echo "🚨 Security gate BLOCKED: $CRITICAL_COUNT critical issues"
        exit 1
      else
        echo "✅ Security gate PASSED"
      fi
  artifacts:
    reports:
      junit: security-results.xml
    paths:
      - security-results.json
    when: always
    expire_in: 30 days
  allow_failure: false  # Block pipeline on security issues

build:
  stage: build
  dependencies:
    - security_scan
  script:
    - echo "✅ Building after security validation"
    - # Your build commands
  only:
    refs:
      - main
      - develop

deploy_production:
  stage: deploy
  dependencies:
    - security_scan
    - build
  script:
    - echo "🚀 Deploying secure application to production"
    - # Your deployment commands
  environment:
    name: production
  only:
    refs:
      - main
  when: manual  # Require manual approval for production
```

### Azure DevOps Security Pipeline

```yaml
trigger:
  branches:
    include:
      - main
      - develop

variables:
  flowlytImage: 'ghcr.io/harekrishnarai/flowlyt:latest'

stages:
- stage: SecurityGate
  displayName: 'Security Gate'
  jobs:
  - job: SecurityScan
    displayName: 'Flowlyt Security Scan'
    pool:
      vmImage: 'ubuntu-latest'
    steps:
    - task: DockerInstaller@0
      displayName: 'Install Docker'
    
    - script: |
        echo "🔍 Running enterprise security scan..."
        docker run --rm \
          -v $(Build.SourcesDirectory):/workspace \
          $(flowlytImage) \
          scan --repo /workspace \
          --config .flowlyt-enterprise.yml \
          --enable-policy-enforcement \
          --enable-vuln-intel \
          --output json \
          --output-file security-results.json \
          --fail-on-severity CRITICAL \
          --max-critical 0
      displayName: 'Security Gate Scan'
      continueOnError: false
    
    - task: PublishTestResults@2
      displayName: 'Publish Security Results'
      inputs:
        testResultsFormat: 'JUnit'
        testResultsFiles: 'security-results.xml'
        failTaskOnFailedTests: true
      condition: always()
    
    - script: |
        # Extract and display metrics
        if [ -f security-results.json ]; then
          CRITICAL=$(jq '[.findings[] | select(.Severity == "CRITICAL")] | length' security-results.json)
          HIGH=$(jq '[.findings[] | select(.Severity == "HIGH")] | length' security-results.json)
          POLICY_VIOLATIONS=$(jq '.policy_evaluation.policy_violations // 0' security-results.json)
          
          echo "##vso[task.setvariable variable=criticalCount]$CRITICAL"
          echo "##vso[task.setvariable variable=highCount]$HIGH"
          echo "##vso[task.setvariable variable=policyViolations]$POLICY_VIOLATIONS"
          
          echo "📊 Security Scan Results:"
          echo "Critical Issues: $CRITICAL"
          echo "High Issues: $HIGH"
          echo "Policy Violations: $POLICY_VIOLATIONS"
          
          if [ "$CRITICAL" -gt 0 ]; then
            echo "##vso[task.logissue type=error]Security gate BLOCKED: $CRITICAL critical issues found"
            exit 1
          elif [ "$POLICY_VIOLATIONS" -gt 0 ]; then
            echo "##vso[task.logissue type=warning]Policy violations detected: $POLICY_VIOLATIONS"
          fi
          
          echo "✅ Security gate PASSED"
        fi
      displayName: 'Evaluate Security Gate'

- stage: Build
  displayName: 'Build'
  dependsOn: SecurityGate
  condition: succeeded()
  jobs:
  - job: BuildApp
    displayName: 'Build Application'
    pool:
      vmImage: 'ubuntu-latest'
    steps:
    - script: |
        echo "✅ Building after security validation"
        # Your build commands here
      displayName: 'Build Application'

- stage: Deploy
  displayName: 'Deploy'
  dependsOn: 
    - SecurityGate
    - Build
  condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
  jobs:
  - deployment: DeployProduction
    displayName: 'Deploy to Production'
    environment: 'production'
    strategy:
      runOnce:
        deploy:
          steps:
          - script: |
              echo "🚀 Deploying to production after security validation"
              echo "Critical Issues: $(criticalCount)"
              echo "Policy Violations: $(policyViolations)"
              # Your deployment commands here
            displayName: 'Deploy to Production'
```

### Jenkins Pipeline with Security Gates

```groovy
pipeline {
    agent any
    
    environment {
        FLOWLYT_IMAGE = 'ghcr.io/harekrishnarai/flowlyt:latest'
        SECURITY_THRESHOLD = 'CRITICAL'
        MAX_CRITICAL = '0'
    }
    
    stages {
        stage('Security Gate') {
            steps {
                script {
                    echo '🔍 Running security gate scan...'
                    
                    def scanResult = sh(
                        script: """
                            docker run --rm \
                                -v \${WORKSPACE}:/workspace \
                                \${FLOWLYT_IMAGE} \
                                scan --repo /workspace \
                                --config .flowlyt-enterprise.yml \
                                --enable-policy-enforcement \
                                --output json \
                                --output-file security-results.json \
                                --fail-on-severity \${SECURITY_THRESHOLD} \
                                --max-critical \${MAX_CRITICAL}
                        """,
                        returnStatus: true
                    )
                    
                    // Parse results
                    def results = readJSON file: 'security-results.json'
                    def criticalCount = results.findings.count { it.Severity == 'CRITICAL' }
                    def highCount = results.findings.count { it.Severity == 'HIGH' }
                    def policyViolations = results.policy_evaluation?.policy_violations ?: 0
                    
                    echo "📊 Security Results: Critical=$criticalCount, High=$highCount, Policy Violations=$policyViolations"
                    
                    // Set build properties
                    currentBuild.description = "Critical: $criticalCount, High: $highCount"
                    
                    if (scanResult != 0) {
                        error("🚨 Security gate BLOCKED: Critical security issues detected")
                    } else {
                        echo "✅ Security gate PASSED"
                    }
                }
            }
            post {
                always {
                    // Archive security results
                    archiveArtifacts artifacts: 'security-results.json', allowEmptyArchive: true
                    
                    // Publish results if available
                    script {
                        if (fileExists('security-results.xml')) {
                            publishTestResults testResultsPattern: 'security-results.xml'
                        }
                    }
                }
                failure {
                    // Notify on security gate failure
                    emailext(
                        subject: "🚨 Security Gate Failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                        body: """
                        Security gate has blocked the pipeline due to critical security issues.
                        
                        Build: ${env.BUILD_URL}
                        Branch: ${env.BRANCH_NAME}
                        
                        Please review and resolve security issues before proceeding.
                        """,
                        to: '${SECURITY_TEAM_EMAIL}'
                    )
                }
            }
        }
        
        stage('Build') {
            when {
                expression { currentBuild.currentResult == 'SUCCESS' }
            }
            steps {
                echo '✅ Building after security validation'
                // Your build commands here
            }
        }
        
        stage('Deploy to Staging') {
            when {
                allOf {
                    expression { currentBuild.currentResult == 'SUCCESS' }
                    anyOf {
                        branch 'main'
                        branch 'develop'
                    }
                }
            }
            steps {
                echo '🚀 Deploying to staging after security validation'
                // Your staging deployment commands here
            }
        }
        
        stage('Deploy to Production') {
            when {
                allOf {
                    expression { currentBuild.currentResult == 'SUCCESS' }
                    branch 'main'
                }
            }
            steps {
                // Require manual approval for production
                input message: 'Deploy to production?', ok: 'Deploy',
                      submitterParameter: 'DEPLOYER'
                
                echo "🚀 Deploying to production (approved by: ${env.DEPLOYER})"
                // Your production deployment commands here
            }
        }
    }
    
    post {
        always {
            // Clean up
            sh 'docker system prune -f || true'
        }
        failure {
            script {
                if (env.STAGE_NAME == 'Security Gate') {
                    // Create Jira ticket for security issues
                    jiraCreateIssue(
                        site: 'your-jira-site',
                        project: 'SEC',
                        issueType: 'Bug',
                        summary: "Security Gate Failure: ${env.JOB_NAME}",
                        description: "Critical security issues detected in pipeline ${env.BUILD_URL}",
                        priority: 'Critical'
                    )
                }
            }
        }
    }
}
```

## 📊 Security Gate Best Practices

### 1. Threshold Configuration

Set appropriate thresholds based on your risk tolerance:

```yaml
# Conservative (high security)
fail-on-severity: 'HIGH'
max-critical: 0
max-high: 2

# Balanced (medium security)
fail-on-severity: 'CRITICAL'
max-critical: 1
max-high: 5

# Permissive (lower security, higher velocity)
fail-on-severity: 'CRITICAL'
max-critical: 3
max-high: 10
```

### 2. Environment-Specific Rules

Different environments should have different security requirements:

| Environment | Critical Limit | High Limit | Policy Enforcement |
|-------------|----------------|------------|--------------------|
| Development | 10 | 20 | Optional |
| Staging | 2 | 8 | Recommended |
| Production | 0 | 3 | Required |

### 3. Progressive Security Gates

Implement security gates that get stricter as code moves through environments:

```yaml
# Development: Advisory only
security-dev:
  fail-on-severity: ''
  continue-on-error: true

# Staging: Block on critical
security-staging:
  fail-on-severity: 'CRITICAL'
  max-critical: 1

# Production: Zero tolerance
security-production:
  fail-on-severity: 'CRITICAL'
  max-critical: 0
  enable-policy-enforcement: true
```

### 4. Exception Handling

Plan for urgent deployments that may need to bypass security gates:

```yaml
- name: Emergency Deployment Check
  if: contains(github.event.head_commit.message, '[EMERGENCY]')
  run: |
    echo "⚠️ EMERGENCY DEPLOYMENT DETECTED"
    echo "Security gate bypassed - manual security review required"
    echo "continue-on-error=true" >> $GITHUB_ENV
```

## 🛠️ Troubleshooting Security Gates

### Common Issues

1. **False Positives Blocking Pipeline**
   ```yaml
   # Solution: Tune ignore patterns
   false_positives:
     global:
       patterns:
         - "test/**"
         - "examples/**"
   ```

2. **Performance Issues**
   ```yaml
   # Solution: Optimize scan scope
   - name: Fast Security Scan
     uses: harekrishnarai/flowlyt@v1
     with:
       min-severity: 'HIGH'  # Skip low-severity checks
       max-workers: 4        # Parallel processing
   ```

3. **Configuration Errors**
   ```yaml
   # Solution: Validate configuration first
   - name: Validate Config
     run: |
       if [ ! -f .flowlyt-enterprise.yml ]; then
         echo "Configuration file missing - using defaults"
         echo "config-file=.flowlyt.yml" >> $GITHUB_ENV
       fi
   ```

### Debug Mode

Enable detailed logging for troubleshooting:

```yaml
- name: Debug Security Scan
  uses: harekrishnarai/flowlyt@v1
  with:
    verbose: true
    continue-on-error: true
  env:
    FLOWLYT_DEBUG: 1
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## 📋 Security Gate Checklist

Before implementing security gates in production:

- [ ] **Define Security Thresholds**
  - [ ] Set appropriate severity limits for each environment
  - [ ] Configure maximum issue counts
  - [ ] Enable policy enforcement where required

- [ ] **Configure Integration**
  - [ ] Set up SARIF upload to GitHub Security tab
  - [ ] Configure PR comments for developer feedback
  - [ ] Set up issue creation for critical findings

- [ ] **Test Security Gates**
  - [ ] Test with repositories containing known vulnerabilities
  - [ ] Verify pipeline blocking behavior
  - [ ] Test exception scenarios

- [ ] **Plan Operations**
  - [ ] Define escalation procedures for blocked deployments
  - [ ] Document exception approval processes
  - [ ] Set up monitoring and alerting

- [ ] **Team Preparation**
  - [ ] Train development teams on security gate processes
  - [ ] Document troubleshooting procedures
  - [ ] Establish security team contacts

## 🎯 Success Metrics

Monitor these metrics to ensure security gates are effective:

- **Security Gate Pass Rate**: Percentage of builds that pass security gates
- **Time to Resolution**: Average time to fix security issues
- **False Positive Rate**: Percentage of blocked builds due to false positives
- **Policy Compliance Rate**: Percentage of builds meeting policy requirements
- **Critical Issue Detection**: Number of critical issues caught before production

The enhanced Flowlyt GitHub Action and CI/CD integration provide enterprise-grade security gate functionality that can effectively block pipelines when critical issues are detected, ensuring that only secure code reaches production environments.
