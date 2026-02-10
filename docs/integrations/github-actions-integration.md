# Example GitHub Actions Workflows for Flowlyt Integration

This directory contains example workflows demonstrating how to integrate Flowlyt security scanning into your CI/CD pipeline with proper error handling and policy enforcement.

## Basic Integration

### Simple Security Scan

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Run Flowlyt Security Scan
      uses: harekrishnarai/flowlyt@v1
      with:
        fail-on-severity: 'HIGH'
        upload-sarif: true
```

### Enterprise Integration with Policy Enforcement

```yaml
name: Enterprise Security Scan
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      issues: write
      pull-requests: write
    
    steps:
    - name: Checkout Code
      uses: actions/checkout@v4
    
    - name: Run Enterprise Security Scan
      id: flowlyt
      uses: harekrishnarai/flowlyt@v1
      with:
        config-file: '.flowlyt-enterprise.yml'
        output-format: 'sarif'
        fail-on-severity: 'CRITICAL'
        max-critical: 0
        max-high: 5
        enable-policy-enforcement: true
        enable-vuln-intel: true
        compliance-frameworks: 'pci-dss,sox'
        upload-sarif: true
        comment-on-pr: true
        create-issue: true
        issue-labels: 'security,critical,flowlyt'
    
    - name: Security Gate Check
      if: steps.flowlyt.outputs.critical-count > 0
      run: |
        echo "🚨 SECURITY GATE FAILED"
        echo "Critical vulnerabilities found: ${{ steps.flowlyt.outputs.critical-count }}"
        echo "Blocking policy violations: ${{ steps.flowlyt.outputs.blocking-violations }}"
        echo "This deployment is blocked until security issues are resolved."
        exit 1
```

## Advanced Pipeline Integration

### Multi-Environment Pipeline with Security Gates

```yaml
name: Multi-Environment Pipeline with Security Gates

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  # Security scan runs first and blocks everything if critical issues found
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      issues: write
      pull-requests: write
    
    outputs:
      security-passed: ${{ steps.security-gate.outputs.passed }}
      critical-count: ${{ steps.flowlyt.outputs.critical-count }}
      compliance-status: ${{ steps.flowlyt.outputs.compliance-status }}
    
    steps:
    - name: Checkout
      uses: actions/checkout@v4
    
    - name: Security Scan
      id: flowlyt
      uses: harekrishnarai/flowlyt@v1
      with:
        config-file: '.flowlyt-enterprise.yml'
        output-format: 'sarif'
        min-severity: 'MEDIUM'
        fail-on-severity: 'CRITICAL'
        enable-policy-enforcement: true
        enable-vuln-intel: true
        compliance-frameworks: 'pci-dss,sox,nist'
        upload-sarif: true
        comment-on-pr: true
        sarif-category: 'workflow-security'
        continue-on-error: true  # Don't fail here, we'll handle it in next step
    
    - name: Security Gate Decision
      id: security-gate
      run: |
        CRITICAL_COUNT=${{ steps.flowlyt.outputs.critical-count }}
        BLOCKING_VIOLATIONS=${{ steps.flowlyt.outputs.blocking-violations }}
        COMPLIANCE_STATUS=${{ steps.flowlyt.outputs.compliance-status }}
        
        echo "🔍 Security Scan Results:"
        echo "Critical Issues: $CRITICAL_COUNT"
        echo "Blocking Violations: $BLOCKING_VIOLATIONS"
        echo "Compliance Status: $COMPLIANCE_STATUS"
        
        # Determine if we should proceed
        if [ "$CRITICAL_COUNT" -gt 0 ] || [ "$BLOCKING_VIOLATIONS" -gt 0 ] || [ "$COMPLIANCE_STATUS" = "false" ]; then
          echo "🚨 SECURITY GATE: BLOCKED"
          echo "Critical security issues must be resolved before deployment"
          echo "passed=false" >> $GITHUB_OUTPUT
          
          # For PRs, we might want to be less strict
          if [ "${{ github.event_name }}" = "pull_request" ]; then
            echo "⚠️ PR detected - security issues noted but not blocking for review"
            echo "passed=true" >> $GITHUB_OUTPUT
          else
            echo "🛑 Main branch deployment blocked due to security issues"
            exit 1
          fi
        else
          echo "✅ SECURITY GATE: PASSED"
          echo "passed=true" >> $GITHUB_OUTPUT
        fi
    
    - name: Generate Security Report
      if: always()
      run: |
        cat > security-report.md << EOF
        # 🛡️ Security Scan Report
        
        **Scan Date:** $(date -u '+%Y-%m-%d %H:%M:%S UTC')
        **Repository:** ${{ github.repository }}
        **Branch:** ${{ github.ref_name }}
        **Commit:** ${{ github.sha }}
        
        ## Summary
        - Critical Issues: ${{ steps.flowlyt.outputs.critical-count }}
        - High Issues: ${{ steps.flowlyt.outputs.high-count }}
        - Medium Issues: ${{ steps.flowlyt.outputs.medium-count }}
        - Policy Violations: ${{ steps.flowlyt.outputs.policy-violations }}
        - Compliance Status: ${{ steps.flowlyt.outputs.compliance-status }}
        
        ## Security Gate Status
        $([ "${{ steps.security-gate.outputs.passed }}" = "true" ] && echo "✅ **PASSED** - Deployment approved" || echo "❌ **BLOCKED** - Critical issues must be resolved")
        
        EOF
        
        cat security-report.md >> $GITHUB_STEP_SUMMARY

  # Build only runs if security gate passes
  build:
    needs: security-scan
    if: needs.security-scan.outputs.security-passed == 'true'
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    
    steps:
    - name: Checkout
      uses: actions/checkout@v4
    
    - name: Security Status Check
      run: |
        echo "✅ Security gate passed - proceeding with build"
        echo "Critical issues: ${{ needs.security-scan.outputs.critical-count }}"
        echo "Compliance: ${{ needs.security-scan.outputs.compliance-status }}"
    
    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v3
    
    - name: Log in to Container Registry
      uses: docker/login-action@v3
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
    
    - name: Build and push
      uses: docker/build-push-action@v5
      with:
        context: .
        push: true
        tags: |
          ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:latest

  # Deploy to staging (always requires security pass)
  deploy-staging:
    needs: [security-scan, build]
    if: needs.security-scan.outputs.security-passed == 'true' && github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    environment: staging
    
    steps:
    - name: Deploy to Staging
      run: |
        echo "🚀 Deploying to staging environment"
        echo "Security validated - deployment approved"
        # Add your deployment commands here

  # Deploy to production (extra strict requirements)
  deploy-production:
    needs: [security-scan, build, deploy-staging]
    if: |
      needs.security-scan.outputs.security-passed == 'true' && 
      needs.security-scan.outputs.critical-count == '0' &&
      needs.security-scan.outputs.compliance-status == 'true' &&
      github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    environment: production
    
    steps:
    - name: Production Security Validation
      run: |
        echo "🔒 Production Security Validation"
        echo "✅ No critical vulnerabilities"
        echo "✅ Full compliance achieved" 
        echo "✅ Security gate passed"
        echo "🚀 Production deployment approved"
    
    - name: Deploy to Production
      run: |
        echo "🚀 Deploying to production environment"
        # Add your production deployment commands here
```

### Compliance-Focused Pipeline

```yaml
name: Compliance Validation Pipeline

on:
  push:
    branches: [main, release/*]
  pull_request:
    branches: [main]
  schedule:
    # Run compliance check daily at 2 AM UTC
    - cron: '0 2 * * *'

jobs:
  compliance-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      issues: write
    
    strategy:
      matrix:
        framework: [pci-dss, sox, nist-800-53]
    
    steps:
    - name: Checkout
      uses: actions/checkout@v4
    
    - name: ${{ matrix.framework }} Compliance Scan
      id: compliance
      uses: harekrishnarai/flowlyt@v1
      with:
        config-file: '.flowlyt-enterprise.yml'
        output-format: 'json'
        output-file: 'compliance-${{ matrix.framework }}.json'
        enable-policy-enforcement: true
        compliance-frameworks: ${{ matrix.framework }}
        fail-on-severity: 'HIGH'
        upload-sarif: true
        sarif-category: 'compliance-${{ matrix.framework }}'
    
    - name: Upload Compliance Report
      uses: actions/upload-artifact@v4
      with:
        name: compliance-report-${{ matrix.framework }}
        path: compliance-${{ matrix.framework }}.json
        retention-days: 90
    
    - name: Compliance Status
      run: |
        COMPLIANCE_STATUS="${{ steps.compliance.outputs.compliance-status }}"
        if [ "$COMPLIANCE_STATUS" = "true" ]; then
          echo "✅ ${{ matrix.framework }} compliance: PASSED"
        else
          echo "❌ ${{ matrix.framework }} compliance: FAILED"
          echo "Violations: ${{ steps.compliance.outputs.policy-violations }}"
          exit 1
        fi

  compliance-report:
    needs: compliance-scan
    if: always()
    runs-on: ubuntu-latest
    
    steps:
    - name: Download All Reports
      uses: actions/download-artifact@v4
      with:
        pattern: compliance-report-*
        merge-multiple: true
    
    - name: Generate Consolidated Report
      run: |
        echo "# 📋 Compliance Dashboard" > compliance-dashboard.md
        echo "" >> compliance-dashboard.md
        echo "**Generated:** $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> compliance-dashboard.md
        echo "**Repository:** ${{ github.repository }}" >> compliance-dashboard.md
        echo "**Branch:** ${{ github.ref_name }}" >> compliance-dashboard.md
        echo "" >> compliance-dashboard.md
        
        echo "## Compliance Status" >> compliance-dashboard.md
        echo "" >> compliance-dashboard.md
        echo "| Framework | Status | Issues | Violations |" >> compliance-dashboard.md
        echo "|-----------|--------|---------|------------|" >> compliance-dashboard.md
        
        for file in compliance-*.json; do
          if [ -f "$file" ]; then
            framework=$(echo "$file" | sed 's/compliance-\(.*\)\.json/\1/')
            issues=$(jq '.findings | length' "$file" 2>/dev/null || echo "0")
            violations=$(jq '.policy_evaluation.policy_violations // 0' "$file" 2>/dev/null || echo "0")
            compliant=$(jq '.compliance_report.compliant // false' "$file" 2>/dev/null || echo "false")
            
            status=$([ "$compliant" = "true" ] && echo "✅ Compliant" || echo "❌ Non-Compliant")
            echo "| $framework | $status | $issues | $violations |" >> compliance-dashboard.md
          fi
        done
        
        cat compliance-dashboard.md >> $GITHUB_STEP_SUMMARY

  # Notify on compliance failures
  notify-compliance-failure:
    needs: compliance-scan
    if: failure()
    runs-on: ubuntu-latest
    
    steps:
    - name: Create Compliance Issue
      uses: actions/github-script@v7
      with:
        script: |
          const title = `🚨 Compliance Violation Detected - ${new Date().toISOString().split('T')[0]}`;
          const body = `## 📋 Compliance Validation Failed
          
          **Repository:** \`${{ github.repository }}\`
          **Branch:** \`${{ github.ref_name }}\`
          **Workflow:** [${{ github.run_number }}](${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }})
          
          ### Action Required
          One or more compliance frameworks are showing violations that must be addressed:
          
          1. Review the workflow run for detailed findings
          2. Address compliance violations according to your organization's policies
          3. Re-run compliance validation to verify fixes
          
          **Priority:** High - Compliance violations may impact audit readiness
          
          ---
          *Auto-generated by Flowlyt Compliance Pipeline*`;
          
          await github.rest.issues.create({
            owner: context.repo.owner,
            repo: context.repo.repo,
            title: title,
            body: body,
            labels: ['compliance', 'security', 'urgent']
          });
```

### Security Monitoring Dashboard

```yaml
name: Security Monitoring Dashboard

on:
  schedule:
    # Run every 6 hours
    - cron: '0 */6 * * *'
  workflow_dispatch:

jobs:
  security-monitoring:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      issues: write
    
    steps:
    - name: Checkout
      uses: actions/checkout@v4
    
    - name: Full Security Scan
      id: security
      uses: harekrishnarai/flowlyt@v1
      with:
        config-file: '.flowlyt-enterprise.yml'
        output-format: 'json'
        output-file: 'security-monitoring.json'
        enable-policy-enforcement: true
        enable-vuln-intel: true
        compliance-frameworks: 'pci-dss,sox,nist-800-53'
        min-severity: 'LOW'
        upload-sarif: true
        sarif-category: 'monitoring'
    
    - name: Store Historical Data
      run: |
        mkdir -p monitoring-data
        timestamp=$(date -u '+%Y%m%d_%H%M%S')
        cp security-monitoring.json "monitoring-data/scan_${timestamp}.json"
        
        # Keep only last 30 scans
        ls -t monitoring-data/scan_*.json | tail -n +31 | xargs -r rm
    
    - name: Generate Trend Analysis
      run: |
        echo "# 📊 Security Monitoring Dashboard" > dashboard.md
        echo "" >> dashboard.md
        echo "**Last Updated:** $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> dashboard.md
        echo "" >> dashboard.md
        
        # Current status
        CRITICAL=$(jq '[.findings[] | select(.Severity == "CRITICAL")] | length' security-monitoring.json)
        HIGH=$(jq '[.findings[] | select(.Severity == "HIGH")] | length' security-monitoring.json)
        MEDIUM=$(jq '[.findings[] | select(.Severity == "MEDIUM")] | length' security-monitoring.json)
        TOTAL=$(jq '.findings | length' security-monitoring.json)
        
        echo "## Current Security Status" >> dashboard.md
        echo "" >> dashboard.md
        echo "| Severity | Count | Trend |" >> dashboard.md
        echo "|----------|-------|-------|" >> dashboard.md
        echo "| 🔴 Critical | $CRITICAL | - |" >> dashboard.md
        echo "| 🟡 High | $HIGH | - |" >> dashboard.md
        echo "| 🟠 Medium | $MEDIUM | - |" >> dashboard.md
        echo "| **Total** | **$TOTAL** | - |" >> dashboard.md
        echo "" >> dashboard.md
        
        # Compliance status
        COMPLIANCE=$(jq '.compliance_report.compliant // false' security-monitoring.json)
        echo "## Compliance Status" >> dashboard.md
        echo "" >> dashboard.md
        if [ "$COMPLIANCE" = "true" ]; then
          echo "✅ **Compliant** - All frameworks passing" >> dashboard.md
        else
          echo "❌ **Non-Compliant** - Issues require attention" >> dashboard.md
        fi
        echo "" >> dashboard.md
        
        cat dashboard.md >> $GITHUB_STEP_SUMMARY
    
    - name: Check for Degradation
      run: |
        # Compare with previous scan if available
        if [ -f "monitoring-data/scan_*.json" ]; then
          latest=$(ls -t monitoring-data/scan_*.json | head -1)
          if [ -f "$latest" ] && [ "$latest" != "monitoring-data/scan_$(date -u '+%Y%m%d_%H%M%S').json" ]; then
            prev_critical=$(jq '[.findings[] | select(.Severity == "CRITICAL")] | length' "$latest")
            curr_critical=$(jq '[.findings[] | select(.Severity == "CRITICAL")] | length' security-monitoring.json)
            
            if [ "$curr_critical" -gt "$prev_critical" ]; then
              echo "🚨 ALERT: Security posture degraded!"
              echo "Critical issues increased from $prev_critical to $curr_critical"
              exit 1
            fi
          fi
        fi
```

These workflow examples demonstrate:

1. **Progressive Security Gates** - Block deployments based on severity
2. **Enterprise Policy Enforcement** - Use advanced configuration features
3. **Compliance Integration** - Multiple framework validation
4. **Automated Issue Creation** - Create GitHub issues for critical findings
5. **SARIF Upload** - Integration with GitHub Security tab
6. **PR Comments** - Automated security feedback
7. **Multi-Environment Pipelines** - Different security requirements per environment
8. **Monitoring & Trending** - Continuous security posture tracking

The workflows properly handle critical issues and can break pipelines when security thresholds are exceeded, providing enterprise-grade security gate functionality.
