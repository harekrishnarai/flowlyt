# SARIF Output Support

Flowlyt now supports **SARIF (Static Analysis Results Interchange Format)** output, enabling seamless integration with enterprise security toolchains, IDEs, and CI/CD pipelines.

## Overview

SARIF is a JSON-based open standard developed by Microsoft for sharing static analysis results between tools. It's the preferred format for:

- **GitHub Advanced Security** and Security tab integration  
- **Azure DevOps** security reporting
- **Visual Studio Code** and other IDE integration
- **Security orchestration platforms** (SOAR)
- **Compliance reporting** and audit trails

## Usage

### Basic SARIF Output

```bash
# Output SARIF to stdout
flowlyt scan --repo /path/to/repo --output sarif

# Save SARIF to file
flowlyt scan --repo /path/to/repo --output sarif --output-file results.sarif

# Scan remote repository with SARIF output
flowlyt scan --url https://github.com/owner/repo --output sarif --output-file security-report.sarif
```

### Organization Analysis with SARIF

```bash
# Organization-wide SARIF report
flowlyt analyze-org --organization myorg --output-format sarif --output-file org-security.sarif

# Filter and save organization SARIF
flowlyt analyze-org --organization mycompany --include-private --max-repos 50 --output-format sarif -o company-audit.sarif
```

### Severity Filtering

```bash
# Include only high-severity findings
flowlyt scan --repo . --output sarif --min-severity HIGH --output-file critical-issues.sarif

# Include all findings (including info level)  
flowlyt scan --repo . --output sarif --min-severity INFO --output-file complete-audit.sarif
```

## SARIF Format Features

Flowlyt's SARIF implementation includes all essential SARIF 2.1.0 features:

### 🔧 Tool Information
- **Driver metadata**: Tool name, version, semantic version
- **Information URI**: Link to Flowlyt repository  
- **Rule definitions**: Complete rule catalog with descriptions

### 📍 Precise Locations  
- **Physical locations**: File paths with line/column numbers
- **Logical locations**: Workflow job and step context
- **Artifact references**: File metadata and timestamps

### 🔍 Rich Results
- **Rule mapping**: Each finding linked to specific rule definition
- **Severity levels**: GitHub Advanced Security compatible severity mapping
  - **Critical** (9.0-10.0): Displayed as "Critical" in GitHub Security tab
  - **High** (7.0-8.9): Displayed as "High" in GitHub Security tab
  - **Medium** (4.0-6.9): Displayed as "Medium" in GitHub Security tab
  - **Low** (0.1-3.9): Displayed as "Low" in GitHub Security tab
  - **Info** (0.0): Informational findings
- **Evidence**: Masked sensitive content for security
- **Remediation**: Actionable fix recommendations

### 🔗 Result Tracking
- **Fingerprints**: Stable identifiers for result deduplication
- **Properties**: Extended metadata for integration including `security-severity` score
- **Categories**: Security category classification

## GitHub Integration

### Upload SARIF to GitHub Security Tab

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # Required for SARIF upload
      
    steps:
    - uses: actions/checkout@v4
    
    - name: Run Flowlyt Security Scan
      run: |
        # Install and run Flowlyt
        curl -sSL https://install.flowlyt.dev | bash
        flowlyt scan --repo . --output sarif --output-file flowlyt.sarif
        
    - name: Upload SARIF to GitHub  
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: flowlyt.sarif
        category: flowlyt-security
```

### View Results in GitHub

After uploading, security findings will appear in:
- **Security tab** → Code scanning alerts
- **Pull request annotations** for new findings
- **Security overview** for organization dashboards

## Azure DevOps Integration

```yaml
# azure-pipelines.yml
trigger: [main]

jobs:
- job: SecurityScan
  pool:
    vmImage: 'ubuntu-latest'
    
  steps:
  - task: Bash@3
    displayName: 'Run Flowlyt Security Scan'
    inputs:
      targetType: 'inline'
      script: |
        # Install and run Flowlyt
        curl -sSL https://install.flowlyt.dev | bash
        flowlyt scan --repo $(System.DefaultWorkingDirectory) --output sarif --output-file $(Agent.TempDirectory)/flowlyt.sarif
        
  - task: PublishBuildArtifacts@1
    displayName: 'Publish SARIF Results'
    inputs:
      pathToPublish: '$(Agent.TempDirectory)/flowlyt.sarif'
      artifactName: 'SecurityScan'
```

## IDE Integration

### Visual Studio Code

1. Install the **SARIF Viewer** extension
2. Generate SARIF report: `flowlyt scan --repo . --output sarif --output-file results.sarif`
3. Open SARIF file in VS Code to see inline annotations

### JetBrains IDEs

1. Use **SARIF Plugin** for IntelliJ/PyCharm/WebStorm
2. Import SARIF file to see security findings as inspections
3. Navigate directly to vulnerable code locations

## SARIF Structure

Flowlyt generates SARIF with GitHub Advanced Security compatible structure:

```json
{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Flowlyt",
        "version": "0.1.0",
        "rules": [{
          "id": "MALICIOUS_CURL_PIPE_BASH",
          "name": "Dangerous Curl Pipe to Bash",
          "shortDescription": { "text": "Dangerous Curl Pipe to Bash" },
          "fullDescription": { "text": "Command downloads and executes code..." },
          "defaultConfiguration": { "level": "error" },
          "properties": {
            "category": "MALICIOUS_PATTERN",
            "severity": "HIGH",
            "security-severity": "8.0",
            "tags": ["security", "ci-cd", "MALICIOUS_PATTERN"],
            "precision": "high"
          }
        }]
      }
    },
    "invocation": {
      "startTimeUtc": "2025-08-30T12:00:00Z",
      "executionSuccessful": true
    },
    "results": [
      {
        "ruleId": "MALICIOUS_CURL_PIPE_BASH",
        "level": "error",
        "message": { "text": "Command downloads and executes code..." },
        "locations": [{
          "physicalLocation": {
            "artifactLocation": { "uri": ".github/workflows/ci.yml" },
            "region": { "startLine": 25 }
          },
          "logicalLocations": [{
            "name": "build",
            "kind": "job"
          }]
        }],
        "properties": {
          "category": "MALICIOUS_PATTERN",
          "severity": "HIGH",
          "remediation": "Download and verify script separately"
        }
      }
    ],
    "artifacts": [/* File metadata */]
  }]
}
```

## Best Practices

### 🔒 Security Considerations
- **Evidence masking**: Sensitive data is automatically masked in SARIF output
- **Safe file paths**: Paths are normalized and made relative
- **Token protection**: Avoid committing SARIF files with sensitive context

### 📊 Result Management
- **Baseline scanning**: Use fingerprints to track new vs. existing issues
- **Severity thresholds**: Filter results based on organizational risk tolerance
- **Category filtering**: Focus on specific security categories as needed

### 🔄 CI/CD Integration
- **Fail conditions**: Set pipeline failure thresholds based on SARIF results
- **Trend analysis**: Track security metrics over time using SARIF data
- **Automated remediation**: Trigger fix workflows based on SARIF findings

## Example SARIF Output

Here's a sample SARIF result for a curl pipe vulnerability with GitHub Advanced Security severity mapping:

```json
{
  "ruleId": "MALICIOUS_CURL_PIPE_BASH",
  "level": "error", 
  "message": {
    "text": "Command downloads and executes code directly from the internet"
  },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": { "uri": ".github/workflows/deploy.yml" },
      "region": { "startLine": 42, "endLine": 42 }
    },
    "logicalLocations": [{
      "name": "deploy-production", 
      "kind": "job"
    }, {
      "name": "Install dependencies",
      "kind": "step"
    }]
  }],
  "partialFingerprints": {
    "flowlyt/v1": "MALICIOUS_CURL_PIPE_BASH:.github/workflows/deploy.yml:42"
  },
  "properties": {
    "category": "MALICIOUS_PATTERN",
    "severity": "HIGH",
    "security-severity": "8.0",
    "evidence": "curl ******* | bash",
    "remediation": "Download the script first, verify its contents, then execute separately",
    "jobName": "deploy-production",
    "stepName": "Install dependencies"
  }
}
```

### Understanding Severity Mapping

Flowlyt uses the `security-severity` property to provide GitHub Advanced Security with precise severity information:

| Flowlyt Severity | security-severity Score | GitHub Display | SARIF Level |
|-----------------|------------------------|----------------|-------------|
| CRITICAL        | 9.0                    | Critical       | error       |
| HIGH            | 8.0                    | High           | error       |
| MEDIUM          | 5.0                    | Medium         | warning     |
| LOW             | 3.0                    | Low            | warning     |
| INFO            | 0.0                    | Note           | note        |

This ensures that findings appear with the correct severity in GitHub's Security tab instead of generic "Error" and "Warning" labels.

## Troubleshooting

### Large SARIF Files
If SARIF files become too large for GitHub (10MB limit):

```bash
# Filter to critical/high findings only
flowlyt scan --repo . --output sarif --min-severity HIGH --output-file filtered.sarif

# Limit organization scope
flowlyt analyze-org --organization company --max-repos 20 --output-format sarif -o limited.sarif
```

### Schema Validation
Validate SARIF compliance:

```bash
# Using Microsoft SARIF SDK
npm install -g @microsoft/sarif-multitool
sarif validate flowlyt.sarif

# Using online validator
# Upload to: https://sarifweb.azurewebsites.net/Validation
```

### Performance Optimization
For large repositories:

```bash
# Use focused scanning
flowlyt scan --repo . --output sarif --max-workers 4 --workflow-timeout 60

# Specific workflow analysis
flowlyt scan --workflow .github/workflows/critical.yml --output sarif
```

## Related Documentation

- [CLI Reference](cli-reference.md) - Complete command reference
- [Configuration Guide](configuration.md) - Advanced configuration options  
- [GitHub Actions Integration](cicd-integration.md) - CI/CD setup examples
- [Security Rules](security-rules.md) - Complete rule documentation

## Resources

- **SARIF Specification**: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
- **GitHub SARIF Upload**: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github
- **Microsoft SARIF Tools**: https://github.com/microsoft/sarif-sdk
- **SARIF Web Viewer**: https://sarifweb.azurewebsites.net/
