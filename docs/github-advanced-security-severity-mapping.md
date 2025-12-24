# GitHub Advanced Security Severity Mapping - Implementation Summary

## Overview
This document describes the improvements made to Flowlyt's SARIF output to ensure proper severity display in GitHub Advanced Security.

## Problem Statement
Previously, Flowlyt's SARIF output was mapping security findings to generic SARIF levels (`error`, `warning`, `note`), which caused GitHub Advanced Security to display all findings as just "Error" or "Warning" without distinguishing between Critical, High, Medium, and Low severity levels.

## Solution
Added GitHub Advanced Security compatibility by implementing the `security-severity` property in SARIF rule definitions. This property uses numeric scores that GitHub maps to its severity categories.

## Changes Made

### 1. Added Security Severity Scoring Function
**File**: `pkg/report/sarif.go`

Added a new function `getSecuritySeverityScore()` that maps Flowlyt's severity levels to numeric scores compatible with GitHub Advanced Security:

```go
func (g *Generator) getSecuritySeverityScore(severity rules.Severity) string {
    switch severity {
    case rules.Critical:
        return "9.0" // Critical: 9.0-10.0 range
    case rules.High:
        return "8.0" // High: 7.0-8.9 range
    case rules.Medium:
        return "5.0" // Medium: 4.0-6.9 range
    case rules.Low:
        return "3.0" // Low: 0.1-3.9 range
    case rules.Info:
        return "0.0" // Info: 0.0 for informational
    default:
        return "5.0" // Default to medium
    }
}
```

### 2. Updated SARIF Level Mapping
**File**: `pkg/report/sarif.go`

Improved the `severityToSARIFLevel()` function to better align with GitHub's expectations:

- **Critical** → `error` (with security-severity: 9.0)
- **High** → `error` (with security-severity: 8.0)
- **Medium** → `warning` (with security-severity: 5.0)
- **Low** → `warning` (with security-severity: 3.0)
- **Info** → `note` (with security-severity: 0.0)

### 3. Enhanced Rule Properties
**File**: `pkg/report/sarif.go`

Modified `addSARIFRule()` to include the `security-severity` property in rule definitions:

```go
rule.WithProperties(sarif.Properties{
    "category":          string(finding.Category),
    "severity":          string(finding.Severity),
    "security-severity": g.getSecuritySeverityScore(finding.Severity), // NEW
    "tags":              []string{"security", "ci-cd", string(finding.Category)},
    "precision":         "high",
    "problem.severity":  string(finding.Severity),
})
```

### 4. Updated Documentation
**File**: `docs/sarif-output.md`

- Added detailed explanation of GitHub Advanced Security severity mapping
- Included severity mapping table showing the relationship between Flowlyt severities and GitHub display
- Updated SARIF structure examples to show `security-severity` property
- Added example SARIF output with complete severity information

### 5. Added Tests
**File**: `pkg/report/sarif_test.go`

- Added `TestGetSecuritySeverityScore()` to verify correct score mapping
- Updated `TestSeverityToSARIFLevel()` to reflect new mappings
- Enhanced `TestSARIFGeneration()` to validate `security-severity` property presence

### 6. Created Example SARIF File
**File**: `examples/sarif-github-advanced-security-example.json`

Created a comprehensive example showing how findings appear with different severity levels in SARIF format.

## Severity Mapping Table

| Flowlyt Severity | security-severity Score | GitHub Display | SARIF Level | Description |
|-----------------|------------------------|----------------|-------------|-------------|
| CRITICAL        | 9.0                    | Critical       | error       | Most severe security issues requiring immediate action |
| HIGH            | 8.0                    | High           | error       | Serious security vulnerabilities |
| MEDIUM          | 5.0                    | Medium         | warning     | Moderate security concerns |
| LOW             | 3.0                    | Low            | warning     | Minor security issues or best practices |
| INFO            | 0.0                    | Note           | note        | Informational findings |

## GitHub Advanced Security Integration

After these changes, when you upload SARIF to GitHub:

```yaml
- name: Upload SARIF to GitHub  
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: flowlyt.sarif
    category: flowlyt-security
```

Findings will now appear in the Security tab with proper severity labels:

- ✅ **Critical** - Repository Jacking Vulnerability
- ✅ **High** - Untrusted Action Source
- ✅ **Medium** - Weak Secret Pattern
- ✅ **Low** - Missing Workflow Permissions

Instead of generic:
- ❌ **Error** - Repository Jacking Vulnerability
- ❌ **Error** - Untrusted Action Source
- ❌ **Warning** - Weak Secret Pattern

## Testing

All tests pass successfully:

```bash
$ go test -v ./pkg/report -run "TestSARIF"
=== RUN   TestSARIFGeneration
--- PASS: TestSARIFGeneration (0.00s)
=== RUN   TestSeverityToSARIFLevel
--- PASS: TestSeverityToSARIFLevel (0.00s)
=== RUN   TestGetSecuritySeverityScore
--- PASS: TestGetSecuritySeverityScore (0.00s)
PASS
```

## Benefits

1. **Better Visibility**: Security teams can immediately identify critical issues in GitHub's Security tab
2. **Improved Prioritization**: Clear severity levels help teams prioritize remediation efforts
3. **Standards Compliance**: Follows GitHub Advanced Security's severity scoring guidelines
4. **Backward Compatible**: Existing SARIF consumers still work correctly
5. **Enhanced Reporting**: More accurate representation of security posture

## References

- [GitHub Code Scanning API - Severity Levels](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#reportingdescriptor-object)
- [SARIF 2.1.0 Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [GitHub Advanced Security Documentation](https://docs.github.com/en/enterprise-cloud@latest/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/about-code-scanning)

## Migration Notes

No migration is required. The changes are fully backward compatible. Existing SARIF consumers will continue to work as expected, and GitHub Advanced Security will automatically use the new `security-severity` property when available.
