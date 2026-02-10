# Changelog - Version 1.0.7

**Release Date:** January 15, 2026

## 🎉 What's New

Version 1.0.7 adds code context to JSON and SARIF reports, making it easier to understand and fix security findings without manually searching through workflow files.

## ✨ Features

### Code Context in Reports

**Implements #20** - JSON and SARIF reports now include code context for each finding, showing the lines of code around the security issue.

#### What's Included:
- **Line Number**: Exact line where the issue was found
- **Code Snippet**: 3 lines before and 3 lines after the issue
- **Highlighted Line**: Clear indication of which line has the security issue
- **Direct Links**: GitHub/GitLab URLs pointing to the exact line

#### Example JSON Output:
```json
{
  "RuleID": "INJECTION_FLAW",
  "LineNumber": 42,
  "GitHubURL": "https://github.com/org/repo/blob/main/.github/workflows/ci.yml#L42",
  "codeContext": {
    "lineNumber": 42,
    "startLine": 39,
    "endLine": 45,
    "lines": [
      {"line": 39, "content": "    steps:"},
      {"line": 40, "content": "      - uses: actions/checkout@v4"},
      {"line": 41, "content": "      - name: Run command"},
      {"line": 42, "content": "        run: echo ${{ github.event.issue.title }}", "highlight": true},
      {"line": 43, "content": "      - name: Deploy"},
      {"line": 44, "content": "        run: ./deploy.sh"},
      {"line": 45, "content": ""}
    ]
  }
}
```

#### SARIF Integration:
Code context is automatically included in SARIF reports for GitHub Security tab integration, providing developers with immediate context when viewing alerts.

## 🔧 Implementation Details

### Files Changed:
- `pkg/rules/rules.go`: Added `CodeContext` struct and helper functions
- `pkg/linenum/linenum.go`: Line number mapping with context extraction
- `pkg/output/json.go`: Include code context in JSON output
- `pkg/output/sarif.go`: Include code context in SARIF output

### Benefits:
✅ Faster remediation - see code without searching
✅ Better understanding - context shows why it's a security issue
✅ Improved developer experience - less context switching
✅ Enhanced SARIF reports - richer GitHub Security tab alerts

## 📝 Notes

Code context is automatically generated for all findings when line numbers are available. This feature works with both local scans and remote repository scans.

For workflows without accurate line mapping, the context field will be omitted to avoid showing incorrect information.
