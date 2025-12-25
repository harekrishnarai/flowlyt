# Flowlyt v0.0.9 Release Notes

**Release Date**: December 24, 2025

## 🚀 Highlights

### 🎯 GitHub Advanced Security Integration Enhancement
- **Improved SARIF Severity Mapping**: Findings now display with proper severity levels (Critical, High, Medium, Low) in GitHub's Security tab instead of generic "Error" and "Warning" labels.
- **Security-Severity Property**: Added GitHub Advanced Security compatible `security-severity` property to SARIF output with numeric scoring.
- **Better Prioritization**: Security teams can now immediately identify critical issues in GitHub's Security tab with accurate severity badges.

## 🔍 What's New

### Enhanced SARIF Output
- **Severity Score Mapping** (commit: TBD):
  - Critical findings: `security-severity: 9.0` → Display as "Critical" 🔴
  - High findings: `security-severity: 8.0` → Display as "High" 🟠
  - Medium findings: `security-severity: 5.0` → Display as "Medium" 🟡
  - Low findings: `security-severity: 3.0` → Display as "Low" 🔵
  - Info findings: `security-severity: 0.0` → Display as "Note" ⚪

- **Improved SARIF Level Assignment**:
  - Critical/High → `error` level
  - Medium/Low → `warning` level
  - Info → `note` level

### New Documentation
- **GitHub Advanced Security Severity Mapping Guide**: Comprehensive documentation on severity mapping implementation
- **Visual Severity Mapping Diagram**: Easy-to-understand visual reference for severity conversions
- **Updated SARIF Output Guide**: Enhanced examples showing new severity properties

### Testing & Quality
- **New Test Coverage**: Added `TestGetSecuritySeverityScore()` to validate severity score mapping
- **Enhanced Validation**: Tests now verify presence of `security-severity` property in SARIF rules
- **All Tests Passing**: 100% test success rate maintained

## 📊 Impact

### Before v0.0.9
```
GitHub Security Tab:
├── Error: Untrusted Action Source
├── Error: Repository Jacking Vulnerability  
├── Error: Git Reference Confusion
└── Warning: Missing Permissions
```

### After v0.0.9
```
GitHub Security Tab:
├── 🔴 Critical: Repository Jacking Vulnerability (9.0)
├── 🟠 High: Untrusted Action Source (8.0)
├── 🟠 High: Git Reference Confusion (8.0)
└── 🔵 Low: Missing Permissions (3.0)
```

## 🛠 Technical Details

### SARIF Format Changes
```json
{
  "rules": [{
    "id": "UNTRUSTED_ACTION_SOURCE",
    "defaultConfiguration": { "level": "error" },
    "properties": {
      "security-severity": "9.0",  // NEW: GitHub-compatible score
      "severity": "CRITICAL",
      "category": "SUPPLY_CHAIN"
    }
  }]
}
```

### GitHub Severity Score Ranges
| Score Range | Severity Display | Flowlyt Mapping |
|-------------|-----------------|-----------------|
| 9.0 - 10.0  | Critical        | CRITICAL        |
| 7.0 - 8.9   | High            | HIGH            |
| 4.0 - 6.9   | Medium          | MEDIUM          |
| 0.1 - 3.9   | Low             | LOW             |
| 0.0         | Note            | INFO            |

## 🔧 Upgrade Notes

### Standard Upgrade
```bash
go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@v0.0.9
flowlyt --version  # should show 0.0.9
```

### GitHub Actions Upgrade
```yaml
- name: Flowlyt Security Scan
  uses: harekrishnarai/flowlyt@v0.0.9
  with:
    output-format: sarif
    output-file: flowlyt-results.sarif

- name: Upload SARIF to GitHub
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: flowlyt-results.sarif
    category: flowlyt-security
```

### Breaking Changes
**None** - This release is fully backward compatible. Existing SARIF consumers will continue to work as expected.

## ✅ Verification Checklist
- [ ] `flowlyt --version` outputs `0.0.9`
- [ ] SARIF output includes `security-severity` property in rule definitions
- [ ] GitHub Security tab shows proper severity labels (Critical/High/Medium/Low)
- [ ] All existing scans continue to work without modification
- [ ] Tests pass: `go test ./pkg/report -v`

## 📈 Benefits

✅ **Clear Prioritization**: Instantly see which issues need immediate attention  
✅ **Better Filtering**: Filter by severity in GitHub's Security UI  
✅ **Accurate Metrics**: Security dashboards show correct severity distribution  
✅ **Compliance Ready**: Meets GitHub Advanced Security scanning standards  
✅ **Team Alignment**: Consistent severity language across tools and teams  
✅ **Enterprise Ready**: Compatible with GitHub Advanced Security features

## 🔗 Related Documentation

- [SARIF Output Guide](docs/sarif-output.md) - Complete SARIF documentation
- [GitHub Advanced Security Severity Mapping](docs/github-advanced-security-severity-mapping.md) - Implementation details
- [Severity Mapping Visual Guide](docs/severity-mapping-visual.md) - Visual reference
- [Example SARIF Output](examples/sarif-github-advanced-security-example.json) - Sample with all severities

## 🐛 Bug Fixes
None in this release - focus was on enhancement.

## 📈 Next (Roadmap Focus)
- Enhanced policy enforcement with severity-based gates
- Improved vulnerability intelligence integration
- Organization-wide security posture reporting with severity trends
- VS Code extension with inline severity indicators

## 🙏 Acknowledgments
Special thanks to the community for reporting the GitHub Advanced Security severity display issue and helping us improve the integration.

---

**Full Changelog**: v0.0.8...v0.0.9  
**Documentation**: https://github.com/harekrishnarai/flowlyt/tree/main/docs  
**Issues**: https://github.com/harekrishnarai/flowlyt/issues
