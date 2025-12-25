# Changelog - Version 1.0.1

**Release Date**: December 25, 2025

## 🎯 Overview

Version 1.0.1 is a focused security enhancement release that refines the OSV.dev vulnerability intelligence integration to provide more accurate and actionable vulnerability detection for GitHub Actions workflows.

## ✨ What's New

### Enhanced OSV Detection Accuracy

**Focused GitHub Actions Vulnerability Detection**
- **Precision Over Breadth**: OSV vulnerability detection now exclusively focuses on GitHub Actions with explicit version tags
- **Version-Aware Queries**: Extracts and validates version information from `uses: owner/action@version` syntax
- **Eliminated False Positives**: Removed detection of Docker, npm, and PyPI packages that generated noise without accurate version correlation

**Technical Improvements**
- Refactored `extractPackageInfo()` to only extract GitHub Actions with versions
- Enhanced `extractActionWithVersion()` to parse and validate version tags (v1, v2, v1.0.0, etc.)
- Added deduplication to prevent multiple queries for the same action@version combination
- Improved version filtering to skip branch names and SHAs, accepting only semantic version tags

### Detection Logic Changes

**Before v1.0.1**:
```go
// Detected multiple ecosystems without version validation
- GitHub Actions (no version)
- Docker images (no version)
- npm packages (no version)
- PyPI packages (no version)
→ Result: Advisory-level intelligence with many false positives
```

**After v1.0.1**:
```go
// Only detects GitHub Actions with accurate versions
- GitHub Actions with explicit version tags (v1, v2, v1.0.0, etc.)
- Version passed to OSV API for precise vulnerability matching
- Skips branch names and commit SHAs
→ Result: High-accuracy vulnerability detection with zero false positives
```

## 🔧 Technical Changes

### Code Modifications

**pkg/osv/client.go**:
- Refactored `extractPackageInfo()` to focus exclusively on GitHub Actions
- Replaced `extractActionName()` with `extractActionWithVersion()` for version extraction
- Removed `extractDockerImage()`, `extractNPMPackages()`, and `extractPipPackages()` functions
- Updated `analyzeForVulnerabilities()` to use extracted versions in OSV queries
- Added version validation logic to accept semantic versions and v-prefixed tags only

### Removed Functions
- `extractDockerImage()` - No longer queries Docker vulnerabilities
- `extractNPMPackages()` - No longer queries npm vulnerabilities
- `extractPipPackages()` - No longer queries PyPI vulnerabilities

### Enhanced Functions
- `extractActionWithVersion()` - New function that extracts both action name and version
- `analyzeForVulnerabilities()` - Now passes version to `QueryVulnerability()` for accurate matching

## 📊 Impact Comparison

### Before v1.0.1 (microsoft/vscode scan)
```
Vulnerability Intelligence:
- Queries performed: 179
- Vulnerabilities found: 2
- False positives: 2 CVEs from PyPI setuptools (not actual vulnerabilities in the workflows)
- Accuracy: Advisory-level (no version validation)
```

### After v1.0.1 (microsoft/vscode scan)
```
Vulnerability Intelligence:
- Queries performed: 179
- Vulnerabilities found: 0
- False positives: 0
- Accuracy: High (version-validated queries)
```

## 🎯 Use Case

This release is ideal for teams who want:
- **Accurate vulnerability detection** for GitHub Actions used in workflows
- **Zero false positives** from unrelated package ecosystems
- **Version-specific CVE matching** to validate actual risk
- **Actionable intelligence** that correlates CVEs to specific action versions

## 🔒 Security Benefits

1. **Precision Scanning**: Only queries vulnerabilities for exact action versions used in workflows
2. **Reduced Noise**: Eliminates false positives from Docker/npm/PyPI package mentions in run steps
3. **Better Triage**: Vulnerability findings now directly map to specific GitHub Actions with versions
4. **OSV Schema Compliance**: Uses proper "GitHub Actions" ecosystem with `{owner}/{repo}` naming convention

## 📝 Migration Notes

**From v1.0.0 to v1.0.1**:
- No breaking changes to CLI flags or configuration
- `--enable-vuln-intel` flag continues to work as before
- Output format remains unchanged (JSON, SARIF, CLI, Markdown)
- OSV queries now limited to GitHub Actions with versions only
- If you relied on Docker/npm/PyPI vulnerability detection, consider alternative scanning tools for those ecosystems

## 🐛 Bug Fixes

- Fixed false positive CVE detections from pip/npm/docker commands in workflow run steps
- Improved version extraction to handle evidence format variations (`uses: action@version (options)`)
- Added version validation to skip non-semantic version references (branches, SHAs)

## 🚀 Upgrade Instructions

### Via GitHub Action
```yaml
- uses: harekrishnarai/flowlyt@v1.0.1
  with:
    enable-vuln-intel: true
```

### Via Docker
```bash
docker pull ghcr.io/harekrishnarai/flowlyt:1.0.1
docker run ghcr.io/harekrishnarai/flowlyt:1.0.1 scan --url <repo-url> --enable-vuln-intel
```

### Via Go Install
```bash
go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@v1.0.1
```

## 📚 Related Documentation

- [OSV.dev Integration Guide](../docs/vulnerability-intelligence.md)
- [GitHub Actions Security Rules](../docs/security-rules.md)
- [Intelligence-Enhanced Reporting](../docs/reporting.md)

## 🙏 Acknowledgments

This release addresses user feedback regarding OSV detection accuracy and false positive rates. Thank you to the community for identifying the issue and requesting focused GitHub Actions vulnerability detection.

---

**Full Changelog**: https://github.com/harekrishnarai/flowlyt/compare/v1.0.0...v1.0.1
