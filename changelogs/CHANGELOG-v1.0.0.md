# Changelog - Version 1.0.0 🎉

**Release Date:** December 25, 2024  
**Major Release:** First Stable Version

## 🎯 Major Features

### Intelligent Branch Detection & Multi-Branch Support

This release introduces comprehensive branch detection and scanning capabilities, making Flowlyt truly production-ready for diverse repository configurations.

#### Key Improvements:
- ✅ **Automatic Default Branch Detection** - Uses GitHub/GitLab APIs to auto-detect repository default branches
- ✅ **Multi-Branch Scanning** - Scan any branch using `--branch` flag
- ✅ **Accurate Link Generation** - Report links now point to the correct branch being scanned
- ✅ **Smart Fallbacks** - Gracefully falls back to `main` if API detection fails
- ✅ **Efficient Cloning** - Uses `--single-branch` for faster, more efficient clones
- ✅ **Verbose Branch Reporting** - See detected branches with `--verbose` flag

### Problem Solved

**Before v1.0.0:**
- All generated links hardcoded to `main` branch
- Broken links for repositories using `master`, `develop`, or other default branches
- No way to scan non-default branches

**After v1.0.0:**
```bash
# Automatically detects and uses correct branch
flowlyt scan --url https://github.com/git/git

Output:
🔍 Auto-detected default branch: master
Links: https://github.com/git/git/blob/master/...  ✅ Correct!
```

## 🔧 Technical Enhancements

### GitHub Integration
- **New API Function:** `GetDefaultBranch()` - Fetches default branch from GitHub API
- **Enhanced Cloning:** `CloneRepositoryWithBranch()` - Clone specific branches efficiently
- **Smart URL Generation:** `GenerateFileURLWithBranch()` - Accurate links with branch detection

### GitLab Integration  
- **API Integration:** `FetchGitLabDefaultBranch()` - Fetches default branch from GitLab API
- **Branch Cloning:** `CloneRepositoryWithBranch()` - Clone specific GitLab branches
- **URL Generation:** `GenerateFileURLWithBranch()` - Correct links for GitLab repositories

### CLI Improvements
- **Auto-Detection Logic:** Smart branch detection in `runAnalysis()` function
- **Updated Help Text:** Clear documentation of auto-detection feature
- **Verbose Output:** Shows detected branch when `--verbose` flag is used
- **Backward Compatible:** Existing commands work without changes

## 📊 Testing & Validation

All features have been comprehensively tested:

✅ **Test 1:** Auto-detection on repository with `master` default (git/git)  
✅ **Test 2:** Auto-detection on repository with `main` default (microsoft/vscode)  
✅ **Test 3:** Explicit branch specification with `--branch` flag  
✅ **Test 4:** CLI help documentation accuracy  

**Test Results:** 100% pass rate - See [TEST_RESULTS.md](TEST_RESULTS.md)

## 📚 Documentation

### New Documentation
- **[Branch Support Guide](docs/branch-support.md)** - Comprehensive guide to branch features
  - Usage examples
  - Implementation details
  - Troubleshooting guide
  - Migration guide

- **[TEST_RESULTS.md](TEST_RESULTS.md)** - Complete test results and verification

### Updated Documentation
- CLI help text updated with auto-detection information
- Repository cloning documentation enhanced

## 🚀 Usage Examples

### Auto-Detection (Recommended)
```bash
# Scans default branch automatically
flowlyt scan --url https://github.com/owner/repo --verbose

# Output shows detected branch
🔍 Auto-detected default branch: master
```

### Explicit Branch Scanning
```bash
# Scan specific branch
flowlyt scan --url https://github.com/owner/repo --branch develop

# Scan feature branch
flowlyt scan --url https://github.com/owner/repo --branch feature/security-improvements

# Scan release branch  
flowlyt scan --url https://github.com/owner/repo --branch release/v2.0.0
```

### GitLab Support
```bash
# Auto-detect GitLab default branch
flowlyt scan --platform gitlab --url https://gitlab.com/owner/repo --verbose

# Scan specific GitLab branch
flowlyt scan --platform gitlab --url https://gitlab.com/owner/repo --branch main
```

## 🔄 Migration Guide

### For Users on v0.0.9 or Earlier

**Good News:** No breaking changes! Existing commands work as before, but now with better accuracy.

**What Changed:**
- Links in reports now use correct branch names automatically
- You can now scan non-default branches with `--branch` flag
- More reliable URL generation for repositories with custom default branches

**What Stayed the Same:**
- All existing commands work without modification
- Same output formats (JSON, SARIF, CLI, Markdown)
- Same security rules and detection capabilities

### For CI/CD Pipelines

No changes required! Your existing workflows will automatically benefit from branch auto-detection:

```yaml
# GitHub Actions - works as before, now more accurate
- name: Security Scan
  uses: harekrishnarai/flowlyt@v1.0.0
  with:
    repository: ${{ github.repository }}
```

## 📦 Installation

### Docker (Recommended)
```bash
# Pull latest version
docker pull ghcr.io/harekrishnarai/flowlyt:1.0.0

# Use in command
docker run ghcr.io/harekrishnarai/flowlyt:1.0.0 scan --url https://github.com/owner/repo
```

### Go Install
```bash
go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@v1.0.0
```

### Binary Download
Download from [GitHub Releases](https://github.com/harekrishnarai/flowlyt/releases/tag/v1.0.0)

## 🐛 Bug Fixes

- **Fixed:** Hardcoded `main` branch in URL generation
- **Fixed:** Broken links for repositories using `master` as default
- **Fixed:** Inability to scan non-default branches
- **Fixed:** No visibility into which branch is being scanned

## ⚡ Performance Improvements

- **Faster Cloning:** Using `--single-branch` reduces clone time and bandwidth
- **Efficient API Usage:** Smart caching and fallbacks for branch detection
- **Optimized Workflow:** Reduced API calls through intelligent detection logic

## 🔐 Security Enhancements

- **Accurate Security Scanning:** Ensures scanning the correct branch state
- **Better Link Security:** Links point to exact code being scanned
- **Branch Integrity:** Single-branch clones reduce attack surface

## 🎁 Additional Features (From v0.0.9)

This release also includes all features from v0.0.9:

### SARIF GitHub Advanced Security Integration
- **security-severity Property:** Proper severity scores (9.0, 8.0, 5.0, 3.0, 0.0)
- **GitHub Security Tab:** Perfect integration with GitHub Advanced Security
- **Severity Mapping:** Critical=9.0, High=8.0, Medium=5.0, Low=3.0, Info=0.0

### Multi-Platform Docker Support
- **Platforms:** linux/amd64, linux/arm64
- **Optimized Images:** Multi-stage builds for minimal size
- **Automated Publishing:** GitHub Actions workflow for releases

## 📈 What's Next?

Future enhancements planned:
- Multi-branch comparison reports
- PR-specific scanning with base branch comparison
- Tag-based scanning support
- Branch pattern matching for bulk scans

## 🙏 Acknowledgments

Thank you to all users who provided feedback on branch handling issues. This release directly addresses community needs.

## 📄 Full Changelog

**Added:**
- Intelligent branch detection using GitHub/GitLab APIs
- `--branch` flag support for scanning specific branches
- `GetDefaultBranch()` function for GitHub API client
- `CloneRepositoryWithBranch()` for GitHub and GitLab clients
- `FetchGitLabDefaultBranch()` public API for GitLab
- Auto-detection logic in `runAnalysis()` function
- Verbose output showing detected branch
- Comprehensive branch support documentation

**Changed:**
- `--branch` flag no longer defaults to "main", uses auto-detection
- Clone functions now support branch parameter
- URL generation functions use actual branch being scanned
- Help text updated to reflect auto-detection capability

**Fixed:**
- Broken links in reports for repositories not using `main` as default
- Inability to scan branches other than default
- Hardcoded branch references throughout codebase

**Improved:**
- Clone efficiency with `--single-branch` flag
- API usage with smart fallbacks
- User experience with verbose branch reporting
- Documentation with comprehensive guides

## 🔗 Links

- **GitHub Repository:** https://github.com/harekrishnarai/flowlyt
- **Docker Images:** https://github.com/harekrishnarai/flowlyt/pkgs/container/flowlyt
- **Documentation:** https://github.com/harekrishnarai/flowlyt/tree/main/docs
- **Issues:** https://github.com/harekrishnarai/flowlyt/issues

## 📝 Version Information

- **Version:** 1.0.0
- **Go Version:** 1.24.6
- **Docker Base:** golang:1.24-bookworm
- **SARIF Version:** 2.1.0
- **GitHub API:** v3 (go-github/v53)
- **GitLab API:** v4

---

**🎉 Thank you for using Flowlyt! This marks our first stable release with comprehensive branch support.**

For questions or issues, please open an issue on GitHub.
