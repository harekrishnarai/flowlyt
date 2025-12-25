# Changelog - Version 1.0.3

**Release Date**: December 25, 2025

## Overview

Version 1.0.3 is a bug fix release that addresses URL generation issues in organization analysis and ensures proper branch detection for GitHub repositories.

## 🐛 Bug Fixes

### Organization Analysis URL Generation

**Fixed Duplicate Path in Finding URLs**
- **Issue**: When using `analyze-org` command, finding URLs contained duplicate `.github/workflows/` paths (e.g., `.github/workflows/.github/workflows/file.yml`)
- **Root Cause**: WorkflowFile Path was being prefixed with `.github/workflows/` even though the filename already represented the relative path
- **Fix**: Removed redundant path prefix when creating WorkflowFile objects in organization analysis
- **Impact**: All finding URLs in organization analysis reports now correctly match the format used in individual repository analysis

**Dynamic Branch Detection in Organization Analysis**
- **Issue**: Organization analysis was not using the repository's actual default branch when generating URLs
- **Enhancement**: Added `DefaultBranch` field to `RepositoryInfo` struct
- **Enhancement**: Updated `DiscoverOrganizationRepositories` to populate default branch from GitHub API
- **Enhancement**: Modified organization analyzer to use `GenerateFileURLWithBranch()` with the detected default branch
- **Impact**: URLs now correctly use the repository's default branch (e.g., `main`, `master`, etc.) instead of always defaulting to `main`

## 📝 Technical Details

### Files Modified

1. **pkg/github/github.go**
   - Added `DefaultBranch` field to `RepositoryInfo` struct
   - Updated `DiscoverOrganizationRepositories` to capture default branch from GitHub API response

2. **pkg/organization/organization.go**
   - Removed redundant `.github/workflows/` prefix in WorkflowFile Path
   - Updated URL generation to use `GenerateFileURLWithBranch()` with detected branch
   - Added `strings` import for branch validation
   - Removed unused `filepath` import

### Verification

Tested with multiple organizations:
- **safedep**: Confirmed URLs use `main` branch correctly
- **actions**: Confirmed URLs use `main` branch correctly  
- **golang**: Confirmed URLs use `master` branch correctly (dynamic detection working)

Example corrected URL:
```
Before: https://github.com/safedep/gateway/blob/main/.github/workflows/.github/workflows/secret_scan.yml#L15
After:  https://github.com/safedep/gateway/blob/main/.github/workflows/secret_scan.yml#L15
```

## 🔄 Compatibility

- Fully backward compatible with v1.0.2
- No breaking changes to CLI interface or configuration
- No changes to API or data structures exposed to users

## 📦 Installation

```bash
go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@v1.0.3
```

## 🙏 Acknowledgments

Thanks to the community for reporting the URL generation issues in organization analysis.
