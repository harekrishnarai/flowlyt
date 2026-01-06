# Changelog - Version 1.0.6

**Release Date:** January 6, 2026

## 🎉 What's New

Version 1.0.6 eliminates false positives for internal organization actions, significantly reducing noise for organizations using their own private GitHub Actions.

## 🐛 Bug Fixes

### Internal Organization Actions No Longer Flagged as Untrusted

**Fixes #19** - Internal organization actions (same org as repository) are now treated as trusted and no longer flagged with false positives.

#### Rules Updated:
- **UNTRUSTED_ACTION_SOURCE**: Skips actions from the same organization
- **REPO_JACKING_VULNERABILITY**: Skips actions from the same organization  
- **REF_CONFUSION**: Skips internal actions using `@main` or `@master` branches
- **UNPINNED_ACTION**: Skips internal actions not pinned to SHA commits

#### How It Works:
When scanning a repository (e.g., `org/repo`), Flowlyt now:
1. Extracts the repository owner/organization (`org`)
2. Automatically trusts actions from the same organization (`org/internal-action`)
3. Maintains strict security checks for external third-party actions

#### Example:
```yaml
# Repository: myorg/myrepo
jobs:
  deploy:
    steps:
      # ✅ Internal action - NOT flagged
      - uses: myorg/internal-action@main
      
      # ⚠️ External action - STILL properly flagged
      - uses: external-org/action@main
```

#### Impact:
- **Before**: Organizations saw false positives for their own internal actions
- **After**: Zero false positives for same-org actions, focus on real external risks
- **Test Results** (org/repo): 
  - Reduced findings from 112 to 104 (8 false positives eliminated)
  - All external actions still properly flagged

## 🔧 Implementation Details

### Files Changed:
- `cmd/flowlyt/main.go`: Added repository owner extraction from URLs
- `pkg/parser/parser.go`: Added `RepositoryOwner` field to `WorkflowFile` struct
- `pkg/organization/organization.go`: Set repository owner during organization analysis
- `pkg/rules/rules.go`: Updated `REF_CONFUSION` and `UNPINNED_ACTION` rules
- `pkg/rules/supply_chain.go`: Updated `UNTRUSTED_ACTION_SOURCE` and `REPO_JACKING_VULNERABILITY` rules

### Benefits:
✅ Eliminates false positives for internal actions  
✅ Maintains security for external dependencies  
✅ Allows `@main` usage for internal actions (reasonable trade-off)  
✅ Reduces alert fatigue and focuses on real risks  
✅ Works automatically with `--url` flag and `analyze-org` command  

## 📝 Notes

This release improves the developer experience for organizations maintaining their own private GitHub Actions by recognizing that internal actions are part of a trusted internal supply chain. External actions continue to receive full security scrutiny.

For local scans without a repository URL, all actions are treated as external (same behavior as before).
