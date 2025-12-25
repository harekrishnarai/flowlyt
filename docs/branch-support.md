# Branch Support Enhancement

## Overview

Flowlyt now includes intelligent branch detection and support for scanning non-default branches. This enhancement ensures that generated links in reports point to the correct branch being scanned, and allows users to scan any branch of a repository.

## Key Features

### 1. Automatic Default Branch Detection

When no `--branch` flag is specified, Flowlyt automatically detects the repository's default branch:

- **GitHub**: Uses GitHub API to fetch the repository's default branch (`main`, `master`, `develop`, etc.)
- **GitLab**: Uses GitLab API to fetch the repository's default branch
- **Fallback**: Falls back to `main` if detection fails

### 2. Branch-Specific Scanning

Users can now scan specific branches using the `--branch` flag:

```bash
# Scan a specific branch
flowlyt scan --url https://github.com/owner/repo --branch develop

# Scan master branch of a repo that uses master as default
flowlyt scan --url https://github.com/owner/repo --branch master

# Scan a feature branch
flowlyt scan --url https://github.com/owner/repo --branch feature/new-security-checks
```

### 3. Accurate Link Generation

Generated links in reports now use the actual branch being scanned:

**Before:**
```
https://github.com/owner/repo/blob/main/.github/workflows/ci.yml#L25
```
(Would be broken if repo uses `master` as default)

**After:**
```
https://github.com/owner/repo/blob/master/.github/workflows/ci.yml#L25
```
(Correctly uses the repository's actual default branch or specified branch)

## Usage Examples

### Auto-Detect Default Branch

```bash
# GitHub - automatically detects default branch
flowlyt scan --url https://github.com/owner/repo

# GitLab - automatically detects default branch
flowlyt scan --platform gitlab --url https://gitlab.com/owner/repo
```

Output:
```
🔍 Auto-detected default branch: master
```

### Scan Specific Branch

```bash
# Scan develop branch
flowlyt scan --url https://github.com/owner/repo --branch develop

# Scan feature branch
flowlyt scan --url https://github.com/owner/repo --branch feature/security-improvements

# Scan release branch
flowlyt scan --url https://github.com/owner/repo --branch release/v1.0.0
```

### Verbose Mode

See what branch is being used:

```bash
flowlyt scan --url https://github.com/owner/repo --verbose
```

Output:
```
⚡ Fetching workflow files from https://github.com/owner/repo...
🔍 Auto-detected default branch: master
✅ Successfully fetched 3 workflow files
```

## Implementation Details

### GitHub Branch Support

#### API-Based Detection
```go
// Automatically detects default branch using GitHub API
func (c *Client) GetDefaultBranch(owner, repo string) (string, error)
```

#### Clone Support
```go
// Clone specific branch
func (c *Client) CloneRepositoryWithBranch(repoURL, destDir, branch string) (string, error)
```

### GitLab Branch Support

#### API-Based Detection
```go
// Fetches default branch from GitLab API
func FetchGitLabDefaultBranch(instanceURL, owner, repo string) string
```

#### Clone Support
```go
// Clone specific branch
func (c *Client) CloneRepositoryWithBranch(repoURL, tempDir, branch string) (string, error)
```

### Link Generation

Links are generated using the actual branch:

```go
// GitHub
findings[i].GitHubURL = github.GenerateFileURLWithBranch(
    repoURL, 
    findings[i].FilePath, 
    findings[i].LineNumber, 
    detectedBranch  // Uses auto-detected or specified branch
)

// GitLab  
findings[i].GitLabURL = gitlab.GenerateFileURLWithBranch(
    repoURL, 
    findings[i].FilePath, 
    findings[i].LineNumber, 
    detectedBranch  // Uses auto-detected or specified branch
)
```

## Technical Details

### Branch Detection Priority

1. **Explicit `--branch` flag** (highest priority)
2. **Auto-detection via API**
   - GitHub: `GET /repos/:owner/:repo` → `default_branch` field
   - GitLab: `GET /api/v4/projects/:id` → `default_branch` field
3. **Fallback to "main"** (if detection fails)

### Cloning with Branches

When cloning a specific branch, Flowlyt uses:

```bash
git clone --branch <branch-name> --single-branch <repo-url>
```

Benefits:
- **Faster cloning**: Only downloads the specified branch
- **Smaller download**: Single-branch clone is more efficient
- **Accurate scanning**: Scans exact branch state

### URL Format

Generated URLs follow the platform's standard format with the correct branch:

**GitHub:**
```
https://github.com/{owner}/{repo}/blob/{branch}/{path}#L{line}
```

**GitLab:**
```
https://gitlab.com/{owner}/{repo}/-/blob/{branch}/{path}#L{line}
```

## Error Handling

### Branch Not Found

If the specified branch doesn't exist:

```bash
$ flowlyt scan --url https://github.com/owner/repo --branch nonexistent

Error: failed to clone repository: git clone failed:
fatal: Remote branch nonexistent not found in upstream origin
```

### API Rate Limiting

If branch detection hits rate limits:

```bash
$ flowlyt scan --url https://github.com/owner/repo

⚠️  Failed to auto-detect branch (rate limit), using fallback: main
```

Solution: Provide a GitHub token:
```bash
export GITHUB_TOKEN=ghp_your_token_here
flowlyt scan --url https://github.com/owner/repo
```

## Migration Guide

### For Existing Users

**No Breaking Changes**: Existing commands continue to work as before.

**Before (v0.0.9 and earlier):**
```bash
# Always used 'main' hardcoded
flowlyt scan --url https://github.com/owner/repo
```

**After (v0.0.10+):**
```bash
# Automatically detects correct default branch
flowlyt scan --url https://github.com/owner/repo
```

### For CI/CD Pipelines

No changes required in CI/CD configurations. Workflows will automatically use the correct branch.

**GitHub Actions Example:**
```yaml
- name: Scan Workflow Security
  uses: harekrishnarai/flowlyt@v0.0.10
  with:
    repository: '.'
    # Branch is auto-detected from the repository
```

## Testing

### Test Scenarios

1. **Repository with `main` default branch:**
   ```bash
   flowlyt scan --url https://github.com/owner/modern-repo
   # Should detect and use 'main'
   ```

2. **Repository with `master` default branch:**
   ```bash
   flowlyt scan --url https://github.com/owner/legacy-repo
   # Should detect and use 'master'
   ```

3. **Scan specific branch:**
   ```bash
   flowlyt scan --url https://github.com/owner/repo --branch develop
   # Should clone and scan 'develop' branch
   ```

4. **Verify links in output:**
   ```bash
   flowlyt scan --url https://github.com/owner/repo --output json | jq '.findings[0].github_url'
   # Link should use correct branch name
   ```

## Benefits

✅ **Accurate Links**: Reports always contain working links to the actual code  
✅ **Flexible Scanning**: Scan any branch, not just default  
✅ **Smart Detection**: Automatically adapts to repository configuration  
✅ **Better DX**: No manual branch configuration needed  
✅ **Enterprise Ready**: Works with custom branch strategies  
✅ **CI/CD Friendly**: Automatically adapts in pipelines

## Future Enhancements

- [ ] Support for scanning multiple branches in one command
- [ ] Branch comparison reports (diff between branches)
- [ ] PR-specific scanning with base branch comparison
- [ ] Tag-based scanning support

## Related Documentation

- [CLI Reference](cli-reference.md)
- [GitHub Actions Integration](cicd-integration.md)
- [SARIF Output](sarif-output.md)

## Troubleshooting

### Issue: Links still use wrong branch

**Solution:** Ensure you're using version 0.0.10 or later:
```bash
flowlyt --version
```

### Issue: Can't clone specific branch

**Solution:** Ensure the branch exists and you have access:
```bash
git ls-remote --heads https://github.com/owner/repo
```

### Issue: API detection fails

**Solution:** Provide authentication token to avoid rate limits:
```bash
export GITHUB_TOKEN=ghp_your_token
# or
export GITLAB_TOKEN=glpat_your_token
```
