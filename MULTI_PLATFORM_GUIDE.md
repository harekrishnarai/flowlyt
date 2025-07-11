# Multi-Platform CI/CD Security Analysis

Flowlyt v2.2.0 now supports multi-platform CI/CD security analysis, starting with GitLab CI/CD support alongside existing GitHub Actions support.

## Platform Support

### Supported Platforms
- **GitHub Actions** (`--platform=github`) - Default
- **GitLab CI/CD** (`--platform=gitlab`) - New!

### Upcoming Platforms
- Jenkins (planned)
- Azure DevOps (planned)

## Usage

### GitHub Actions (Default)
```bash
# Analyze GitHub Actions workflows
flowlyt --repo /path/to/repo
flowlyt --platform=github --repo /path/to/repo
flowlyt --url https://github.com/user/repo
```

### GitLab CI/CD
```bash
# Analyze GitLab CI/CD pipelines (local repository)
flowlyt --platform=gitlab --repo /path/to/repo
flowlyt --platform=gitlab --workflow .gitlab-ci.yml

# Analyze GitLab SaaS repositories
flowlyt --platform=gitlab --url https://gitlab.com/user/repo
flowlyt --url https://gitlab.com/user/repo  # Auto-detects GitLab

# Analyze on-premise GitLab repositories
flowlyt --platform=gitlab --url https://gitlab.company.com/team/project
flowlyt --platform=gitlab --url https://gitlab.company.com/team/project --gitlab-instance https://gitlab.company.com
```

### Authentication

#### GitHub
Set the `GITHUB_TOKEN` environment variable for private repositories:
```bash
export GITHUB_TOKEN=your_github_token
flowlyt --url https://github.com/user/private-repo
```

#### GitLab
Set the `GITLAB_TOKEN` environment variable for private repositories:
```bash
export GITLAB_TOKEN=your_gitlab_token
flowlyt --url https://gitlab.com/user/private-repo
```

For on-premise GitLab instances:
```bash
export GITLAB_TOKEN=your_gitlab_token
flowlyt --url https://gitlab.company.com/team/project --gitlab-instance https://gitlab.company.com
```

## Platform Auto-Detection

Flowlyt can automatically detect the platform based on repository URLs:

```bash
# These commands automatically detect GitLab and switch platform
flowlyt --url https://gitlab.com/user/repo
flowlyt --url https://gitlab.company.com/team/project

# GitHub URLs work as expected
flowlyt --url https://github.com/user/repo
```

## Supported Repository Sources

### Local Repositories
- **GitHub**: Local repositories with `.github/workflows/` directory
- **GitLab**: Local repositories with `.gitlab-ci.yml` or `.gitlab/ci/` directory

### Remote URLs
- **GitHub SaaS**: `https://github.com/owner/repo`
- **GitLab SaaS**: `https://gitlab.com/owner/repo`
- **GitLab On-Premise**: `https://gitlab.company.com/owner/repo`

### Single Workflow Files
- **GitHub**: Any `.yml`/`.yaml` file with GitHub Actions syntax
- **GitLab**: Any `.yml`/`.yaml` file with GitLab CI syntax

## GitLab CI/CD Security Rules

The following GitLab-specific security rules have been implemented:

### High Severity Rules
- **GITLAB_INSECURE_IMAGE**: Detects use of `latest` tag or unverified Docker images
- **GITLAB_EXPOSED_VARIABLES**: Identifies potentially sensitive variables exposed in pipeline configuration
- **GITLAB_PRIVILEGED_SERVICES**: Detects privileged Docker services usage

### Critical Severity Rules
- **GITLAB_SCRIPT_INJECTION**: Identifies script injection vulnerabilities where user input is used directly in commands

### Medium Severity Rules
- **GITLAB_UNRESTRICTED_RULES**: Detects pipelines without proper branch/tag restrictions
- **GITLAB_INSECURE_ARTIFACTS**: Identifies artifacts configured without proper expiration or access controls

## File Discovery

### GitHub Actions
- `.github/workflows/*.yml`
- `.github/workflows/*.yaml`

### GitLab CI/CD
- `.gitlab-ci.yml`
- `.gitlab-ci.yaml`
- `.gitlab/ci/*.yml`
- `.gitlab/ci/*.yaml`

## Example Output

### GitLab CI/CD Analysis
```bash
$ flowlyt --platform=gitlab --workflow=.gitlab-ci.yml

🔍 Flowlyt - Multi-Platform CI/CD Security Analyzer
Platform: GITLAB
=======================================
Scanning single workflow file .gitlab-ci.yml...
Found 1 workflow files.
Analyzing .gitlab-ci.yml...

► SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SEVERITY | COUNT | INDICATOR      
-----------+-------+----------------
  CRITICAL |   0   |                
  HIGH     |   4   | █████████████  
  MEDIUM   |   2   | ███████        
  LOW      |   0   |                
  INFO     |   0   |                
  TOTAL    |   6   |                

► FINDINGS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

■ HIGH SEVERITY FINDINGS
─────────────────────────────────────────────────

⚠ [1] Exposed Sensitive Variables (GITLAB_EXPOSED_VARIABLES)
  File:        .gitlab-ci.yml
  Line:        9
  Description: Potentially sensitive variables exposed in pipeline configuration

⚠ [2] Privileged Docker Services (GITLAB_PRIVILEGED_SERVICES)
  File:        .gitlab-ci.yml
  Line:        40
  Description: Using privileged Docker services increases attack surface

■ MEDIUM SEVERITY FINDINGS
─────────────────────────────────────────────────

⚠ [3] Unrestricted Pipeline Rules (GITLAB_UNRESTRICTED_RULES)
  File:        .gitlab-ci.yml
  Line:        1
  Description: Pipeline runs without proper branch, tag, or merge request restrictions

⚠ [4] Insecure Artifact Configuration (GITLAB_INSECURE_ARTIFACTS)
  File:        .gitlab-ci.yml
  Line:        31
  Description: Artifacts configured without proper expiration time

✅ Scan completed in 4ms
Found 6 issues (0 Critical, 4 High, 2 Medium, 0 Low, 0 Info)
```

## Rule Coverage

### Total Rules by Platform
- **GitHub Actions**: 8 rules (standard security rules)
- **GitLab CI/CD**: 14 rules (8 standard + 6 GitLab-specific rules)

### Common Security Categories
- Supply Chain Security
- Injection Attack Prevention
- Secrets Exposure Detection
- Access Control Validation
- Privilege Escalation Prevention
- Data Exposure Protection

## Configuration

All existing configuration options work with multi-platform support:

```yaml
# .flowlyt.yml
rules:
  enabled:
    - GITLAB_INSECURE_IMAGE
    - GITLAB_SCRIPT_INJECTION
  disabled:
    - GITLAB_UNRESTRICTED_RULES
    
output:
  format: json
  minSeverity: HIGH
```

## Future Enhancements

1. **Jenkins Pipeline Support**: Analyze Jenkinsfile configurations
2. **Azure DevOps Support**: Analyze azure-pipelines.yml files
3. **Cross-Platform Rule Harmonization**: Unified rule IDs across platforms
4. **Platform-Specific Configuration**: Per-platform rule configuration
5. **Comparative Analysis**: Compare security posture across platforms

## Testing

The multi-platform functionality includes comprehensive tests:

```bash
# Run all tests
go test ./...

# Run GitLab-specific tests
go test ./pkg/gitlab/...

# Test both platforms
flowlyt --platform=github --repo .
flowlyt --platform=gitlab --workflow .gitlab-ci.yml
```

## Troubleshooting

### GitLab Repository Access Issues

**Problem**: "failed to clone repository" error
**Solutions**:
1. Check if the repository URL is correct and accessible
2. For private repositories, set `GITLAB_TOKEN` environment variable
3. For on-premise GitLab, specify `--gitlab-instance` flag
4. Ensure `git` command is available in your PATH

**Problem**: "Auto-detected GitLab repository" but analysis fails
**Solutions**:
1. Explicitly set `--platform=gitlab` to avoid auto-detection issues
2. Check if the repository contains `.gitlab-ci.yml` files

**Problem**: On-premise GitLab instance not recognized
**Solutions**:
1. Use `--gitlab-instance https://your-gitlab.com` flag
2. Ensure the instance URL includes the protocol (https://)
3. Verify network connectivity to the GitLab instance

### Authentication Issues

**GitHub**: Set `GITHUB_TOKEN` for private repositories
```bash
export GITHUB_TOKEN=ghp_your_token_here
```

**GitLab**: Set `GITLAB_TOKEN` for private repositories  
```bash
export GITLAB_TOKEN=glpat-your_token_here
```

### Performance Considerations

- Repository cloning may take time for large repositories
- Use `--workflow` flag to scan single files for faster analysis
- Temporary directories are cleaned up automatically unless `--temp-dir` is specified

## Migration Guide

Existing Flowlyt users can continue using the tool without any changes, as GitHub Actions remains the default platform. To analyze GitLab CI/CD pipelines, simply add the `--platform=gitlab` flag.

The tool maintains backward compatibility with all existing features:
- Configuration files
- Policy files
- Output formats
- CLI flags
- Rule filtering
