# Flowlyt Organization Analysis

## Overview

Flowlyt now supports organization-wide security analysis, allowing you to scan all repositories in a GitHub organization simultaneously. This enterprise-grade feature enables comprehensive CI/CD security assessment across your entire organization.

## Features

### 🏢 Organization-Wide Scanning
- Automatically discovers all repositories in a GitHub organization
- Concurrent analysis of multiple repositories for performance
- Comprehensive security rule application across all repositories
- Intelligent filtering and repository selection

### 📊 Advanced Reporting
- Organization-level security summaries
- Repository-by-repository breakdown
- Risk-based repository classification
- Aggregated findings statistics

### ⚙️ Flexible Configuration
- Repository filtering (public/private, forks, archived)
- Custom repository name patterns
- Configurable concurrency limits
- Progress reporting with real-time updates

## Usage

### Basic Organization Analysis
```bash
# Analyze all repositories in an organization
flowlyt analyze-org --organization microsoft

# Analyze with GitHub token for private repositories
GITHUB_TOKEN=your_token flowlyt analyze-org --org kubernetes
```

### Advanced Filtering
```bash
# Include only public repositories
flowlyt analyze-org --org mycompany --include-private=false

# Include forks and archived repositories
flowlyt analyze-org --org mycompany --include-forks --include-archived

# Filter repositories by name pattern
flowlyt analyze-org --org mycompany --repo-filter "^api-.*"

# Limit number of repositories analyzed
flowlyt analyze-org --org mycompany --max-repos 50
```

### Output Configuration
```bash
# Generate JSON report
flowlyt analyze-org --org mycompany --output-format json --output-file org-report.json

# Generate Markdown report
flowlyt analyze-org --org mycompany --output-format markdown --output-file SECURITY-REPORT.md

# Show only summary (skip individual repository details)
flowlyt analyze-org --org mycompany --summary-only
```

### Performance Tuning
```bash
# Adjust concurrent workers
flowlyt analyze-org --org mycompany --max-workers 8

# Disable progress reporting (useful for CI)
flowlyt analyze-org --org mycompany --no-progress
```

## Command Line Options

| Option | Alias | Description | Default |
|--------|-------|-------------|---------|
| `--organization` | `--org`, `-o` | GitHub organization name (required) | - |
| `--output-format` | `-f` | Output format: cli, json, markdown | cli |
| `--output-file` | `-o` | Output file path | stdout |
| `--config` | `-c` | Configuration file path | - |
| `--min-severity` | - | Minimum severity: INFO, LOW, MEDIUM, HIGH, CRITICAL | LOW |
| `--max-repos` | - | Maximum repositories to analyze (0 = no limit) | 100 |
| `--repo-filter` | - | Regular expression for repository names | - |
| `--include-forks` | - | Include forked repositories | false |
| `--include-archived` | - | Include archived repositories | false |
| `--include-private` | - | Include private repositories | true |
| `--include-public` | - | Include public repositories | true |
| `--max-workers` | - | Concurrent workers (0 = CPU count) | 0 |
| `--no-progress` | - | Disable progress reporting | false |
| `--summary-only` | - | Show only organization summary | false |

## Authentication

### GitHub Token
For access to private repositories and higher API rate limits:

```bash
# Set environment variable
export GITHUB_TOKEN=your_personal_access_token

# Or pass inline
GITHUB_TOKEN=your_token flowlyt analyze-org --org mycompany
```

### Required Permissions
Your GitHub token needs:
- `repo` (for private repositories)
- `read:org` (for organization access)
- `read:user` (for user information)

## Repository Filtering

### Visibility Filters
- `--include-private`: Include private repositories (default: true)
- `--include-public`: Include public repositories (default: true)

### Repository Type Filters
- `--include-forks`: Include forked repositories (default: false)
- `--include-archived`: Include archived repositories (default: false)

### Name Pattern Filtering
Use regular expressions to filter repository names:

```bash
# Only API repositories
--repo-filter "^api-"

# Exclude test repositories
--repo-filter "^(?!.*test).*$"

# Only repositories ending with "-service"
--repo-filter ".*-service$"
```

## Report Formats

### CLI Output (Default)
Human-readable console output with:
- Organization overview
- Repository count and status
- Summary statistics by severity
- Risk distribution across repositories
- Individual repository details (unless `--summary-only`)

### JSON Output
Machine-readable JSON with complete analysis data:
```json
{
  "organization": "mycompany",
  "scan_time": "2024-01-15T10:30:00Z",
  "duration": "2m30s",
  "total_repositories": 45,
  "analyzed_repositories": 43,
  "skipped_repositories": 2,
  "summary": {
    "total_findings": 127,
    "findings_by_severity": {
      "CRITICAL": 5,
      "HIGH": 23,
      "MEDIUM": 67,
      "LOW": 32
    },
    "repositories_by_risk": {
      "CRITICAL": 2,
      "HIGH": 8,
      "MEDIUM": 15,
      "LOW": 18,
      "CLEAN": 0
    }
  },
  "repository_results": [...]
}
```

### Markdown Output
Documentation-friendly format suitable for:
- Security review reports
- GitHub repository documentation
- Compliance documentation
- Team sharing and communication

## Performance Considerations

### Concurrency
- Default workers: CPU core count
- Recommended for large organizations: 4-8 workers
- Higher concurrency may hit GitHub API rate limits

### Rate Limiting
- Authenticated requests: 5,000/hour
- Unauthenticated requests: 60/hour
- Consider using `--max-repos` for large organizations

### Memory Usage
- Each repository requires temporary disk space for cloning
- Memory usage scales with concurrent workers
- Monitor disk space for organizations with large repositories

## Use Cases

### Security Teams
```bash
# Weekly security assessment
flowlyt analyze-org --org mycompany \
  --output-format json \
  --output-file weekly-security-$(date +%Y%m%d).json

# Critical issues only
flowlyt analyze-org --org mycompany \
  --min-severity CRITICAL \
  --summary-only
```

### DevOps Teams
```bash
# CI/CD pipeline integration
flowlyt analyze-org --org mycompany \
  --no-progress \
  --output-format json \
  --max-repos 20

# Focus on active repositories only
flowlyt analyze-org --org mycompany \
  --include-archived=false \
  --include-forks=false
```

### Compliance Teams
```bash
# Comprehensive audit report
flowlyt analyze-org --org mycompany \
  --include-forks \
  --include-archived \
  --output-format markdown \
  --output-file COMPLIANCE-REPORT.md
```

## Integration Examples

### GitHub Actions
```yaml
name: Organization Security Scan
on:
  schedule:
    - cron: '0 2 * * 1'  # Weekly on Monday at 2 AM

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Organization Security Scan
        run: |
          flowlyt analyze-org \
            --org ${{ github.repository_owner }} \
            --output-format json \
            --output-file security-report.json \
            --no-progress
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Upload Security Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.json
```

### Shell Script
```bash
#!/bin/bash
# organization-security-scan.sh

ORG_NAME="${1:-mycompany}"
REPORT_DATE=$(date +%Y%m%d)
REPORT_FILE="security-report-${ORG_NAME}-${REPORT_DATE}.json"

echo "🔍 Scanning organization: $ORG_NAME"

flowlyt analyze-org \
  --org "$ORG_NAME" \
  --output-format json \
  --output-file "$REPORT_FILE" \
  --max-workers 4 \
  --include-forks=false

echo "📊 Report saved to: $REPORT_FILE"

# Extract critical findings
jq '.summary.findings_by_severity.CRITICAL' "$REPORT_FILE"
```

## Troubleshooting

### Common Issues

#### Authentication Errors
```
Error: failed to discover repositories: GET https://api.github.com/orgs/mycompany/repos: 401 Bad credentials
```
**Solution**: Set valid `GITHUB_TOKEN` environment variable

#### Rate Limiting
```
Error: failed to discover repositories: GET https://api.github.com/orgs/mycompany/repos: 403 API rate limit exceeded
```
**Solution**: 
- Use authenticated requests with `GITHUB_TOKEN`
- Reduce `--max-workers`
- Use `--max-repos` to limit scope

#### Organization Not Found
```
Error: failed to discover repositories: GET https://api.github.com/orgs/mycompany/repos: 404 Not Found
```
**Solution**: 
- Verify organization name spelling
- Ensure your token has access to the organization
- Check if organization exists and is accessible

#### No Repositories Found
```
⚠️  No repositories found in organization 'mycompany' matching the specified criteria
```
**Solution**:
- Check filter settings (`--include-private`, `--include-public`)
- Verify `--repo-filter` pattern
- Ensure organization has repositories

### Debug Mode
Enable verbose logging:
```bash
FLOWLYT_DEBUG=1 flowlyt analyze-org --org mycompany
```

## Comparison with Single Repository Analysis

| Feature | Single Repository | Organization Analysis |
|---------|------------------|----------------------|
| Scope | One repository | All org repositories |
| Discovery | Manual URL/path | Automatic via GitHub API |
| Concurrency | File-level | Repository-level |
| Reporting | Individual | Aggregated + Individual |
| Filtering | N/A | Advanced repository filters |
| Authentication | Optional | Required for private repos |
| Use Case | Focused analysis | Enterprise assessment |

## Future Enhancements

The organization analysis feature is designed to be extensible. Planned enhancements include:

- **Multi-platform support**: GitLab, Azure DevOps organization scanning
- **Advanced filtering**: Language-based, last-activity, size filters
- **Trend analysis**: Historical comparison and security posture trending
- **Integration APIs**: REST API for automated security dashboards
- **Custom rules**: Organization-specific security policies
- **Compliance frameworks**: SOC2, PCI-DSS, NIST framework mapping

## Contributing

Organization analysis is an active area of development. Contributions are welcome for:
- Additional filtering options
- Performance optimizations
- Report format enhancements
- Integration examples
- Documentation improvements

See [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution guidelines.
