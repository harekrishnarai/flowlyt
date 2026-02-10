# GitHub Actions Workflow Examples

Example workflows showing how to integrate Flowlyt Security Scanner into your GitHub Actions pipelines.

## Available Examples

### [Basic Security Scan](./basic-security-scan.yml)
Simple security scanning with SARIF upload to GitHub Security tab.

**Use case**: Quick security check for every pull request and push to main branch.

**Features**:
- Scans repository workflows
- Uploads SARIF results to GitHub Security tab
- Minimal configuration

### [Enterprise Security Pipeline](./enterprise-pipeline.yml)
Comprehensive enterprise security pipeline with advanced features.

**Use case**: Production-grade security scanning for enterprise environments.

**Features**:
- Policy enforcement
- Compliance checking
- Multiple output formats
- Automated notifications

## Quick Start

Copy any example workflow to your `.github/workflows/` directory:

```bash
# Copy basic security scan
curl -o .github/workflows/security-scan.yml \
  https://raw.githubusercontent.com/harekrishnarai/flowlyt/main/examples/workflows/basic-security-scan.yml

# Or manually copy
cp examples/workflows/basic-security-scan.yml .github/workflows/security-scan.yml
```

## Configuration

Each example includes:
- **Pre-configured inputs** - Common security scanning configurations
- **Best practices** - Recommended settings for different use cases
- **Comments** - Explanation of each configuration option
- **Customization notes** - How to adapt for your needs

## Documentation

For more information, see:
- [Main README](../../README.md) - Project overview and features
- [CLI Reference](../../docs/reference/cli-reference.md) - All command options
- [Configuration Guide](../../docs/reference/configuration.md) - Configuration file examples
- [Security Rules](../../docs/reference/security-rules.md) - Available security rules
- [GitHub Actions Integration](../../docs/integrations/github-actions-integration.md) - Integration guide

## Contributing

Have a useful workflow example? Please submit a pull request!

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.
