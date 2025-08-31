# 🛡️ Flowlyt Action Usage Examples

This directory contains example workflows showing how to integrate Flowlyt Security Scanner into your GitHub Actions pipelines.

## 📋 Examples

### [Basic Security Scan](./basic-security-scan.yml)
Simple security scanning with SARIF upload to GitHub Security tab.

### [Enterprise Security Pipeline](./enterprise-pipeline.yml)
Comprehensive enterprise security pipeline with policy enforcement, compliance checking, and automated remediation.

### [Multi-Environment Scanning](./multi-environment.yml)
Security scanning across different environments (dev, staging, production) with environment-specific policies.

### [Pull Request Security Gate](./pr-security-gate.yml)
Automated security gate for pull requests with inline comments and blocking on critical issues.

### [Compliance Monitoring](./compliance-monitoring.yml)
Continuous compliance monitoring with automated reporting and audit trails.

### [Security Dashboard Integration](./dashboard-integration.yml)
Integration with external security dashboards and notification systems.

## 🚀 Quick Start

Copy any example workflow to your `.github/workflows/` directory and customize the configuration:

```bash
# Copy basic security scan
curl -o .github/workflows/security-scan.yml \
  https://raw.githubusercontent.com/harekrishnarai/flowlyt/main/examples/workflows/basic-security-scan.yml

# Copy enterprise pipeline
curl -o .github/workflows/security-pipeline.yml \
  https://raw.githubusercontent.com/harekrishnarai/flowlyt/main/examples/workflows/enterprise-pipeline.yml
```

## ⚙️ Configuration

Each example includes:
- **Pre-configured inputs** - Common security scanning configurations
- **Best practices** - Recommended settings for different use cases
- **Comments** - Explanation of each configuration option
- **Customization notes** - How to adapt for your needs

## 📚 Documentation

- [Action Documentation](../README-ACTION.md) - Complete action reference
- [Configuration Guide](../CONFIGURATION.md) - Configuration file examples
- [Security Rules](../docs/security-rules.md) - Available security rules
- [Enterprise Features](../docs/enterprise-features.md) - Advanced capabilities
