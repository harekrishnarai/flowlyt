# Flowlyt Documentation

**Comprehensive documentation for Flowlyt - AI-Powered Multi-Platform CI/CD Security Analyzer**

---

## 📚 Documentation Structure

### 🚀 Getting Started

**New to Flowlyt? Start here:**

- [Installation](guides/installation.md) - Install Flowlyt on your system
- [Quick Start](guides/quick-start.md) - Get scanning in 5 minutes
- [Best Practices](guides/best-practices.md) - Security best practices for CI/CD
- [Testing](guides/testing.md) - Testing guide for contributors
- [Troubleshooting](guides/troubleshooting.md) - Common issues and solutions

### ✨ Features

**Explore Flowlyt's powerful features:**

- [🎯 Context-Aware Analysis](features/context-aware-analysis.md) - **NEW!** 50-60% false positive reduction
- [🤖 AI Integration](features/ai-integration.md) - AI-powered false positive detection
- [🔍 AST Analysis](features/ast-analysis.md) - Abstract Syntax Tree analysis
- [🌐 Multi-Platform Support](features/multi-platform-support.md) - GitHub Actions + GitLab CI/CD
- [🏢 Organization Analysis](features/organization-analysis.md) - Scan entire organizations
- [🔐 Secret Detection](features/secret-detection.md) - Find exposed secrets
- [🛡️ Vulnerability Intelligence](features/vulnerability-intelligence.md) - OSV.dev integration

### 🔗 Integrations

**Integrate Flowlyt into your workflow:**

- [CI/CD Integration](integrations/cicd-integration.md) - Run Flowlyt in your pipelines
- [GitHub Actions Integration](integrations/github-actions-integration.md) - Native GitHub integration
- [SARIF Output](integrations/sarif-output.md) - GitHub Security tab support
- [Pipeline Security Gates](integrations/pipeline-security-gates.md) - Automated security gates

### 📖 Reference

**Complete reference documentation:**

- [CLI Reference](reference/cli-reference.md) - All commands and options
- [Configuration](reference/configuration.md) - Configure Flowlyt behavior
- [Security Rules](reference/security-rules.md) - All 85+ security rules
- [Custom Rules](reference/custom-rules.md) - Write your own rules
- [Reporting](reference/reporting.md) - Output formats and reporting

### 🔬 Advanced

**Advanced features and customization:**

- [Advanced AST Features](advanced/advanced-ast-features.md) - Deep dive into AST analysis
- [Advanced Configuration](advanced/advanced-configuration.md) - Advanced config options
- [Policy Enforcement](advanced/policy-enforcement.md) - Enterprise policy enforcement
- [Shell Analysis](advanced/shell-analysis.md) - Shell script security analysis
- [Templates](advanced/templates.md) - Workflow templates and patterns
- [Architecture](advanced/architecture.md) - Flowlyt's internal architecture

---

## 🎯 Quick Navigation

### For New Users

1. [Install Flowlyt](guides/installation.md)
2. [Run your first scan](guides/quick-start.md)
3. [Understand the results](reference/security-rules.md)
4. [Configure for your needs](reference/configuration.md)

### For Security Teams

1. [Context-Aware Analysis](features/context-aware-analysis.md) - Reduce false positives
2. [Organization Analysis](features/organization-analysis.md) - Scan all repositories
3. [Policy Enforcement](advanced/policy-enforcement.md) - Enforce security policies
4. [Pipeline Security Gates](integrations/pipeline-security-gates.md) - Automated gates

### For Developers

1. [CI/CD Integration](integrations/cicd-integration.md) - Add to your pipeline
2. [GitHub Actions Integration](integrations/github-actions-integration.md) - Native integration
3. [Custom Rules](reference/custom-rules.md) - Write custom security rules
4. [Testing Guide](guides/testing.md) - Run and write tests
5. [Architecture](advanced/architecture.md) - Understand the internals

---

## 🌟 Highlights

### NEW: Context-Aware Analysis

**50-60% false positive reduction while maintaining 100% critical vulnerability detection**

Flowlyt now intelligently adjusts severity based on workflow context:
- Test workflows get appropriate treatment
- Release workflows maintain strict standards
- Zero false negatives

[Learn more →](features/context-aware-analysis.md)

### AI-Powered Analysis

**Best-in-class false positive detection with AI**

- Bring Your Own Key (BYOK) model
- Supports OpenAI, Gemini, Claude, Grok, Perplexity
- Context-aware AI reasoning
- Confidence scoring (0-100%)

[Learn more →](features/ai-integration.md)

### Multi-Platform Support

**One tool for all your CI/CD platforms**

- GitHub Actions workflows
- GitLab CI/CD pipelines
- More platforms coming soon

[Learn more →](features/multi-platform-support.md)

---

## 📊 Feature Comparison

| Feature | Description | Documentation |
|---------|-------------|---------------|
| **Context-Aware Analysis** | Intelligent severity adjustment | [Guide](features/context-aware-analysis.md) |
| **AI-Powered Verification** | Reduce false positives with AI | [Guide](features/ai-integration.md) |
| **AST Analysis** | Deep code analysis | [Guide](features/ast-analysis.md) |
| **85+ Security Rules** | Comprehensive detection | [Reference](reference/security-rules.md) |
| **SARIF Output** | GitHub Security integration | [Guide](integrations/sarif-output.md) |
| **Custom Rules** | Extend Flowlyt | [Guide](reference/custom-rules.md) |
| **Organization Scan** | Scan entire GitHub orgs | [Guide](features/organization-analysis.md) |
| **Policy Enforcement** | Enterprise compliance | [Guide](advanced/policy-enforcement.md) |

---

## 🎓 Learning Path

### Beginner

1. **Install** - [Installation Guide](guides/installation.md)
2. **First Scan** - [Quick Start](guides/quick-start.md)
3. **Understand Findings** - [Security Rules](reference/security-rules.md)

### Intermediate

1. **Configure** - [Configuration Guide](reference/configuration.md)
2. **Integrate** - [CI/CD Integration](integrations/cicd-integration.md)
3. **Reduce False Positives** - [Context-Aware Analysis](features/context-aware-analysis.md)

### Advanced

1. **Custom Rules** - [Custom Rules Guide](reference/custom-rules.md)
2. **Policy Enforcement** - [Policy Guide](advanced/policy-enforcement.md)
3. **Architecture** - [Architecture Deep Dive](advanced/architecture.md)

---

## 🔍 Search by Topic

### Security Rules
- [All Security Rules](reference/security-rules.md)
- [Custom Rules](reference/custom-rules.md)
- [Shell Analysis](advanced/shell-analysis.md)

### Configuration
- [Basic Configuration](reference/configuration.md)
- [Advanced Configuration](advanced/advanced-configuration.md)
- [Context-Aware Config](features/context-aware-analysis.md#configuration-optional)

### Integration
- [GitHub Actions](integrations/github-actions-integration.md)
- [CI/CD Pipelines](integrations/cicd-integration.md)
- [SARIF Export](integrations/sarif-output.md)

### Analysis
- [AST Analysis](features/ast-analysis.md)
- [AI-Powered Analysis](features/ai-integration.md)
- [Context-Aware Analysis](features/context-aware-analysis.md)

---

## 🆘 Need Help?

### Common Questions

**Q: How do I reduce false positives?**
A: Use [Context-Aware Analysis](features/context-aware-analysis.md) (enabled by default) and [AI-Powered Verification](features/ai-integration.md).

**Q: How do I integrate with GitHub Actions?**
A: See the [GitHub Actions Integration Guide](integrations/github-actions-integration.md).

**Q: Can I write custom security rules?**
A: Yes! See the [Custom Rules Guide](reference/custom-rules.md).

**Q: How do I scan an entire organization?**
A: Use the [Organization Analysis](features/organization-analysis.md) feature.

### Get Support

- 📖 [Troubleshooting Guide](guides/troubleshooting.md)
- 🐛 [Report an Issue](https://github.com/harekrishnarai/flowlyt/issues)
- 💬 [GitHub Discussions](https://github.com/harekrishnarai/flowlyt/discussions)
- 📧 [Contact](https://github.com/harekrishnarai/flowlyt#-contact)

---

## 🤝 Contributing

Want to contribute to Flowlyt documentation?

1. Fork the repository
2. Update documentation in `docs/` folder
3. Submit a pull request
4. See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines

---

## 📝 Documentation Updates

- **2026-02-10**: Added context-aware analysis documentation
- **2026-02-09**: Reorganized docs into logical subdirectories
- **2026-01**: Added AI integration and multi-platform support docs
- **2025-12**: Initial documentation release

---

## 🔗 Quick Links

- [Main README](../README.md)
- [GitHub Repository](https://github.com/harekrishnarai/flowlyt)
- [Releases](https://github.com/harekrishnarai/flowlyt/releases)
- [Changelog](../CHANGELOG.md)
- [Contributing](../CONTRIBUTING.md)
- [Security Policy](../SECURITY.md)

---

**Need to find something specific?** Use the navigation above or search the docs folder for keywords.
