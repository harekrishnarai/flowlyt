# Changelog - Version 1.0.4

**Release Date:** December 20, 2025

## 🎉 What's New

Version 1.0.4 adds AI-powered false positive detection and introduces policy enforcement capabilities for enterprise users.

## ✨ Features

### AI-Powered False Positive Detection
- Integrated OpenAI, Google Gemini, Anthropic Claude, and xAI Grok
- BYOK (Bring Your Own Key) model for privacy and control
- Confidence scoring (0-100%) for each assessment
- Real-time AI verification of security findings

### Enterprise Policy Enforcement
- Custom policy rules for compliance (PCI-DSS, SOX, NIST)
- Policy configuration via YAML
- Automated compliance reporting
- Policy violation tracking

### Advanced AST Analysis
- Call graph analysis for workflow dependencies
- Data flow tracking across jobs
- Reachability analysis for secrets
- Enhanced metric collection

## 🐛 Bug Fixes

- Fixed issue with GitLab CI/CD integration
- Corrected severity mapping for custom rules
- Fixed edge case in permission analysis

## 🔧 Improvements

- Faster AST parsing for complex workflows
- Better caching for repeated scans
- Enhanced documentation
- Improved CLI help messages

## 📝 Notes

This release introduces powerful AI capabilities that help distinguish between real security threats and configuration noise, significantly improving the user experience.

The policy enforcement features make Flowlyt suitable for enterprise environments with strict compliance requirements.
