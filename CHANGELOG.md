# Changelog

All notable changes to Flowlyt will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.9] - 2026-03-17

### 🎉 Major Features

**Expression Taint Analysis + 11 New Rules** — 2024-2025 attack class coverage

- **Expression Taint Engine** (`pkg/analysis/ast/taint.go`): Tracks `${{ expr }}` through source → transform → sink. Env-var indirection is now correctly classified as safe, eliminating the root cause of injection false positives.
- **`workflow_run` trust boundary rules** (`WRT-001/002/003`): Detects artifact trust violations — the exact pattern used in the March 2025 tj-actions/reviewdog supply chain attack (CVE-2025-30066)
- **OIDC token abuse rules** (`OA-001/002`): Workflow-level `id-token: write` exposure and missing deployment environment scope
- **Cache poisoning rules** (`CP-001/002`): Broad `restore-keys` without `hashFiles` and cache writes in PR workflows
- **New injection sub-rules** (`EI-001/002/003`): `$GITHUB_ENV` untrusted write, memdump.py exfiltration signature, indirect PPE via build tools
- **`pull_request_target` 3-tier severity**: CRITICAL (head checkout) / MEDIUM (base checkout) / no finding (no checkout)

### ✨ Added

- `pkg/analysis/ast/taint.go` — ExprTaintTracker with 24 untrusted expression sources
- `pkg/rules/workflow_run_trust.go` — WRT-001/002/003
- `pkg/rules/oidc_abuse.go` — OA-001/002
- `pkg/rules/cache_poisoning.go` — CP-001/002
- Integration test fixtures (`testdata/workflows/`) with FP regression and detection tests

### 🐛 Fixed

- Env-var indirection false positive eliminated (taint engine)
- `pull_request_target` labelers/commenters no longer fire CRITICAL
- Duplicate cache findings (2× every finding) fixed
- EI-001/002/003 wired into StandardRules (were previously unreachable via normal scan)
- `classifyExpression` precedence for `workflow_run.head_commit.*` expressions

[Full Details](changelogs/CHANGELOG-v1.0.9.md)

---

## [1.0.8] - 2026-02-10

### 🎉 Major Features

**Context-Aware Analysis** - Revolutionary false positive reduction

- **50-60% false positive reduction** achieved (from 60-70% to 10-15%)
- Intelligent severity adjustment based on workflow context
- Workflow intent detection (ReadOnly, ReadWrite, Deploy, Release)
- Trigger risk assessment (CRITICAL to LOW based on trigger type)
- Permission analysis (actual needs vs. granted permissions)
- Dynamic severity adjustment while preserving 100% of critical findings
- Validated on 6 major open-source projects (968 total findings analyzed)

### ✨ Added

- `pkg/analysis/context/` - Complete context-aware analysis framework
  - `analyzer.go` - Unified context analysis and severity adjustment
  - `intent.go` - Workflow intent detection
  - `permissions.go` - Permission analysis
  - `triggers.go` - Trigger risk assessment
- Comprehensive documentation for context-aware analysis
- Token sanitization in git operations (`pkg/github/security.go`)

### 🔧 Changed

- Integrated context-aware analysis into RuleEngine
- Updated README with context-aware information
- Reorganized documentation into logical subdirectories
- Improved credential handling security

### 🧹 Cleaned

- Removed 192 lines of commented-out code
- Organized 36 documentation files into 5 subdirectories
- Removed temporary and redundant files (~655 KB saved)

### 📊 Results

- Test workflows: Appropriate severity downgrade (HIGH → MEDIUM)
- Release workflows: Strict security standards maintained
- Critical vulnerabilities: 100% preserved (zero false negatives)
- Multi-repo validation: 62% of findings appropriately MEDIUM/LOW
- Industry-leading: Best-in-class 10-15% false positive rate

[Full Details](changelogs/CHANGELOG-v1.0.8.md)

---

## [1.0.7] - 2026-01-15

### ✨ Added

- Code context in JSON and SARIF reports (#20)
- Line number mapping with 3-line context before/after
- Direct GitHub/GitLab URLs to exact line
- Enhanced SARIF integration for GitHub Security tab

### 🔧 Improved

- Faster remediation with immediate code context
- Better developer experience with less context switching
- Richer GitHub Security tab alerts

[Full Details](changelogs/CHANGELOG-v1.0.7.md)

---

## [1.0.6] - 2026-01-06

### 🐛 Fixed

- **Eliminated false positives for internal organization actions** (#19)
- Internal actions (same org) now treated as trusted
- Zero false positives for same-org actions

### 🔧 Changed

- `UNTRUSTED_ACTION_SOURCE` - Skips same-org actions
- `REPO_JACKING_VULNERABILITY` - Skips same-org actions
- `REF_CONFUSION` - Skips internal actions with `@main`/`@master`
- `UNPINNED_ACTION` - Skips internal actions

### 📊 Impact

- Reduced findings from 112 to 104 for org repos
- Maintained full security for external actions
- Improved developer experience for organizations

[Full Details](changelogs/CHANGELOG-v1.0.6.md)

---

## [1.0.5] - 2025-12-28

### ✨ Added

- Multi-platform support (GitHub Actions + GitLab CI/CD)
- GitLab CI/CD workflow scanning
- Platform-specific rule filtering
- Enhanced organization analysis

### 🔧 Improved

- Better error handling for remote repositories
- Improved progress reporting
- Enhanced CLI output

[Full Details](changelogs/CHANGELOG-v1.0.5.md)

---

## [1.0.4] - 2025-12-20

### ✨ Added

- **AI-powered false positive detection**
  - OpenAI, Google Gemini, Anthropic Claude, xAI Grok support
  - BYOK (Bring Your Own Key) model
  - Confidence scoring (0-100%)
- **Enterprise policy enforcement**
  - Custom policy rules (PCI-DSS, SOX, NIST)
  - Automated compliance reporting
- **Advanced AST analysis**
  - Call graph analysis
  - Data flow tracking
  - Reachability analysis

### 🐛 Fixed

- GitLab CI/CD integration issues
- Severity mapping for custom rules
- Permission analysis edge cases

[Full Details](changelogs/CHANGELOG-v1.0.4.md)

---

## [1.0.3] - 2025-12-15

### ✨ Added

- Organization-wide analysis capability
- Bulk repository scanning
- Aggregated security reports
- Top findings across organization

### 🔧 Improved

- Faster scanning for multiple repositories
- Better rate limit handling
- Enhanced reporting formats

[Full Details](changelogs/CHANGELOG-v1.0.3.md)

---

## [1.0.2] - 2025-12-05

### ✨ Added

- Enhanced secret detection (AWS, GCP, Azure)
- Improved entropy-based detection
- Better SARIF output for GitHub Security

### 🐛 Fixed

- Remote repository cloning (#12)
- Line number mapping in SARIF
- Panic with empty workflow files

### 🔧 Improved

- Faster organization scanning
- Better error messages
- Enhanced progress indicators

[Full Details](changelogs/CHANGELOG-v1.0.2.md)

---

## [1.0.1] - 2025-11-25

### ✨ Added

- Custom rules support
- Advanced configuration options
- Template workflow scanning
- Shell script security analysis

### 🐛 Fixed

- Multiple parsing edge cases
- Memory leaks in large scans
- Incorrect severity mapping

### 🔧 Improved

- Performance optimization (62% faster)
- Better documentation
- Enhanced error reporting

[Full Details](changelogs/CHANGELOG-v1.0.1.md)

---

## [1.0.0] - 2025-11-15

### 🎉 Major Release

First stable release of Flowlyt!

### ✨ Added

- 85+ security rules covering:
  - Injection attacks
  - Secret exposure
  - Supply chain security
  - Misconfigurations
  - Shell obfuscation
  - Access control
- GitHub Actions workflow scanning
- SARIF output format
- JSON and YAML reporting
- CLI interface
- Configuration file support
- Remote repository scanning

### 📊 Detection Categories

- Malicious patterns
- Injection flaws
- Secrets exposure
- Supply chain vulnerabilities
- Privilege escalation
- Data exfiltration

[Full Details](changelogs/CHANGELOG-v1.0.0.md)

---

## [0.0.9] - 2025-11-01

### ✨ Added

- SARIF output support
- GitHub Security tab integration
- Severity mapping improvements

### 🐛 Fixed

- Various parsing bugs
- Memory optimization

[Full Details](changelogs/CHANGELOG-v0.0.9.md)

---

## [0.0.8] - 2025-11-01

### 🐛 Fixed

- YAML parsing for complex workflows
- Network timeout handling
- Shell script analysis false positives

### 🔧 Improved

- Progress reporting
- Memory usage optimization
- CLI output formatting

[Full Details](changelogs/CHANGELOG-v0.0.8.md)

---

## [0.0.7] - 2025-10-15

### ✨ Added

- Initial rule set (50+ rules)
- Basic workflow scanning
- JSON output format

### 🔧 Improved

- Rule accuracy
- Scanning performance

[Full Details](changelogs/CHANGELOG-v0.0.7.md)

---

## [0.0.6] - 2025-10-01

### 🎉 Initial Beta Release

- Basic CI/CD security scanning
- GitHub Actions support
- Command-line interface
- Core security rules

[Full Details](changelogs/CHANGELOG-v0.0.6.md)

---

## Version Comparison

| Version | Key Feature | False Positive Rate |
|---------|-------------|-------------------|
| **1.0.8** | Context-Aware Analysis | **10-15%** ✅ |
| 1.0.7 | Code Context in Reports | 60-70% |
| 1.0.6 | Internal Action Trust | 60-70% |
| 1.0.5 | Multi-Platform Support | 60-70% |
| 1.0.4 | AI-Powered Detection | 50-60% with AI |
| 1.0.3 | Organization Analysis | 60-70% |
| 1.0.2 | Enhanced Secret Detection | 60-70% |
| 1.0.1 | Custom Rules | 65-75% |
| 1.0.0 | First Stable Release | 70-80% |

## Links

- [GitHub Repository](https://github.com/harekrishnarai/flowlyt)
- [Documentation](docs/README.md)
- [Installation Guide](docs/guides/installation.md)
- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)

## Versioning

We use [Semantic Versioning](https://semver.org/):
- **Major** version for incompatible API changes
- **Minor** version for added functionality in a backward-compatible manner
- **Patch** version for backward-compatible bug fixes

## Support

- 🐛 [Report Issues](https://github.com/harekrishnarai/flowlyt/issues)
- 💬 [GitHub Discussions](https://github.com/harekrishnarai/flowlyt/discussions)
- 📧 [Contact](https://github.com/harekrishnarai/flowlyt#contact)
