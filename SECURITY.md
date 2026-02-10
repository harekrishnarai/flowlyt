# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Flowlyt, please send an email to **hi@harekrishnarai.me** with details about the issue. Please include:

- A description of the vulnerability
- Steps to reproduce the issue
- Potential impact and affected versions
- Proof of concept (if applicable)
- Suggestions for mitigations (if any)

We take security seriously and will:
- Acknowledge receipt within 48 hours
- Provide a detailed response within 7 days
- Work with you to understand and address the issue
- Keep you informed throughout the resolution process
- Credit you in the security advisory (unless you prefer to remain anonymous)

**Please do not disclose the vulnerability publicly until we have released a fix.**

## Supported Versions

We actively support the following versions with security updates:

| Version | Supported          | End of Support |
| ------- | ------------------ | -------------- |
| 1.0.x   | :white_check_mark: | Active         |
| 0.0.x   | :x:                | Deprecated     |

**Recommendation**: Always use the latest stable release (v1.0.8+) for the best security and features.

## Security Features in Flowlyt

### Supply Chain Security

#### Binary Verification (v1.0.8+)

All Flowlyt releases include multiple layers of verification:

**1. SHA256 Checksums**
```bash
# Download checksums file
curl -sSL https://github.com/harekrishnarai/flowlyt/releases/download/v1.0.8/checksums.txt -o checksums.txt

# Verify binary integrity
sha256sum -c checksums.txt --ignore-missing
```

**2. Cosign Signatures**

Flowlyt binaries and container images are signed with Cosign:

```bash
# Verify binary signature
cosign verify-blob \
  --signature flowlyt-linux-amd64.sig \
  --certificate flowlyt-linux-amd64.pem \
  --certificate-identity "https://github.com/harekrishnarai/flowlyt/.github/workflows/release.yml@refs/tags/v1.0.8" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  flowlyt-linux-amd64

# Verify container image signature
cosign verify \
  --certificate-identity "https://github.com/harekrishnarai/flowlyt/.github/workflows/docker-publish.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/harekrishnarai/flowlyt:latest
```

**3. SLSA Provenance**

Flowlyt achieves [SLSA Level 3](https://slsa.dev/) build provenance:

```bash
# Verify SLSA provenance
slsa-verifier verify-artifact \
  --provenance-path flowlyt-linux-amd64.intoto.jsonl \
  --source-uri github.com/harekrishnarai/flowlyt \
  flowlyt-linux-amd64
```

**4. SBOM (Software Bill of Materials)**

Each release includes a comprehensive SBOM:

```bash
# View SBOM
curl -sSL https://github.com/harekrishnarai/flowlyt/releases/download/v1.0.8/sbom.json | jq .
```

### GitHub Action Security (v1.0.8+)

Our official GitHub Action (`harekrishnarai/flowlyt`) implements:

- ✅ **Pinned Dependencies**: All actions pinned to full SHA commits
- ✅ **Checksum Verification**: Binary integrity checked before execution
- ✅ **Secure Token Handling**: Tokens passed via environment variables, never command-line
- ✅ **Command Injection Prevention**: Array-based argument construction
- ✅ **Timeout Protection**: Download and execution timeouts
- ✅ **Minimal Permissions**: Least privilege principle

Example secure usage:
```yaml
- name: Run Flowlyt Security Scan
  uses: harekrishnarai/flowlyt@v1.0.8  # Pin to specific version
  with:
    platform: github
    output-format: sarif
    min-severity: MEDIUM
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}  # Token via env, not args
```

### Workflow Security

Our own GitHub Actions workflows follow security best practices:

- ✅ All actions pinned to SHA commits
- ✅ Minimal permissions with explicit grants
- ✅ Timeout protection on all jobs
- ✅ No persist-credentials where unnecessary
- ✅ Regular security scanning (CodeQL, govulncheck, Flowlyt self-scan)
- ✅ OpenSSF Scorecard monitoring

## Security Best Practices

### For Flowlyt Users

**1. Keep Updated**
```bash
# Check for updates
flowlyt --version

# Install latest version
go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
```

**2. Use in CI/CD**

Integrate Flowlyt into your pipeline for continuous security monitoring:

```yaml
- name: Security Scan
  run: |
    flowlyt scan --repo . \
      --output sarif \
      --output-file results.sarif \
      --min-severity MEDIUM
```

**3. Follow Remediation Advice**

Flowlyt provides actionable remediation steps for each finding. Review and implement these recommendations.

**4. Verify Binary Integrity**

Always verify checksums when downloading releases:

```bash
# Automated verification
curl -sSL https://raw.githubusercontent.com/harekrishnarai/flowlyt/main/scripts/verify.sh | bash -s v1.0.8
```

### For Contributors

**1. Security Testing**

Run security checks before submitting PRs:

```bash
# Run Flowlyt self-scan
make test-security

# Run all security checks
go test ./... -v
govulncheck ./...
```

**2. Dependency Updates**

Keep dependencies updated and review security advisories:

```bash
go list -m -u all
go mod tidy
```

**3. Code Review**

Security-sensitive changes require thorough review:
- Input validation changes
- Authentication/authorization logic
- Cryptographic operations
- External command execution

## Security-Related Configuration

### Scanning Options

```bash
# Adjust secret detection sensitivity
flowlyt scan --entropy-threshold 4.5

# Use custom severity threshold
flowlyt scan --min-severity HIGH

# Output formats for integration
flowlyt scan --output sarif    # GitHub Advanced Security
flowlyt scan --output json     # Machine-readable
```

### Context-Aware Analysis (v1.0.8+)

Flowlyt uses intelligent context-aware analysis to reduce false positives by 50-60%:

```yaml
# .flowlyt.yml
context_aware:
  enabled: true  # Default: true

  # Custom severity overrides
  severity_overrides:
    BROAD_PERMISSIONS:
      test_workflows: MEDIUM
      release_workflows: HIGH
```

Disable only if you need raw findings:
```bash
export FLOWLYT_CONTEXT_AWARE=false
```

## Compliance & Certifications

Flowlyt adheres to industry security standards:

- ✅ **OpenSSF Best Practices**: Badge earned
- ✅ **SLSA Level 3**: Build provenance attestations
- ✅ **NIST SSDF**: Secure Software Development Framework alignment
- ✅ **GitHub Security Best Practices**: All workflows hardened

**OpenSSF Scorecard**: Results published weekly via [GitHub Actions](https://github.com/harekrishnarai/flowlyt/actions/workflows/scorecard.yml)

## Security Scanning

Flowlyt undergoes continuous security scanning:

### Automated Scans

- **Flowlyt Self-Scan**: Weekly and on every PR
- **CodeQL Analysis**: Semantic code analysis for vulnerabilities
- **govulncheck**: Go vulnerability database checks
- **Dependency Review**: Automated dependency vulnerability scanning
- **OpenSSF Scorecard**: Supply chain security posture assessment

### Results

All scan results are available:
- [Security Tab](https://github.com/harekrishnarai/flowlyt/security)
- [Code Scanning Alerts](https://github.com/harekrishnarai/flowlyt/security/code-scanning)
- [Dependabot Alerts](https://github.com/harekrishnarai/flowlyt/security/dependabot)

## Security Advisories

Security advisories are published at:
- [GitHub Security Advisories](https://github.com/harekrishnarai/flowlyt/security/advisories)
- Release notes for security fixes

Subscribe to releases to stay informed: [Watch Releases](https://github.com/harekrishnarai/flowlyt/releases)

## Security Resources

### CI/CD Security

- [GitHub Actions Security Hardening Guide](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [Flowlyt Documentation](https://github.com/harekrishnarai/flowlyt/tree/main/docs)

### Supply Chain Security

- [SLSA Framework](https://slsa.dev/)
- [Sigstore (Cosign)](https://www.sigstore.dev/)
- [OpenSSF Best Practices](https://bestpractices.coreinfrastructure.org/)
- [NIST SSDF](https://csrc.nist.gov/Projects/ssdf)

### Security Tools

- [Cosign](https://github.com/sigstore/cosign) - Binary signing and verification
- [slsa-verifier](https://github.com/slsa-framework/slsa-verifier) - SLSA provenance verification
- [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) - Go vulnerability scanner

## Contact

- **Security Issues**: hi@harekrishnarai.me (GPG key available upon request)
- **General Questions**: [GitHub Discussions](https://github.com/harekrishnarai/flowlyt/discussions)
- **Bug Reports**: [GitHub Issues](https://github.com/harekrishnarai/flowlyt/issues)

---

**Last Updated**: February 2026 (v1.0.8)
**Next Review**: May 2026