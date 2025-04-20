# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Flowlyt, please send an email to hi@harekrishnarai.me with details about the issue. Please include:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggestions for mitigations (if any)

I'll do my best to respond promptly and work with you to address the issue.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.0   | :white_check_mark: |

## Security Best Practices

When using Flowlyt:

- Keep your installation updated to the latest version
- Follow remediation advice provided in scan reports
- Consider using Flowlyt in your CI pipeline to automate workflow scanning

## Security-Related Configuration

- Use `--entropy-threshold` to adjust sensitivity of secret detection
- Use `--policy` to provide custom policy files
- Use `--no-default-rules` to disable default rules if needed

## Security Resources

For more information on securing GitHub Actions workflows:

- [GitHub Actions Security Hardening Guide](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)