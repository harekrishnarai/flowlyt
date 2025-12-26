#!/bin/bash
# Example demonstrating the enhanced CLI output

cat << 'EOF'

╔═══════════════════════════════════════════╗
║             FLOWLYT SCAN RESULTS          ║
╚═══════════════════════════════════════════╝

► SCAN INFORMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Repository:           harekrishnarai/flowlyt
Scan Time:            Thu, 26 Dec 2025 10:30:00 UTC
Duration:             245ms
Workflows Analyzed:   8
Rules Applied:        47

► SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
┌───────────┬───────┬──────────────────────────────┐
│ Severity  │ Count │ Indicator                    │
├───────────┼───────┼──────────────────────────────┤
│ CRITICAL  │   2   │ ██████░░░░░░░░░░░░░░        │
│ HIGH      │   5   │ █████████████░░░░░░░░░░░    │
│ MEDIUM    │   3   │ ███████░░░░░░░░░░░░░░░░░░   │
│ LOW       │   1   │ ██░░░░░░░░░░░░░░░░░░░░░░    │
│ INFO      │   2   │ ██░░░░░░░░░░░░░░░░░░░░░░    │
├───────────┼───────┼──────────────────────────────┤
│ TOTAL     │  13   │                              │
└───────────┴───────┴──────────────────────────────┘

► FINDINGS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

■ CRITICAL SEVERITY FINDINGS
─────────────────────────────────────────────────

[CRITICAL] .github/workflows/terraform.yml:42
Rule: AST_SENSITIVE_DATA_FLOW

   40 │    - name: Setup shared secrets if needed
   41 │      env:
   42 │ >    CORALOGIX_SECRETS: ${{ secrets.CORALOGIX_SECRETS_PEM_BASE64 }}
       │    └─→ Potential Issue Here
   43 │      with:
   44 │ >      token: ${{ secrets.GITHUB_TOKEN }}
       │    └─→ Potential Issue Here

Message: Sensitive data flows from 'CORALOGIX_SECRETS_PEM_BASE64' to 'github-token' (Potential sensitive data flow)

🔻 Data Flow Analysis:
   [Source] CORALOGIX_SECRETS_PEM_BASE64
      │
      ▼
   [Sink]   GITHUB_TOKEN

💡 Remediation: Ensure secrets are not passed directly to untrusted actions. Use OIDC tokens or temporary credentials instead.

[CRITICAL] .github/workflows/deploy.yml:18
Rule: MALICIOUS_BASE64_DECODE

    16 │    - name: Download and execute script
    17 │      run: |
    18 │ >      echo $SCRIPT | base64 -d | bash
         │    └─→ Potential Issue Here
    19 │      env:
    20 │        SCRIPT: ${{ secrets.SCRIPT_B64 }}

Message: Detects execution of base64-decoded data, which can hide malicious code

💡 Remediation: Avoid executing dynamically decoded scripts. Use explicit, reviewed scripts instead.

■ HIGH SEVERITY FINDINGS
─────────────────────────────────────────────────

[HIGH] .github/workflows/ci.yml:15
Rule: MALICIOUS_CURL_PIPE_BASH

    13 │    - name: Install dependencies
    14 │      run: |
    15 │ >      curl https://example.com/install.sh | bash
         │    └─→ Potential Issue Here
    16 │

Message: Detects curl or wget piped to bash/sh/zsh, which can execute malicious code

💡 Remediation: Download the script first, review it, and then execute it explicitly.

[HIGH] .github/workflows/build.yml:8
Rule: HARDCODED_SECRETS_IN_WORKFLOW

     6 │    - name: Authenticate with Docker Hub
     7 │      run: |
     8 │ >      docker login -u myuser -p hardcoded_password_here
         │    └─→ Potential Issue Here
     9 │

Message: Found hardcoded credentials in workflow file

💡 Remediation: Use GitHub secrets for sensitive credentials. Never hardcode passwords.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

FINDINGS SUMMARY:
  ✓ 13 findings detected
  ✓ 2 critical issues require immediate attention
  ✓ 5 high-severity issues should be reviewed soon
  ✓ 10 medium/low/info issues for continuous improvement

NEXT STEPS:
  1. Address critical and high-severity findings immediately
  2. Review remediation suggestions for each finding
  3. Update workflows to follow security best practices
  4. Run scan again to verify fixes

EOF
