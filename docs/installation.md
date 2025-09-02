# Installation & Quick Start

This guide will help you install Flowlyt and get started with your first security scan.

## Installation Methods

### Option 1: Using Pre-built Binaries (Recommended)

Download the latest release from the [GitHub Releases page](https://github.com/harekrishnarai/flowlyt/releases).

```bash
# Example for Linux amd64
wget https://github.com/harekrishnarai/flowlyt/releases/latest/download/flowlyt-linux-amd64.tar.gz
tar -xzf flowlyt-linux-amd64.tar.gz
sudo mv flowlyt /usr/local/bin/
```

### Option 2: Using Go Package Manager

> **⚠️ Important**: Due to Go module proxy cache issues, using `go install @latest` may install an incorrect version (v1.0.0) instead of the actual latest version. Use the workaround below:

```bash
# Recommended method (bypasses proxy cache issues)
GOPRIVATE=github.com/harekrishnarai/flowlyt go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest

# Alternative: install specific version
go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@v0.0.5
```

This installs the `flowlyt` binary to your `$GOPATH/bin` directory. Ensure `$GOPATH/bin` is in your system's `PATH`.

### Option 3: Building from Source

```bash
# Clone the repository
git clone https://github.com/harekrishnarai/flowlyt.git
cd flowlyt

# Install dependencies
go mod download

# Build the binary
go build -o flowlyt ./cmd/flowlyt

# (Optional) Install globally
sudo mv flowlyt /usr/local/bin/
```

### Option 4: Using Docker

```bash
# Pull the latest image
docker pull harekrishnarai/flowlyt:latest

# Run a scan
docker run --rm -v $(pwd):/repo harekrishnarai/flowlyt scan --repo /repo
```

## Quick Start Guide

### 1. Verify Installation

```bash
flowlyt --version
# Output: flowlyt version 0.0.1
```

### 2. Your First Scan

**Scan a local repository:**
```bash
# Basic repository scan
flowlyt --repo ./my-repository

# Scan current directory
flowlyt --repo .
```

**Scan a remote repository:**
```bash
# GitHub repository
flowlyt --url https://github.com/user/repository

# GitLab repository
flowlyt --platform gitlab --url https://gitlab.com/user/repository
```

**Scan a specific workflow file:**
```bash
# GitHub Actions workflow
flowlyt --workflow .github/workflows/ci.yml

# GitLab CI/CD pipeline
flowlyt --platform gitlab --workflow .gitlab-ci.yml
```

### 3. Understanding the Output

A typical scan produces output like this:

```
🔍 Flowlyt - Multi-Platform CI/CD Security Analyzer
Platform: GITHUB
=======================================

► SCAN INFORMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Repository:          ./my-repo
Scan Time:           Thu, 10 Jul 2025 16:00:00 IST
Duration:            45ms
Workflows Analyzed:  3
Rules Applied:       12

► SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SEVERITY | COUNT | INDICATOR       
-----------+-------+-----------------
  CRITICAL |   2   | ██████████████  
  HIGH     |   3   | ██████████████  
  MEDIUM   |   1   | ████            
  LOW      |   0   |                 
  INFO     |   0   |                 
  TOTAL    |   6   |                 

► FINDINGS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[CRITICAL] Hardcoded Secret
File: .github/workflows/deploy.yml (Line 25)
Evidence: GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
Remediation: Use GitHub secrets instead of hardcoded tokens
```

### 4. Common Usage Patterns

**Filter by severity:**
```bash
# Show only high and critical issues
flowlyt --repo . --min-severity HIGH

# Show only critical issues
flowlyt --repo . --min-severity CRITICAL
```

**Generate reports:**
```bash
# JSON report
flowlyt --repo . --output json --output-file security-report.json

# Markdown report
flowlyt --repo . --output markdown --output-file security-report.md
```

**Rule management:**
```bash
# Disable specific rules
flowlyt --repo . --disable-rules UNPINNED_ACTION,HARDCODED_SECRET

# Enable only specific rules
flowlyt --repo . --enable-rules MALICIOUS_BASE64_DECODE,BROAD_PERMISSIONS
```

## Platform-Specific Usage

### GitHub Actions

```bash
# Default - automatically detects GitHub Actions
flowlyt --repo ./github-project

# Explicit platform specification
flowlyt --platform github --repo ./github-project

# Scan specific workflow
flowlyt --workflow .github/workflows/ci.yml
```

### GitLab CI/CD

```bash
# GitLab.com repository
flowlyt --platform gitlab --repo ./gitlab-project

# On-premise GitLab instance
flowlyt --platform gitlab --gitlab-instance https://gitlab.company.com --repo ./project

# Scan GitLab CI file
flowlyt --platform gitlab --workflow .gitlab-ci.yml
```

## Next Steps

1. **Learn about Configuration**: Set up a [`.flowlyt.yml` configuration file](configuration.md)
2. **Explore Security Rules**: Understand the [built-in security rules](security-rules.md)
3. **Custom Rules**: Create [custom security rules](custom-rules.md) for your organization
4. **CI/CD Integration**: Integrate Flowlyt into your [CI/CD pipeline](cicd-integration.md)

## Troubleshooting

### Common Issues

**Command not found:**
```bash
# Check if flowlyt is in PATH
which flowlyt

# Add to PATH if using Go install
export PATH=$PATH:$(go env GOPATH)/bin
```

**Permission denied:**
```bash
# Make binary executable
chmod +x flowlyt

# Or install with proper permissions
sudo install flowlyt /usr/local/bin/
```

**Docker issues:**
```bash
# Ensure proper volume mounting
docker run --rm -v $(pwd):/repo harekrishnarai/flowlyt scan --repo /repo

# For Windows users
docker run --rm -v %cd%:/repo harekrishnarai/flowlyt scan --repo /repo
```

For more troubleshooting help, see the [Troubleshooting Guide](troubleshooting.md).

---

**Next:** [Multi-Platform Support](multi-platform-support.md)
