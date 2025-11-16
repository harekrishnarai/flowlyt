# Flowlyt Commands Reference

Quick reference guide for all Flowlyt commands and common usage patterns.

## Table of Contents

- [Installation](#installation)
- [Basic Commands](#basic-commands)
- [Scan Command](#scan-command)
- [Organization Analysis](#organization-analysis)
- [Common Use Cases](#common-use-cases)
- [AI-Powered Analysis](#ai-powered-analysis)
- [Output Formats](#output-formats)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

---

## Installation

### Build from Source

```bash
# Clone the repository
git clone https://github.com/harekrishnarai/flowlyt.git
cd flowlyt

# Build the binary
go build ./cmd/flowlyt

# On Windows
.\flowlyt.exe --version

# On Linux/Mac
./flowlyt --version
```

### Install via Go

```bash
# Recommended method (bypasses proxy cache)
GOPRIVATE=github.com/harekrishnarai/flowlyt go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest

# Verify installation
flowlyt --version
```

---

## Basic Commands

### Get Help

```bash
# General help
flowlyt --help

# Command-specific help
flowlyt scan --help
flowlyt analyze-org --help
```

### Check Version

```bash
flowlyt --version
```

---

## Scan Command

The `scan` command is the primary command for analyzing repositories and workflow files.

### Basic Syntax

```bash
flowlyt scan [OPTIONS]
```

### Quick Examples

```bash
# Scan current directory
flowlyt scan --repo .

# Scan specific directory
flowlyt scan --repo /path/to/repository

# Scan remote GitHub repository
flowlyt scan --url https://github.com/user/repository

# Scan specific workflow file
flowlyt scan --workflow .github/workflows/ci.yml

# Scan without banner
flowlyt scan --repo . --no-banner
```

### Input Options

| Flag         | Short | Description                     | Example                                            |
| ------------ | ----- | ------------------------------- | -------------------------------------------------- |
| `--repo`     | `-r`  | Local repository path           | `flowlyt scan --repo .`                            |
| `--url`      | `-u`  | Remote repository URL           | `flowlyt scan --url https://github.com/user/repo`  |
| `--workflow` | `-w`  | Specific workflow file          | `flowlyt scan --workflow .github/workflows/ci.yml` |
| `--platform` | `-pl` | CI/CD platform (github, gitlab) | `flowlyt scan --platform gitlab --repo .`          |

### Output Options

| Flag             | Short        | Description                                          | Example                                           |
| ---------------- | ------------ | ---------------------------------------------------- | ------------------------------------------------- |
| `--output`       | `-o`         | Output format (cli, json, yaml, table, sarif)        | `flowlyt scan --output json --repo .`             |
| `--output-file`  |              | Output file path                                     | `flowlyt scan --output-file report.json --repo .` |
| `--min-severity` | `--severity` | Minimum severity (info, low, medium, high, critical) | `flowlyt scan --min-severity high --repo .`       |

### Performance Options

| Flag                 | Short | Description                        | Default   |
| -------------------- | ----- | ---------------------------------- | --------- |
| `--max-workers`      | `-j`  | Concurrent workers (0 = CPU count) | CPU count |
| `--workflow-timeout` |       | Timeout per workflow (seconds)     | 300       |
| `--total-timeout`    |       | Total analysis timeout (seconds)   | 1800      |

### Display Options

| Flag            | Description                |
| --------------- | -------------------------- |
| `--verbose`     | Enable verbose output      |
| `--no-banner`   | Disable banner output      |
| `--no-progress` | Disable progress reporting |

### Rule Management

| Flag                 | Description                              | Example                                                 |
| -------------------- | ---------------------------------------- | ------------------------------------------------------- |
| `--no-default-rules` | Disable all default rules                | `flowlyt scan --no-default-rules --repo .`              |
| `--enable-rules`     | Enable specific rules (comma-separated)  | `flowlyt scan --enable-rules HARDCODED_SECRET --repo .` |
| `--disable-rules`    | Disable specific rules (comma-separated) | `flowlyt scan --disable-rules UNPINNED_ACTION --repo .` |

### Advanced Options

| Flag                          | Description                                           |
| ----------------------------- | ----------------------------------------------------- |
| `--entropy-threshold`         | Entropy threshold for secret detection (default: 4.5) |
| `--ignore-errors`             | Continue scanning even if errors occur                |
| `--enable-vuln-intel`         | Enable OSV.dev vulnerability intelligence             |
| `--enable-policy-enforcement` | Enable policy enforcement                             |
| `--policy-config`             | Path to policy configuration file                     |
| `--compliance-frameworks`     | Compliance frameworks (pci-dss, sox, nist)            |

---

## Organization Analysis

Analyze all repositories in a GitHub organization.

### Basic Syntax

```bash
flowlyt analyze-org --organization ORGNAME [OPTIONS]
```

### Quick Examples

```bash
# Basic organization scan
flowlyt analyze-org --organization mycompany

# With output file
flowlyt analyze-org --organization mycompany --output-file org-report.json

# Filter by repository name pattern
flowlyt analyze-org --organization mycompany --repo-filter "^api-.*"

# High severity only
flowlyt analyze-org --organization mycompany --min-severity HIGH

# Include forks and archived repos
flowlyt analyze-org --organization mycompany --include-forks --include-archived
```

### Required Flags

| Flag             | Short | Description              |
| ---------------- | ----- | ------------------------ |
| `--organization` | `-o`  | GitHub organization name |

### Optional Flags

| Flag                 | Short   | Description                                | Default      |
| -------------------- | ------- | ------------------------------------------ | ------------ |
| `--token`            | `-t`    | GitHub token (or use GITHUB_TOKEN env var) | Auto-detect  |
| `--output-format`    | `-f`    | Output format (cli, json, markdown)        | cli          |
| `--output-file`      | `--out` | Output file path                           | stdout       |
| `--config`           | `--cfg` | Configuration file path                    | .flowlyt.yml |
| `--min-severity`     |         | Minimum severity level                     | LOW          |
| `--max-repos`        |         | Maximum repositories to analyze            | 100          |
| `--repo-filter`      |         | Regex to filter repository names           | -            |
| `--include-forks`    |         | Include forked repositories                | false        |
| `--include-archived` |         | Include archived repositories              | false        |
| `--include-private`  |         | Include private repositories               | true         |
| `--include-public`   |         | Include public repositories                | true         |
| `--max-workers`      |         | Concurrent workers                         | CPU count    |
| `--no-progress`      |         | Disable progress reporting                 | false        |
| `--summary-only`     |         | Show only organization summary             | false        |

---

## Common Use Cases

### 1. Quick Local Scan

```bash
# Scan current directory
flowlyt scan --repo .

# Scan with verbose output
flowlyt scan --repo . --verbose

# Scan specific workflow
flowlyt scan --workflow .github/workflows/deploy.yml
```

### 2. Remote Repository Scan

```bash
# Scan GitHub repository
flowlyt scan --url https://github.com/step-security/github-actions-goat --no-banner

# Scan GitLab repository
flowlyt scan --platform gitlab --url https://gitlab.com/user/repo
```

### 3. Generate Reports

```bash
# JSON report
flowlyt scan --repo . --output json --output-file report.json

# SARIF report (for GitHub Security tab)
flowlyt scan --repo . --output sarif --output-file flowlyt.sarif

# Markdown report
flowlyt scan --repo . --output markdown --output-file report.md
```

### 4. Filter by Severity

```bash
# Only critical issues
flowlyt scan --repo . --min-severity critical

# High and critical issues
flowlyt scan --repo . --min-severity high

# All issues (default)
flowlyt scan --repo . --min-severity low
```

### 5. Custom Rule Configuration

```bash
# Disable specific noisy rules
flowlyt scan --repo . --disable-rules UNPINNED_ACTION,CONTINUE_ON_ERROR_CRITICAL_JOB

# Run only specific rules
flowlyt scan --repo . --no-default-rules --enable-rules HARDCODED_SECRET,DANGEROUS_COMMAND

# Custom entropy threshold
flowlyt scan --repo . --entropy-threshold 5.0
```

### 6. CI/CD Integration

```bash
# GitHub Actions example
flowlyt scan --repo . \
  --output sarif \
  --output-file flowlyt-results.sarif \
  --min-severity medium \
  --no-banner

# GitLab CI example
flowlyt scan --platform gitlab \
  --repo . \
  --output json \
  --output-file security-report.json \
  --min-severity high
```

### 7. Performance Tuning

```bash
# Use more workers for faster scanning
flowlyt scan --repo . --max-workers 8

# Set timeouts for large repositories
flowlyt scan --repo . --workflow-timeout 600 --total-timeout 3600
```

---

## AI-Powered Analysis

Flowlyt supports AI-powered false positive detection using multiple providers.

### Setup

```bash
# Set API key via environment variable (recommended)
export AI_API_KEY=your-api-key-here

# Or use --ai-key flag
flowlyt scan --repo . --ai gemini --ai-key your-api-key
```

### Supported Providers

| Provider         | Flag Value   | Get API Key                            |
| ---------------- | ------------ | -------------------------------------- |
| OpenAI           | `openai`     | https://platform.openai.com/api-keys   |
| Google Gemini    | `gemini`     | https://aistudio.google.com/app/apikey |
| Anthropic Claude | `claude`     | https://console.anthropic.com/         |
| xAI Grok         | `grok`       | https://console.x.ai/                  |
| Perplexity       | `perplexity` | https://www.perplexity.ai/settings/api |

### Basic AI Usage

```bash
# Use Gemini (fast and cost-effective)
flowlyt scan --repo . --ai gemini

# Use OpenAI
flowlyt scan --repo . --ai openai

# Use Claude
flowlyt scan --repo . --ai claude
```

### Advanced AI Options

| Flag            | Description                                            | Default          |
| --------------- | ------------------------------------------------------ | ---------------- |
| `--ai`          | AI provider (openai, gemini, claude, grok, perplexity) | -                |
| `--ai-key`      | API key (or use AI_API_KEY env var)                    | -                |
| `--ai-model`    | Specific model to use                                  | Provider default |
| `--ai-base-url` | Custom base URL (for self-hosted)                      | -                |
| `--ai-timeout`  | Timeout in seconds                                     | 30               |
| `--ai-workers`  | Concurrent AI workers                                  | 5                |

### AI Examples

```bash
# Basic AI scan
export AI_API_KEY=your-key
flowlyt scan --repo . --ai gemini

# Custom model
flowlyt scan --repo . --ai openai --ai-model gpt-4

# High-performance AI analysis
flowlyt scan --repo . \
  --ai gemini \
  --ai-workers 10 \
  --ai-timeout 60

# AI with SARIF output
flowlyt scan --repo . \
  --ai claude \
  --output sarif \
  --output-file ai-enhanced.sarif

# Self-hosted model
flowlyt scan --repo . \
  --ai openai \
  --ai-key your-key \
  --ai-base-url https://your-llm-server.com/v1
```

---

## Output Formats

### CLI Output (Default)

```bash
flowlyt scan --repo .
# Human-readable colored output
```

### JSON Output

```bash
flowlyt scan --repo . --output json --output-file report.json
```

### YAML Output

```bash
flowlyt scan --repo . --output yaml --output-file report.yaml
```

### Table Output

```bash
flowlyt scan --repo . --output table
```

### SARIF Output

```bash
# For GitHub Security tab integration
flowlyt scan --repo . --output sarif --output-file flowlyt.sarif
```

### Markdown Output

```bash
flowlyt scan --repo . --output markdown --output-file report.md
```

---

## Configuration

### Configuration File

Flowlyt uses `.flowlyt.yml` by default. You can specify a custom path:

```bash
flowlyt scan --repo . --config custom-config.yml
```

### Environment Variables

| Variable         | Description              |
| ---------------- | ------------------------ |
| `AI_API_KEY`     | AI provider API key      |
| `GITHUB_TOKEN`   | GitHub API token         |
| `GITLAB_TOKEN`   | GitLab API token         |
| `FLOWLYT_CONFIG` | Default config file path |

### Example Configuration Usage

```bash
# Use custom config
flowlyt scan --repo . --config .flowlyt.prod.yml

# Use config with specific rules
flowlyt scan --repo . \
  --config .flowlyt.yml \
  --disable-rules UNPINNED_ACTION
```

---

## Troubleshooting

### Command Not Found

```bash
# Check if flowlyt is in PATH
which flowlyt  # Linux/Mac
where.exe flowlyt  # Windows

# Add Go bin to PATH
export PATH=$PATH:$(go env GOPATH)/bin  # Linux/Mac
$env:Path += ";$env:GOPATH\bin"  # Windows PowerShell
```

### Permission Issues

```bash
# Ensure read access to repository
ls -la /path/to/repository  # Linux/Mac
Get-ChildItem D:\path\to\repository  # Windows

# For remote repos, check token
export GITHUB_TOKEN=your-token
flowlyt scan --url https://github.com/private/repo
```

### No Workflows Found

```bash
# Check for workflow files
find . -name "*.yml" -path "*/.github/workflows/*"  # Linux/Mac
Get-ChildItem -Recurse -Filter "*.yml" | Where-Object { $_.FullName -like "*\.github\workflows\*" }  # Windows

# Specify platform explicitly
flowlyt scan --platform gitlab --repo .
```

### Verbose Debugging

```bash
# Enable verbose output
flowlyt scan --repo . --verbose

# JSON output for detailed info
flowlyt scan --repo . --output json | jq '.'
```

### Common Errors

**Error: "repository not found"**

- Check repository URL is correct
- Verify token has access (for private repos)
- Ensure repository exists and is accessible

**Error: "no workflows found"**

- Verify workflow files exist in `.github/workflows/` (GitHub) or `.gitlab-ci.yml` (GitLab)
- Check platform flag matches repository type

**Error: "AI analysis failed"**

- Verify API key is correct
- Check API key has sufficient credits/quota
- Try different AI provider
- Increase `--ai-timeout` for slow responses

---

## Quick Reference Card

### Most Common Commands

```bash
# Local scan
flowlyt scan --repo .

# Remote scan
flowlyt scan --url https://github.com/user/repo

# SARIF output
flowlyt scan --repo . --output sarif --output-file results.sarif

# AI-enhanced scan
export AI_API_KEY=your-key
flowlyt scan --repo . --ai gemini

# High severity only
flowlyt scan --repo . --min-severity high

# Organization scan
flowlyt analyze-org --organization mycompany
```

### Flag Shortcuts

```bash
# Short flags
flowlyt scan -r . -o json -f report.json
flowlyt analyze-org -o mycompany -f json
```

---

## Exit Codes

| Code | Meaning                   |
| ---- | ------------------------- |
| 0    | Success - no issues found |
| 1    | Security issues found     |
| 2    | Configuration error       |
| 3    | Runtime error             |
| 4    | Invalid arguments         |

---

## Additional Resources

- [Full CLI Reference](docs/cli-reference.md) - Complete flag documentation
- [Configuration Guide](docs/configuration.md) - Detailed configuration options
- [AI Integration](docs/ai-integration.md) - AI setup and best practices
- [Security Rules](docs/security-rules.md) - Complete rule reference

---

**Need Help?** Open an issue at https://github.com/harekrishnarai/flowlyt/issues
