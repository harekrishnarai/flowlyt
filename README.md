# Flowlyt

A static security analyzer for GitHub Actions and GitLab CI/CD workflows.

Presented at AppSec Village DEF CON 33 and Black Hat Europe 2025.

## Installation

```bash
go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
```

Or build from source:

```bash
git clone https://github.com/harekrishnarai/flowlyt.git
cd flowlyt
go build -o flowlyt cmd/flowlyt/main.go
```

## Usage

### Scan a local repository

```bash
flowlyt scan --repo ./my-repo
```

### Scan a single workflow file

```bash
flowlyt scan --workflow .github/workflows/ci.yml
```

### Scan a remote repository

```bash
# GitHub — via environment variable, gh CLI, or flag
export GITHUB_TOKEN=ghp_your_token
export GITHUB_TOKEN=$(gh auth token)
flowlyt scan --url https://github.com/owner/repo --github-token <your-github-token>

# GitLab
export GITLAB_TOKEN=glpat_your_token
flowlyt scan --platform gitlab --url https://gitlab.com/owner/repo --gitlab-token glpat_your_token
```

### Output formats

```bash
flowlyt scan --repo ./my-repo --output json --output-file results.json
flowlyt scan --repo ./my-repo --output sarif --output-file results.sarif
```

## How It Works

Flowlyt parses workflow files into an AST, runs a rule engine across the tree
(injection, secrets, supply chain, misconfigurations), then optionally passes
findings through an AI layer for false positive verification. Results are
emitted as text, JSON, or SARIF.

## Features

- 85+ security rules covering injection, secrets, supply chain, and misconfigurations
- AST-based analysis with call graph, reachability, and data flow
- AI-assisted false positive reduction (OpenAI, Gemini, Claude, Grok, Perplexity)
- Context-aware severity adjustment based on workflow type and triggers
- SARIF output for GitHub Security tab integration
- OSV.dev vulnerability intelligence
- Custom rules and policy enforcement
- GitHub Actions and GitLab CI/CD support

## GitHub Actions Integration

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Run Flowlyt
        uses: harekrishnarai/flowlyt@v1.1.0
        with:
          output-format: 'sarif'
          output-file: 'flowlyt-results.sarif'
          min-severity: 'MEDIUM'
          fail-on-severity: 'HIGH'

      - name: Upload to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: flowlyt-results.sarif
          category: flowlyt
```

> AI analysis is available via CLI only. Use `--ai` flag for AI-enhanced local scans.

## AI Analysis

Flowlyt supports AI-assisted verification using your own API key (BYOK).

```bash
export AI_API_KEY=your-api-key
flowlyt scan --repo ./my-repo --ai openai
flowlyt scan --repo ./my-repo --ai gemini
flowlyt scan --repo ./my-repo --ai claude
flowlyt scan --repo ./my-repo --ai grok
flowlyt scan --repo ./my-repo --ai perplexity
```

| Provider | Environment Variable | Get Key |
|----------|---------------------|---------|
| OpenAI | `AI_API_KEY` | platform.openai.com/api-keys |
| Gemini | `AI_API_KEY` | aistudio.google.com/app/apikey |
| Claude | `AI_API_KEY` | console.anthropic.com |
| Grok | `AI_API_KEY` | console.x.ai |
| Perplexity | `AI_API_KEY` | perplexity.ai/settings/api |

## Documentation

| Topic | Path |
|-------|------|
| Quick Start | [docs/guides/quick-start.md](docs/guides/quick-start.md) |
| Installation | [docs/guides/installation.md](docs/guides/installation.md) |
| CLI Reference | [docs/reference/cli-reference.md](docs/reference/cli-reference.md) |
| Configuration | [docs/reference/configuration.md](docs/reference/configuration.md) |
| Security Rules | [docs/reference/security-rules.md](docs/reference/security-rules.md) |
| Custom Rules | [docs/reference/custom-rules.md](docs/reference/custom-rules.md) |
| AI Integration | [docs/features/ai-integration.md](docs/features/ai-integration.md) |
| AST Analysis | [docs/features/ast-analysis.md](docs/features/ast-analysis.md) |
| CI/CD Integration | [docs/integrations/cicd-integration.md](docs/integrations/cicd-integration.md) |
| Architecture | [docs/advanced/architecture.md](docs/advanced/architecture.md) |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

## Contributors

[Hare Krishna Rai](https://www.linkedin.com/in/harekrishnarai/)
[Gaurav Joshi](https://www.linkedin.com/in/gauravjoshii/)
[Chanchal Kalnarayan](https://www.linkedin.com/in/ckalnarayan)
[Prashant Venkatesh](https://www.linkedin.com/in/prashant-venkatesh-99018999/)
[Nandan Gupta](https://www.linkedin.com/in/nandan-gupta-698aa11b)
[Mohd. Arif](https://www.linkedin.com/in/mohd--arif/)

<a href="https://github.com/harekrishnarai/flowlyt/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=harekrishnarai/flowlyt" alt="Contributors" />
</a>
