# Flowlyt - GitHub Actions Workflow Security Analyzer

Flowlyt is a security analyzer that scans GitHub Actions workflows to detect malicious patterns, misconfigurations, and secrets exposure, helping enforce secure CI/CD practices.

## Features

- **Static Analysis of Workflows**
  - Parse and analyze workflow YAML files
  - Detect unsafe patterns like `curl | bash`, base64-encoded payloads
  - Identify unpinned actions and risky trigger contexts

- **Misconfiguration Detection**
  - Scan for insecure `permissions:` settings
  - Identify `continue-on-error: true` in critical jobs
  - Highlight missing trigger filters

- **Secret Detection**
  - Detect hardcoded secrets, tokens, and credentials
  - Use entropy and regex-based scanning techniques

- **Shell Command Analyzer**
  - Parse `run:` blocks to detect shell obfuscation
  - Flag usage of `eval`, encoded payloads, and subshell tricks

- **Policy Enforcement via OPA**
  - Define custom policies in Rego
  - Enforce org-level rules for workflow security

## Installation

### Option 1: Using pre-built binaries

Download the latest release from the [GitHub Releases page](https://github.com/harekrishnarai/flowlyt/releases).

### Option 2: Using Go package manager

```bash
# Install directly using Go
go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
```

This will download, compile, and install the `flowlyt` binary to your `$GOPATH/bin` directory. Make sure your `$GOPATH/bin` is in your system's `PATH` to run the tool from anywhere.

### Option 3: Building from source

```bash
# Clone the repository
git clone https://github.com/harekrishnarai/flowlyt.git
cd flowlyt

# Build the binary
go build -o flowlyt ./cmd/flowlyt
```

### Option 4: Using Docker

```bash
docker pull harekrishnarai/flowlyt:latest
docker run --rm -v $(pwd):/repo harekrishnarai/flowlyt scan --repo /repo
```

## Usage

### CLI Examples

Scan a local repository:
```bash
flowlyt scan --repo ./myrepo
```

Scan a GitHub repository:
```bash
flowlyt scan --url https://github.com/user/repo
```

Generate a JSON report:
```bash
flowlyt scan --repo ./myrepo --output json --output-file results.json
```

Use custom policies:
```bash
flowlyt scan --repo ./myrepo --policy ./my-policies/
```

Create an example policy file:
```bash
flowlyt init-policy ./policies/custom.rego
```

### GitHub Action Integration

To use Flowlyt in your GitHub Actions workflow:

```yaml
name: Flowlyt Security Check
on: [pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Scan workflows
        uses: harekrishnarai/flowlyt@v1.0.2
        with:
          # Optional: Specify repository path (defaults to current workspace)
          # repository: ''
          
          # Optional: Output format (cli, json, markdown)
          output-format: markdown
          
          # Optional: Output file path
          output-file: flowlyt-results.md
          
          # Optional: Set to 'true' to comment results on PRs
          comment-on-pr: 'true'
          
          # Optional: Path to custom policies
          # policy-path: './policies'
          
          # Optional: Set to 'true' to disable default rules
          # no-default-rules: 'false'
          
          # Optional: Fail on severity level
          # fail-on-severity: 'HIGH'
      
      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: flowlyt-results
          path: flowlyt-results.md
```

#### Action Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `repository` | Repository to scan | No | Current workspace |
| `token` | GitHub token for repository access | No | GitHub-provided token |
| `output-format` | Output format (cli, json, markdown) | No | markdown |
| `output-file` | Path to output file | No | flowlyt-results.md |
| `policy-path` | Path to custom policy files | No | |
| `no-default-rules` | Disable default security rules | No | false |
| `entropy-threshold` | Entropy threshold for secret detection | No | 4.5 |
| `comment-on-pr` | Whether to comment results on PRs | No | true |
| `fail-on-severity` | Fail if findings with this severity or higher are found | No | |

#### Action Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total number of findings |
| `critical-count` | Number of critical findings |
| `high-count` | Number of high severity findings |
| `results-file` | Path to the results file |

### Using the Action with a Self-Hosted Runner

If you're using a self-hosted runner, make sure Docker is installed and you have sufficient permissions:

```yaml
jobs:
  security:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v3
      - name: Scan workflows
        uses: harekrishnarai/flowlyt@v1.0.2
        with:
          output-format: markdown
          output-file: flowlyt-results.md
```

## Custom Policies

Flowlyt supports custom policies written in Rego (Open Policy Agent language). 

Example policy:

```rego
package flowlyt

# Detect workflows with write-all permissions
deny[violation] {
    input.workflow.permissions == "write-all"
    
    violation := {
        "id": "POLICY_BROAD_PERMISSIONS",
        "name": "Workflow Has Broad Permissions",
        "description": "Workflow has 'write-all' permissions, which grants excessive access",
        "severity": "HIGH",
        "evidence": "permissions: write-all",
        "remediation": "Use more specific permissions instead of 'write-all'"
    }
}
```

Generate an example policy with:

```bash
flowlyt init-policy
```

## License

MIT