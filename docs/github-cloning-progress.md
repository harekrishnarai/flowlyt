# Flowlyt GitHub Cloning Progress Feature

## Overview

Flowlyt now includes intelligent GitHub repository cloning with progress indication for larger codebases. The feature automatically adapts based on the environment:

## Features

### 1. Interactive Progress Bar (Local Development)
When running locally (not in CI), Flowlyt displays a real-time progress bar during repository cloning:

```
🔄 Cloning GitHub repository: https://github.com/owner/repo
[████████████████████░░░░░░░░░░░░░░░░░░░░] 75% - Receiving objects
```

### 2. CI Environment Detection
Flowlyt automatically detects CI environments and adjusts behavior:
- **GitHub Actions**: Detected via `GITHUB_ACTIONS=true`
- **Generic CI**: Detected via `CI=true`
- **Other CI platforms**: Travis, CircleCI, Jenkins, GitLab CI, etc.

In CI environments, progress reporting is minimal to avoid log spam:
```
Cloning repository: https://github.com/owner/repo
```

### 3. Manual Control
Users can disable progress reporting with the `--no-progress` flag:
```bash
flowlyt scan --url https://github.com/owner/repo --no-progress
```

## Implementation Details

### Progress Stages
The progress tracker reports different stages of the git clone process:
1. **Initializing clone** - Setting up the clone operation
2. **Counting objects** - Git counting objects to transfer
3. **Compressing objects** - Git compressing data for transfer
4. **Receiving objects** - Downloading repository data
5. **Resolving deltas** - Processing delta compression
6. **Checking out files** - Creating working directory
7. **Completed** - Clone operation finished

### Progress Parsing
Flowlyt parses git's `--progress` output using regex patterns to extract:
- Percentage completion
- Current stage/operation
- Objects processed

### GitHub Actions Integration
When running in GitHub Actions workflows, Flowlyt:
- Disables interactive progress bars
- Uses simple status messages
- Avoids overwhelming CI logs
- Maintains compatibility with action output formatting

## Usage Examples

### Local Development
```bash
# Shows progress bar for large repositories
flowlyt scan --url https://github.com/kubernetes/kubernetes

# Disable progress explicitly
flowlyt scan --url https://github.com/owner/repo --no-progress
```

### GitHub Actions Workflow
```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: harekrishnarai/flowlyt-action@v1
        with:
          repository: https://github.com/target/repo
          # Progress automatically disabled in CI
```

### CI Environment Variables
Flowlyt detects these environment variables for CI identification:
- `GITHUB_ACTIONS=true` (GitHub Actions)
- `CI=true` (Generic CI)
- `TRAVIS=true` (Travis CI)
- `CIRCLECI=true` (Circle CI)
- `JENKINS_URL` (Jenkins)
- `GITLAB_CI=true` (GitLab CI)
- `BUILDKITE=true` (Buildkite)
- `TF_BUILD=true` (Azure DevOps)

## Benefits

1. **Better User Experience**: Visual feedback for long-running clone operations
2. **CI Compatibility**: Clean, minimal output in automated environments
3. **Large Repository Support**: Especially useful for monorepos and large codebases
4. **Flexible Control**: Users can disable progress when needed
5. **Automatic Detection**: No manual configuration required

## Technical Architecture

- **Environment Detection**: `pkg/constants/constants.go`
- **Progress Implementation**: `pkg/github/github.go`
- **CLI Integration**: `cmd/flowlyt/main.go`
- **Progress Callback**: Real-time parsing of git output
- **CI Adaptation**: Automatic behavior switching
