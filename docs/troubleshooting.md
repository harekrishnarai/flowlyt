# Troubleshooting

This guide helps you diagnose and resolve common issues when using Flowlyt for CI/CD security analysis.

## CLI Issues

### 1. Flag Conflict Errors

#### Issue: "analyze-org flag redefined: o" panic

**Symptoms:**
```bash
$ flowlyt analyze-org myorg
analyze-org flag redefined: o
panic: analyze-org flag redefined: o
```

**Cause:** This was caused by duplicate flag aliases in earlier versions.

**Solution:**
Update to the latest version of Flowlyt:
```bash
# Update to latest version
go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest

# Verify the fix
flowlyt analyze-org --help
```

**Fixed in:** v0.0.5+

#### Issue: "Unexpected CLI errors or panics"

**Symptoms:**
- CLI commands crash unexpectedly
- Panic messages with stack traces
- Commands that worked before suddenly fail

**Solution:**
```bash
# Check version
flowlyt --version

# Update to latest
go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest

# If still experiencing issues, report at:
# https://github.com/harekrishnarai/flowlyt/issues
```

## Common Issues

### 1. Installation Problems

#### Issue: "flowlyt: command not found"

**Symptoms:**
```bash
$ flowlyt --version
zsh: command not found: flowlyt
```

**Solution:**
```bash
# Check if Go bin directory is in PATH
echo $PATH | grep -q "$(go env GOPATH)/bin" && echo "Go bin in PATH" || echo "Go bin NOT in PATH"

# Add Go bin to PATH (add to ~/.zshrc or ~/.bashrc)
export PATH=$PATH:$(go env GOPATH)/bin

# Reload shell configuration
source ~/.zshrc  # or ~/.bashrc

# Verify installation
which flowlyt
flowlyt --version
```
```

#### Issue: "permission denied" during installation

**Symptoms:**
```bash
$ go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
go: permission denied
```

**Solution:**
```bash
# Check Go installation and permissions
go env GOPATH
ls -la $(go env GOPATH)

# If GOPATH is not writable, set custom GOPATH
export GOPATH=$HOME/go
mkdir -p $GOPATH/bin

# Reinstall
go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
```

#### Issue: Network/proxy problems during installation

**Symptoms:**
```bash
$ go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
go: github.com/harekrishnarai/flowlyt@latest: Get "https://proxy.golang.org/...": dial tcp: i/o timeout
```

**Solution:**
```bash
# Configure Go proxy settings
export GOPROXY=https://proxy.golang.org,direct
export GOSUMDB=sum.golang.org

# For corporate environments, configure proxy
export GOPROXY=https://your-corp-proxy.com
export GONOSUMDB=github.com/your-org/*

# Disable proxy if needed
export GOPROXY=direct
export GOSUMDB=off
```

### 2. Configuration Issues

#### Issue: Configuration file not found

**Symptoms:**
```bash
$ flowlyt --config .flowlyt.yml --repo .
Error: configuration file '.flowlyt.yml' not found
```

**Diagnosis:**
```bash
# Check if file exists and is readable
ls -la .flowlyt.yml
file .flowlyt.yml

# Check current directory
pwd
find . -name "*.flowlyt*" -o -name "*flowlyt*"
```

**Solution:**
```bash
# Create basic configuration file
cat > .flowlyt.yml << 'EOF'
# Flowlyt configuration
output:
  format: "cli"
  min_severity: "MEDIUM"

rules:
  enabled:
    - "HARDCODED_SECRET"
    - "DANGEROUS_COMMAND"
    - "BROAD_PERMISSIONS"

ignore:
  files:
    - "test/**/*"
    - "docs/**/*"
EOF

# Validate configuration
flowlyt validate-config .flowlyt.yml
```

#### Issue: Invalid YAML configuration

**Symptoms:**
```bash
$ flowlyt --config .flowlyt.yml --repo .
Error: yaml: line 5: mapping values are not allowed in this context
```

**Diagnosis:**
```bash
# Check YAML syntax
python3 -c "import yaml; yaml.safe_load(open('.flowlyt.yml'))"

# Or use yq if available
yq eval . .flowlyt.yml

# Check for common YAML issues
grep -n "	" .flowlyt.yml  # Check for tabs (should use spaces)
```

**Solution:**
```bash
# Fix common YAML issues
# 1. Use consistent indentation (2 spaces)
# 2. Ensure proper mapping syntax
# 3. Quote special characters

# Example of correct YAML structure:
cat > .flowlyt.yml << 'EOF'
output:
  format: "cli"
  min_severity: "MEDIUM"

rules:
  enabled:
    - "HARDCODED_SECRET"
    - "DANGEROUS_COMMAND"
  
  disabled:
    - "INFO_LEVEL_RULE"

ignore:
  files:
    - "test/**/*"
EOF
```

#### Issue: Custom rules not loading

**Symptoms:**
```bash
$ flowlyt --repo . --verbose
INFO: Loading configuration from .flowlyt.yml
WARN: Custom rule 'MY_CUSTOM_RULE' not found
```

**Diagnosis:**
```bash
# Check custom rules configuration
grep -A 10 "custom_rules" .flowlyt.yml

# Verify rule file exists
ls -la custom-rules/

# Check rule syntax
flowlyt validate-rules custom-rules/
```

**Solution:**
```yaml
# Correct custom rules configuration
custom_rules:
  - id: "MY_CUSTOM_RULE"
    name: "My Custom Security Rule"
    description: "Detects custom security patterns"
    severity: "HIGH"
    category: "CUSTOM"
    patterns:
      - "CUSTOM_SECRET_[A-Za-z0-9]{32}"
    remediation: "Use proper secret management"
    
# Ensure proper file structure
custom_rules_directory: "./custom-rules"
```

### 3. Analysis Issues

#### Issue: No workflows detected

**Symptoms:**
```bash
$ flowlyt --repo .
INFO: Scanning repository: .
INFO: No workflows found
```

**Diagnosis:**
```bash
# Check for workflow files manually
find . -name "*.yml" -o -name "*.yaml" | grep -E "(\.github|\.gitlab)"

# Check directory structure
ls -la .github/workflows/
ls -la .gitlab-ci.yml

# Verify file permissions
ls -la .github/workflows/*.yml
```

**Solution:**
```bash
# Check if in correct directory
cd path/to/your/repository

# Verify workflow files exist
mkdir -p .github/workflows
ls .github/workflows/

# For GitLab projects
ls .gitlab-ci.yml

# Check if files are accessible
file .github/workflows/*.yml
head -5 .github/workflows/*.yml
```

#### Issue: Platform detection failed

**Symptoms:**
```bash
$ flowlyt --repo .
Error: unable to detect CI/CD platform
```

**Diagnosis:**
```bash
# Check for platform indicators
echo "Checking for GitHub Actions:"
ls -la .github/workflows/

echo "Checking for GitLab CI:"
ls -la .gitlab-ci.yml .gitlab/

echo "Checking for other CI platforms:"
ls -la Jenkinsfile azure-pipelines.yml .circleci/
```

**Solution:**
```bash
# Explicitly specify platform
flowlyt --repo . --platform github

# Or
flowlyt --repo . --platform gitlab

# Check supported platforms
flowlyt platforms list
```

#### Issue: Analysis taking too long

**Symptoms:**
```bash
$ flowlyt --repo .
# Hangs for several minutes
```

**Diagnosis:**
```bash
# Check repository size
du -sh .
find . -name "*.yml" -o -name "*.yaml" | wc -l

# Check system resources
top
ps aux | grep flowlyt
```

**Solution:**
```bash
# Use verbose mode to see progress
flowlyt --repo . --verbose

# Limit analysis scope
flowlyt --repo . --max-files 100

# Exclude large directories
# .flowlyt.yml
ignore:
  files:
    - "node_modules/**/*"
    - "vendor/**/*"
    - "build/**/*"
    - "dist/**/*"

# Use timeout
timeout 60s flowlyt --repo .
```

### 4. Rule Engine Issues

#### Issue: Rules not triggering as expected

**Symptoms:**
```bash
$ flowlyt --repo .
No security issues found

# But you know there are hardcoded secrets
```

**Diagnosis:**
```bash
# Check which rules are enabled
flowlyt --repo . --list-rules

# Run with verbose output
flowlyt --repo . --verbose --debug

# Test specific rule
flowlyt --repo . --rule HARDCODED_SECRET --verbose
```

**Solution:**
```bash
# Enable specific rules
# .flowlyt.yml
rules:
  enabled:
    - "HARDCODED_SECRET"
    - "DANGEROUS_COMMAND"
    - "BROAD_PERMISSIONS"
  
  # Check minimum severity
  min_severity: "LOW"  # Show all issues

# Disable ignore patterns temporarily
ignore:
  files: []
```

#### Issue: Too many false positives

**Symptoms:**
```bash
$ flowlyt --repo .
Found 50 security issues
# Many are test files or legitimate patterns
```

**Solution:**
```yaml
# .flowlyt.yml - Configure proper ignores
ignore:
  files:
    - "test/**/*"
    - "tests/**/*"
    - "spec/**/*"
    - "examples/**/*"
    - "docs/**/*"
    
  patterns:
    - "**/*-test.yml"
    - "**/test-*.yml"
    - "**/*.template.yml"

# Use inline suppressions
# In workflow files:
# flowlyt:ignore HARDCODED_SECRET - This is test data
test_api_key: "sk-test_1234567890"
```

#### Issue: Custom rules not working

**Symptoms:**
```bash
$ flowlyt --repo .
WARN: Custom rule 'COMPANY_SECRET' pattern failed to compile
```

**Diagnosis:**
```bash
# Test regex patterns separately
echo "COMPANY_API_KEY_abc123" | grep -E "COMPANY_API_KEY_[A-Za-z0-9]+"

# Validate rule configuration
flowlyt validate-rules --file custom-rules.yml
```

**Solution:**
```yaml
# Fix regex patterns (escape special characters)
custom_rules:
  - id: "COMPANY_SECRET"
    patterns:
      # ❌ Wrong: unescaped special characters
      - "API_KEY_[A-Za-z0-9]{32}+"
      
      # ✅ Correct: properly escaped
      - "API_KEY_[A-Za-z0-9]{32}"
      - "SECRET_TOKEN_[A-Fa-f0-9]{40}"
```

### 5. Output and Reporting Issues

#### Issue: Output format not supported

**Symptoms:**
```bash
$ flowlyt --repo . --output xml
Error: unsupported output format: xml
```

**Solution:**
```bash
# Check supported output formats
flowlyt --help | grep -A 5 "output"

# Use supported formats
flowlyt --repo . --output json
flowlyt --repo . --output markdown
flowlyt --repo . --output cli
```

#### Issue: JSON output malformed

**Symptoms:**
```bash
$ flowlyt --repo . --output json | jq .
parse error: Invalid numeric literal at line 1, column 10
```

**Diagnosis:**
```bash
# Check raw output
flowlyt --repo . --output json > output.json
head -20 output.json

# Validate JSON
python3 -m json.tool output.json
```

**Solution:**
```bash
# Use output file instead of stdout redirection
flowlyt --repo . --output json --output-file report.json

# Check for mixed output (warnings in JSON)
flowlyt --repo . --output json --quiet > clean-output.json
```

#### Issue: Report file permissions

**Symptoms:**
```bash
$ flowlyt --repo . --output-file /root/report.json
Error: permission denied: /root/report.json
```

**Solution:**
```bash
# Use writable directory
flowlyt --repo . --output-file ./report.json
flowlyt --repo . --output-file ~/flowlyt-reports/report.json

# Create directory first
mkdir -p reports
flowlyt --repo . --output-file reports/security-report.json
```

### 6. CI/CD Integration Issues

#### Issue: GitHub Action failing

**Symptoms:**
```yaml
# In GitHub Actions workflow
- name: Security Analysis
  run: flowlyt --repo .
# Error: flowlyt: command not found
```

**Solution:**
```yaml
# Install Flowlyt in GitHub Actions
steps:
  - uses: actions/checkout@v4
  
  - name: Setup Go
    uses: actions/setup-go@v4
    with:
      go-version: '1.21'
      
  - name: Install Flowlyt
    run: go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
    
  - name: Security Analysis
    run: flowlyt --repo . --output json --output-file security-report.json
    
  - name: Upload Report
    uses: actions/upload-artifact@v3
    with:
      name: security-report
      path: security-report.json
```

#### Issue: GitLab CI integration problems

**Symptoms:**
```yaml
# .gitlab-ci.yml
security_scan:
  script:
    - flowlyt --repo .
# Job fails with command not found
```

**Solution:**
```yaml
# .gitlab-ci.yml
security_scan:
  image: golang:1.21-alpine
  before_script:
    - go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
    - export PATH=$PATH:$(go env GOPATH)/bin
  script:
    - flowlyt --repo . --output json --output-file security-report.json
  artifacts:
    reports:
      junit: security-report.json
    paths:
      - security-report.json
    expire_in: 1 week
```

#### Issue: Container/Docker issues

**Symptoms:**
```bash
$ docker run -v $(pwd):/workspace flowlyt/flowlyt --repo /workspace
Error: permission denied
```

**Solution:**
```bash
# Fix volume permissions
docker run --rm -v $(pwd):/workspace:ro flowlyt/flowlyt --repo /workspace

# Or use user mapping
docker run --rm -u $(id -u):$(id -g) -v $(pwd):/workspace flowlyt/flowlyt --repo /workspace

# Build custom image if needed
cat > Dockerfile << 'EOF'
FROM golang:1.21-alpine
RUN go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
WORKDIR /workspace
ENTRYPOINT ["flowlyt"]
EOF

docker build -t my-flowlyt .
docker run --rm -v $(pwd):/workspace my-flowlyt --repo /workspace
```

## Debugging Techniques

### 1. Enable Verbose Logging

```bash
# Enable verbose output
flowlyt --repo . --verbose

# Enable debug output
flowlyt --repo . --debug

# Combine with log file
flowlyt --repo . --verbose --log-file flowlyt-debug.log
```

### 2. Validate Components Separately

```bash
# Validate configuration
flowlyt validate-config .flowlyt.yml

# Validate custom rules
flowlyt validate-rules custom-rules.yml

# Test rule patterns
flowlyt test-pattern "API_KEY_[A-Za-z0-9]{32}" --test-string "API_KEY_abc123def456"

# Check platform detection
flowlyt detect-platform --repo .
```

### 3. Incremental Testing

```bash
# Test single file
flowlyt --file .github/workflows/ci.yml

# Test specific rule
flowlyt --repo . --rule HARDCODED_SECRET

# Test with minimal config
flowlyt --repo . --no-config

# Test different platforms
flowlyt --repo . --platform github --verbose
```

### 4. Environment Information

```bash
# Collect environment information
echo "Flowlyt version: $(flowlyt --version)"
echo "Go version: $(go version)"
echo "OS: $(uname -a)"
echo "Working directory: $(pwd)"
echo "Repository info:"
git remote -v
git status --porcelain

# Check dependencies
flowlyt --version --verbose
```

## Performance Troubleshooting

### Memory Issues

```bash
# Monitor memory usage
/usr/bin/time -v flowlyt --repo .

# Limit memory usage
ulimit -m 512000  # Limit to 512MB
flowlyt --repo .

# Use streaming mode for large repositories
flowlyt --repo . --streaming --max-memory 256MB
```

### Speed Optimization

```bash
# Profile performance
flowlyt --repo . --profile cpu --profile-output cpu.prof

# Exclude large directories
# .flowlyt.yml
ignore:
  files:
    - "node_modules/**/*"
    - "vendor/**/*"
    - "build/**/*"
    - ".git/**/*"

# Use parallel processing
flowlyt --repo . --parallel --workers 4
```

## Common Error Messages

### "invalid character 'x' looking for beginning of value"

**Cause:** Mixed output in JSON mode  
**Solution:** Use `--quiet` flag or redirect stderr

### "yaml: unmarshal errors"

**Cause:** Invalid YAML syntax in workflow files  
**Solution:** Validate YAML syntax, check indentation

### "context deadline exceeded"

**Cause:** Analysis timeout  
**Solution:** Increase timeout, exclude large directories

### "permission denied"

**Cause:** File/directory access issues  
**Solution:** Check permissions, use correct user context

## Getting Help

### Community Resources

```bash
# Check documentation
flowlyt --help
flowlyt <command> --help

# Visit project resources
# - GitHub repository: https://github.com/harekrishnarai/flowlyt
# - Documentation: https://flowlyt.dev/docs
# - Issues: https://github.com/harekrishnarai/flowlyt/issues
```

### Issue Reporting

When reporting issues, include:

```bash
# Generate diagnostic information
flowlyt diagnose --repo . --output diagnostic-report.txt

# Include in issue report:
# 1. Flowlyt version
# 2. Operating system
# 3. Go version
# 4. Configuration file
# 5. Sample workflow that causes the issue
# 6. Expected vs actual behavior
# 7. Full error message
```

### Debug Information Collection

```bash
#!/bin/bash
# collect-debug-info.sh

echo "=== Flowlyt Debug Information ==="
echo "Date: $(date)"
echo "Flowlyt version: $(flowlyt --version)"
echo "Go version: $(go version)"
echo "OS: $(uname -a)"
echo "Working directory: $(pwd)"

echo -e "\n=== Repository Information ==="
git remote -v 2>/dev/null || echo "Not a git repository"
git status --porcelain 2>/dev/null || echo "No git status available"

echo -e "\n=== Configuration ==="
if [ -f .flowlyt.yml ]; then
    echo "Configuration file found:"
    cat .flowlyt.yml
else
    echo "No configuration file found"
fi

echo -e "\n=== Workflow Files ==="
find . -name "*.yml" -o -name "*.yaml" | grep -E "(\.github|\.gitlab)" | head -10

echo -e "\n=== Analysis Output ==="
flowlyt --repo . --verbose 2>&1 | head -50

echo "=== End Debug Information ==="
```

---

**Next:** [Examples](examples.md)
