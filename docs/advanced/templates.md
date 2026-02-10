# Templates & Workflows

Understanding how Flowlyt analyzes workflow templates and how you can customize the analysis for different workflow patterns and templates.

## Workflow Template Analysis

Flowlyt analyzes CI/CD workflow files to understand their structure, identify security patterns, and apply appropriate rules based on the workflow context.

### Supported Template Formats

#### GitHub Actions Workflows
```yaml
# .github/workflows/ci.yml
name: CI Pipeline
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: npm ci && npm run build
```

#### GitLab CI/CD Pipelines
```yaml
# .gitlab-ci.yml
stages:
  - build
  - test
  - deploy

build:
  stage: build
  script:
    - npm ci
    - npm run build
  artifacts:
    paths:
      - dist/
```

#### Jenkins Pipelines (Planned)
```groovy
// Jenkinsfile
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'npm ci'
                sh 'npm run build'
            }
        }
    }
}
```

## Template Categories

Flowlyt recognizes different template categories and applies appropriate rules:

### 1. Build Templates

**Characteristics:**
- Focus on compilation and artifact creation
- Package installation and dependency management
- Code compilation and bundling

**Example GitHub Actions Build Template:**
```yaml
name: Build
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '18'
          cache: 'npm'
      - run: npm ci
      - run: npm run build
      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/
```

**Flowlyt Rules Applied:**
- `UNPINNED_ACTION` - Checks for unpinned actions
- `DANGEROUS_COMMAND` - Analyzes npm/build commands
- `HARDCODED_SECRET` - Scans for exposed credentials

### 2. Test Templates

**Characteristics:**
- Test execution and reporting
- Code coverage analysis
- Quality gates

**Example Test Template:**
```yaml
name: Test
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '18'
      - run: npm ci
      - run: npm test
      - run: npm run coverage
      - uses: codecov/codecov-action@v4
        with:
          token: ${{ secrets.CODECOV_TOKEN }}
```

**Flowlyt Rules Applied:**
- Secret detection for test service tokens
- Command injection analysis
- Third-party action security review

### 3. Deployment Templates

**Characteristics:**
- Environment deployment
- Infrastructure provisioning
- Production releases

**Example Deployment Template:**
```yaml
name: Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
      - name: Deploy to AWS
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: |
          aws s3 sync ./dist s3://my-bucket
          aws cloudfront create-invalidation --distribution-id ${{ secrets.DISTRIBUTION_ID }}
```

**Flowlyt Rules Applied:**
- `BROAD_PERMISSIONS` - Deployment permission analysis
- `HARDCODED_SECRET` - Cloud credential security
- `INSECURE_PULL_REQUEST_TARGET` - Deployment trigger security

### 4. Security Templates

**Characteristics:**
- Security scanning and analysis
- Vulnerability assessment
- Compliance checking

**Example Security Template:**
```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Snyk
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      - name: Run CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: javascript
      - uses: github/codeql-action/analyze@v3
```

**Flowlyt Rules Applied:**
- Security tool validation
- Token and credential management
- Workflow security configuration

## Template Customization

### Template-Specific Configuration

Configure Flowlyt behavior based on workflow templates:

```yaml
# .flowlyt.yml
templates:
  # Build template configuration
  build:
    file_patterns:
      - "**/build.yml"
      - "**/ci.yml"
      - "**/compile.yml"
    rules:
      enabled:
        - "UNPINNED_ACTION"
        - "DANGEROUS_COMMAND"
      disabled:
        - "CONTINUE_ON_ERROR_CRITICAL_JOB"  # Allow build failures
    severity_adjustments:
      UNPINNED_ACTION: "MEDIUM"  # Lower severity for build actions
  
  # Test template configuration
  test:
    file_patterns:
      - "**/test.yml"
      - "**/qa.yml"
      - "**/*test*.yml"
    rules:
      enabled:
        - "HARDCODED_SECRET"
        - "DANGEROUS_COMMAND"
      disabled:
        - "CONTINUE_ON_ERROR_CRITICAL_JOB"  # Tests may continue on error
    ignore:
      secrets:
        patterns:
          - ".*_test$"
          - "test_.*"
  
  # Deployment template configuration
  deploy:
    file_patterns:
      - "**/deploy.yml"
      - "**/release.yml"
      - "**/production.yml"
    rules:
      enabled:
        - "BROAD_PERMISSIONS"
        - "INSECURE_PULL_REQUEST_TARGET"
        - "HARDCODED_SECRET"
      severity_adjustments:
        BROAD_PERMISSIONS: "CRITICAL"  # Higher severity for deployment
    require_approval: true
  
  # Security template configuration
  security:
    file_patterns:
      - "**/security.yml"
      - "**/scan.yml"
      - "**/*security*.yml"
    rules:
      enabled:
        - "HARDCODED_SECRET"
        - "DANGEROUS_COMMAND"
      custom_rules:
        - id: "SECURITY_TOOL_VALIDATION"
          name: "Required Security Tools"
          pattern: "(snyk|codeql|semgrep|trivy)"
          severity: "HIGH"
          remediation: "Include required security scanning tools"
```

### Auto-Detection

Flowlyt can automatically detect template types:

```yaml
# Auto-detection based on workflow content
detection:
  build:
    keywords: ["build", "compile", "npm ci", "yarn install", "go build"]
    actions: ["actions/setup-node", "actions/setup-go", "actions/setup-java"]
  
  test:
    keywords: ["test", "spec", "coverage", "jest", "mocha", "pytest"]
    actions: ["codecov/codecov-action", "coverallsapp/github-action"]
  
  deploy:
    keywords: ["deploy", "release", "production", "staging"]
    environments: ["production", "staging", "deploy"]
    actions: ["aws-actions/", "azure/", "google-github-actions/"]
  
  security:
    keywords: ["security", "scan", "vulnerability", "audit"]
    actions: ["github/codeql-action", "snyk/actions", "securecodewarrior/"]
```

## Common Template Patterns

### 1. Matrix Builds

**Template Pattern:**
```yaml
name: Matrix Build
on: [push, pull_request]

jobs:
  build:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        node-version: [16, 18, 20]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}
      - run: npm ci
      - run: npm test
```

**Flowlyt Analysis:**
- Validates security across all matrix combinations
- Applies rules to each matrix configuration
- Reports issues that affect any combination

**Custom Configuration:**
```yaml
# .flowlyt.yml
templates:
  matrix:
    detection:
      keywords: ["matrix", "strategy"]
    rules:
      custom_rules:
        - id: "MATRIX_SECURITY_CONSISTENCY"
          name: "Matrix Security Consistency"
          description: "Ensure security measures are consistent across matrix"
          pattern: "matrix\\."
          remediation: "Apply security measures consistently across all matrix combinations"
```

### 2. Multi-Stage Pipelines

**Template Pattern:**
```yaml
name: Multi-Stage Pipeline
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      artifact-id: ${{ steps.build.outputs.artifact-id }}
    steps:
      - uses: actions/checkout@v4
      - id: build
        run: |
          npm ci
          npm run build
          echo "artifact-id=$(date +%s)" >> $GITHUB_OUTPUT
  
  test:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm test
  
  deploy:
    needs: [build, test]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    environment: production
    steps:
      - name: Deploy
        run: echo "Deploying artifact ${{ needs.build.outputs.artifact-id }}"
```

**Flowlyt Analysis:**
- Analyzes job dependencies and data flow
- Validates security at each stage
- Ensures secure artifact passing between jobs

### 3. Reusable Workflows

**Template Pattern:**
```yaml
# .github/workflows/reusable-security.yml
name: Reusable Security Scan
on:
  workflow_call:
    inputs:
      scan-type:
        required: true
        type: string
    secrets:
      SECURITY_TOKEN:
        required: true

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Security Scan
        env:
          TOKEN: ${{ secrets.SECURITY_TOKEN }}
        run: |
          security-tool --type ${{ inputs.scan-type }}
```

**Usage:**
```yaml
# .github/workflows/main.yml
name: Main Pipeline
on: [push]

jobs:
  security:
    uses: ./.github/workflows/reusable-security.yml
    with:
      scan-type: "full"
    secrets:
      SECURITY_TOKEN: ${{ secrets.SECURITY_TOKEN }}
```

**Flowlyt Analysis:**
- Analyzes reusable workflow security
- Validates input and secret passing
- Checks for security issues in both caller and callee

## Template Best Practices

### 1. Security-First Templates

**Secure Build Template:**
```yaml
name: Secure Build
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read      # Minimal permissions

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608  # Pinned
      - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8    # Pinned
        with:
          node-version: '18'
          cache: 'npm'
      - name: Install dependencies
        run: npm ci --audit-level=high  # Security audit
      - name: Build
        run: npm run build
      - name: Security scan
        run: npm audit --production
```

### 2. Template Validation

**Pre-deployment Validation:**
```yaml
name: Template Validation
on:
  pull_request:
    paths:
      - '.github/workflows/**'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Flowlyt
        run: GOPRIVATE=github.com/harekrishnarai/flowlyt go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
      - name: Validate Templates
        run: |
          for workflow in .github/workflows/*.yml; do
            echo "Validating $workflow..."
            flowlyt --workflow "$workflow" --min-severity HIGH
          done
```

### 3. Template Documentation

Document template security considerations:

```yaml
# .github/workflows/build.yml
# Security Template: Build Pipeline
# 
# Security Features:
# - Pinned actions to specific commit SHAs
# - Minimal permissions (contents: read)
# - Dependency audit during installation
# - Artifact integrity verification
#
# Customization Points:
# - Node.js version (update in setup-node step)
# - Build commands (update in build step)
# - Security audit level (--audit-level parameter)

name: Secure Build Pipeline
on: [push, pull_request]

permissions:
  contents: read
  
jobs:
  build:
    # ... workflow definition
```

## Template Migration

### From Insecure to Secure Templates

**Before (Insecure):**
```yaml
name: Old Build
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4        # Version tag (not pinned)
      - run: |
          curl -s https://get.docker.com | bash    # Dangerous
          docker run --privileged myapp            # Privileged
        env:
          API_KEY: "sk-1234567890"                  # Hardcoded secret
```

**After (Secure):**
```yaml
name: Secure Build
on: [push]

permissions:
  contents: read                        # Minimal permissions

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608  # Pinned SHA
      - name: Setup Docker
        uses: docker/setup-buildx-action@v3      # Official action
      - name: Build Container
        env:
          API_KEY: ${{ secrets.API_KEY }}         # Proper secret management
        run: |
          docker build -t myapp .
          docker run --cap-drop=ALL myapp        # Minimal capabilities
```

### Migration Validation

```bash
# Validate migration
flowlyt --workflow old-workflow.yml --output json > old-report.json
flowlyt --workflow new-workflow.yml --output json > new-report.json

# Compare security improvements
echo "Old workflow issues:"
jq '.findings | length' old-report.json

echo "New workflow issues:"
jq '.findings | length' new-report.json
```

## Template Testing

### Automated Template Testing

```yaml
# .github/workflows/template-test.yml
name: Template Security Test
on:
  push:
    paths:
      - 'templates/**'

jobs:
  test-templates:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Flowlyt
        run: GOPRIVATE=github.com/harekrishnarai/flowlyt go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
      - name: Test Secure Templates
        run: |
          for template in templates/secure/*.yml; do
            echo "Testing secure template: $template"
            # Should pass with no high/critical issues
            if flowlyt --workflow "$template" --min-severity HIGH | grep -q "CRITICAL\|HIGH"; then
              echo "❌ Secure template has security issues: $template"
              exit 1
            fi
          done
      - name: Test Insecure Templates
        run: |
          for template in templates/insecure/*.yml; do
            echo "Testing insecure template: $template"
            # Should fail with security issues
            if ! flowlyt --workflow "$template" --min-severity HIGH | grep -q "CRITICAL\|HIGH"; then
              echo "❌ Insecure template not detected: $template"
              exit 1
            fi
          done
```

### Template Test Suite

Create a comprehensive test suite:

```
templates/
├── secure/
│   ├── build-secure.yml          # Secure build template
│   ├── deploy-secure.yml         # Secure deployment template
│   └── test-secure.yml           # Secure test template
├── insecure/
│   ├── build-insecure.yml        # Known vulnerable build template
│   ├── deploy-insecure.yml       # Known vulnerable deployment template
│   └── test-insecure.yml         # Known vulnerable test template
└── test-suite.sh                 # Automated test runner
```

---

**Next:** [False Positive Management](false-positives.md)
