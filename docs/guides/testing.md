# Testing Guide for Flowlyt

Comprehensive guide for testing Flowlyt components.

## Table of Contents

- [Quick Start](#quick-start)
- [Running Tests](#running-tests)
- [Coverage](#coverage)
- [Writing Tests](#writing-tests)
- [Test Structure](#test-structure)
- [Best Practices](#best-practices)
- [CI/CD Integration](#cicd-integration)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# View coverage in browser
make test-coverage-html

# Run specific package tests
make test-ai
make test-rules
```

---

## Running Tests

### Using Make (Recommended)

```bash
# Run all tests with race detection
make test

# Run tests with verbose output
make test-verbose

# Run short tests (skip slow tests)
make test-short

# Run tests with race detector
make test-race

# Run integration tests
make test-integration

# Run tests for specific packages
make test-ai        # AI package tests
make test-rules     # Rules package tests
make test-parser    # Parser package tests
make test-github    # GitHub package tests
make test-gitlab    # GitLab package tests
make test-report    # Report package tests
```

### Using Go Directly

```bash
# Run all tests
go test ./...

# Run with verbose output
go test ./... -v

# Run specific package
go test ./pkg/ai/... -v

# Run specific test
go test ./pkg/ai/... -run TestAnalyzer -v

# Run with coverage
go test ./... -cover

# Run with race detection
go test ./... -race
```

---

## Coverage

### Generating Coverage Reports

```bash
# Generate coverage report
make test-coverage

# Generate HTML coverage report
make test-coverage-html

# Check if coverage meets threshold (60%)
make coverage-check

# View coverage by package
make coverage-report
```

### Understanding Coverage Output

```bash
$ make coverage-report

================================
  Coverage Report by Package
================================
github.com/harekrishnarai/flowlyt/pkg/ai                    37.9%
github.com/harekrishnarai/flowlyt/pkg/analysis/ast          51.4%
github.com/harekrishnarai/flowlyt/pkg/config                21.4%
github.com/harekrishnarai/flowlyt/pkg/constants             100.0%
github.com/harekrishnarai/flowlyt/pkg/github                6.1%
...
================================
Total Coverage: 35.2%
Coverage Threshold: 60%
================================
```

### Coverage Goals

| Priority | Package | Current | Target |
|----------|---------|---------|--------|
| 🔴 Critical | pkg/rules | 36.9% | 80% |
| 🔴 Critical | pkg/parser | 46.3% | 80% |
| 🟡 High | pkg/ai | 37.9% | 70% |
| 🟡 High | pkg/github | 6.1% | 60% |
| 🟡 High | pkg/gitlab | 42.2% | 60% |
| 🟢 Medium | pkg/report | 14.7% | 60% |
| 🔴 Critical | pkg/organization | 0.0% | 60% |

---

## Writing Tests

### Test File Naming

```bash
# Test files should end with _test.go
pkg/ai/analyzer.go       # Implementation
pkg/ai/analyzer_test.go  # Tests
```

### Basic Test Structure

```go
package ai

import (
    "testing"
)

func TestAnalyzer(t *testing.T) {
    // Arrange
    analyzer := NewAnalyzer(Config{
        Provider: "openai",
        APIKey:   "test-key",
    })

    // Act
    result, err := analyzer.Analyze(finding)

    // Assert
    if err != nil {
        t.Fatalf("Expected no error, got: %v", err)
    }

    if result.Confidence < 0 || result.Confidence > 100 {
        t.Errorf("Invalid confidence: %d", result.Confidence)
    }
}
```

### Table-Driven Tests

```go
func TestValidateProvider(t *testing.T) {
    tests := []struct {
        name     string
        provider string
        wantErr  bool
    }{
        {
            name:     "valid openai",
            provider: "openai",
            wantErr:  false,
        },
        {
            name:     "valid gemini",
            provider: "gemini",
            wantErr:  false,
        },
        {
            name:     "invalid provider",
            provider: "invalid",
            wantErr:  true,
        },
        {
            name:     "empty provider",
            provider: "",
            wantErr:  true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := ValidateProvider(tt.provider)
            if (err != nil) != tt.wantErr {
                t.Errorf("ValidateProvider() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

### Testing with Subtests

```go
func TestGitHubClient(t *testing.T) {
    t.Run("ListRepositories", func(t *testing.T) {
        // Test repository listing
    })

    t.Run("GetWorkflow", func(t *testing.T) {
        // Test workflow fetching
    })

    t.Run("ErrorHandling", func(t *testing.T) {
        // Test error cases
    })
}
```

### Testing Error Cases

```go
func TestErrorHandling(t *testing.T) {
    tests := []struct {
        name        string
        input       string
        expectedErr error
    }{
        {
            name:        "empty input",
            input:       "",
            expectedErr: ErrEmptyInput,
        },
        {
            name:        "invalid format",
            input:       "invalid",
            expectedErr: ErrInvalidFormat,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            _, err := Parse(tt.input)
            if err != tt.expectedErr {
                t.Errorf("Expected error %v, got %v", tt.expectedErr, err)
            }
        })
    }
}
```

### Testing with Context

```go
func TestWithTimeout(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
    defer cancel()

    _, err := SomeOperation(ctx)
    if err != context.DeadlineExceeded {
        t.Errorf("Expected timeout error, got: %v", err)
    }
}
```

### Mock External Dependencies

```go
// Define interface for dependency
type GitHubClient interface {
    GetRepository(owner, repo string) (*Repository, error)
}

// Mock implementation for testing
type mockGitHubClient struct {
    repos map[string]*Repository
}

func (m *mockGitHubClient) GetRepository(owner, repo string) (*Repository, error) {
    key := fmt.Sprintf("%s/%s", owner, repo)
    if repo, ok := m.repos[key]; ok {
        return repo, nil
    }
    return nil, ErrNotFound
}

func TestWithMock(t *testing.T) {
    mock := &mockGitHubClient{
        repos: map[string]*Repository{
            "user/repo": {Name: "repo", Owner: "user"},
        },
    }

    analyzer := NewAnalyzer(mock)
    result, err := analyzer.AnalyzeRepo("user", "repo")

    if err != nil {
        t.Fatalf("Unexpected error: %v", err)
    }

    if result == nil {
        t.Error("Expected result, got nil")
    }
}
```

---

## Test Structure

### Recommended Package Layout

```
pkg/
├── ai/
│   ├── analyzer.go
│   ├── analyzer_test.go
│   ├── client.go
│   ├── client_test.go
│   └── testdata/          # Test fixtures
│       ├── findings.json
│       └── expected.json
├── rules/
│   ├── rules.go
│   ├── rules_test.go
│   └── testdata/
│       └── workflows/
│           ├── valid.yml
│           └── vulnerable.yml
```

### Using Testdata

```go
func TestParseWorkflow(t *testing.T) {
    data, err := os.ReadFile("testdata/workflows/valid.yml")
    if err != nil {
        t.Fatalf("Failed to read test data: %v", err)
    }

    workflow, err := Parse(data)
    if err != nil {
        t.Errorf("Parse failed: %v", err)
    }

    // Assert expectations
}
```

---

## Best Practices

### 1. Test Naming

```go
// Good: Descriptive test names
func TestAnalyzer_WhenAPIKeyMissing_ReturnsError(t *testing.T) {}
func TestParser_WithValidYAML_ParsesSuccessfully(t *testing.T) {}

// Bad: Unclear test names
func TestAnalyzer1(t *testing.T) {}
func TestParser(t *testing.T) {}
```

### 2. Arrange-Act-Assert Pattern

```go
func TestSomething(t *testing.T) {
    // Arrange: Set up test data and dependencies
    input := "test input"
    expected := "expected output"

    // Act: Execute the code under test
    result, err := ProcessInput(input)

    // Assert: Verify the results
    if err != nil {
        t.Fatalf("Unexpected error: %v", err)
    }
    if result != expected {
        t.Errorf("Expected %q, got %q", expected, result)
    }
}
```

### 3. Use Helper Functions

```go
func TestMultipleCases(t *testing.T) {
    t.Helper()  // Mark as helper

    assertNoError := func(t *testing.T, err error) {
        t.Helper()
        if err != nil {
            t.Fatalf("Unexpected error: %v", err)
        }
    }

    assertEqual := func(t *testing.T, got, want interface{}) {
        t.Helper()
        if got != want {
            t.Errorf("got %v, want %v", got, want)
        }
    }

    // Use helpers in tests
    result, err := DoSomething()
    assertNoError(t, err)
    assertEqual(t, result, "expected")
}
```

### 4. Clean Up Resources

```go
func TestWithTempFile(t *testing.T) {
    tmpFile, err := os.CreateTemp("", "test-*.txt")
    if err != nil {
        t.Fatalf("Failed to create temp file: %v", err)
    }
    defer os.Remove(tmpFile.Name())  // Clean up
    defer tmpFile.Close()

    // Use tmpFile in test
}
```

### 5. Parallel Tests

```go
func TestParallel(t *testing.T) {
    tests := []struct {
        name string
        input string
    }{
        {"case1", "input1"},
        {"case2", "input2"},
    }

    for _, tt := range tests {
        tt := tt  // Capture range variable
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel()  // Run subtests in parallel

            result := Process(tt.input)
            // Assertions
        })
    }
}
```

### 6. Test Coverage Comments

```go
// Mark untestable code (use sparingly)
func unreachableError() {
    // This should never happen
    panic("unreachable")  // nosemgrep: no-panic
}

// Skip coverage for specific blocks
//go:coverage:skip
func debugCode() {
    // Debug code not covered by tests
}
```

---

## CI/CD Integration

### GitHub Actions

The project includes comprehensive CI workflows:

```yaml
# .github/workflows/test.yml
- Test on multiple OS (Linux, macOS, Windows)
- Test with multiple Go versions (1.23, 1.24)
- Generate coverage reports
- Upload to Codecov
- Comment coverage on PRs
- Run integration tests
- Lint code
- Run benchmarks
```

### Local CI Simulation

```bash
# Run all CI checks locally
make ci

# Run individual CI steps
make ci-lint   # Linting
make ci-test   # Testing with coverage
make ci-build  # Build verification
```

---

## Troubleshooting

### Tests Failing Locally But Pass in CI

```bash
# Clean test cache
go clean -testcache

# Run with verbose output
go test ./... -v

# Check for race conditions
go test ./... -race
```

### Coverage Not Updating

```bash
# Remove old coverage files
rm -rf coverage/

# Regenerate coverage
make test-coverage
```

### Slow Tests

```bash
# Run only short tests
make test-short

# Identify slow tests
go test ./... -v | grep -E "PASS.*\d+\.\d+s"

# Run specific package
go test ./pkg/specific/... -v
```

### Test Flakiness

```bash
# Run tests multiple times
go test ./... -count=10

# Run with race detector
go test ./... -race -count=5
```

---

## Next Steps

1. **Increase Coverage**: Focus on packages below 60% coverage
2. **Add Integration Tests**: Test end-to-end workflows
3. **Performance Tests**: Add benchmarks for critical paths
4. **Property-Based Testing**: Consider using testing/quick for fuzz testing
5. **Mocking**: Add comprehensive mocks for external dependencies

---

## Resources

- [Go Testing Package](https://pkg.go.dev/testing)
- [Table Driven Tests](https://github.com/golang/go/wiki/TableDrivenTests)
- [Advanced Testing](https://github.com/golang/go/wiki/AdvancedTesting)
- [Testify Package](https://github.com/stretchr/testify) (if we add it)
- [GoMock](https://github.com/golang/mock) (for mocking)

---

**Questions?** Open an issue at https://github.com/harekrishnarai/flowlyt/issues
