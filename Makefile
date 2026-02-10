# Flowlyt Makefile
# Comprehensive test and build automation

.PHONY: all test test-verbose test-coverage test-coverage-html coverage-report test-short test-race test-integration lint fmt vet build clean install help

# Colors for output
GREEN  := \033[0;32m
YELLOW := \033[0;33m
RED    := \033[0;31m
NC     := \033[0m # No Color

# Coverage thresholds
COVERAGE_THRESHOLD := 60
CURRENT_COVERAGE := $(shell go test ./... -cover -coverprofile=coverage.tmp 2>/dev/null | grep -E "^ok" | awk '{sum+=$$NF} END {if (NR>0) printf "%.1f", (sum/NR)*100}' && rm -f coverage.tmp)

all: fmt vet lint test build ## Run all checks and build

## Testing targets

test: ## Run all tests
	@echo "$(GREEN)Running all tests...$(NC)"
	@go test ./... -v -race -timeout 5m

test-short: ## Run short tests only (fast)
	@echo "$(GREEN)Running short tests...$(NC)"
	@go test ./... -short -v

test-verbose: ## Run tests with verbose output
	@echo "$(GREEN)Running tests with verbose output...$(NC)"
	@go test ./... -v -race -timeout 5m

test-race: ## Run tests with race detector
	@echo "$(GREEN)Running tests with race detector...$(NC)"
	@go test ./... -race -timeout 10m

test-coverage: ## Run tests with coverage report
	@echo "$(GREEN)Running tests with coverage...$(NC)"
	@mkdir -p coverage
	@go test ./... -cover -coverprofile=coverage/coverage.out -covermode=atomic
	@go tool cover -func=coverage/coverage.out | tail -1
	@echo ""
	@$(MAKE) coverage-report

test-coverage-html: test-coverage ## Generate HTML coverage report
	@echo "$(GREEN)Generating HTML coverage report...$(NC)"
	@go tool cover -html=coverage/coverage.out -o coverage/coverage.html
	@echo "$(GREEN)Coverage report generated: coverage/coverage.html$(NC)"
	@open coverage/coverage.html 2>/dev/null || xdg-open coverage/coverage.html 2>/dev/null || echo "Open coverage/coverage.html in your browser"

coverage-report: ## Display coverage summary by package
	@echo "$(YELLOW)================================$(NC)"
	@echo "$(YELLOW)  Coverage Report by Package$(NC)"
	@echo "$(YELLOW)================================$(NC)"
	@go tool cover -func=coverage/coverage.out | grep -E "^github.com" | awk '{printf "%-60s %s\n", $$1, $$3}' | column -t
	@echo "$(YELLOW)================================$(NC)"
	@echo "$(GREEN)Total Coverage:$(NC) $$(go tool cover -func=coverage/coverage.out | grep total | awk '{print $$3}')"
	@echo "$(YELLOW)Coverage Threshold:$(NC) $(COVERAGE_THRESHOLD)%"
	@echo "$(YELLOW)================================$(NC)"

coverage-check: test-coverage ## Check if coverage meets threshold
	@TOTAL_COV=$$(go tool cover -func=coverage/coverage.out | grep total | awk '{print $$3}' | sed 's/%//'); \
	if [ "$$(echo "$$TOTAL_COV < $(COVERAGE_THRESHOLD)" | bc -l)" -eq 1 ]; then \
		echo "$(RED)FAIL: Coverage $$TOTAL_COV% is below threshold $(COVERAGE_THRESHOLD)%$(NC)"; \
		exit 1; \
	else \
		echo "$(GREEN)PASS: Coverage $$TOTAL_COV% meets threshold $(COVERAGE_THRESHOLD)%$(NC)"; \
	fi

test-integration: ## Run integration tests only
	@echo "$(GREEN)Running integration tests...$(NC)"
	@go test ./... -v -tags=integration -timeout 10m

## Package-specific test targets

test-ai: ## Test AI package
	@go test ./pkg/ai/... -v -cover

test-rules: ## Test rules package
	@go test ./pkg/rules/... -v -cover

test-parser: ## Test parser package
	@go test ./pkg/parser/... -v -cover

test-github: ## Test GitHub package
	@go test ./pkg/github/... -v -cover

test-gitlab: ## Test GitLab package
	@go test ./pkg/gitlab/... -v -cover

test-report: ## Test report package
	@go test ./pkg/report/... -v -cover

test-organization: ## Test organization package
	@go test ./pkg/organization/... -v -cover

## Code quality targets

lint: ## Run linters (requires golangci-lint)
	@echo "$(GREEN)Running linters...$(NC)"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "$(YELLOW)golangci-lint not installed. Run: make install-tools$(NC)"; \
	fi

fmt: ## Format code
	@echo "$(GREEN)Formatting code...$(NC)"
	@go fmt ./...

vet: ## Run go vet
	@echo "$(GREEN)Running go vet...$(NC)"
	@go vet ./...

staticcheck: ## Run staticcheck (requires staticcheck)
	@echo "$(GREEN)Running staticcheck...$(NC)"
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "$(YELLOW)staticcheck not installed. Run: make install-tools$(NC)"; \
	fi

## Build targets

build: ## Build the binary
	@echo "$(GREEN)Building flowlyt...$(NC)"
	@go build -o flowlyt ./cmd/flowlyt
	@echo "$(GREEN)Binary created: ./flowlyt$(NC)"

build-all: ## Build for all platforms
	@echo "$(GREEN)Building for all platforms...$(NC)"
	@mkdir -p dist
	@GOOS=linux GOARCH=amd64 go build -o dist/flowlyt-linux-amd64 ./cmd/flowlyt
	@GOOS=linux GOARCH=arm64 go build -o dist/flowlyt-linux-arm64 ./cmd/flowlyt
	@GOOS=darwin GOARCH=amd64 go build -o dist/flowlyt-darwin-amd64 ./cmd/flowlyt
	@GOOS=darwin GOARCH=arm64 go build -o dist/flowlyt-darwin-arm64 ./cmd/flowlyt
	@GOOS=windows GOARCH=amd64 go build -o dist/flowlyt-windows-amd64.exe ./cmd/flowlyt
	@echo "$(GREEN)Binaries created in dist/$(NC)"

install: ## Install the binary
	@echo "$(GREEN)Installing flowlyt...$(NC)"
	@go install ./cmd/flowlyt
	@echo "$(GREEN)Installed to $$(go env GOPATH)/bin/flowlyt$(NC)"

## Tool installation

install-tools: ## Install development tools
	@echo "$(GREEN)Installing development tools...$(NC)"
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install honnef.co/go/tools/cmd/staticcheck@latest
	@go install github.com/axw/gocov/gocov@latest
	@go install github.com/AlekSi/gocov-xml@latest
	@echo "$(GREEN)Tools installed$(NC)"

## Cleanup

clean: ## Clean build artifacts and test cache
	@echo "$(GREEN)Cleaning...$(NC)"
	@rm -f flowlyt
	@rm -rf dist/
	@rm -rf coverage/
	@go clean -testcache
	@echo "$(GREEN)Clean complete$(NC)"

## CI/CD helpers

ci-test: ## Run tests for CI (with coverage and race detection)
	@echo "$(GREEN)Running CI tests...$(NC)"
	@mkdir -p coverage
	@go test ./... -v -race -coverprofile=coverage/coverage.out -covermode=atomic -timeout 10m
	@go tool cover -func=coverage/coverage.out

ci-lint: ## Run linters for CI
	@echo "$(GREEN)Running CI linters...$(NC)"
	@go fmt ./...
	@go vet ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./... --timeout 5m; \
	fi

ci-build: ## Build for CI
	@echo "$(GREEN)Building for CI...$(NC)"
	@go build -v ./cmd/flowlyt

ci: ci-lint ci-test ci-build ## Run all CI checks

## Benchmarks

bench: ## Run benchmarks
	@echo "$(GREEN)Running benchmarks...$(NC)"
	@go test ./... -bench=. -benchmem -run=^$$ | tee coverage/benchmark.txt

bench-compare: ## Run benchmarks and compare with previous
	@echo "$(GREEN)Running benchmark comparison...$(NC)"
	@go test ./... -bench=. -benchmem -run=^$$ | tee coverage/benchmark-new.txt
	@if [ -f coverage/benchmark-old.txt ]; then \
		echo "$(YELLOW)Comparing with previous benchmark...$(NC)"; \
		benchstat coverage/benchmark-old.txt coverage/benchmark-new.txt; \
	fi
	@mv coverage/benchmark-new.txt coverage/benchmark-old.txt

## Help

help: ## Display this help message
	@echo "$(GREEN)Flowlyt Development Makefile$(NC)"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*##"; printf ""} /^[a-zA-Z_-]+:.*?##/ { printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo ""
	@echo "Current Coverage: $(YELLOW)$(CURRENT_COVERAGE)%$(NC)"
	@echo "Coverage Target:  $(YELLOW)$(COVERAGE_THRESHOLD)%$(NC)"

.DEFAULT_GOAL := help
