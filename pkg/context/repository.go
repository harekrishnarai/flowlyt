/*
Copyright 2025 Hare Krishna Rai

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package context

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/parser"
)

// RepositoryContext provides context about the repository being analyzed
type RepositoryContext struct {
	IsPublic          bool
	IsPrivate         bool
	IsFork            bool
	HasSecurityPolicy bool
	HasDependabot     bool
	HasCodeScanning   bool
	DefaultBranch     string
	RepositoryPath    string
	Owner             string
	Name              string
}

// RepositoryAnalyzer analyzes repository context for security rules
type RepositoryAnalyzer struct {
	repoPath string
}

// NewRepositoryAnalyzer creates a new repository analyzer
func NewRepositoryAnalyzer(repoPath string) *RepositoryAnalyzer {
	return &RepositoryAnalyzer{
		repoPath: repoPath,
	}
}

// AnalyzeRepository analyzes repository context
func (ra *RepositoryAnalyzer) AnalyzeRepository() (*RepositoryContext, error) {
	ctx := &RepositoryContext{
		RepositoryPath: ra.repoPath,
	}

	// Analyze repository structure
	if err := ra.analyzeRepositoryStructure(ctx); err != nil {
		return nil, fmt.Errorf("failed to analyze repository structure: %w", err)
	}

	// Determine visibility (heuristic analysis)
	ra.determineRepositoryVisibility(ctx)

	// Analyze security features
	ra.analyzeSecurityFeatures(ctx)

	return ctx, nil
}

// analyzeRepositoryStructure examines the repository structure
func (ra *RepositoryAnalyzer) analyzeRepositoryStructure(ctx *RepositoryContext) error {
	// Check for .github directory
	githubDir := filepath.Join(ra.repoPath, ".github")
	if _, err := os.Stat(githubDir); err == nil {
		ctx.HasSecurityPolicy = ra.hasFile(githubDir, "SECURITY.md")
		ctx.HasDependabot = ra.hasFile(githubDir, "dependabot.yml") || ra.hasFile(githubDir, "dependabot.yaml")

		// Check for code scanning workflows
		workflowsDir := filepath.Join(githubDir, "workflows")
		ctx.HasCodeScanning = ra.hasCodeScanningWorkflows(workflowsDir)
	}

	// Extract owner and name from path
	ra.extractRepositoryInfo(ctx)

	return nil
}

// determineRepositoryVisibility uses heuristics to determine if repo is public
func (ra *RepositoryAnalyzer) determineRepositoryVisibility(ctx *RepositoryContext) {
	// Heuristics for public repositories:

	// 1. Check for typical public repo files
	publicIndicators := []string{
		"README.md", "readme.md", "README.rst",
		"LICENSE", "LICENSE.md", "LICENSE.txt",
		"CODE_OF_CONDUCT.md", "CONTRIBUTING.md",
		"CHANGELOG.md", "CHANGELOG",
	}

	publicFileCount := 0
	for _, file := range publicIndicators {
		if ra.hasFile(ra.repoPath, file) {
			publicFileCount++
		}
	}

	// 2. Check for typical open source patterns
	hasOpenSourceStructure := ra.hasFile(ra.repoPath, "package.json") ||
		ra.hasFile(ra.repoPath, "setup.py") ||
		ra.hasFile(ra.repoPath, "Cargo.toml") ||
		ra.hasFile(ra.repoPath, "go.mod") ||
		ra.hasFile(ra.repoPath, "pom.xml")

	// 3. Check for CI/CD configurations that suggest public repo
	hasCIConfig := ra.hasFile(filepath.Join(ra.repoPath, ".github", "workflows"), "") ||
		ra.hasFile(ra.repoPath, ".travis.yml") ||
		ra.hasFile(ra.repoPath, ".circleci") ||
		ra.hasFile(ra.repoPath, "azure-pipelines.yml")

	// Determine visibility based on indicators
	if publicFileCount >= 3 && hasOpenSourceStructure && hasCIConfig {
		ctx.IsPublic = true
		ctx.IsPrivate = false
	} else if publicFileCount <= 1 && !hasOpenSourceStructure {
		ctx.IsPublic = false
		ctx.IsPrivate = true
	} else {
		// Default to private for security (conservative approach)
		ctx.IsPublic = false
		ctx.IsPrivate = true
	}
}

// analyzeSecurityFeatures checks for security-related configurations
func (ra *RepositoryAnalyzer) analyzeSecurityFeatures(ctx *RepositoryContext) {
	// Additional security feature detection could be added here
	// For now, we've covered the main ones in analyzeRepositoryStructure
}

// hasFile checks if a file exists in the given directory
func (ra *RepositoryAnalyzer) hasFile(dir, filename string) bool {
	if filename == "" {
		// Check if directory exists
		_, err := os.Stat(dir)
		return err == nil
	}

	filePath := filepath.Join(dir, filename)
	_, err := os.Stat(filePath)
	return err == nil
}

// hasCodeScanningWorkflows checks for code scanning in workflows
func (ra *RepositoryAnalyzer) hasCodeScanningWorkflows(workflowsDir string) bool {
	if !ra.hasFile(workflowsDir, "") {
		return false
	}

	entries, err := os.ReadDir(workflowsDir)
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if strings.HasSuffix(entry.Name(), ".yml") || strings.HasSuffix(entry.Name(), ".yaml") {
			content, err := os.ReadFile(filepath.Join(workflowsDir, entry.Name()))
			if err != nil {
				continue
			}

			contentStr := string(content)
			if strings.Contains(contentStr, "github/codeql-action") ||
				strings.Contains(contentStr, "security-events") ||
				strings.Contains(contentStr, "sarif") {
				return true
			}
		}
	}

	return false
}

// extractRepositoryInfo extracts owner and name from repository path
func (ra *RepositoryAnalyzer) extractRepositoryInfo(ctx *RepositoryContext) {
	// Extract from path like: /Users/user/github-repos/owner-name/repo-name
	// or /path/to/repo

	parts := strings.Split(filepath.Clean(ra.repoPath), string(filepath.Separator))
	if len(parts) > 0 {
		ctx.Name = parts[len(parts)-1]
	}

	// Try to extract owner from path patterns
	for i := len(parts) - 2; i >= 0; i-- {
		if parts[i] == "github-repos" || parts[i] == "repos" ||
			parts[i] == "projects" || parts[i] == "src" {
			if i+1 < len(parts) {
				ctx.Owner = parts[i+1]
				break
			}
		}
	}

	// If we couldn't extract owner, use a default
	if ctx.Owner == "" {
		ctx.Owner = "unknown"
	}
}

// WorkflowContext provides context about a specific workflow
type WorkflowContext struct {
	Repository           *RepositoryContext
	WorkflowFile         parser.WorkflowFile
	HasSecrets           bool
	HasPrivileges        bool
	IsTriggeredByPR      bool
	IsTriggeredByIssue   bool
	UsesSelHostedRunners bool
	RunnerLabels         []string
}

// AnalyzeWorkflowContext analyzes workflow-specific context
func AnalyzeWorkflowContext(workflow parser.WorkflowFile, repoCtx *RepositoryContext) *WorkflowContext {
	ctx := &WorkflowContext{
		Repository:   repoCtx,
		WorkflowFile: workflow,
	}

	// Analyze triggers
	ctx.analyzeWorkflowTriggers()

	// Analyze runner usage
	ctx.analyzeRunnerUsage()

	// Analyze permissions and secrets
	ctx.analyzePermissionsAndSecrets()

	return ctx
}

// analyzeWorkflowTriggers analyzes what triggers the workflow
func (wc *WorkflowContext) analyzeWorkflowTriggers() {
	if wc.WorkflowFile.Workflow.On == nil {
		return
	}

	triggers := make(map[string]bool)

	switch on := wc.WorkflowFile.Workflow.On.(type) {
	case map[string]interface{}:
		for key := range on {
			triggers[key] = true
		}
	case []interface{}:
		for _, trigger := range on {
			if triggerStr, ok := trigger.(string); ok {
				triggers[triggerStr] = true
			}
		}
	case string:
		triggers[on] = true
	}

	wc.IsTriggeredByPR = triggers["pull_request"] || triggers["pull_request_target"]
	wc.IsTriggeredByIssue = triggers["issues"] || triggers["issue_comment"]
}

// analyzeRunnerUsage analyzes runner configuration
func (wc *WorkflowContext) analyzeRunnerUsage() {
	for _, job := range wc.WorkflowFile.Workflow.Jobs {
		if job.RunsOn != nil {
			runnerInfo := parseRunsOn(job.RunsOn)
			for _, runner := range runnerInfo {
				if strings.Contains(runner, "self-hosted") {
					wc.UsesSelHostedRunners = true
				}
				wc.RunnerLabels = append(wc.RunnerLabels, runner)
			}
		}
	}
}

// analyzePermissionsAndSecrets analyzes permissions and secret usage
func (wc *WorkflowContext) analyzePermissionsAndSecrets() {
	// Check workflow-level permissions
	if wc.WorkflowFile.Workflow.Permissions != nil {
		wc.HasPrivileges = true
	}

	// Check job-level permissions and secrets
	for _, job := range wc.WorkflowFile.Workflow.Jobs {
		if job.Permissions != nil {
			wc.HasPrivileges = true
		}

		// Check for secret usage in steps
		for _, step := range job.Steps {
			if containsSecrets(step.Run) || containsSecrets(step.With) ||
				containsSecrets(step.Env) {
				wc.HasSecrets = true
			}
		}
	}
}

// Helper functions

func parseRunsOn(runsOn interface{}) []string {
	var runners []string

	switch r := runsOn.(type) {
	case string:
		runners = append(runners, r)
	case []interface{}:
		for _, runner := range r {
			if runnerStr, ok := runner.(string); ok {
				runners = append(runners, runnerStr)
			}
		}
	}

	return runners
}

func containsSecrets(data interface{}) bool {
	switch d := data.(type) {
	case string:
		return strings.Contains(d, "secrets.")
	case map[string]interface{}:
		for _, value := range d {
			if containsSecrets(value) {
				return true
			}
		}
	}
	return false
}
