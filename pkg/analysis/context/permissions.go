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
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/parser"
)

// PermissionNeeds represents which permissions a workflow actually needs
type PermissionNeeds struct {
	Contents      bool // Read/write repository contents
	PullRequests  bool // Create/update pull requests
	Issues        bool // Create/update issues
	Packages      bool // Publish packages
	Deployments   bool // Create deployments
	Checks        bool // Create/update checks
	Statuses      bool // Create/update statuses
	Actions       bool // Manage Actions
	SecurityEvents bool // Manage security events
}

// IsEmpty returns true if no permissions are needed
func (p *PermissionNeeds) IsEmpty() bool {
	return !p.Contents && !p.PullRequests && !p.Issues && !p.Packages &&
		!p.Deployments && !p.Checks && !p.Statuses && !p.Actions && !p.SecurityEvents
}

// PermissionAnalyzer analyzes workflows to determine actual permission needs
type PermissionAnalyzer struct{}

// NewPermissionAnalyzer creates a new permission analyzer
func NewPermissionAnalyzer() *PermissionAnalyzer {
	return &PermissionAnalyzer{}
}

// AnalyzeNeeds determines what permissions a workflow actually needs
func (a *PermissionAnalyzer) AnalyzeNeeds(workflow *parser.Workflow) PermissionNeeds {
	needs := PermissionNeeds{}

	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			// Analyze step uses
			if step.Uses != "" {
				a.analyzeAction(&needs, step.Uses)
			}

			// Analyze run commands
			if step.Run != "" {
				a.analyzeCommand(&needs, step.Run)
			}
		}
	}

	return needs
}

// analyzeAction checks what permissions an action might need
func (a *PermissionAnalyzer) analyzeAction(needs *PermissionNeeds, uses string) {
	usesLower := strings.ToLower(uses)

	// Checkout action - needs contents read
	if strings.Contains(usesLower, "actions/checkout") {
		needs.Contents = true
	}

	// Upload/download artifacts - no special permissions needed (uses GITHUB_TOKEN implicitly)

	// Release actions
	if strings.Contains(usesLower, "gh-release") ||
	   strings.Contains(usesLower, "create-release") ||
	   strings.Contains(usesLower, "upload-release-asset") {
		needs.Contents = true // Releases need contents: write
	}

	// Package publishing
	if strings.Contains(usesLower, "publish") ||
	   strings.Contains(usesLower, "docker/build-push-action") {
		needs.Packages = true
	}

	// Deployment actions
	if strings.Contains(usesLower, "deploy") {
		needs.Deployments = true
	}
}

// analyzeCommand checks what permissions a command might need
func (a *PermissionAnalyzer) analyzeCommand(needs *PermissionNeeds, command string) {
	cmdLower := strings.ToLower(command)

	// Git operations
	if strings.Contains(cmdLower, "git push") {
		needs.Contents = true
	}

	// GitHub CLI operations
	if strings.Contains(cmdLower, "gh pr create") ||
	   strings.Contains(cmdLower, "gh pr edit") ||
	   strings.Contains(cmdLower, "gh pr merge") ||
	   strings.Contains(cmdLower, "gh pr comment") {
		needs.PullRequests = true
	}

	if strings.Contains(cmdLower, "gh issue create") ||
	   strings.Contains(cmdLower, "gh issue edit") ||
	   strings.Contains(cmdLower, "gh issue comment") {
		needs.Issues = true
	}

	if strings.Contains(cmdLower, "gh release create") ||
	   strings.Contains(cmdLower, "gh release upload") {
		needs.Contents = true
	}

	// Package publishing
	if strings.Contains(cmdLower, "npm publish") ||
	   strings.Contains(cmdLower, "docker push") ||
	   strings.Contains(cmdLower, "go publish") {
		needs.Packages = true
	}

	// Deployment commands
	if strings.Contains(cmdLower, "kubectl apply") ||
	   strings.Contains(cmdLower, "kubectl create") ||
	   strings.Contains(cmdLower, "helm install") ||
	   strings.Contains(cmdLower, "terraform apply") {
		needs.Deployments = true
	}
}

// GetGrantedPermissions extracts permissions granted in the workflow
func (a *PermissionAnalyzer) GetGrantedPermissions(workflow *parser.Workflow) map[string]string {
	granted := make(map[string]string)

	// Check workflow-level permissions
	if workflow.Permissions != nil {
		// Handle permissions as map[string]interface{}
		if perms, ok := workflow.Permissions.(map[string]interface{}); ok {
			for key, value := range perms {
				if valueStr, ok := value.(string); ok {
					granted[key] = valueStr
				}
			}
		}
		// Handle permissions as string (e.g., "read-all" or "write-all")
		if permsStr, ok := workflow.Permissions.(string); ok {
			// Special case: "read-all", "write-all", etc.
			granted["_all"] = permsStr
		}
	}

	// Note: Job-level permissions would need to be checked per-job
	// For now, we check workflow-level which is more common

	return granted
}

// HasSufficientPermissions checks if granted permissions satisfy needs
func (a *PermissionAnalyzer) HasSufficientPermissions(needs PermissionNeeds, granted map[string]string) bool {
	// If no permissions are granted explicitly, default permissions apply
	// This is actually more permissive, so we return false to flag it
	if len(granted) == 0 {
		return false
	}

	// Check each needed permission
	if needs.Contents && !a.hasPermission(granted, "contents", "write") {
		return false
	}

	if needs.PullRequests && !a.hasPermission(granted, "pull-requests", "write") {
		return false
	}

	if needs.Issues && !a.hasPermission(granted, "issues", "write") {
		return false
	}

	if needs.Packages && !a.hasPermission(granted, "packages", "write") {
		return false
	}

	if needs.Deployments && !a.hasPermission(granted, "deployments", "write") {
		return false
	}

	return true
}

// hasPermission checks if a specific permission is granted
func (a *PermissionAnalyzer) hasPermission(granted map[string]string, permission string, level string) bool {
	if value, ok := granted[permission]; ok {
		return value == level || value == "write"
	}
	return false
}

// ShouldHaveExplicitPermissions returns true if workflow should declare permissions
func (a *PermissionAnalyzer) ShouldHaveExplicitPermissions(workflow *parser.Workflow, intent WorkflowIntent) bool {
	needs := a.AnalyzeNeeds(workflow)

	// If workflow needs permissions, it should declare them
	if !needs.IsEmpty() {
		return true
	}

	// Critical workflows should always have explicit permissions
	if intent.IsCritical() {
		return true
	}

	// Read-only workflows don't need explicit permissions
	if intent.IsReadOnly() {
		return false
	}

	return false
}
