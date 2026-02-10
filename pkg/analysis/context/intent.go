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
	"regexp"
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/parser"
)

// WorkflowIntent represents the detected purpose of a workflow
type WorkflowIntent int

const (
	// IntentUnknown - Cannot determine intent
	IntentUnknown WorkflowIntent = iota

	// IntentReadOnly - Read-only operations (tests, linting, checks)
	IntentReadOnly

	// IntentReadWrite - Modifies code or creates artifacts
	IntentReadWrite

	// IntentDeploy - Deploys applications or services
	IntentDeploy

	// IntentRelease - Creates releases, publishes packages
	IntentRelease
)

// String returns the string representation of WorkflowIntent
func (w WorkflowIntent) String() string {
	switch w {
	case IntentReadOnly:
		return "ReadOnly"
	case IntentReadWrite:
		return "ReadWrite"
	case IntentDeploy:
		return "Deploy"
	case IntentRelease:
		return "Release"
	default:
		return "Unknown"
	}
}

// IntentDetector analyzes workflows to determine their purpose
type IntentDetector struct {
	// Patterns for workflow name analysis
	readOnlyPatterns  []*regexp.Regexp
	deployPatterns    []*regexp.Regexp
	releasePatterns   []*regexp.Regexp

	// Patterns for operation detection
	writeOperations   []*regexp.Regexp
	deployOperations  []*regexp.Regexp
	releaseOperations []*regexp.Regexp
}

// NewIntentDetector creates a new intent detector
func NewIntentDetector() *IntentDetector {
	return &IntentDetector{
		readOnlyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(test|ci|check|lint|validate|verify|scan|analyze)`),
		},
		deployPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(deploy|deployment|k8s|kubernetes|docker|container)`),
		},
		releasePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(release|publish|package|version|tag)`),
		},
		writeOperations: []*regexp.Regexp{
			regexp.MustCompile(`git\s+(push|commit)`),
			regexp.MustCompile(`gh\s+pr\s+(create|edit|merge)`),
			regexp.MustCompile(`gh\s+issue\s+(create|edit)`),
		},
		deployOperations: []*regexp.Regexp{
			regexp.MustCompile(`kubectl\s+(apply|create|deploy)`),
			regexp.MustCompile(`docker\s+(push|deploy)`),
			regexp.MustCompile(`terraform\s+(apply|deploy)`),
			regexp.MustCompile(`aws\s+(deploy|ecs|eks)`),
		},
		releaseOperations: []*regexp.Regexp{
			regexp.MustCompile(`gh\s+release\s+create`),
			regexp.MustCompile(`npm\s+publish`),
			regexp.MustCompile(`docker\s+push.*:(latest|\$\{\{.*version)`),
			regexp.MustCompile(`goreleaser`),
			regexp.MustCompile(`semantic-release`),
		},
	}
}

// DetectIntent analyzes a workflow to determine its purpose
func (d *IntentDetector) DetectIntent(workflow *parser.Workflow) WorkflowIntent {
	// Check workflow name first
	nameIntent := d.detectFromName(workflow.Name)
	if nameIntent != IntentUnknown {
		// Verify with operation analysis
		opIntent := d.detectFromOperations(workflow)

		// If operations suggest higher risk, use that
		if opIntent > nameIntent {
			return opIntent
		}
		return nameIntent
	}

	// Check triggers for hints
	triggerIntent := d.detectFromTriggers(workflow)
	if triggerIntent != IntentUnknown {
		return triggerIntent
	}

	// Analyze operations
	return d.detectFromOperations(workflow)
}

// detectFromName analyzes workflow name
func (d *IntentDetector) detectFromName(name string) WorkflowIntent {
	nameLower := strings.ToLower(name)

	// Check release patterns first (most specific)
	for _, pattern := range d.releasePatterns {
		if pattern.MatchString(nameLower) {
			return IntentRelease
		}
	}

	// Check deploy patterns
	for _, pattern := range d.deployPatterns {
		if pattern.MatchString(nameLower) {
			return IntentDeploy
		}
	}

	// Check read-only patterns
	for _, pattern := range d.readOnlyPatterns {
		if pattern.MatchString(nameLower) {
			return IntentReadOnly
		}
	}

	return IntentUnknown
}

// detectFromTriggers analyzes workflow triggers
func (d *IntentDetector) detectFromTriggers(workflow *parser.Workflow) WorkflowIntent {
	if workflow.On == nil {
		return IntentUnknown
	}

	// Parse triggers
	triggers := d.parseTriggers(workflow.On)

	// Release trigger
	if triggers["release"] {
		return IntentRelease
	}

	// Tag pushes often indicate releases
	if triggers["push"] {
		// Check if it's a tag push (would need to inspect On map structure)
		if onMap, ok := workflow.On.(map[string]interface{}); ok {
			if pushConfig, ok := onMap["push"].(map[string]interface{}); ok {
				if tags, ok := pushConfig["tags"]; ok && tags != nil {
					return IntentRelease
				}
			}
		}
	}

	// Workflow dispatch might be deploy
	if triggers["workflow_dispatch"] {
		// Check if there are environment inputs
		if onMap, ok := workflow.On.(map[string]interface{}); ok {
			if wdConfig, ok := onMap["workflow_dispatch"].(map[string]interface{}); ok {
				if inputs, ok := wdConfig["inputs"].(map[string]interface{}); ok {
					for key := range inputs {
						if strings.Contains(strings.ToLower(key), "environment") ||
						   strings.Contains(strings.ToLower(key), "deploy") {
							return IntentDeploy
						}
					}
				}
			}
		}
	}

	return IntentUnknown
}

// parseTriggers extracts trigger names from the On interface{}
func (d *IntentDetector) parseTriggers(on interface{}) map[string]bool {
	triggers := make(map[string]bool)

	switch v := on.(type) {
	case string:
		triggers[v] = true
	case []interface{}:
		for _, trigger := range v {
			if triggerStr, ok := trigger.(string); ok {
				triggers[triggerStr] = true
			}
		}
	case map[string]interface{}:
		for key := range v {
			triggers[key] = true
		}
	}

	return triggers
}

// detectFromOperations analyzes workflow steps and actions
func (d *IntentDetector) detectFromOperations(workflow *parser.Workflow) WorkflowIntent {
	hasReleaseOps := false
	hasDeployOps := false
	hasWriteOps := false
	hasOnlyReadOps := true

	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			// Check step uses
			if step.Uses != "" {
				stepUsesLower := strings.ToLower(step.Uses)

				// Release actions
				if strings.Contains(stepUsesLower, "gh-release") ||
				   strings.Contains(stepUsesLower, "create-release") ||
				   strings.Contains(stepUsesLower, "goreleaser") ||
				   strings.Contains(stepUsesLower, "semantic-release") {
					hasReleaseOps = true
					hasOnlyReadOps = false
				}

				// Deploy actions
				if strings.Contains(stepUsesLower, "deploy") ||
				   strings.Contains(stepUsesLower, "kubernetes") ||
				   strings.Contains(stepUsesLower, "aws-actions") {
					hasDeployOps = true
					hasOnlyReadOps = false
				}

				// Write actions
				if strings.Contains(stepUsesLower, "upload-artifact") ||
				   strings.Contains(stepUsesLower, "upload-release-asset") ||
				   strings.Contains(stepUsesLower, "publish") {
					hasWriteOps = true
					hasOnlyReadOps = false
				}
			}

			// Check run commands
			if step.Run != "" {
				runLower := strings.ToLower(step.Run)

				// Release operations
				for _, pattern := range d.releaseOperations {
					if pattern.MatchString(step.Run) {
						hasReleaseOps = true
						hasOnlyReadOps = false
						break
					}
				}

				// Deploy operations
				for _, pattern := range d.deployOperations {
					if pattern.MatchString(step.Run) {
						hasDeployOps = true
						hasOnlyReadOps = false
						break
					}
				}

				// Write operations
				for _, pattern := range d.writeOperations {
					if pattern.MatchString(step.Run) {
						hasWriteOps = true
						hasOnlyReadOps = false
						break
					}
				}

				// Check for common read-only operations
				if strings.Contains(runLower, "test") ||
				   strings.Contains(runLower, "lint") ||
				   strings.Contains(runLower, "check") ||
				   strings.Contains(runLower, "validate") {
					// These are read-only operations
					continue
				}
			}
		}
	}

	// Determine intent based on detected operations
	if hasReleaseOps {
		return IntentRelease
	}
	if hasDeployOps {
		return IntentDeploy
	}
	if hasWriteOps {
		return IntentReadWrite
	}
	if hasOnlyReadOps {
		return IntentReadOnly
	}

	return IntentUnknown
}

// IsReadOnly returns true if the workflow is read-only
func (w WorkflowIntent) IsReadOnly() bool {
	return w == IntentReadOnly
}

// IsCritical returns true if the workflow is deployment or release
func (w WorkflowIntent) IsCritical() bool {
	return w == IntentDeploy || w == IntentRelease
}

// RequiresStrictSecurity returns true if the workflow needs strict security
func (w WorkflowIntent) RequiresStrictSecurity() bool {
	return w == IntentRelease || w == IntentDeploy
}
