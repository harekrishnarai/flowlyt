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
	"github.com/harekrishnarai/flowlyt/pkg/parser"
)

// TriggerRisk represents the risk level of a workflow trigger
type TriggerRisk int

const (
	// RiskUnknown - Cannot determine risk
	RiskUnknown TriggerRisk = iota

	// RiskLow - Low risk triggers (schedule, workflow_dispatch with auth)
	RiskLow

	// RiskMedium - Medium risk triggers (push to protected branches)
	RiskMedium

	// RiskHigh - High risk triggers (pull_request, issue_comment)
	RiskHigh

	// RiskCritical - Critical risk triggers (pull_request_target, public events)
	RiskCritical
)

// String returns the string representation of TriggerRisk
func (t TriggerRisk) String() string {
	switch t {
	case RiskLow:
		return "Low"
	case RiskMedium:
		return "Medium"
	case RiskHigh:
		return "High"
	case RiskCritical:
		return "Critical"
	default:
		return "Unknown"
	}
}

// TriggerAnalyzer analyzes workflow triggers to assess risk
type TriggerAnalyzer struct{}

// NewTriggerAnalyzer creates a new trigger analyzer
func NewTriggerAnalyzer() *TriggerAnalyzer {
	return &TriggerAnalyzer{}
}

// AnalyzeRisk determines the risk level of a workflow's triggers
func (a *TriggerAnalyzer) AnalyzeRisk(workflow *parser.Workflow) TriggerRisk {
	if workflow.On == nil {
		return RiskUnknown
	}

	maxRisk := RiskLow

	// Parse triggers based on On type
	triggers := a.parseTriggers(workflow.On)

	// pull_request_target is CRITICAL risk
	if triggers["pull_request_target"] {
		return RiskCritical
	}

	// workflow_run can be risky if it uses untrusted artifacts
	if triggers["workflow_run"] {
		if maxRisk < RiskHigh {
			maxRisk = RiskHigh
		}
	}

	// issue_comment and other public events are HIGH risk
	if triggers["issue_comment"] || triggers["issues"] || triggers["discussion"] || triggers["discussion_comment"] {
		if maxRisk < RiskHigh {
			maxRisk = RiskHigh
		}
	}

	// pull_request is HIGH risk (untrusted code)
	if triggers["pull_request"] {
		if maxRisk < RiskHigh {
			maxRisk = RiskHigh
		}
	}

	// push can be MEDIUM or LOW risk depending on branches
	if triggers["push"] {
		// Push to any branch is some risk
		if maxRisk < RiskMedium {
			maxRisk = RiskMedium
		}
	}

	// release is LOW risk (trusted maintainers only)
	if triggers["release"] {
		if maxRisk < RiskLow {
			maxRisk = RiskLow
		}
	}

	// schedule is LOW risk (no external input)
	if triggers["schedule"] {
		if maxRisk < RiskLow {
			maxRisk = RiskLow
		}
	}

	// workflow_dispatch is LOW risk (requires auth)
	if triggers["workflow_dispatch"] {
		if maxRisk < RiskLow {
			maxRisk = RiskLow
		}
	}

	return maxRisk
}

// parseTriggers extracts trigger names from the On interface{}
func (a *TriggerAnalyzer) parseTriggers(on interface{}) map[string]bool {
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

// isProtectedBranch checks if branches include protected branches
func (a *TriggerAnalyzer) isProtectedBranch(branches []string) bool {
	if len(branches) == 0 {
		return true // No filter means all branches, including protected ones
	}

	for _, branch := range branches {
		if branch == "main" || branch == "master" || branch == "production" {
			return true
		}
	}
	return false
}

// HasUntrustedInput returns true if the workflow trigger accepts untrusted input
func (a *TriggerAnalyzer) HasUntrustedInput(workflow *parser.Workflow) bool {
	if workflow.On == nil {
		return false
	}

	triggers := a.parseTriggers(workflow.On)

	// These triggers accept untrusted input
	return triggers["pull_request"] ||
		triggers["pull_request_target"] ||
		triggers["issue_comment"] ||
		triggers["issues"] ||
		triggers["discussion"] ||
		triggers["discussion_comment"]
}

// IsTrustedTrigger returns true if the trigger is from trusted sources only
func (a *TriggerAnalyzer) IsTrustedTrigger(workflow *parser.Workflow) bool {
	if workflow.On == nil {
		return false
	}

	triggers := a.parseTriggers(workflow.On)

	// These triggers are trusted (require maintainer access)
	return triggers["release"] ||
		triggers["schedule"] ||
		(triggers["workflow_dispatch"] && !triggers["pull_request"] && !triggers["pull_request_target"])
}

// RequiresCredentialProtection returns true if the workflow should use persist-credentials: false
func (a *TriggerAnalyzer) RequiresCredentialProtection(workflow *parser.Workflow) bool {
	// If workflow has untrusted input, credentials should be protected
	if a.HasUntrustedInput(workflow) {
		return true
	}

	// If workflow is not critical and has trusted triggers, credentials can persist
	return false
}

// GetTriggerType returns a human-readable description of the trigger type
func (a *TriggerAnalyzer) GetTriggerType(workflow *parser.Workflow) string {
	if workflow.On == nil {
		return "unknown"
	}

	triggers := a.parseTriggers(workflow.On)

	// Return most critical trigger first
	if triggers["pull_request_target"] {
		return "pull_request_target"
	}
	if triggers["pull_request"] {
		return "pull_request"
	}
	if triggers["push"] {
		return "push"
	}
	if triggers["release"] {
		return "release"
	}
	if triggers["schedule"] {
		return "schedule"
	}
	if triggers["workflow_dispatch"] {
		return "workflow_dispatch"
	}
	if triggers["issue_comment"] {
		return "issue_comment"
	}
	if triggers["workflow_run"] {
		return "workflow_run"
	}

	return "other"
}
