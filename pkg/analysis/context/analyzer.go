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

// WorkflowContext holds contextual information about a workflow
type WorkflowContext struct {
	Intent            WorkflowIntent
	TriggerRisk       TriggerRisk
	PermissionNeeds   PermissionNeeds
	GrantedPerms      map[string]string
	HasUntrustedInput bool
	IsTrusted         bool
}

// ContextAnalyzer provides comprehensive workflow context analysis
type ContextAnalyzer struct {
	intentDetector   *IntentDetector
	permAnalyzer     *PermissionAnalyzer
	triggerAnalyzer  *TriggerAnalyzer
}

// NewContextAnalyzer creates a new context analyzer
func NewContextAnalyzer() *ContextAnalyzer {
	return &ContextAnalyzer{
		intentDetector:  NewIntentDetector(),
		permAnalyzer:    NewPermissionAnalyzer(),
		triggerAnalyzer: NewTriggerAnalyzer(),
	}
}

// Analyze performs comprehensive context analysis on a workflow
func (ca *ContextAnalyzer) Analyze(workflow *parser.Workflow) *WorkflowContext {
	return &WorkflowContext{
		Intent:            ca.intentDetector.DetectIntent(workflow),
		TriggerRisk:       ca.triggerAnalyzer.AnalyzeRisk(workflow),
		PermissionNeeds:   ca.permAnalyzer.AnalyzeNeeds(workflow),
		GrantedPerms:      ca.permAnalyzer.GetGrantedPermissions(workflow),
		HasUntrustedInput: ca.triggerAnalyzer.HasUntrustedInput(workflow),
		IsTrusted:         ca.triggerAnalyzer.IsTrustedTrigger(workflow),
	}
}

// AdjustSeverity adjusts finding severity based on workflow context
func (ca *ContextAnalyzer) AdjustSeverity(ruleID string, baseSeverity string, ctx *WorkflowContext) string {
	switch ruleID {
	case "BROAD_PERMISSIONS":
		return ca.adjustBroadPermissions(baseSeverity, ctx)

	case "STALE_ACTION_REFS":
		return ca.adjustStaleActionRefs(baseSeverity, ctx)

	case "ARTIPACKED_VULNERABILITY":
		return ca.adjustArtipacked(baseSeverity, ctx)

	case "INJECTION_FLAW", "SHELL_SCRIPT_ISSUES":
		return ca.adjustInjection(baseSeverity, ctx)

	case "PR_TARGET_ABUSE", "DANGEROUS_WRITE_OPERATION":
		// Always critical - no adjustment
		return "CRITICAL"

	case "REPO_JACKING_VULNERABILITY", "CACHE_POISONING", "UNSOUND_CONTAINS":
		// Supply chain issues - keep high for all workflows
		return baseSeverity

	case "EXTERNAL_TRIGGER_DEBUG":
		// Debug statements - adjust based on context
		if ctx.Intent.IsReadOnly() {
			return "LOW"
		}
		return baseSeverity

	default:
		// Default context-aware adjustment for other rules
		return ca.adjustDefault(baseSeverity, ctx)
	}
}

// adjustDefault provides default context-aware adjustment for unhandled rules
func (ca *ContextAnalyzer) adjustDefault(severity string, ctx *WorkflowContext) string {
	// Don't downgrade CRITICAL findings by default
	if severity == "CRITICAL" {
		return severity
	}

	// For read-only workflows without untrusted input, downgrade non-critical findings
	if ctx.Intent.IsReadOnly() && !ctx.HasUntrustedInput {
		switch severity {
		case "HIGH":
			return "MEDIUM"
		case "MEDIUM":
			return "LOW"
		}
	}

	// For trusted triggers (tags, releases), slightly downgrade
	if ctx.IsTrusted {
		switch severity {
		case "HIGH":
			// Keep HIGH for critical workflows, downgrade for others
			if !ctx.Intent.IsCritical() {
				return "MEDIUM"
			}
		}
	}

	return severity
}

// adjustBroadPermissions adjusts severity for BROAD_PERMISSIONS findings
func (ca *ContextAnalyzer) adjustBroadPermissions(baseSeverity string, ctx *WorkflowContext) string {
	// If workflow is read-only and doesn't need permissions, downgrade to INFO
	if ctx.Intent.IsReadOnly() && ctx.PermissionNeeds.IsEmpty() {
		return "INFO"
	}

	// If workflow doesn't actually need permissions, downgrade to LOW
	if ctx.PermissionNeeds.IsEmpty() {
		return "LOW"
	}

	// If workflow is critical (deploy/release), keep HIGH
	if ctx.Intent.IsCritical() {
		return "HIGH"
	}

	// If workflow has untrusted input, keep HIGH
	if ctx.HasUntrustedInput {
		return "HIGH"
	}

	// Otherwise downgrade to MEDIUM
	return "MEDIUM"
}

// adjustStaleActionRefs adjusts severity for STALE_ACTION_REFS findings
func (ca *ContextAnalyzer) adjustStaleActionRefs(baseSeverity string, ctx *WorkflowContext) string {
	// Critical workflows (deploy/release) should use commit SHAs
	if ctx.Intent.IsCritical() {
		return "HIGH"
	}

	// Read-only workflows (tests) can use tags
	if ctx.Intent.IsReadOnly() {
		return "MEDIUM"
	}

	// Workflows with untrusted input should use commit SHAs
	if ctx.HasUntrustedInput {
		return "HIGH"
	}

	// Otherwise it's acceptable
	return "MEDIUM"
}

// adjustArtipacked adjusts severity for ARTIPACKED_VULNERABILITY findings
func (ca *ContextAnalyzer) adjustArtipacked(baseSeverity string, ctx *WorkflowContext) string {
	// If workflow has explicit write permissions, token is needed
	if ctx.GrantedPerms != nil {
		if contents, ok := ctx.GrantedPerms["contents"]; ok && contents == "write" {
			return "INFO" // Token needed intentionally
		}
	}

	// If workflow is trusted (tags, release), token is likely needed
	if ctx.IsTrusted && ctx.Intent.IsCritical() {
		return "LOW" // Likely intentional
	}

	// If workflow has untrusted input, keep HIGH
	if ctx.HasUntrustedInput {
		return "HIGH"
	}

	// Otherwise MEDIUM
	return "MEDIUM"
}

// adjustInjection adjusts severity for injection findings
func (ca *ContextAnalyzer) adjustInjection(baseSeverity string, ctx *WorkflowContext) string {
	// If workflow has untrusted input, keep CRITICAL
	if ctx.HasUntrustedInput {
		return "CRITICAL"
	}

	// If workflow is trusted, downgrade slightly
	if ctx.IsTrusted {
		return "HIGH"
	}

	// Keep base severity
	return baseSeverity
}

// ShouldSuppress determines if a finding should be suppressed
func (ca *ContextAnalyzer) ShouldSuppress(ruleID string, ctx *WorkflowContext) bool {
	switch ruleID {
	case "BROAD_PERMISSIONS":
		// Suppress for read-only workflows with no permission needs
		return ctx.Intent.IsReadOnly() && ctx.PermissionNeeds.IsEmpty()

	case "ARTIPACKED_VULNERABILITY":
		// Suppress for trusted workflows that don't handle untrusted input.
		// The token exposure via persist-credentials is only exploitable if an
		// attacker can read .git/config from an uploaded artifact or step output.
		return ctx.IsTrusted && !ctx.HasUntrustedInput

	default:
		return false
	}
}

// GetRiskScore calculates a numeric risk score (0-100) for a workflow
func (ca *ContextAnalyzer) GetRiskScore(ctx *WorkflowContext) int {
	score := 0

	// Intent risk
	switch ctx.Intent {
	case IntentRelease:
		score += 40
	case IntentDeploy:
		score += 35
	case IntentReadWrite:
		score += 20
	case IntentReadOnly:
		score += 5
	}

	// Trigger risk
	switch ctx.TriggerRisk {
	case RiskCritical:
		score += 40
	case RiskHigh:
		score += 25
	case RiskMedium:
		score += 15
	case RiskLow:
		score += 5
	}

	// Untrusted input adds risk
	if ctx.HasUntrustedInput {
		score += 20
	}

	// Permission needs add risk
	if !ctx.PermissionNeeds.IsEmpty() {
		score += 10
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// GetRecommendations provides context-aware recommendations
func (ca *ContextAnalyzer) GetRecommendations(ctx *WorkflowContext) []string {
	recommendations := []string{}

	// Intent-based recommendations
	if ctx.Intent.IsCritical() {
		recommendations = append(recommendations, "Use commit SHAs for all actions in critical workflows")
		recommendations = append(recommendations, "Declare explicit permissions with minimal scope")
	}

	// Trigger-based recommendations
	if ctx.HasUntrustedInput {
		recommendations = append(recommendations, "Use persist-credentials: false for checkout actions")
		recommendations = append(recommendations, "Validate and sanitize all inputs before use")
		recommendations = append(recommendations, "Avoid using secrets in workflows with untrusted input")
	}

	// Permission-based recommendations
	if !ctx.PermissionNeeds.IsEmpty() && len(ctx.GrantedPerms) == 0 {
		recommendations = append(recommendations, "Declare explicit permissions instead of using defaults")
	}

	return recommendations
}
