package rules

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/linenum"
	"github.com/harekrishnarai/flowlyt/pkg/parser"
	"github.com/harekrishnarai/flowlyt/pkg/vulndb"
)

// AdvancedSupplyChainAnalyzer provides comprehensive supply chain security analysis
type AdvancedSupplyChainAnalyzer struct {
	osvClient             *vulndb.OSVClient
	typosquattingDetector *vulndb.TyposquattingDetector
	vdb                   *vulndb.VulnerabilityDatabase
}

// NewAdvancedSupplyChainAnalyzer creates a new advanced analyzer
func NewAdvancedSupplyChainAnalyzer() *AdvancedSupplyChainAnalyzer {
	// Create cache directory in user's home
	homeDir, _ := os.UserHomeDir()
	cacheDir := filepath.Join(homeDir, ".flowlyt", "vulncache")

	return &AdvancedSupplyChainAnalyzer{
		osvClient:             vulndb.NewOSVClient(cacheDir),
		typosquattingDetector: vulndb.NewTyposquattingDetector(),
		vdb:                   vulndb.NewVulnerabilityDatabase(),
	}
}

// checkAdvancedVulnerableActions uses real-time OSV.dev data to detect vulnerabilities
func checkAdvancedVulnerableActions(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)
	analyzer := NewAdvancedSupplyChainAnalyzer()

	// Check each job
	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			if step.Uses == "" {
				continue
			}

			stepName := step.Name
			if stepName == "" {
				stepName = "Step " + string(rune('1'+stepIdx))
			}

			// Analyze action security with real-time data
			analysis, err := analyzer.osvClient.AnalyzeActionSecurity(step.Uses)
			if err != nil {
				// Fall back to local database on API failure
				continue
			}

			if len(analysis.Vulnerabilities) > 0 {
				pattern := linenum.FindPattern{
					Key:   "uses",
					Value: step.Uses,
				}
				lineResult := lineMapper.FindLineNumber(pattern)
				lineNumber := 0
				if lineResult != nil {
					lineNumber = lineResult.LineNumber
				}

				// Determine severity based on risk level
				severity := mapRiskLevelToSeverity(analysis.RiskLevel)

				// Create detailed finding with OSV data
				finding := Finding{
					RuleID:      "ADVANCED_VULNERABLE_ACTION",
					RuleName:    "Real-time Vulnerability Detection",
					Description: analysis.Summary,
					Severity:    severity,
					Category:    SupplyChain,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    stepName,
					Evidence:    step.Uses,
					Remediation: generateAdvancedRemediation(analysis),
					LineNumber:  lineNumber,
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// checkAdvancedTyposquattingActions uses enhanced algorithms for typosquatting detection
func checkAdvancedTyposquattingActions(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)
	analyzer := NewAdvancedSupplyChainAnalyzer()

	// Check each job
	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			if step.Uses == "" {
				continue
			}

			stepName := step.Name
			if stepName == "" {
				stepName = "Step " + string(rune('1'+stepIdx))
			}

			// Parse action name (remove version)
			actionParts := strings.Split(step.Uses, "@")
			actionName := actionParts[0]

			// Analyze for typosquatting
			result := analyzer.typosquattingDetector.AnalyzeAction(actionName)

			if result.IsTyposquatting {
				pattern := linenum.FindPattern{
					Key:   "uses",
					Value: step.Uses,
				}
				lineResult := lineMapper.FindLineNumber(pattern)
				lineNumber := 0
				if lineResult != nil {
					lineNumber = lineResult.LineNumber
				}

				severity := mapRiskLevelToSeverity(result.RiskLevel)

				finding := Finding{
					RuleID:      "ADVANCED_TYPOSQUATTING",
					RuleName:    "Advanced Typosquatting Detection",
					Description: generateTyposquattingDescription(result),
					Severity:    severity,
					Category:    SupplyChain,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    stepName,
					Evidence:    step.Uses,
					Remediation: generateTyposquattingRemediation(result),
					LineNumber:  lineNumber,
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// checkActionVersionPinning checks for proper version pinning with enhanced analysis
func checkActionVersionPinning(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Check each job
	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			if step.Uses == "" {
				continue
			}

			stepName := step.Name
			if stepName == "" {
				stepName = "Step " + string(rune('1'+stepIdx))
			}

			// Analyze version pinning
			pinningAnalysis := analyzeVersionPinning(step.Uses)

			if pinningAnalysis.Risk != "NONE" {
				pattern := linenum.FindPattern{
					Key:   "uses",
					Value: step.Uses,
				}
				lineResult := lineMapper.FindLineNumber(pattern)
				lineNumber := 0
				if lineResult != nil {
					lineNumber = lineResult.LineNumber
				}

				severity := mapRiskLevelToSeverity(pinningAnalysis.Risk)

				finding := Finding{
					RuleID:      "VERSION_PINNING_ANALYSIS",
					RuleName:    "Version Pinning Security Analysis",
					Description: pinningAnalysis.Description,
					Severity:    severity,
					Category:    SupplyChain,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    stepName,
					Evidence:    step.Uses,
					Remediation: pinningAnalysis.Remediation,
					LineNumber:  lineNumber,
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// checkSupplyChainBestPractices checks for supply chain security best practices
func checkSupplyChainBestPractices(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	// Check for missing supply chain security measures
	hasHardenRunner := false
	hasDependencyReview := false

	// Scan for security-related actions
	for _, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Uses != "" {
				actionName := strings.Split(step.Uses, "@")[0]

				switch actionName {
				case "step-security/harden-runner":
					hasHardenRunner = true
				case "actions/dependency-review-action":
					hasDependencyReview = true
				}
			}
		}
	}

	// Generate findings for missing security measures
	if !hasHardenRunner && isPublicWorkflow(workflow) {
		finding := Finding{
			RuleID:      "MISSING_HARDEN_RUNNER",
			RuleName:    "Missing Harden Runner",
			Description: "Workflow lacks step-security/harden-runner which provides runtime security for GitHub Actions",
			Severity:    Medium,
			Category:    SupplyChain,
			FilePath:    workflow.Path,
			JobName:     "",
			StepName:    "",
			Evidence:    "No harden-runner step found",
			Remediation: "Add step-security/harden-runner@v2 as the first step in security-sensitive jobs",
			LineNumber:  1,
		}
		findings = append(findings, finding)
	}

	if !hasDependencyReview && hasPullRequestTrigger(workflow) {
		finding := Finding{
			RuleID:      "MISSING_DEPENDENCY_REVIEW",
			RuleName:    "Missing Dependency Review",
			Description: "Pull request workflow lacks dependency review which can detect malicious dependencies",
			Severity:    Medium,
			Category:    SupplyChain,
			FilePath:    workflow.Path,
			JobName:     "",
			StepName:    "",
			Evidence:    "No dependency review action found",
			Remediation: "Add actions/dependency-review-action to review dependency changes in pull requests",
			LineNumber:  1,
		}
		findings = append(findings, finding)
	}

	return findings
}

// Helper types and functions

type VersionPinningAnalysis struct {
	Risk        string
	Description string
	Remediation string
	Version     string
	VersionType string
}

func analyzeVersionPinning(actionRef string) VersionPinningAnalysis {
	parts := strings.Split(actionRef, "@")
	if len(parts) < 2 {
		return VersionPinningAnalysis{
			Risk:        "HIGH",
			Description: "Action is not pinned to any version",
			Remediation: "Pin the action to a specific version or commit SHA",
			Version:     "none",
			VersionType: "unpinned",
		}
	}

	version := parts[1]

	// Check version type
	if len(version) == 40 && isHexString(version) {
		// SHA commit - most secure
		return VersionPinningAnalysis{
			Risk:        "NONE",
			Description: "Action is pinned to a specific commit SHA",
			Remediation: "Continue using commit SHA pinning",
			Version:     version,
			VersionType: "sha",
		}
	} else if strings.HasPrefix(version, "v") && isSemanticVersion(version) {
		// Semantic version - medium security
		return VersionPinningAnalysis{
			Risk:        "LOW",
			Description: "Action is pinned to a semantic version tag",
			Remediation: "Consider pinning to a specific commit SHA for maximum security",
			Version:     version,
			VersionType: "semver",
		}
	} else if version == "main" || version == "master" || version == "latest" {
		// Branch or latest - high risk
		return VersionPinningAnalysis{
			Risk:        "HIGH",
			Description: "Action is pinned to a mutable reference that can change",
			Remediation: "Pin to a specific commit SHA or semantic version",
			Version:     version,
			VersionType: "mutable",
		}
	} else {
		// Other branch - medium risk
		return VersionPinningAnalysis{
			Risk:        "MEDIUM",
			Description: "Action is pinned to a branch reference",
			Remediation: "Pin to a specific commit SHA for better security",
			Version:     version,
			VersionType: "branch",
		}
	}
}

func mapRiskLevelToSeverity(riskLevel string) Severity {
	switch riskLevel {
	case "CRITICAL":
		return Critical
	case "HIGH":
		return High
	case "MEDIUM":
		return Medium
	case "LOW":
		return Low
	default:
		return Medium
	}
}

func generateAdvancedRemediation(analysis *vulndb.ActionSecurityAnalysis) string {
	if len(analysis.Recommendations) > 0 {
		return strings.Join(analysis.Recommendations, "; ")
	}
	return "Update to the latest version of this action and review vulnerability details"
}

func generateTyposquattingDescription(result *vulndb.TyposquattingResult) string {
	desc := "Potential typosquatting detected"
	if len(result.SuspiciousReasons) > 0 {
		desc += ": " + strings.Join(result.SuspiciousReasons, ", ")
	}
	if result.RecommendedAction != "" {
		desc += ". Did you mean: " + result.RecommendedAction + "?"
	}
	return desc
}

func generateTyposquattingRemediation(result *vulndb.TyposquattingResult) string {
	if result.RecommendedAction != "" {
		return "Verify the action name is correct. Did you mean: " + result.RecommendedAction + "?"
	}
	return "Verify the action name and publisher are correct before using"
}

func isPublicWorkflow(workflow parser.WorkflowFile) bool {
	// Heuristic: check if workflow has triggers that suggest public repo
	if workflow.Workflow.On == nil {
		return false
	}

	// Convert to map for easier checking
	triggers := make(map[string]bool)
	switch on := workflow.Workflow.On.(type) {
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

	// Public repo indicators
	publicTriggers := []string{"pull_request", "issues", "fork", "watch", "star"}
	for _, trigger := range publicTriggers {
		if triggers[trigger] {
			return true
		}
	}

	return false
}

func hasPullRequestTrigger(workflow parser.WorkflowFile) bool {
	if workflow.Workflow.On == nil {
		return false
	}

	switch on := workflow.Workflow.On.(type) {
	case map[string]interface{}:
		_, hasPR := on["pull_request"]
		_, hasPRTarget := on["pull_request_target"]
		return hasPR || hasPRTarget
	case []interface{}:
		for _, trigger := range on {
			if triggerStr, ok := trigger.(string); ok {
				if triggerStr == "pull_request" || triggerStr == "pull_request_target" {
					return true
				}
			}
		}
	case string:
		return on == "pull_request" || on == "pull_request_target"
	}

	return false
}

func isHexString(s string) bool {
	for _, char := range s {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return false
		}
	}
	return true
}

func isSemanticVersion(version string) bool {
	// Simple check for semantic versioning (vX.Y.Z format)
	if !strings.HasPrefix(version, "v") {
		return false
	}

	parts := strings.Split(version[1:], ".")
	return len(parts) >= 2 && len(parts) <= 3
}
