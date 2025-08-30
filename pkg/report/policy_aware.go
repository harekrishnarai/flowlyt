package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/harekrishnarai/flowlyt/pkg/config"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

// PolicyAwareReportGenerator generates reports with policy evaluation
type PolicyAwareReportGenerator struct {
	config       *config.Config
	policyEngine *config.PolicyEngine
}

// NewPolicyAwareReportGenerator creates a new policy-aware report generator
func NewPolicyAwareReportGenerator(cfg *config.Config) *PolicyAwareReportGenerator {
	return &PolicyAwareReportGenerator{
		config:       cfg,
		policyEngine: config.NewPolicyEngine(cfg),
	}
}

// PolicyEnhancedFinding extends Finding with policy information
type PolicyEnhancedFinding struct {
	rules.Finding
	PolicyViolations []config.PolicyViolation `json:"policy_violations,omitempty"`
	PolicyExceptions []config.PolicyException `json:"policy_exceptions,omitempty"`
	ComplianceInfo   *ComplianceInfo          `json:"compliance_info,omitempty"`
	RiskScore        int                      `json:"risk_score"`
	EnforcementLevel string                   `json:"enforcement_level,omitempty"`
}

// ComplianceInfo provides compliance framework information
type ComplianceInfo struct {
	Frameworks   []string          `json:"frameworks"`
	Controls     []string          `json:"controls"`
	Requirements []string          `json:"requirements"`
	Violations   map[string]string `json:"violations"`
}

// PolicyAwareReport extends standard reports with policy information
type PolicyAwareReport struct {
	Standard         interface{}             `json:"standard_report"`
	PolicyEvaluation PolicyEvaluationSummary `json:"policy_evaluation"`
	ComplianceReport config.ComplianceReport `json:"compliance_report"`
	EnhancedFindings []PolicyEnhancedFinding `json:"enhanced_findings"`
	Recommendations  []PolicyRecommendation  `json:"recommendations"`
	GeneratedAt      time.Time               `json:"generated_at"`
}

// PolicyEvaluationSummary summarizes policy evaluation results
type PolicyEvaluationSummary struct {
	TotalPolicies      int                    `json:"total_policies"`
	PoliciesEvaluated  int                    `json:"policies_evaluated"`
	PolicyViolations   int                    `json:"policy_violations"`
	BlockingViolations int                    `json:"blocking_violations"`
	ErrorViolations    int                    `json:"error_violations"`
	WarningViolations  int                    `json:"warning_violations"`
	ExceptionsApplied  int                    `json:"exceptions_applied"`
	ComplianceStatus   map[string]bool        `json:"compliance_status"`
	PolicyBreakdown    map[string]PolicyStats `json:"policy_breakdown"`
}

// PolicyStats provides statistics for individual policies
type PolicyStats struct {
	PolicyID    string `json:"policy_id"`
	PolicyName  string `json:"policy_name"`
	Violations  int    `json:"violations"`
	Exceptions  int    `json:"exceptions"`
	Compliant   bool   `json:"compliant"`
	Enforcement string `json:"enforcement"`
}

// PolicyRecommendation provides actionable recommendations
type PolicyRecommendation struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Priority    string   `json:"priority"`
	Actions     []string `json:"actions"`
	Resources   []string `json:"resources"`
}

// GenerateReport generates a policy-aware report
func (parg *PolicyAwareReportGenerator) GenerateReport(findings []rules.Finding, context config.PolicyContext, outputFormat string) (*PolicyAwareReport, error) {
	// Enhance findings with policy information
	enhancedFindings := parg.enhanceFindings(findings, context)

	// Generate compliance report
	complianceReport := parg.policyEngine.GetComplianceReport(findings, context)

	// Generate policy evaluation summary
	policyEvaluation := parg.generatePolicyEvaluationSummary(enhancedFindings)

	// Generate recommendations
	recommendations := parg.generateRecommendations(enhancedFindings, complianceReport)

	// Generate base report using standard generator
	var standardReport interface{}
	switch outputFormat {
	case "cli":
		standardReport = "CLI Report Generated" // Placeholder
	case "json":
		standardReport = "JSON Report Generated" // Placeholder
	case "sarif":
		standardReport = "SARIF Report Generated" // Placeholder
	}

	return &PolicyAwareReport{
		Standard:         standardReport,
		PolicyEvaluation: policyEvaluation,
		ComplianceReport: complianceReport,
		EnhancedFindings: enhancedFindings,
		Recommendations:  recommendations,
		GeneratedAt:      time.Now(),
	}, nil
}

// enhanceFindings enhances findings with policy and compliance information
func (parg *PolicyAwareReportGenerator) enhanceFindings(findings []rules.Finding, context config.PolicyContext) []PolicyEnhancedFinding {
	var enhanced []PolicyEnhancedFinding

	for _, finding := range findings {
		// Evaluate policy for this finding
		evaluation := parg.policyEngine.EvaluatePolicy(finding, context)

		// Calculate risk score with policy impact
		riskScore := parg.calculateRiskScore(finding, evaluation)

		// Get compliance information
		complianceInfo := parg.getComplianceInfo(finding, evaluation)

		// Determine enforcement level
		enforcementLevel := parg.getEnforcementLevel(evaluation)

		enhanced = append(enhanced, PolicyEnhancedFinding{
			Finding:          finding,
			PolicyViolations: evaluation.Violations,
			PolicyExceptions: evaluation.Exceptions,
			ComplianceInfo:   complianceInfo,
			RiskScore:        riskScore,
			EnforcementLevel: enforcementLevel,
		})
	}

	return enhanced
}

// calculateRiskScore calculates risk score with policy impact
func (parg *PolicyAwareReportGenerator) calculateRiskScore(finding rules.Finding, evaluation config.PolicyEvaluation) int {
	baseScore := 50 // Base score

	// Adjust based on severity
	switch finding.Severity {
	case "CRITICAL":
		baseScore += 40
	case "HIGH":
		baseScore += 30
	case "MEDIUM":
		baseScore += 20
	case "LOW":
		baseScore += 10
	}

	// Adjust based on policy violations
	for _, violation := range evaluation.Violations {
		switch violation.Enforcement {
		case config.EnforcementBlock:
			baseScore += 20
		case config.EnforcementError:
			baseScore += 15
		case config.EnforcementWarn:
			baseScore += 5
		}
	}

	// Reduce score if exceptions apply
	if len(evaluation.Exceptions) > 0 {
		baseScore -= 10
	}

	// Ensure score is within bounds
	if baseScore > 100 {
		baseScore = 100
	}
	if baseScore < 0 {
		baseScore = 0
	}

	return baseScore
}

// getComplianceInfo gets compliance framework information for a finding
func (parg *PolicyAwareReportGenerator) getComplianceInfo(finding rules.Finding, evaluation config.PolicyEvaluation) *ComplianceInfo {
	frameworks := make(map[string]bool)
	controls := make(map[string]bool)
	requirements := make(map[string]bool)
	violations := make(map[string]string)

	for _, violation := range evaluation.Violations {
		// Extract compliance information from policy
		// This would be enhanced based on actual policy compliance mappings
		if violation.PolicyID != "" {
			frameworks[violation.PolicyID] = true
			violations[violation.PolicyID] = violation.RuleID
		}
	}

	if len(frameworks) == 0 {
		return nil
	}

	return &ComplianceInfo{
		Frameworks:   mapKeysToSlice(frameworks),
		Controls:     mapKeysToSlice(controls),
		Requirements: mapKeysToSlice(requirements),
		Violations:   violations,
	}
}

// getEnforcementLevel determines the highest enforcement level for a finding
func (parg *PolicyAwareReportGenerator) getEnforcementLevel(evaluation config.PolicyEvaluation) string {
	if len(evaluation.Violations) == 0 {
		return ""
	}

	// Find highest enforcement level
	highestLevel := config.EnforcementDisabled
	for _, violation := range evaluation.Violations {
		if violation.Enforcement > highestLevel {
			highestLevel = violation.Enforcement
		}
	}

	return string(highestLevel)
}

// generatePolicyEvaluationSummary generates a summary of policy evaluation
func (parg *PolicyAwareReportGenerator) generatePolicyEvaluationSummary(findings []PolicyEnhancedFinding) PolicyEvaluationSummary {
	summary := PolicyEvaluationSummary{
		ComplianceStatus: make(map[string]bool),
		PolicyBreakdown:  make(map[string]PolicyStats),
	}

	policyStats := make(map[string]*PolicyStats)

	for _, finding := range findings {
		for _, violation := range finding.PolicyViolations {
			summary.PolicyViolations++

			switch violation.Enforcement {
			case config.EnforcementBlock:
				summary.BlockingViolations++
			case config.EnforcementError:
				summary.ErrorViolations++
			case config.EnforcementWarn:
				summary.WarningViolations++
			}

			// Track policy statistics
			if _, exists := policyStats[violation.PolicyID]; !exists {
				policyStats[violation.PolicyID] = &PolicyStats{
					PolicyID:    violation.PolicyID,
					PolicyName:  violation.PolicyName,
					Enforcement: string(violation.Enforcement),
				}
			}
			policyStats[violation.PolicyID].Violations++
		}

		summary.ExceptionsApplied += len(finding.PolicyExceptions)
	}

	// Convert policy stats to breakdown
	for id, stats := range policyStats {
		stats.Compliant = stats.Violations == 0
		summary.PolicyBreakdown[id] = *stats
		summary.ComplianceStatus[stats.PolicyName] = stats.Compliant
	}

	summary.PoliciesEvaluated = len(policyStats)

	return summary
}

// generateRecommendations generates actionable recommendations
func (parg *PolicyAwareReportGenerator) generateRecommendations(findings []PolicyEnhancedFinding, compliance config.ComplianceReport) []PolicyRecommendation {
	var recommendations []PolicyRecommendation

	// High-priority recommendations for blocking violations
	blockingCount := 0
	for _, finding := range findings {
		if finding.EnforcementLevel == string(config.EnforcementBlock) {
			blockingCount++
		}
	}

	if blockingCount > 0 {
		recommendations = append(recommendations, PolicyRecommendation{
			ID:          "blocking-violations",
			Title:       "Resolve Blocking Policy Violations",
			Description: fmt.Sprintf("Found %d findings that violate blocking policies and must be resolved", blockingCount),
			Priority:    "CRITICAL",
			Actions: []string{
				"Review each blocking violation",
				"Apply appropriate fixes or request exceptions",
				"Re-run scan to verify compliance",
			},
			Resources: []string{
				"https://security.enterprise.com/policy-violations",
				"https://security.enterprise.com/exceptions",
			},
		})
	}

	// Compliance framework recommendations
	if !compliance.Compliant {
		recommendations = append(recommendations, PolicyRecommendation{
			ID:          "compliance-violations",
			Title:       "Address Compliance Framework Violations",
			Description: fmt.Sprintf("Found violations affecting compliance frameworks"),
			Priority:    "HIGH",
			Actions: []string{
				"Review compliance requirements",
				"Implement required security controls",
				"Document compliance status",
			},
			Resources: []string{
				"https://security.enterprise.com/compliance",
			},
		})
	}

	// Security best practices recommendations
	secretFindings := 0
	for _, finding := range findings {
		if finding.Category == "SECRET_EXPOSURE" {
			secretFindings++
		}
	}

	if secretFindings > 0 {
		recommendations = append(recommendations, PolicyRecommendation{
			ID:          "secret-management",
			Title:       "Improve Secret Management",
			Description: fmt.Sprintf("Found %d potential secret exposures", secretFindings),
			Priority:    "HIGH",
			Actions: []string{
				"Replace hardcoded secrets with GitHub secrets",
				"Implement secret scanning in CI/CD",
				"Review secret rotation policies",
			},
			Resources: []string{
				"https://docs.github.com/en/actions/security-guides/encrypted-secrets",
				"https://security.enterprise.com/secrets",
			},
		})
	}

	return recommendations
}

// PolicyAwareCLIReport generates enhanced CLI output with policy information
func (parg *PolicyAwareReportGenerator) PolicyAwareCLIReport(findings []rules.Finding, context config.PolicyContext) string {
	report, err := parg.GenerateReport(findings, context, "cli")
	if err != nil {
		return fmt.Sprintf("Error generating policy-aware report: %v", err)
	}

	var output strings.Builder

	// Standard CLI output first
	if report.Standard != nil {
		output.WriteString(fmt.Sprintf("%v\n", report.Standard))
	}

	// Add policy evaluation section
	output.WriteString("\n🏛️ POLICY EVALUATION\n")
	output.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	eval := report.PolicyEvaluation
	output.WriteString(fmt.Sprintf("Policies Evaluated:   %d\n", eval.PoliciesEvaluated))
	output.WriteString(fmt.Sprintf("Policy Violations:    %d\n", eval.PolicyViolations))

	if eval.BlockingViolations > 0 {
		output.WriteString(fmt.Sprintf("❌ Blocking:          %d (MUST RESOLVE)\n", eval.BlockingViolations))
	}
	if eval.ErrorViolations > 0 {
		output.WriteString(fmt.Sprintf("⚠️  Errors:           %d\n", eval.ErrorViolations))
	}
	if eval.WarningViolations > 0 {
		output.WriteString(fmt.Sprintf("⚠️  Warnings:         %d\n", eval.WarningViolations))
	}
	if eval.ExceptionsApplied > 0 {
		output.WriteString(fmt.Sprintf("🔒 Exceptions:        %d\n", eval.ExceptionsApplied))
	}

	// Compliance status
	if len(eval.ComplianceStatus) > 0 {
		output.WriteString("\nCompliance Status:\n")
		for framework, compliant := range eval.ComplianceStatus {
			status := "✅"
			if !compliant {
				status = "❌"
			}
			output.WriteString(fmt.Sprintf("  %s %s\n", status, framework))
		}
	}

	// Recommendations
	if len(report.Recommendations) > 0 {
		output.WriteString("\n💡 RECOMMENDATIONS\n")
		output.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

		for i, rec := range report.Recommendations {
			priority := rec.Priority
			if priority == "CRITICAL" {
				priority = "🔥 CRITICAL"
			} else if priority == "HIGH" {
				priority = "⚠️  HIGH"
			}

			output.WriteString(fmt.Sprintf("[%d] %s (%s)\n", i+1, rec.Title, priority))
			output.WriteString(fmt.Sprintf("    %s\n", rec.Description))
			if len(rec.Actions) > 0 {
				output.WriteString("    Actions:\n")
				for _, action := range rec.Actions {
					output.WriteString(fmt.Sprintf("    • %s\n", action))
				}
			}
			output.WriteString("\n")
		}
	}

	return output.String()
}

// PolicyAwareJSONReport generates enhanced JSON output with policy information
func (parg *PolicyAwareReportGenerator) PolicyAwareJSONReport(findings []rules.Finding, context config.PolicyContext) (string, error) {
	report, err := parg.GenerateReport(findings, context, "json")
	if err != nil {
		return "", err
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal policy-aware JSON report: %w", err)
	}

	return string(data), nil
}

// Helper functions
func mapKeysToSlice(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
