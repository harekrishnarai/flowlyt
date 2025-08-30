package report

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/harekrishnarai/flowlyt/pkg/osv"
)

// IntelligenceReport represents a scan result enhanced with vulnerability intelligence
type IntelligenceReport struct {
	ScanResult
	VulnerabilityIntelligence VulnerabilityIntelligence `json:"vulnerability_intelligence"`
	EnhancedFindings         []osv.EnhancedFinding      `json:"enhanced_findings"`
	IntelligenceSummary      IntelligenceSummary        `json:"intelligence_summary"`
}

// VulnerabilityIntelligence provides metadata about vulnerability correlation
type VulnerabilityIntelligence struct {
	Enabled           bool      `json:"enabled"`
	QueryTime         time.Time `json:"query_time"`
	QueriesPerformed  int       `json:"queries_performed"`
	VulnerabilitiesFound int    `json:"vulnerabilities_found"`
	HighRiskFindings  int       `json:"high_risk_findings"`
	CVEsFound         []string  `json:"cves_found"`
	DataSource        string    `json:"data_source"`
}

// IntelligenceSummary provides intelligence-enhanced summary statistics
type IntelligenceSummary struct {
	ResultSummary
	IntelligenceLevels map[string]int `json:"intelligence_levels"`
	RiskScoreDistribution map[string]int `json:"risk_score_distribution"`
	VulnerabilityCategories map[string]int `json:"vulnerability_categories"`
	RecentVulnerabilities int           `json:"recent_vulnerabilities"`
	KnownExploits        int            `json:"known_exploits"`
}

// IntelligenceGenerator creates intelligence-enhanced reports
type IntelligenceGenerator struct {
	*Generator
	osvClient    *osv.Client
	enableIntel  bool
	timeout      time.Duration
}

// NewIntelligenceGenerator creates a new intelligence-enhanced report generator
func NewIntelligenceGenerator(result ScanResult, format string, verbose bool, filePath string, enableIntel bool) *IntelligenceGenerator {
	return &IntelligenceGenerator{
		Generator:   NewGenerator(result, format, verbose, filePath),
		osvClient:   osv.NewClient(),
		enableIntel: enableIntel,
		timeout:     30 * time.Second,
	}
}

// GenerateWithIntelligence creates a report enhanced with vulnerability intelligence
func (ig *IntelligenceGenerator) GenerateWithIntelligence() error {
	if !ig.enableIntel {
		// Fall back to standard generation
		return ig.Generator.Generate()
	}

	// Enhance findings with vulnerability intelligence
	ctx, cancel := context.WithTimeout(context.Background(), ig.timeout)
	defer cancel()

	startTime := time.Now()
	enhancedFindings, err := ig.osvClient.EnhanceFindings(ctx, ig.Result.Findings)
	if err != nil {
		// On error, fall back to standard report but log the issue
		fmt.Fprintf(os.Stderr, "Warning: Failed to enhance findings with vulnerability intelligence: %v\n", err)
		return ig.Generator.Generate()
	}

	// Create intelligence report
	intelReport := ig.createIntelligenceReport(enhancedFindings, startTime)

	// Generate enhanced output based on format
	switch strings.ToLower(ig.Format) {
	case "cli":
		return ig.generateIntelligenceCLIReport(intelReport)
	case "json":
		return ig.generateIntelligenceJSONReport(intelReport)
	case "markdown":
		return ig.generateIntelligenceMarkdownReport(intelReport)
	case "sarif":
		return ig.generateIntelligenceSARIFReport(intelReport)
	default:
		return fmt.Errorf("unsupported report format: %s", ig.Format)
	}
}

// createIntelligenceReport creates an intelligence-enhanced report structure
func (ig *IntelligenceGenerator) createIntelligenceReport(enhanced []osv.EnhancedFinding, startTime time.Time) IntelligenceReport {
	// Calculate intelligence statistics
	vulnIntel := VulnerabilityIntelligence{
		Enabled:     true,
		QueryTime:   startTime,
		DataSource:  "OSV.dev",
	}

	intelSummary := IntelligenceSummary{
		ResultSummary:           ig.Result.Summary,
		IntelligenceLevels:      make(map[string]int),
		RiskScoreDistribution:   make(map[string]int),
		VulnerabilityCategories: make(map[string]int),
	}

	var cveIDs []string
	for _, finding := range enhanced {
		vulnIntel.QueriesPerformed++
		
		if finding.VulnerabilityInfo != nil {
			vulnIntel.VulnerabilitiesFound++
			
			if finding.VulnerabilityInfo.CVEID != "" {
				cveIDs = append(cveIDs, finding.VulnerabilityInfo.CVEID)
			}

			// Check if it's a recent vulnerability (last 6 months)
			if time.Since(finding.VulnerabilityInfo.Published) < 180*24*time.Hour {
				intelSummary.RecentVulnerabilities++
			}

			// Categorize by ecosystem
			if finding.VulnerabilityInfo.Ecosystem != "" {
				intelSummary.VulnerabilityCategories[finding.VulnerabilityInfo.Ecosystem]++
			}
		}

		// Track intelligence levels
		intelSummary.IntelligenceLevels[finding.IntelligenceLevel]++

		// Track risk score distribution
		scoreRange := ig.getRiskScoreRange(finding.RiskScore)
		intelSummary.RiskScoreDistribution[scoreRange]++

		// Count high-risk findings
		if finding.RiskScore >= 70 {
			vulnIntel.HighRiskFindings++
		}
	}

	vulnIntel.CVEsFound = cveIDs

	return IntelligenceReport{
		ScanResult:                ig.Result,
		VulnerabilityIntelligence: vulnIntel,
		EnhancedFindings:         enhanced,
		IntelligenceSummary:      intelSummary,
	}
}

// getRiskScoreRange categorizes risk scores into ranges
func (ig *IntelligenceGenerator) getRiskScoreRange(score int) string {
	switch {
	case score >= 80:
		return "Critical (80-100)"
	case score >= 60:
		return "High (60-79)"
	case score >= 40:
		return "Medium (40-59)"
	case score >= 20:
		return "Low (20-39)"
	default:
		return "Minimal (0-19)"
	}
}

// generateIntelligenceCLIReport generates an enhanced CLI report
func (ig *IntelligenceGenerator) generateIntelligenceCLIReport(report IntelligenceReport) error {
	// First generate the standard CLI report
	if err := ig.Generator.generateCLIReport(); err != nil {
		return err
	}

	// Add intelligence section
	fmt.Println()
	fmt.Println("🧠 VULNERABILITY INTELLIGENCE")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	intel := report.VulnerabilityIntelligence
	fmt.Printf("Data Source:          %s\n", intel.DataSource)
	fmt.Printf("Queries Performed:    %d\n", intel.QueriesPerformed)
	fmt.Printf("Vulnerabilities Found: %d\n", intel.VulnerabilitiesFound)
	fmt.Printf("High-Risk Findings:   %d\n", intel.HighRiskFindings)

	if len(intel.CVEsFound) > 0 {
		fmt.Printf("CVEs Identified:      %s\n", strings.Join(intel.CVEsFound, ", "))
	}

	// Intelligence levels summary
	if len(report.IntelligenceSummary.IntelligenceLevels) > 0 {
		fmt.Println("\nIntelligence Levels:")
		for level, count := range report.IntelligenceSummary.IntelligenceLevels {
			fmt.Printf("  %s: %d\n", level, count)
		}
	}

	// Risk score distribution
	if len(report.IntelligenceSummary.RiskScoreDistribution) > 0 {
		fmt.Println("\nRisk Score Distribution:")
		for range_, count := range report.IntelligenceSummary.RiskScoreDistribution {
			fmt.Printf("  %s: %d\n", range_, count)
		}
	}

	fmt.Println()
	return nil
}

// generateIntelligenceJSONReport generates an enhanced JSON report
func (ig *IntelligenceGenerator) generateIntelligenceJSONReport(report IntelligenceReport) error {
	data, err := MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal intelligence JSON: %w", err)
	}

	if ig.FilePath != "" {
		err = os.WriteFile(ig.FilePath, data, 0644)
		if err != nil {
			return fmt.Errorf("failed to write intelligence JSON report to file: %w", err)
		}
		fmt.Printf("Intelligence-enhanced JSON report written to %s\n", ig.FilePath)
	} else {
		fmt.Println(string(data))
	}

	return nil
}

// generateIntelligenceMarkdownReport generates an enhanced Markdown report
func (ig *IntelligenceGenerator) generateIntelligenceMarkdownReport(report IntelligenceReport) error {
	// Generate standard markdown first
	if err := ig.Generator.generateMarkdownReport(); err != nil {
		return err
	}

	// Add intelligence section to the markdown
	var markdownBuilder strings.Builder
	
	markdownBuilder.WriteString("\n## 🧠 Vulnerability Intelligence\n\n")
	intel := report.VulnerabilityIntelligence
	
	markdownBuilder.WriteString(fmt.Sprintf("- **Data Source:** %s\n", intel.DataSource))
	markdownBuilder.WriteString(fmt.Sprintf("- **Queries Performed:** %d\n", intel.QueriesPerformed))
	markdownBuilder.WriteString(fmt.Sprintf("- **Vulnerabilities Found:** %d\n", intel.VulnerabilitiesFound))
	markdownBuilder.WriteString(fmt.Sprintf("- **High-Risk Findings:** %d\n", intel.HighRiskFindings))

	if len(intel.CVEsFound) > 0 {
		markdownBuilder.WriteString(fmt.Sprintf("- **CVEs Identified:** %s\n", strings.Join(intel.CVEsFound, ", ")))
	}

	// Intelligence levels
	if len(report.IntelligenceSummary.IntelligenceLevels) > 0 {
		markdownBuilder.WriteString("\n### Intelligence Levels\n\n")
		markdownBuilder.WriteString("| Level | Count |\n")
		markdownBuilder.WriteString("|-------|-------|\n")
		for level, count := range report.IntelligenceSummary.IntelligenceLevels {
			markdownBuilder.WriteString(fmt.Sprintf("| %s | %d |\n", level, count))
		}
	}

	// Risk distribution  
	if len(report.IntelligenceSummary.RiskScoreDistribution) > 0 {
		markdownBuilder.WriteString("\n### Risk Score Distribution\n\n")
		markdownBuilder.WriteString("| Risk Range | Count |\n")
		markdownBuilder.WriteString("|------------|-------|\n")
		for range_, count := range report.IntelligenceSummary.RiskScoreDistribution {
			markdownBuilder.WriteString(fmt.Sprintf("| %s | %d |\n", range_, count))
		}
	}

	// Append to existing file or create new
	content := markdownBuilder.String()
	if ig.FilePath != "" {
		// Append to existing file
		file, err := os.OpenFile(ig.FilePath, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open markdown file for append: %w", err)
		}
		defer file.Close()

		if _, err := file.WriteString(content); err != nil {
			return fmt.Errorf("failed to append intelligence section to markdown: %w", err)
		}
		fmt.Printf("Intelligence section appended to %s\n", ig.FilePath)
	} else {
		fmt.Print(content)
	}

	return nil
}

// generateIntelligenceSARIFReport generates an enhanced SARIF report
func (ig *IntelligenceGenerator) generateIntelligenceSARIFReport(report IntelligenceReport) error {
	// For SARIF, we can add vulnerability information as properties
	// This will require modifying the SARIF generation to include CVE info

	// For now, generate standard SARIF and add intelligence as properties
	return ig.Generator.generateSARIFReport()
}

// MarshalIndent is a placeholder for json.MarshalIndent to avoid import conflicts
func MarshalIndent(v interface{}, prefix, indent string) ([]byte, error) {
	// Use json.MarshalIndent for proper implementation
	return json.MarshalIndent(v, prefix, indent)
}
