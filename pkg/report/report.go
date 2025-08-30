package report

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
	"github.com/olekukonko/tablewriter"
)

// ScanResult represents the overall result of a security scan
type ScanResult struct {
	Repository     string          `json:"repository"`
	ScanTime       time.Time       `json:"scanTime"`
	Duration       time.Duration   `json:"duration"`
	WorkflowsCount int             `json:"workflowsCount"`
	RulesCount     int             `json:"rulesCount"`
	Findings       []rules.Finding `json:"findings"`
	Summary        ResultSummary   `json:"summary"`
}

// ResultSummary provides a summary of the scan findings by severity
type ResultSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// Generator creates a formatted report from scan results
type Generator struct {
	Result   ScanResult
	Format   string
	Verbose  bool
	FilePath string
}

// NewGenerator creates a new report generator
func NewGenerator(result ScanResult, format string, verbose bool, filePath string) *Generator {
	return &Generator{
		Result:   result,
		Format:   format,
		Verbose:  verbose,
		FilePath: filePath,
	}
}

// Generate creates and outputs the report in the specified format
func (g *Generator) Generate() error {
	switch strings.ToLower(g.Format) {
	case "cli":
		return g.generateCLIReport()
	case "json":
		return g.generateJSONReport()
	case "markdown":
		return g.generateMarkdownReport()
	case "sarif":
		return g.generateSARIFReport()
	default:
		return fmt.Errorf("unsupported report format: %s", g.Format)
	}
}

// generateCLIReport creates a modern, visually appealing CLI report
func (g *Generator) generateCLIReport() error {
	// Define color styles
	titleStyle := color.New(color.FgHiCyan, color.Bold)
	subtitleStyle := color.New(color.FgCyan, color.Bold)
	infoStyle := color.New(color.FgBlue)
	successStyle := color.New(color.FgGreen, color.Bold)
	criticalStyle := color.New(color.FgHiRed, color.Bold)
	highStyle := color.New(color.FgHiYellow, color.Bold)
	mediumStyle := color.New(color.FgYellow)
	lowStyle := color.New(color.FgBlue)
	infoLevelStyle := color.New(color.FgHiBlue)

	// Header with logo and version
	fmt.Println()
	titleStyle.Println("╔═══════════════════════════════════════════╗")
	titleStyle.Println("║             FLOWLYT SCAN RESULTS          ║")
	titleStyle.Println("╚═══════════════════════════════════════════╝")

	// Print scan information
	fmt.Println()
	subtitleStyle.Println("► SCAN INFORMATION")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	infoStyle.Printf("%-20s ", "Repository:")
	fmt.Println(g.Result.Repository)
	infoStyle.Printf("%-20s ", "Scan Time:")
	fmt.Println(g.Result.ScanTime.Format(time.RFC1123))
	infoStyle.Printf("%-20s ", "Duration:")
	fmt.Println(g.Result.Duration.Round(time.Millisecond))
	infoStyle.Printf("%-20s ", "Workflows Analyzed:")
	fmt.Println(g.Result.WorkflowsCount)
	infoStyle.Printf("%-20s ", "Rules Applied:")
	fmt.Println(g.Result.RulesCount)

	// Summary section with table
	fmt.Println()
	subtitleStyle.Println("► SUMMARY")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Create table for summary
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Severity", "Count", "Indicator"})
	table.SetBorder(false)
	table.SetColumnAlignment([]int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT})
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeaderColor(
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
	)

	// Add data rows with colored cells
	criticalRow := []string{"CRITICAL", fmt.Sprintf("%d", g.Result.Summary.Critical)}
	highRow := []string{"HIGH", fmt.Sprintf("%d", g.Result.Summary.High)}
	mediumRow := []string{"MEDIUM", fmt.Sprintf("%d", g.Result.Summary.Medium)}
	lowRow := []string{"LOW", fmt.Sprintf("%d", g.Result.Summary.Low)}
	infoRow := []string{"INFO", fmt.Sprintf("%d", g.Result.Summary.Info)}
	totalRow := []string{"TOTAL", fmt.Sprintf("%d", g.Result.Summary.Total)}

	// Create bar indicators based on severity
	criticalBar := createSeverityBar(g.Result.Summary.Critical, g.Result.Summary.Total, "█", 20)
	highBar := createSeverityBar(g.Result.Summary.High, g.Result.Summary.Total, "█", 20)
	mediumBar := createSeverityBar(g.Result.Summary.Medium, g.Result.Summary.Total, "█", 20)
	lowBar := createSeverityBar(g.Result.Summary.Low, g.Result.Summary.Total, "█", 20)
	infoBar := createSeverityBar(g.Result.Summary.Info, g.Result.Summary.Total, "█", 20)

	criticalRow = append(criticalRow, criticalBar)
	highRow = append(highRow, highBar)
	mediumRow = append(mediumRow, mediumBar)
	lowRow = append(lowRow, lowBar)
	infoRow = append(infoRow, infoBar)
	totalRow = append(totalRow, "")

	table.Rich(criticalRow, []tablewriter.Colors{
		{tablewriter.Bold, tablewriter.FgHiRedColor},
		{tablewriter.Bold, tablewriter.FgHiRedColor},
		{tablewriter.FgHiRedColor},
	})
	table.Rich(highRow, []tablewriter.Colors{
		{tablewriter.Bold, tablewriter.FgHiYellowColor},
		{tablewriter.Bold, tablewriter.FgHiYellowColor},
		{tablewriter.FgHiYellowColor},
	})
	table.Rich(mediumRow, []tablewriter.Colors{
		{tablewriter.Bold, tablewriter.FgYellowColor},
		{tablewriter.Bold, tablewriter.FgYellowColor},
		{tablewriter.FgYellowColor},
	})
	table.Rich(lowRow, []tablewriter.Colors{
		{tablewriter.Bold, tablewriter.FgBlueColor},
		{tablewriter.Bold, tablewriter.FgBlueColor},
		{tablewriter.FgBlueColor},
	})
	table.Rich(infoRow, []tablewriter.Colors{
		{tablewriter.Bold, tablewriter.FgCyanColor},
		{tablewriter.Bold, tablewriter.FgCyanColor},
		{tablewriter.FgCyanColor},
	})
	table.Rich(totalRow, []tablewriter.Colors{
		{tablewriter.Bold},
		{tablewriter.Bold},
		{tablewriter.Normal},
	})

	table.Render()

	// Print findings
	if len(g.Result.Findings) > 0 {
		fmt.Println()
		subtitleStyle.Println("► FINDINGS")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

		// Group findings by severity
		findingsBySeverity := map[rules.Severity][]rules.Finding{
			rules.Critical: {},
			rules.High:     {},
			rules.Medium:   {},
			rules.Low:      {},
			rules.Info:     {},
		}

		for _, finding := range g.Result.Findings {
			findingsBySeverity[finding.Severity] = append(findingsBySeverity[finding.Severity], finding)
		}

		// Print findings in order of severity
		severities := []rules.Severity{rules.Critical, rules.High, rules.Medium, rules.Low, rules.Info}
		severityStyles := map[rules.Severity]*color.Color{
			rules.Critical: criticalStyle,
			rules.High:     highStyle,
			rules.Medium:   mediumStyle,
			rules.Low:      lowStyle,
			rules.Info:     infoLevelStyle,
		}
		severityIcons := map[rules.Severity]string{
			rules.Critical: "✗",
			rules.High:     "⚠",
			rules.Medium:   "⚠",
			rules.Low:      "ℹ",
			rules.Info:     "ℹ",
		}

		count := 0
		for _, severity := range severities {
			severityFindings := findingsBySeverity[severity]
			if len(severityFindings) == 0 {
				continue
			}

			fmt.Println()
			severityStyles[severity].Printf("■ %s SEVERITY FINDINGS\n", strings.ToUpper(string(severity)))
			fmt.Println("─────────────────────────────────────────────────")

			for i, finding := range severityFindings {
				count++
				fmt.Println()
				severityStyles[severity].Printf("%s [%d] %s (%s)\n", severityIcons[severity], count, finding.RuleName, finding.RuleID)

				// Format finding details in a visually appealing way
				if finding.GitHubURL != "" {
					infoStyle.Printf("  %-12s ", "GitHub URL:")
					fmt.Println(finding.GitHubURL)
				} else if finding.GitLabURL != "" {
					infoStyle.Printf("  %-12s ", "GitLab URL:")
					fmt.Println(finding.GitLabURL)
				} else {
					infoStyle.Printf("  %-12s ", "File:")
					fmt.Println(finding.FilePath)
				}

				if finding.LineNumber > 0 {
					infoStyle.Printf("  %-12s ", "Line:")
					fmt.Println(finding.LineNumber)
				}

				if finding.JobName != "" {
					infoStyle.Printf("  %-12s ", "Job:")
					fmt.Println(finding.JobName)
				}

				if finding.StepName != "" {
					infoStyle.Printf("  %-12s ", "Step:")
					fmt.Println(finding.StepName)
				}

				infoStyle.Printf("  %-12s ", "Description:")
				fmt.Println(finding.Description)

				if g.Verbose {
					fmt.Println()
					infoStyle.Println("  Evidence:")
					// Use masked evidence instead of raw evidence
					maskedEvidence := MaskSecrets(finding.Evidence)
					fmt.Printf("  %s\n", strings.ReplaceAll(maskedEvidence, "\n", "\n  "))

					fmt.Println()
					infoStyle.Printf("  %-12s ", "Remediation:")
					fmt.Println(finding.Remediation)
				}

				// Add a separator line between findings
				if i < len(severityFindings)-1 {
					fmt.Println("\n  ‧ ‧ ‧ ‧ ‧ ‧ ‧ ‧ ‧ ‧ ‧ ‧ ‧ ‧ ‧ ‧ ‧ ‧ ‧ ‧ ‧ ‧ ‧ ‧ ‧ ‧ ‧ ‧ ‧")
				}
			}
		}
	} else {
		fmt.Println()
		successStyle.Println("✅ NO SECURITY ISSUES FOUND!")
		fmt.Println("No security issues were detected in the analyzed workflows.")
	}

	// Footer
	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	return nil
}

// generateJSONReport creates a JSON report
func (g *Generator) generateJSONReport() error {
	data, err := json.MarshalIndent(g.Result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if g.FilePath != "" {
		err = os.WriteFile(g.FilePath, data, 0644)
		if err != nil {
			return fmt.Errorf("failed to write JSON report to file: %w", err)
		}
		fmt.Printf("JSON report written to %s\n", g.FilePath)
	} else {
		fmt.Println(string(data))
	}

	return nil
}

// generateMarkdownReport creates a Markdown report
func (g *Generator) generateMarkdownReport() error {
	var markdownBuilder strings.Builder

	// Title and metadata
	markdownBuilder.WriteString("# Flowlyt Security Scan Report\n\n")
	markdownBuilder.WriteString("## Scan Information\n\n")
	markdownBuilder.WriteString(fmt.Sprintf("- **Repository:** %s\n", g.Result.Repository))
	markdownBuilder.WriteString(fmt.Sprintf("- **Scan Time:** %s\n", g.Result.ScanTime.Format(time.RFC1123)))
	markdownBuilder.WriteString(fmt.Sprintf("- **Duration:** %s\n", g.Result.Duration.Round(time.Millisecond)))
	markdownBuilder.WriteString(fmt.Sprintf("- **Workflows Analyzed:** %d\n", g.Result.WorkflowsCount))
	markdownBuilder.WriteString(fmt.Sprintf("- **Rules Applied:** %d\n", g.Result.RulesCount))

	// Summary section
	markdownBuilder.WriteString("\n## Summary\n\n")
	markdownBuilder.WriteString("| Severity | Count |\n")
	markdownBuilder.WriteString("|----------|-------|\n")
	markdownBuilder.WriteString(fmt.Sprintf("| 🔴 Critical | %d |\n", g.Result.Summary.Critical))
	markdownBuilder.WriteString(fmt.Sprintf("| 🟠 High     | %d |\n", g.Result.Summary.High))
	markdownBuilder.WriteString(fmt.Sprintf("| 🟡 Medium   | %d |\n", g.Result.Summary.Medium))
	markdownBuilder.WriteString(fmt.Sprintf("| 🔵 Low      | %d |\n", g.Result.Summary.Low))
	markdownBuilder.WriteString(fmt.Sprintf("| ⚪ Info     | %d |\n", g.Result.Summary.Info))
	markdownBuilder.WriteString(fmt.Sprintf("| **Total**   | %d |\n", g.Result.Summary.Total))

	if len(g.Result.Findings) > 0 {
		markdownBuilder.WriteString("\n## Findings\n\n")

		// Group findings by severity
		findingsBySeverity := map[rules.Severity][]rules.Finding{
			rules.Critical: {},
			rules.High:     {},
			rules.Medium:   {},
			rules.Low:      {},
			rules.Info:     {},
		}

		for _, finding := range g.Result.Findings {
			findingsBySeverity[finding.Severity] = append(findingsBySeverity[finding.Severity], finding)
		}

		// Print findings in order of severity
		severities := []rules.Severity{rules.Critical, rules.High, rules.Medium, rules.Low, rules.Info}
		severityEmojis := map[rules.Severity]string{
			rules.Critical: "🔴",
			rules.High:     "🟠",
			rules.Medium:   "🟡",
			rules.Low:      "🔵",
			rules.Info:     "⚪",
		}

		for _, severity := range severities {
			severityFindings := findingsBySeverity[severity]
			if len(severityFindings) == 0 {
				continue
			}

			markdownBuilder.WriteString(fmt.Sprintf("\n### %s %s Severity Findings\n\n", severityEmojis[severity], severity))

			for i, finding := range severityFindings {
				markdownBuilder.WriteString(fmt.Sprintf("#### %d. %s (%s)\n\n", i+1, finding.RuleName, finding.RuleID))
				if finding.GitHubURL != "" {
					markdownBuilder.WriteString(fmt.Sprintf("- **GitHub URL:** [%s](%s)\n", finding.FilePath, finding.GitHubURL))
				} else if finding.GitLabURL != "" {
					markdownBuilder.WriteString(fmt.Sprintf("- **GitLab URL:** [%s](%s)\n", finding.FilePath, finding.GitLabURL))
				} else {
					markdownBuilder.WriteString(fmt.Sprintf("- **File:** `%s`\n", finding.FilePath))
				}
				if finding.JobName != "" {
					markdownBuilder.WriteString(fmt.Sprintf("- **Job:** `%s`\n", finding.JobName))
				}
				if finding.StepName != "" {
					markdownBuilder.WriteString(fmt.Sprintf("- **Step:** `%s`\n", finding.StepName))
				}
				markdownBuilder.WriteString(fmt.Sprintf("- **Description:** %s\n", finding.Description))

				// Include evidence and remediation if verbose
				if g.Verbose {
					markdownBuilder.WriteString(fmt.Sprintf("- **Evidence:**\n```\n%s\n```\n", finding.Evidence))
					markdownBuilder.WriteString(fmt.Sprintf("- **Remediation:** %s\n", finding.Remediation))
				}

				markdownBuilder.WriteString("\n")
			}
		}
	} else {
		markdownBuilder.WriteString("\n## ✅ No Security Issues Found\n\n")
		markdownBuilder.WriteString("No security issues were found in the analyzed workflows.\n")
	}

	// Add a footer
	markdownBuilder.WriteString("\n---\n")
	markdownBuilder.WriteString("Generated by Flowlyt v0.1.0 - GitHub Actions Security Analyzer\n")

	// Write to file or stdout
	if g.FilePath != "" {
		err := os.WriteFile(g.FilePath, []byte(markdownBuilder.String()), 0644)
		if err != nil {
			return fmt.Errorf("failed to write Markdown report to file: %w", err)
		}
		fmt.Printf("Markdown report written to %s\n", g.FilePath)
	} else {
		fmt.Println(markdownBuilder.String())
	}

	return nil
}

// createSeverityBar generates a visual bar representation for severity counts
func createSeverityBar(count, total int, char string, maxLength int) string {
	if total == 0 {
		return ""
	}

	ratio := float64(count) / float64(total)
	barLength := int(math.Round(ratio * float64(maxLength)))

	if count > 0 && barLength == 0 {
		barLength = 1 // Always show at least one character if there's a count
	}

	return strings.Repeat(char, barLength)
}

// MaskSecrets masks sensitive information in the evidence field of a finding
func MaskSecrets(evidence string) string {
	// If the evidence is short, return as is
	if len(evidence) < 12 {
		return evidence
	}

	// Otherwise, mask the middle part
	visible := 4 // Number of characters to show at the beginning and end
	return evidence[:visible] + strings.Repeat("*", len(evidence)-visible*2) + evidence[len(evidence)-visible:]
}

// CalculateSummary computes the summary statistics for scan findings
func CalculateSummary(findings []rules.Finding) ResultSummary {
	summary := ResultSummary{}

	for _, finding := range findings {
		switch finding.Severity {
		case rules.Critical:
			summary.Critical++
		case rules.High:
			summary.High++
		case rules.Medium:
			summary.Medium++
		case rules.Low:
			summary.Low++
		case rules.Info:
			summary.Info++
		}
	}

	summary.Total = summary.Critical + summary.High + summary.Medium + summary.Low + summary.Info
	return summary
}

// SortFindingsBySeverity sorts findings by severity (Critical, High, Medium, Low, Info)
func SortFindingsBySeverity(findings []rules.Finding) []rules.Finding {
	// Create a severity ranking
	severityRank := map[rules.Severity]int{
		rules.Critical: 0,
		rules.High:     1,
		rules.Medium:   2,
		rules.Low:      3,
		rules.Info:     4,
	}

	// Create a sorted copy
	sortedFindings := make([]rules.Finding, len(findings))
	copy(sortedFindings, findings)

	// Sort by severity
	sort.Slice(sortedFindings, func(i, j int) bool {
		return severityRank[sortedFindings[i].Severity] < severityRank[sortedFindings[j].Severity]
	})

	return sortedFindings
}
