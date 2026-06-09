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

package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/harekrishnarai/flowlyt/v2/pkg/constants"
	"github.com/harekrishnarai/flowlyt/v2/pkg/rules"
	"github.com/harekrishnarai/flowlyt/v2/pkg/terminal"
)

// ScanResult represents the overall result of a security scan
type ScanResult struct {
	Repository      string          `json:"repository"`
	ScanTime        time.Time       `json:"scanTime"`
	Duration        time.Duration   `json:"duration"`
	WorkflowsCount  int             `json:"workflowsCount"`
	RulesCount      int             `json:"rulesCount"`
	Findings        []rules.Finding `json:"findings"`
	Summary         ResultSummary   `json:"summary"`
	SuppressedCount int             `json:"suppressedCount"`
	GeneratedByAST  int             `json:"astGeneratedCount"`
}

// FindingReport augments a finding with code context for report outputs.
type FindingReport struct {
	rules.Finding
	CodeContext *CodeContext `json:"codeContext,omitempty"`
}

// ScanResultReport represents the JSON report with enriched findings.
type ScanResultReport struct {
	Repository      string          `json:"repository"`
	ScanTime        time.Time       `json:"scanTime"`
	Duration        time.Duration   `json:"duration"`
	DurationNs      int64           `json:"durationNs"`
	DurationMs      int64           `json:"durationMs"`
	WorkflowsCount  int             `json:"workflowsCount"`
	RulesCount      int             `json:"rulesCount"`
	Findings        []FindingReport `json:"findings"`
	Summary         ResultSummary   `json:"summary"`
	SuppressedCount int             `json:"suppressedCount"`
	GeneratedByAST  int             `json:"astGeneratedCount"`
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
	Result              ScanResult
	Format              string
	Verbose             bool
	FilePath            string
	EnhancedFormatting  bool   // Use enhanced formatting for CLI output
	CLIStyle            string // CLI style: "standard", "detailed", "compact", "boxed"
	term                *terminal.Terminal // Intelligent terminal for xterm output
}

// NewGenerator creates a new report generator
func NewGenerator(result ScanResult, format string, verbose bool, filePath string) *Generator {
	return &Generator{
		Result:              result,
		Format:              format,
		Verbose:             verbose,
		FilePath:            filePath,
		EnhancedFormatting:  true, // Enable enhanced formatting by default
		CLIStyle:            "detailed", // Use detailed style by default
		term:                terminal.Default(), // Initialize intelligent terminal
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

// generateCLIReport prints a minimal, scanner-style report (in the spirit of
// semgrep / scorecard): a short header, findings grouped by file with the
// offending line and a fix hint, and a one-line summary.
func (g *Generator) generateCLIReport() error {
	dim := color.New(color.Faint)

	// Header.
	fmt.Println()
	title := color.New(color.Bold, color.FgHiCyan).Sprint("● Flowlyt")
	if g.Result.Repository != "" {
		fmt.Printf("%s  %s\n", title, dim.Sprint(g.Result.Repository))
	} else {
		fmt.Println(title)
	}
	meta := fmt.Sprintf("%d workflows · %d rules · scanned in %s",
		g.Result.WorkflowsCount, g.Result.RulesCount, g.Result.Duration.Round(time.Millisecond))
	if g.Result.SuppressedCount > 0 {
		meta += fmt.Sprintf(" · %d suppressed (reachability)", g.Result.SuppressedCount)
	}
	dim.Println(meta)

	if len(g.Result.Findings) == 0 {
		fmt.Println()
		color.New(color.FgGreen, color.Bold).Println("  ✓ No security issues found")
		fmt.Println()
		return nil
	}

	// Group findings by file (sorted). Findings keep their incoming severity order.
	order := []string{}
	byFile := map[string][]rules.Finding{}
	for _, f := range g.Result.Findings {
		path := cleanFilePath(f.FilePath)
		if path == "" {
			path = "(unknown file)"
		}
		if _, ok := byFile[path]; !ok {
			order = append(order, path)
		}
		byFile[path] = append(byFile[path], f)
	}
	sort.Strings(order)

	fileStyle := color.New(color.Bold, color.FgCyan)
	for _, path := range order {
		findings := byFile[path]
		fmt.Println()
		fmt.Printf("%s  %s\n", fileStyle.Sprint(path), dim.Sprintf("%d finding(s)", len(findings)))
		fmt.Println()
		for _, f := range findings {
			g.printFindingCLI(f)
		}
	}

	g.printSummaryCLI()
	return nil
}

// cliWidth returns the wrap width for CLI text, clamped to a readable range.
func (g *Generator) cliWidth() int {
	w := 0
	if g.term != nil {
		w = g.term.Width()
	}
	if w <= 0 {
		w = 100 // piped / non-interactive
	}
	if w > 120 {
		w = 120
	}
	if w < 60 {
		w = 60
	}
	return w
}

// body is the left padding for a finding's detail lines (description, snippet,
// link, fix), indented under the finding header.
const body = "      "

// printFindingCLI renders one finding semgrep-style: a severity-marked header,
// a wrapped description, a pinpointed code snippet, the link, and a fix hint.
func (g *Generator) printFindingCLI(f rules.Finding) {
	width := g.cliWidth()
	textWidth := width - len(body)
	sevC := severityColor(f.Severity)

	// Header: "  ❯ CRITICAL  RULE_ID            line 38"
	header := fmt.Sprintf("  %s %s  %s",
		sevC.Sprint("❯"),
		sevC.Sprintf("%-8s", strings.ToUpper(string(f.Severity))),
		color.New(color.Bold).Sprint(f.RuleID))
	if f.LineNumber > 0 {
		header += "  " + color.New(color.Faint).Sprintf("line %d", f.LineNumber)
	}
	fmt.Println(header)

	// Description (wrapped).
	for _, line := range wrapLines(f.Description, textWidth) {
		fmt.Println(body + line)
	}

	// Pinpointed code snippet with a line-number gutter.
	g.printSnippet(f)

	// Link to the exact location.
	if u := findingURL(f); u != "" {
		color.New(color.Faint).Printf("%s%s %s\n", body, color.New(color.Faint).Sprint("↳"), u)
	}

	// Compact AI verdict.
	if f.AIVerified {
		switch {
		case f.AIError != "":
			color.New(color.FgMagenta).Println(body + "AI: analysis failed")
		case f.AILikelyFalsePositive != nil && *f.AILikelyFalsePositive:
			color.New(color.FgYellow).Printf("%sAI: likely false positive (%.0f%%)\n", body, f.AIConfidence*100)
		case f.AILikelyFalsePositive != nil:
			color.New(color.FgRed).Printf("%sAI: likely true positive (%.0f%%)\n", body, f.AIConfidence*100)
		}
		if f.AIReasoning != "" && g.Verbose {
			for _, line := range wrapLines("AI reasoning: "+f.AIReasoning, textWidth) {
				fmt.Println(body + line)
			}
		}
	} else if f.AISkipped && g.Verbose {
		color.New(color.Faint).Printf("%sAI: skipped (%s)\n", body, f.AISkipReason)
	}

	if g.Verbose && strings.TrimSpace(f.Evidence) != "" {
		for _, line := range wrapLines("evidence: "+MaskSecrets(f.Evidence), textWidth) {
			fmt.Println(body + line)
		}
	}

	// Fix (wrapped, cyan, with a hanging indent aligned under the text).
	if f.Remediation != "" {
		c := color.New(color.FgCyan)
		label := color.New(color.FgCyan, color.Bold).Sprint("fix:")
		for i, line := range wrapLines(f.Remediation, textWidth-5) {
			if i == 0 {
				fmt.Printf("%s%s %s\n", body, label, c.Sprint(line))
			} else {
				c.Printf("%s     %s\n", body, line) // align under text after "fix: "
			}
		}
	}

	fmt.Println() // separate findings
}

// printSnippet renders the source lines around a finding with a line-number
// gutter, marking and highlighting the offending line. No-op when the source
// cannot be read (e.g. line 0, or a cleaned-up clone).
func (g *Generator) printSnippet(f rules.Finding) {
	ctx := buildCodeContext(f.FilePath, f.LineNumber)
	if ctx == nil || len(ctx.Lines) == 0 {
		return
	}
	sevC := severityColor(f.Severity)
	dim := color.New(color.Faint)
	gutter := len(fmt.Sprintf("%d", ctx.EndLine))
	// body + marker(1) + space + gutter + space + "│" + space
	codeWidth := g.cliWidth() - len(body) - gutter - 5
	if codeWidth < 20 {
		codeWidth = 20
	}

	fmt.Println()
	for _, ln := range ctx.Lines {
		code := truncate(strings.ReplaceAll(ln.Content, "\t", "  "), codeWidth)
		num := fmt.Sprintf("%*d", gutter, ln.Line)
		if ln.Highlight {
			fmt.Printf("%s%s %s %s %s\n",
				body, sevC.Sprint("❱"), sevC.Sprint(num), dim.Sprint("│"), color.New(color.Bold).Sprint(code))
		} else {
			fmt.Printf("%s  %s %s %s\n", body, dim.Sprint(num), dim.Sprint("│"), dim.Sprint(code))
		}
	}
	fmt.Println()
}

// findingURL returns the platform link for a finding, if any.
func findingURL(f rules.Finding) string {
	if f.GitHubURL != "" {
		return f.GitHubURL
	}
	return f.GitLabURL
}

// truncate shortens s to width characters, adding an ellipsis when cut.
func truncate(s string, width int) string {
	if width <= 1 || len(s) <= width {
		return s
	}
	if width <= 3 {
		return s[:width]
	}
	return s[:width-1] + "…"
}

// wrapLines word-wraps s to width, preserving existing hard line breaks.
func wrapLines(s string, width int) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	if width < 20 {
		width = 20
	}
	var lines []string
	for _, paragraph := range strings.Split(s, "\n") {
		words := strings.Fields(paragraph)
		if len(words) == 0 {
			continue
		}
		cur := words[0]
		for _, w := range words[1:] {
			if len(cur)+1+len(w) > width {
				lines = append(lines, cur)
				cur = w
			} else {
				cur += " " + w
			}
		}
		lines = append(lines, cur)
	}
	return lines
}

// printSummaryCLI prints the closing severity summary.
func (g *Generator) printSummaryCLI() {
	s := g.Result.Summary
	color.New(color.Faint).Println(strings.Repeat("─", g.cliWidth()))

	parts := []string{}
	addPart := func(n int, name string, sev rules.Severity) {
		if n > 0 {
			parts = append(parts, severityColor(sev).Sprintf("%d %s", n, name))
		}
	}
	addPart(s.Critical, "critical", rules.Critical)
	addPart(s.High, "high", rules.High)
	addPart(s.Medium, "medium", rules.Medium)
	addPart(s.Low, "low", rules.Low)
	addPart(s.Info, "info", rules.Info)

	total := color.New(color.Bold).Sprintf("%d finding(s)", s.Total)
	if len(parts) > 0 {
		fmt.Printf("%s   %s\n\n", total, strings.Join(parts, color.New(color.Faint).Sprint(" · ")))
	} else {
		fmt.Printf("%s\n\n", total)
	}
}

// severityColor returns the color style for a severity level.
func severityColor(sev rules.Severity) *color.Color {
	switch sev {
	case rules.Critical:
		return color.New(color.FgHiRed, color.Bold)
	case rules.High:
		return color.New(color.FgRed, color.Bold)
	case rules.Medium:
		return color.New(color.FgYellow, color.Bold)
	case rules.Low:
		return color.New(color.FgBlue, color.Bold)
	case rules.Info:
		return color.New(color.FgCyan)
	default:
		return color.New(color.FgWhite)
	}
}

// generateJSONReport creates a JSON report
func (g *Generator) generateJSONReport() error {
	// Sanitize file paths to avoid temp/local prefixes
	report := ScanResultReport{
		Repository:      g.Result.Repository,
		ScanTime:        g.Result.ScanTime,
		Duration:        g.Result.Duration,
		DurationNs:      g.Result.Duration.Nanoseconds(),
		DurationMs:      g.Result.Duration.Milliseconds(),
		WorkflowsCount:  g.Result.WorkflowsCount,
		RulesCount:      g.Result.RulesCount,
		Summary:         g.Result.Summary,
		SuppressedCount: g.Result.SuppressedCount,
		GeneratedByAST:  g.Result.GeneratedByAST,
	}

	if len(g.Result.Findings) > 0 {
		deduped := deduplicateFindings(g.Result.Findings, cleanFilePath)
		enhancedFindings := make([]FindingReport, 0, len(deduped))
		for _, f := range deduped {
			codeContext := buildCodeContext(f.FilePath, f.LineNumber)
			f.FilePath = cleanFilePath(f.FilePath)
			enhancedFindings = append(enhancedFindings, FindingReport{
				Finding:     f,
				CodeContext: codeContext,
			})
		}
		report.Findings = enhancedFindings
	}

	data, err := json.MarshalIndent(report, "", "  ")
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

type findingKey struct {
	ruleID     string
	filePath   string
	jobName    string
	stepName   string
	lineNumber int
	githubURL  string
	gitlabURL  string
}

// DeduplicateFindings collapses findings that describe the same issue: the same
// rule at the same file+line (regardless of the job/step it was attributed to),
// or, for findings without a line, the same rule+file+job+step. Call this before
// computing the summary so the reported issue count matches the findings emitted
// by every report format (the JSON and SARIF generators deduplicate internally).
func DeduplicateFindings(findings []rules.Finding) []rules.Finding {
	return deduplicateFindings(findings, nil)
}

func deduplicateFindings(findings []rules.Finding, normalizePath func(string) string) []rules.Finding {
	if len(findings) == 0 {
		return nil
	}
	seen := make(map[findingKey]struct{}, len(findings))
	deduped := make([]rules.Finding, 0, len(findings))
	for _, f := range findings {
		path := f.FilePath
		if normalizePath != nil {
			path = normalizePath(path)
		}
		key := findingKey{
			ruleID:     f.RuleID,
			filePath:   path,
			lineNumber: f.LineNumber,
			githubURL:  f.GitHubURL,
			gitlabURL:  f.GitLabURL,
		}
		// When a finding points at a concrete source line, the same rule firing
		// on that line is the same issue regardless of which job/step the
		// line-mapper attributed it to (e.g. one `uses:` line referenced from
		// several jobs). Collapse those. Only keep job/step in the key when
		// there is no line to disambiguate by.
		if f.LineNumber == 0 {
			key.jobName = f.JobName
			key.stepName = f.StepName
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, f)
	}
	return deduped
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
	if g.Result.SuppressedCount > 0 {
		markdownBuilder.WriteString(fmt.Sprintf("- **AST Reachability Suppressed:** %d findings\n", g.Result.SuppressedCount))
	}
	if g.Result.GeneratedByAST > 0 {
		markdownBuilder.WriteString(fmt.Sprintf("- **AST Data Flow Insights:** %d findings\n", g.Result.GeneratedByAST))
	}

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
				displayPath := cleanFilePath(finding.FilePath)
				if finding.GitHubURL != "" {
					markdownBuilder.WriteString(fmt.Sprintf("- **GitHub URL:** [%s](%s)\n", displayPath, finding.GitHubURL))
				} else if finding.GitLabURL != "" {
					markdownBuilder.WriteString(fmt.Sprintf("- **GitLab URL:** [%s](%s)\n", displayPath, finding.GitLabURL))
				} else {
					markdownBuilder.WriteString(fmt.Sprintf("- **File:** `%s`\n", displayPath))
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
	markdownBuilder.WriteString("Generated by Flowlyt v" + constants.AppVersion + " - CI/CD Security Analyzer\n")

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
