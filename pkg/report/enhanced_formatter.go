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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

// EnhancedFinding wraps a finding with additional formatting context
type EnhancedFinding struct {
	Finding   rules.Finding
	FileLines map[int]string // Line number -> content
	Number    int            // Overall finding number
}

// EnhancedFormatter provides modern, visually appealing output formatting
type EnhancedFormatter struct {
	findings []EnhancedFinding
}

// NewEnhancedFormatter creates a new enhanced formatter
func NewEnhancedFormatter() *EnhancedFormatter {
	return &EnhancedFormatter{
		findings: make([]EnhancedFinding, 0),
	}
}

// AddFinding adds a finding with file context
func (ef *EnhancedFormatter) AddFinding(finding rules.Finding, findingNumber int) {
	enhanced := EnhancedFinding{
		Finding:   finding,
		FileLines: loadFileLines(finding.FilePath, finding.LineNumber),
		Number:    findingNumber,
	}
	ef.findings = append(ef.findings, enhanced)
}

// loadFileLines loads file content around the issue
func loadFileLines(filePath string, lineNumber int) map[int]string {
	lines := make(map[int]string)

	if filePath == "" || lineNumber == 0 {
		return lines
	}

	// Try to read the file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return lines
	}

	fileLines := strings.Split(string(content), "\n")

	// Calculate context range (3 lines before and after)
	startLine := lineNumber - 4
	endLine := lineNumber + 2

	if startLine < 1 {
		startLine = 1
	}
	if endLine > len(fileLines) {
		endLine = len(fileLines)
	}

	// Store lines (convert to 0-indexed for array access)
	for i := startLine; i <= endLine; i++ {
		if i > 0 && i <= len(fileLines) {
			lines[i] = fileLines[i-1]
		}
	}

	return lines
}

// FormatFinding returns a formatted string for a single finding
func (ef *EnhancedFormatter) FormatFinding(enhanced EnhancedFinding) string {
	var output strings.Builder

	// Styles
	failStyle := color.New(color.FgHiRed, color.Bold)
	highStyle := color.New(color.FgHiYellow, color.Bold)
	mediumStyle := color.New(color.FgYellow)
	lowStyle := color.New(color.FgBlue)
	infoStyle := color.New(color.FgBlue)
	pathStyle := color.New(color.FgCyan, color.Bold)
	lineNumStyle := color.New(color.FgMagenta)
	codeStyle := color.New(color.FgWhite)
	highlightStyle := color.New(color.FgHiRed, color.Bold)

	// Get appropriate style for severity
	severityStyle := infoStyle
	switch enhanced.Finding.Severity {
	case rules.Critical:
		severityStyle = failStyle
	case rules.High:
		severityStyle = highStyle
	case rules.Medium:
		severityStyle = mediumStyle
	case rules.Low:
		severityStyle = lowStyle
	}

	// Header with severity badge
	output.WriteString("\n")
	severityStr := fmt.Sprintf("[%s]", strings.ToUpper(string(enhanced.Finding.Severity)))
	severityStyle.Fprint(&output, severityStr)
	output.WriteString(" ")
	pathStyle.Fprint(&output, enhanced.Finding.FilePath)
	if enhanced.Finding.LineNumber > 0 {
		output.WriteString(":")
		lineNumStyle.Fprint(&output, fmt.Sprintf("%d", enhanced.Finding.LineNumber))
	}
	output.WriteString("\n")

	// Rule information
	output.WriteString("Rule: ")
	failStyle.Fprint(&output, enhanced.Finding.RuleID)
	output.WriteString("\n")

	// Code snippet if available
	if len(enhanced.FileLines) > 0 {
		output.WriteString("\n")
		ef.formatCodeSnippet(&output, enhanced, codeStyle, highlightStyle, lineNumStyle)
	}

	// Message/Description
	output.WriteString("\nMessage: ")
	output.WriteString(enhanced.Finding.Description)
	output.WriteString("\n")

	// Data flow information (for sensitive data flow rules)
	if strings.Contains(strings.ToUpper(enhanced.Finding.RuleID), "DATA_FLOW") ||
		strings.Contains(strings.ToUpper(enhanced.Finding.RuleID), "SENSITIVE") {
		output.WriteString("\n")
		ef.formatDataFlow(&output, enhanced)
	}

	// Remediation
	if enhanced.Finding.Remediation != "" {
		output.WriteString("\n💡 Remediation: ")
		output.WriteString(enhanced.Finding.Remediation)
		output.WriteString("\n")
	}

	return output.String()
}

// formatCodeSnippet formats the code context around the issue
func (ef *EnhancedFormatter) formatCodeSnippet(output *strings.Builder, enhanced EnhancedFinding, codeStyle, highlightStyle, lineNumStyle *color.Color) {
	lineNum := enhanced.Finding.LineNumber
	lines := enhanced.FileLines

	if len(lines) == 0 {
		return
	}

	// Find min and max line numbers
	minLine := lineNum
	maxLine := lineNum
	for lineNo := range lines {
		if lineNo < minLine {
			minLine = lineNo
		}
		if lineNo > maxLine {
			maxLine = lineNo
		}
	}

	output.WriteString("\n")

	// Print lines with context
	for i := minLine; i <= maxLine; i++ {
		content, exists := lines[i]
		if !exists {
			continue
		}

		// Line number with styling
		lineNumStyle.Fprintf(output, "%4d ", i)
		output.WriteString("│ ")

		// Content with highlighting for the problem line
		if i == lineNum {
			highlightStyle.Fprint(output, ">")
			highlightStyle.Fprint(output, " ")
			highlightStyle.Fprint(output, content)
			output.WriteString("\n")
			// Add arrow pointing to the issue
			output.WriteString("      ")
			highlightStyle.Fprint(output, "└─→ Potential Issue Here")
		} else {
			output.WriteString("  ")
			codeStyle.Fprint(output, content)
			output.WriteString("\n")
		}
	}
}

// formatDataFlow formats sensitive data flow information
func (ef *EnhancedFormatter) formatDataFlow(output *strings.Builder, enhanced EnhancedFinding) {
	output.WriteString("🔻 Data Flow Analysis:\n")

	// Parse evidence for data flow information
	evidence := enhanced.Finding.Evidence
	if evidence == "" {
		return
	}

	lines := strings.Split(evidence, "\n")

	// Extract source and sink information
	var sourceVar string
	var sinkVar string
	var dataFlowPath []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse source (environment variables, secrets, etc.)
		if (strings.Contains(strings.ToLower(line), "step_env") ||
			strings.Contains(strings.ToLower(line), "secret") ||
			strings.Contains(strings.ToLower(line), "env")) &&
			sourceVar == "" {
			sourceVar = extractVarName(line)
		}

		// Parse sink (action inputs, etc.)
		if (strings.Contains(strings.ToLower(line), "action_input") ||
			strings.Contains(strings.ToLower(line), "with")) &&
			sinkVar == "" {
			sinkVar = extractVarName(line)
		}

		dataFlowPath = append(dataFlowPath, line)
	}

	// Format the data flow
	if sourceVar != "" && sinkVar != "" {
		output.WriteString("   [Source] ")
		output.WriteString(sourceVar)
		output.WriteString("\n")
		output.WriteString("      │\n")
		output.WriteString("      ▼\n")
		output.WriteString("   [Sink]   ")
		output.WriteString(sinkVar)
		output.WriteString("\n")
	} else if len(dataFlowPath) > 0 {
		// Fallback to showing raw evidence if we couldn't parse it
		for _, path := range dataFlowPath {
			output.WriteString("   ")
			output.WriteString(path)
			output.WriteString("\n")
		}
	}
}

// extractVarName extracts a variable name from evidence text
func extractVarName(line string) string {
	// Clean up common patterns
	cleaners := []struct {
		pattern string
		repl    string
	}{
		{"step_env_", ""},
		{"action_input_", ""},
		{"${{ ", ""},
		{" }}", ""},
		{"secrets.", ""},
		{"env.", ""},
	}

	result := line
	for _, cleaner := range cleaners {
		result = strings.ReplaceAll(result, cleaner.pattern, cleaner.repl)
	}

	// Extract just the variable name part
	if idx := strings.Index(result, "("); idx != -1 {
		result = result[:idx]
	}
	if idx := strings.Index(result, ")"); idx != -1 {
		result = result[idx+1:]
	}

	return strings.TrimSpace(result)
}

// FormatAll returns a formatted string for all findings
func (ef *EnhancedFormatter) FormatAll() string {
	if len(ef.findings) == 0 {
		return ""
	}

	var output strings.Builder
	for _, enhanced := range ef.findings {
		output.WriteString(ef.FormatFinding(enhanced))
	}

	return output.String()
}

// PrintCompactFinding prints a compact version of a finding (original style but improved)
func (ef *EnhancedFormatter) PrintCompactFinding(finding rules.Finding, number int) string {
	var output strings.Builder

	// Styles
	severityStyle := color.New(color.FgBlue)
	switch finding.Severity {
	case rules.Critical:
		severityStyle = color.New(color.FgHiRed, color.Bold)
	case rules.High:
		severityStyle = color.New(color.FgHiYellow, color.Bold)
	case rules.Medium:
		severityStyle = color.New(color.FgYellow)
	case rules.Low:
		severityStyle = color.New(color.FgBlue)
	}

	infoStyle := color.New(color.FgBlue)
	pathStyle := color.New(color.FgCyan)
	ruleStyle := color.New(color.FgMagenta, color.Bold)

	output.WriteString("\n")
	severityStyle.Fprintf(&output, "[%s]", strings.ToUpper(string(finding.Severity)))
	output.WriteString(" ")
	ruleStyle.Fprintf(&output, "[%d] %s", number, finding.RuleName)
	output.WriteString(" (")
	ruleStyle.Fprint(&output, finding.RuleID)
	output.WriteString(")\n")

	if finding.FilePath != "" {
		infoStyle.Fprintf(&output, "  %-12s ", "📂 File:")
		pathStyle.Fprint(&output, finding.FilePath)
		if finding.LineNumber > 0 {
			output.WriteString(":")
			output.WriteString(fmt.Sprintf("%d", finding.LineNumber))
		}
		output.WriteString("\n")
	}

	if finding.JobName != "" {
		infoStyle.Fprintf(&output, "  %-12s ", "⚙️  Job:")
		output.WriteString(finding.JobName)
		output.WriteString("\n")
	}

	if finding.StepName != "" {
		infoStyle.Fprintf(&output, "  %-12s ", "📝 Step:")
		output.WriteString(finding.StepName)
		output.WriteString("\n")
	}

	infoStyle.Fprintf(&output, "  %-12s ", "📋 Message:")
	output.WriteString(finding.Description)
	output.WriteString("\n")

	return output.String()
}

// FormatBoxedFinding returns a visually boxed finding format
func (ef *EnhancedFormatter) FormatBoxedFinding(finding rules.Finding, number int) string {
	var output strings.Builder

	// Styles
	boxStyle := color.New(color.FgCyan, color.Bold)
	severityStyle := color.New(color.FgBlue)
	switch finding.Severity {
	case rules.Critical:
		severityStyle = color.New(color.FgHiRed, color.Bold)
	case rules.High:
		severityStyle = color.New(color.FgHiYellow, color.Bold)
	case rules.Medium:
		severityStyle = color.New(color.FgYellow, color.Bold)
	}

	// Top border
	output.WriteString("\n")
	boxStyle.Fprint(&output, "┌─")
	severityStyle.Fprintf(&output, " [%s]", strings.ToUpper(string(finding.Severity)))
	boxStyle.Fprint(&output, " ")
	output.WriteString(finding.RuleName)
	boxStyle.Fprint(&output, " ")

	// Calculate padding
	width := 80
	content := fmt.Sprintf(" [%s] %s ", strings.ToUpper(string(finding.Severity)), finding.RuleName)
	padding := width - len(content) - 5
	if padding < 0 {
		padding = 0
	}

	boxStyle.Fprint(&output, strings.Repeat("─", padding))
	boxStyle.Fprint(&output, "┐\n")

	// Body
	boxStyle.Fprint(&output, "│")
	output.WriteString(fmt.Sprintf(" ID: %d  |  Rule: %s", number, finding.RuleID))
	boxStyle.Fprint(&output, "\n│\n")

	// File info
	boxStyle.Fprint(&output, "│")
	output.WriteString(" 📂 ")
	output.WriteString(filepath.Base(finding.FilePath))
	if finding.LineNumber > 0 {
		output.WriteString(fmt.Sprintf(":%d", finding.LineNumber))
	}
	boxStyle.Fprint(&output, "\n")

	if finding.JobName != "" {
		boxStyle.Fprint(&output, "│")
		output.WriteString(fmt.Sprintf("    └── Job: %s\n", finding.JobName))
	}

	if finding.StepName != "" {
		boxStyle.Fprint(&output, "│")
		output.WriteString(fmt.Sprintf("        └── Step: \"%s\"\n", finding.StepName))
	}

	// Description
	boxStyle.Fprint(&output, "│\n")
	boxStyle.Fprint(&output, "│")
	output.WriteString(fmt.Sprintf(" 💡 %s\n", finding.Description))

	// Bottom border
	boxStyle.Fprint(&output, "└")
	boxStyle.Fprint(&output, strings.Repeat("─", width-2))
	boxStyle.Fprint(&output, "┘\n")

	return output.String()
}
