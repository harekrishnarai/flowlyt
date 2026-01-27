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
	"strconv"
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/rules"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

// generateSARIFReport creates a SARIF-compliant report using the go-sarif library
func (g *Generator) generateSARIFReport() error {
	report, err := g.createSARIFReport()
	if err != nil {
		return fmt.Errorf("failed to create SARIF report: %w", err)
	}

	if g.FilePath != "" {
		err = report.WriteFile(g.FilePath)
		if err != nil {
			return fmt.Errorf("failed to write SARIF report to file: %w", err)
		}
		fmt.Printf("SARIF report written to %s\n", g.FilePath)
	} else {
		// Write to stdout
		err = report.PrettyWrite(os.Stdout)
		if err != nil {
			return fmt.Errorf("failed to write SARIF to stdout: %w", err)
		}
	}

	return nil
}

// createSARIFReport converts scan results to SARIF format using go-sarif library
func (g *Generator) createSARIFReport() (*sarif.Report, error) {
	// Create a new SARIF report
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return nil, fmt.Errorf("failed to create SARIF report: %w", err)
	}

	// Add run to the report
	run := sarif.NewRunWithInformationURI("Flowlyt", "https://github.com/harekrishnarai/flowlyt")
	run.Tool.Driver.WithVersion("1.0.7")
	run.Tool.Driver.WithFullName("Flowlyt - CI/CD Security Analyzer")
	run.Tool.Driver.WithSemanticVersion("1.0.7")

	// Set invocation information
	run.AddInvocation(true).
		WithStartTimeUTC(g.Result.ScanTime).
		WithEndTimeUTC(g.Result.ScanTime.Add(g.Result.Duration))

	// Add run properties - initialize the Properties map first
	if run.Properties == nil {
		run.Properties = make(sarif.Properties)
	}
	run.Properties["repository"] = g.Result.Repository
	run.Properties["workflowsCount"] = g.Result.WorkflowsCount
	run.Properties["rulesCount"] = g.Result.RulesCount
	run.Properties["summary"] = g.Result.Summary

	if g.Result.SuppressedCount > 0 {
		run.Properties["flowlyt.suppressedReachability"] = g.Result.SuppressedCount
	}
	if g.Result.GeneratedByAST > 0 {
		run.Properties["flowlyt.generatedAstFindings"] = g.Result.GeneratedByAST
	}

	// Create rule definitions from findings
	dedupedFindings := deduplicateFindings(g.Result.Findings, g.normalizeFilePath)
	ruleMap := make(map[string]bool)
	for _, finding := range dedupedFindings {
		if !ruleMap[finding.RuleID] {
			g.addSARIFRule(run, finding)
			ruleMap[finding.RuleID] = true
		}
	}

	// Add results from findings
	for _, finding := range dedupedFindings {
		g.addSARIFResult(run, finding)
	}

	// Add artifacts (files) referenced in the scan
	g.addSARIFArtifacts(run, dedupedFindings)

	report.AddRun(run)
	return report, nil
}

// addSARIFRule adds a rule definition to the SARIF run
func (g *Generator) addSARIFRule(run *sarif.Run, finding rules.Finding) {
	level := g.severityToSARIFLevel(finding.Severity)

	rule := run.AddRule(finding.RuleID).
		WithName(finding.RuleName).
		WithShortDescription(sarif.NewMultiformatMessageString(finding.RuleName)).
		WithFullDescription(sarif.NewMultiformatMessageString(finding.Description)).
		WithHelp(sarif.NewMultiformatMessageString(finding.Remediation).WithMarkdown(g.formatRemediation(finding.Remediation)))

	// Set default configuration level
	rule.WithDefaultConfiguration(sarif.NewReportingConfiguration().WithLevel(level))

	// Add rule properties with GitHub Advanced Security compatible severity
	rule.WithProperties(sarif.Properties{
		"category":          string(finding.Category),
		"severity":          string(finding.Severity),
		"security-severity": g.getSecuritySeverityScore(finding.Severity),
		"tags":              []string{"security", "ci-cd", string(finding.Category)},
		"precision":         "high",
		"problem.severity":  string(finding.Severity),
	})
}

// addSARIFResult adds a result to the SARIF run
func (g *Generator) addSARIFResult(run *sarif.Run, finding rules.Finding) {
	level := g.severityToSARIFLevel(finding.Severity)

	// Normalize file path
	normalizedPath := g.normalizeFilePath(finding.FilePath)

	// Create the result
	result := run.CreateResultForRule(finding.RuleID).
		WithLevel(level).
		WithMessage(sarif.NewTextMessage(finding.Description))

	// Add location
	location := sarif.NewPhysicalLocation().
		WithArtifactLocation(sarif.NewSimpleArtifactLocation(normalizedPath))

	if finding.LineNumber > 0 {
		codeContext := buildCodeContext(finding.FilePath, finding.LineNumber)
		if codeContext != nil {
			region := sarif.NewRegion().
				WithStartLine(codeContext.StartLine).
				WithEndLine(codeContext.EndLine).
				WithSnippet(sarif.NewArtifactContent().WithText(formatSnippetRaw(codeContext.Lines)))
			location.WithRegion(region)
		} else {
			region := sarif.NewSimpleRegion(finding.LineNumber, finding.LineNumber)
			location.WithRegion(region)
		}
	}

	result.AddLocation(sarif.NewLocation().WithPhysicalLocation(location))

	// Add logical locations for workflow context
	if finding.JobName != "" {
		logicalLocation := sarif.NewLogicalLocation().
			WithName(finding.JobName).
			WithKind("job").
			WithFullyQualifiedName(finding.JobName)
		result.Locations[0].AddLogicalLocations(logicalLocation)
	}

	if finding.StepName != "" {
		logicalLocation := sarif.NewLogicalLocation().
			WithName(finding.StepName).
			WithKind("step").
			WithFullyQualifiedName(g.getFullyQualifiedStepName(finding))
		result.Locations[0].AddLogicalLocations(logicalLocation)
	}

	// Add partial fingerprints
	result.WithPartialFingerPrints(map[string]interface{}{
		"flowlyt/v1": g.generateFingerprint(finding),
	})

	// Add result properties - initialize the Properties map first
	if result.Properties == nil {
		result.Properties = make(sarif.Properties)
	}
	result.Properties["category"] = string(finding.Category)
	result.Properties["severity"] = string(finding.Severity)
	result.Properties["evidence"] = MaskSecrets(finding.Evidence)
	result.Properties["remediation"] = finding.Remediation

	if finding.JobName != "" {
		result.Properties["jobName"] = finding.JobName
	}
	if finding.StepName != "" {
		result.Properties["stepName"] = finding.StepName
	}
	if finding.GitHubURL != "" {
		result.Properties["githubUrl"] = finding.GitHubURL
	}
	if finding.GitLabURL != "" {
		result.Properties["gitlabUrl"] = finding.GitLabURL
	}
	if finding.RunnerType != "" {
		result.Properties["runnerType"] = finding.RunnerType
	}
	if finding.FileContext != "" {
		result.Properties["fileContext"] = finding.FileContext
	}
	if finding.AIVerified {
		result.Properties["ai.verified"] = true
		if finding.AILikelyFalsePositive != nil {
			result.Properties["ai.likelyFalsePositive"] = *finding.AILikelyFalsePositive
		}
		if finding.AIConfidence > 0 {
			result.Properties["ai.confidence"] = finding.AIConfidence
		}
		if finding.AIReasoning != "" {
			result.Properties["ai.reasoning"] = finding.AIReasoning
		}
		if finding.AISuggestedSeverity != "" {
			result.Properties["ai.suggestedSeverity"] = finding.AISuggestedSeverity
		}
		if finding.AIError != "" {
			result.Properties["ai.error"] = finding.AIError
		}
	}
}

// addSARIFArtifacts adds artifact entries for analyzed files
func (g *Generator) addSARIFArtifacts(run *sarif.Run, findings []rules.Finding) {
	artifactMap := make(map[string]bool)

	for _, finding := range findings {
		normalizedPath := g.normalizeFilePath(finding.FilePath)

		if !artifactMap[normalizedPath] {
			artifact := run.AddDistinctArtifact(normalizedPath)

			// Set MIME type and source language
			artifact.WithMimeType(g.getMimeType(finding.FilePath))
			artifact.WithSourceLanguage("yaml")
			artifact.WithDescription(sarif.NewMessage().WithText("CI/CD workflow file"))

			// Add properties - initialize the Properties map first
			if artifact.Properties == nil {
				artifact.Properties = make(sarif.Properties)
			}
			artifact.Properties["fileType"] = "workflow"

			// Try to get file info if it's a local file
			if info, err := os.Stat(finding.FilePath); err == nil {
				artifact.WithLength(int(info.Size()))
			}

			artifactMap[normalizedPath] = true
		}
	}
}

// Helper functions

// severityToSARIFLevel converts Flowlyt severity to SARIF level
// GitHub Advanced Security uses this along with security-severity for display
func (g *Generator) severityToSARIFLevel(severity rules.Severity) string {
	switch severity {
	case rules.Critical:
		return "error" // Critical issues are always errors
	case rules.High:
		return "error" // High severity issues are errors
	case rules.Medium:
		return "warning" // Medium severity issues are warnings
	case rules.Low:
		return "warning" // Low severity issues are warnings
	case rules.Info:
		return "note" // Informational findings are notes
	default:
		return "warning"
	}
}

// getSecuritySeverityScore returns a numeric severity score for GitHub Advanced Security
// GitHub uses this score to categorize findings:
// 9.0-10.0: Critical
// 7.0-8.9: High
// 4.0-6.9: Medium
// 0.1-3.9: Low
func (g *Generator) getSecuritySeverityScore(severity rules.Severity) float64 {
	switch severity {
	case rules.Critical:
		return 9.0 // Critical: 9.0-10.0 range
	case rules.High:
		return 8.0 // High: 7.0-8.9 range
	case rules.Medium:
		return 5.0 // Medium: 4.0-6.9 range
	case rules.Low:
		return 3.0 // Low: 0.1-3.9 range
	case rules.Info:
		return 0.0 // Info: 0.0 for informational
	default:
		return 5.0 // Default to medium
	}
}

// normalizeFilePath normalizes file paths for SARIF format
func (g *Generator) normalizeFilePath(filePath string) string {
	// Convert to forward slashes
	normalized := filepath.ToSlash(filePath)

	// Remove common temporary directory patterns and make relative
	if strings.Contains(normalized, ".github/workflows/") {
		if idx := strings.Index(normalized, ".github/workflows/"); idx != -1 {
			normalized = normalized[idx:]
		}
	} else if strings.HasSuffix(normalized, ".gitlab-ci.yml") {
		normalized = ".gitlab-ci.yml"
	} else {
		// Try to make relative to current directory
		if strings.HasPrefix(normalized, "/") {
			// Remove absolute path prefixes
			parts := strings.Split(normalized, "/")
			for i, part := range parts {
				if strings.HasPrefix(part, ".github") || strings.HasSuffix(part, ".yml") || strings.HasSuffix(part, ".yaml") {
					normalized = strings.Join(parts[i:], "/")
					break
				}
			}
		}
	}

	return normalized
}

// getMimeType returns the MIME type for a file
func (g *Generator) getMimeType(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".yml", ".yaml":
		return "text/yaml"
	case ".json":
		return "application/json"
	default:
		return "text/plain"
	}
}

// generateFingerprint creates a fingerprint for result deduplication
func (g *Generator) generateFingerprint(finding rules.Finding) string {
	// Create a fingerprint based on rule ID, file path, and line number
	parts := []string{
		finding.RuleID,
		g.normalizeFilePath(finding.FilePath),
		strconv.Itoa(finding.LineNumber),
	}
	return strings.Join(parts, ":")
}

// getFullyQualifiedStepName creates a fully qualified step name
func (g *Generator) getFullyQualifiedStepName(finding rules.Finding) string {
	if finding.JobName != "" && finding.StepName != "" {
		return finding.JobName + "." + finding.StepName
	}
	return finding.StepName
}

// formatRemediation formats remediation advice as Markdown
func (g *Generator) formatRemediation(remediation string) string {
	// Convert plain text to basic Markdown
	lines := strings.Split(remediation, "\n")
	var markdownLines []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			markdownLines = append(markdownLines, "")
			continue
		}

		// Convert code snippets
		if strings.Contains(line, "`") {
			markdownLines = append(markdownLines, line)
		} else if strings.Contains(line, "http") {
			// Convert URLs to links
			markdownLines = append(markdownLines, line)
		} else {
			markdownLines = append(markdownLines, line)
		}
	}

	return strings.Join(markdownLines, "\n")
}
