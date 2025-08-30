package report

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

// SARIF represents a Static Analysis Results Interchange Format report
// Based on SARIF v2.1.0 specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
type SARIF struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single analysis run
type SARIFRun struct {
	Tool       SARIFTool              `json:"tool"`
	Invocation SARIFInvocation        `json:"invocation"`
	Results    []SARIFResult          `json:"results"`
	Artifacts  []SARIFArtifact        `json:"artifacts,omitempty"`
	Rules      []SARIFRule            `json:"rules,omitempty"`
	ColumnKind string                 `json:"columnKind,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// SARIFTool represents the analysis tool
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver represents the tool driver
type SARIFDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version,omitempty"`
	InformationUri  string      `json:"informationUri,omitempty"`
	FullName        string      `json:"fullName,omitempty"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	Rules           []SARIFRule `json:"rules,omitempty"`
}

// SARIFRule represents a rule definition
type SARIFRule struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name,omitempty"`
	ShortDescription     SARIFMessage           `json:"shortDescription,omitempty"`
	FullDescription      SARIFMessage           `json:"fullDescription,omitempty"`
	DefaultConfiguration SARIFRuleConfiguration `json:"defaultConfiguration,omitempty"`
	Help                 SARIFMessage           `json:"help,omitempty"`
	HelpUri              string                 `json:"helpUri,omitempty"`
	Properties           map[string]interface{} `json:"properties,omitempty"`
}

// SARIFRuleConfiguration represents rule configuration
type SARIFRuleConfiguration struct {
	Level string `json:"level"`
}

// SARIFInvocation represents tool invocation details
type SARIFInvocation struct {
	CommandLine         string    `json:"commandLine,omitempty"`
	StartTimeUtc        time.Time `json:"startTimeUtc"`
	EndTimeUtc          time.Time `json:"endTimeUtc"`
	ExecutionSuccessful bool      `json:"executionSuccessful"`
}

// SARIFResult represents a single analysis result (finding)
type SARIFResult struct {
	RuleID              string                 `json:"ruleId"`
	RuleIndex           int                    `json:"ruleIndex,omitempty"`
	Level               string                 `json:"level"`
	Message             SARIFMessage           `json:"message"`
	Locations           []SARIFLocation        `json:"locations"`
	PartialFingerprints map[string]string      `json:"partialFingerprints,omitempty"`
	Properties          map[string]interface{} `json:"properties,omitempty"`
}

// SARIFMessage represents a message in SARIF
type SARIFMessage struct {
	Text       string                 `json:"text"`
	Markdown   string                 `json:"markdown,omitempty"`
	Arguments  []string               `json:"arguments,omitempty"`
	ID         string                 `json:"id,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// SARIFLocation represents a location where an issue was found
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation  `json:"physicalLocation"`
	LogicalLocations []SARIFLogicalLocation `json:"logicalLocations,omitempty"`
	Message          SARIFMessage           `json:"message,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

// SARIFPhysicalLocation represents a physical location in source code
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region,omitempty"`
	ContextRegion    SARIFRegion           `json:"contextRegion,omitempty"`
}

// SARIFLogicalLocation represents a logical location (job, step, etc.)
type SARIFLogicalLocation struct {
	Name               string                 `json:"name,omitempty"`
	Index              int                    `json:"index,omitempty"`
	FullyQualifiedName string                 `json:"fullyQualifiedName,omitempty"`
	DecoratedName      string                 `json:"decoratedName,omitempty"`
	Kind               string                 `json:"kind,omitempty"`
	Properties         map[string]interface{} `json:"properties,omitempty"`
}

// SARIFArtifactLocation represents a reference to an artifact
type SARIFArtifactLocation struct {
	URI         string                 `json:"uri"`
	URIBaseId   string                 `json:"uriBaseId,omitempty"`
	Index       int                    `json:"index,omitempty"`
	Description SARIFMessage           `json:"description,omitempty"`
	Properties  map[string]interface{} `json:"properties,omitempty"`
}

// SARIFRegion represents a region in a file
type SARIFRegion struct {
	StartLine   int                    `json:"startLine,omitempty"`
	StartColumn int                    `json:"startColumn,omitempty"`
	EndLine     int                    `json:"endLine,omitempty"`
	EndColumn   int                    `json:"endColumn,omitempty"`
	CharOffset  int                    `json:"charOffset,omitempty"`
	CharLength  int                    `json:"charLength,omitempty"`
	ByteOffset  int                    `json:"byteOffset,omitempty"`
	ByteLength  int                    `json:"byteLength,omitempty"`
	Snippet     SARIFArtifactContent   `json:"snippet,omitempty"`
	Message     SARIFMessage           `json:"message,omitempty"`
	Properties  map[string]interface{} `json:"properties,omitempty"`
}

// SARIFArtifactContent represents content of an artifact
type SARIFArtifactContent struct {
	Text       string                  `json:"text,omitempty"`
	Binary     string                  `json:"binary,omitempty"`
	Rendered   SARIFMultiformatMessage `json:"rendered,omitempty"`
	Properties map[string]interface{}  `json:"properties,omitempty"`
}

// SARIFMultiformatMessage represents a message that can be rendered in multiple formats
type SARIFMultiformatMessage struct {
	Text       string                 `json:"text,omitempty"`
	Markdown   string                 `json:"markdown,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// SARIFArtifact represents a file or other artifact
type SARIFArtifact struct {
	Location            SARIFArtifactLocation  `json:"location"`
	Length              int64                  `json:"length,omitempty"`
	MimeType            string                 `json:"mimeType,omitempty"`
	Contents            SARIFArtifactContent   `json:"contents,omitempty"`
	Encoding            string                 `json:"encoding,omitempty"`
	SourceLanguage      string                 `json:"sourceLanguage,omitempty"`
	Hashes              map[string]string      `json:"hashes,omitempty"`
	LastModifiedTimeUtc time.Time              `json:"lastModifiedTimeUtc,omitempty"`
	Description         SARIFMessage           `json:"description,omitempty"`
	Properties          map[string]interface{} `json:"properties,omitempty"`
}

// generateSARIFReport creates a SARIF-compliant report
func (g *Generator) generateSARIFReport() error {
	sarif := g.createSARIFReport()

	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SARIF: %w", err)
	}

	if g.FilePath != "" {
		err = os.WriteFile(g.FilePath, data, 0644)
		if err != nil {
			return fmt.Errorf("failed to write SARIF report to file: %w", err)
		}
		fmt.Printf("SARIF report written to %s\n", g.FilePath)
	} else {
		fmt.Println(string(data))
	}

	return nil
}

// createSARIFReport converts scan results to SARIF format
func (g *Generator) createSARIFReport() SARIF {
	// Create rule definitions from findings
	ruleMap := make(map[string]SARIFRule)
	for _, finding := range g.Result.Findings {
		if _, exists := ruleMap[finding.RuleID]; !exists {
			ruleMap[finding.RuleID] = g.createSARIFRule(finding)
		}
	}

	// Convert map to slice for consistent ordering
	var rules []SARIFRule
	for _, rule := range ruleMap {
		rules = append(rules, rule)
	}

	// Create results from findings
	var results []SARIFResult
	for _, finding := range g.Result.Findings {
		result := g.createSARIFResult(finding, g.getRuleIndex(finding.RuleID, rules))
		results = append(results, result)
	}

	// Create artifacts (files) referenced in the scan
	artifacts := g.createSARIFArtifacts()

	run := SARIFRun{
		Tool: SARIFTool{
			Driver: SARIFDriver{
				Name:            "Flowlyt",
				Version:         "0.1.0",
				InformationUri:  "https://github.com/harekrishnarai/flowlyt",
				FullName:        "Flowlyt - CI/CD Security Analyzer",
				SemanticVersion: "0.1.0",
				Rules:           rules,
			},
		},
		Invocation: SARIFInvocation{
			StartTimeUtc:        g.Result.ScanTime,
			EndTimeUtc:          g.Result.ScanTime.Add(g.Result.Duration),
			ExecutionSuccessful: true,
		},
		Results:    results,
		Artifacts:  artifacts,
		ColumnKind: "utf16CodeUnits",
		Properties: map[string]interface{}{
			"repository":     g.Result.Repository,
			"workflowsCount": g.Result.WorkflowsCount,
			"rulesCount":     g.Result.RulesCount,
			"summary":        g.Result.Summary,
		},
	}

	return SARIF{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs:    []SARIFRun{run},
	}
}

// createSARIFRule converts a finding to a SARIF rule definition
func (g *Generator) createSARIFRule(finding rules.Finding) SARIFRule {
	level := g.severityToSARIFLevel(finding.Severity)

	return SARIFRule{
		ID:   finding.RuleID,
		Name: finding.RuleName,
		ShortDescription: SARIFMessage{
			Text: finding.RuleName,
		},
		FullDescription: SARIFMessage{
			Text: finding.Description,
		},
		DefaultConfiguration: SARIFRuleConfiguration{
			Level: level,
		},
		Help: SARIFMessage{
			Text:     finding.Remediation,
			Markdown: g.formatRemediation(finding.Remediation),
		},
		Properties: map[string]interface{}{
			"category":         string(finding.Category),
			"severity":         string(finding.Severity),
			"tags":             []string{"security", "ci-cd", string(finding.Category)},
			"precision":        "high",
			"problem.severity": string(finding.Severity),
		},
	}
}

// createSARIFResult converts a finding to a SARIF result
func (g *Generator) createSARIFResult(finding rules.Finding, ruleIndex int) SARIFResult {
	level := g.severityToSARIFLevel(finding.Severity)

	// Create message with context
	message := SARIFMessage{
		Text: finding.Description,
	}

	// Create locations
	locations := []SARIFLocation{
		g.createSARIFLocation(finding),
	}

	// Create partial fingerprints for result tracking
	fingerprints := map[string]string{
		"flowlyt/v1": g.generateFingerprint(finding),
	}

	properties := map[string]interface{}{
		"category":    string(finding.Category),
		"severity":    string(finding.Severity),
		"evidence":    MaskSecrets(finding.Evidence),
		"remediation": finding.Remediation,
	}

	// Add job/step context if available
	if finding.JobName != "" {
		properties["jobName"] = finding.JobName
	}
	if finding.StepName != "" {
		properties["stepName"] = finding.StepName
	}
	if finding.GitHubURL != "" {
		properties["githubUrl"] = finding.GitHubURL
	}

	return SARIFResult{
		RuleID:              finding.RuleID,
		RuleIndex:           ruleIndex,
		Level:               level,
		Message:             message,
		Locations:           locations,
		PartialFingerprints: fingerprints,
		Properties:          properties,
	}
}

// createSARIFLocation creates a SARIF location from a finding
func (g *Generator) createSARIFLocation(finding rules.Finding) SARIFLocation {
	// Normalize file path for SARIF (use forward slashes, relative path)
	normalizedPath := g.normalizeFilePath(finding.FilePath)

	physicalLocation := SARIFPhysicalLocation{
		ArtifactLocation: SARIFArtifactLocation{
			URI: normalizedPath,
		},
	}

	// Add line/column information if available
	if finding.LineNumber > 0 {
		physicalLocation.Region = SARIFRegion{
			StartLine: finding.LineNumber,
			EndLine:   finding.LineNumber,
		}
	}

	location := SARIFLocation{
		PhysicalLocation: physicalLocation,
	}

	// Add logical locations for workflow context
	var logicalLocations []SARIFLogicalLocation

	if finding.JobName != "" {
		logicalLocations = append(logicalLocations, SARIFLogicalLocation{
			Name:               finding.JobName,
			Kind:               "job",
			FullyQualifiedName: finding.JobName,
		})
	}

	if finding.StepName != "" {
		logicalLocations = append(logicalLocations, SARIFLogicalLocation{
			Name:               finding.StepName,
			Kind:               "step",
			FullyQualifiedName: g.getFullyQualifiedStepName(finding),
		})
	}

	if len(logicalLocations) > 0 {
		location.LogicalLocations = logicalLocations
	}

	return location
}

// createSARIFArtifacts creates artifact entries for analyzed files
func (g *Generator) createSARIFArtifacts() []SARIFArtifact {
	artifactMap := make(map[string]SARIFArtifact)

	for _, finding := range g.Result.Findings {
		normalizedPath := g.normalizeFilePath(finding.FilePath)

		if _, exists := artifactMap[normalizedPath]; !exists {
			artifact := SARIFArtifact{
				Location: SARIFArtifactLocation{
					URI: normalizedPath,
				},
				MimeType:       g.getMimeType(finding.FilePath),
				SourceLanguage: "yaml",
				Description: SARIFMessage{
					Text: "CI/CD workflow file",
				},
				Properties: map[string]interface{}{
					"fileType": "workflow",
				},
			}

			// Try to get file info if it's a local file
			if info, err := os.Stat(finding.FilePath); err == nil {
				artifact.Length = info.Size()
				artifact.LastModifiedTimeUtc = info.ModTime()
			}

			artifactMap[normalizedPath] = artifact
		}
	}

	// Convert map to slice
	var artifacts []SARIFArtifact
	for _, artifact := range artifactMap {
		artifacts = append(artifacts, artifact)
	}

	return artifacts
}

// Helper functions

// severityToSARIFLevel converts Flowlyt severity to SARIF level
func (g *Generator) severityToSARIFLevel(severity rules.Severity) string {
	switch severity {
	case rules.Critical:
		return "error"
	case rules.High:
		return "error"
	case rules.Medium:
		return "warning"
	case rules.Low:
		return "note"
	case rules.Info:
		return "note"
	default:
		return "warning"
	}
}

// getRuleIndex finds the index of a rule in the rules array
func (g *Generator) getRuleIndex(ruleID string, rules []SARIFRule) int {
	for i, rule := range rules {
		if rule.ID == ruleID {
			return i
		}
	}
	return 0
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

	// URL encode if necessary
	if strings.Contains(normalized, " ") {
		normalized = url.QueryEscape(normalized)
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
