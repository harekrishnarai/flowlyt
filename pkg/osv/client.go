package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

// Client represents an OSV.dev API client for vulnerability queries
type Client struct {
	baseURL    string
	httpClient *http.Client
	timeout    time.Duration
}

// NewClient creates a new OSV.dev API client
func NewClient() *Client {
	return &Client{
		baseURL: "https://api.osv.dev",
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		timeout: 30 * time.Second,
	}
}

// Vulnerability represents an OSV vulnerability record
type Vulnerability struct {
	ID             string           `json:"id"`
	Summary        string           `json:"summary"`
	Details        string           `json:"details"`
	Aliases        []string         `json:"aliases"`
	Modified       time.Time        `json:"modified"`
	Published      time.Time        `json:"published"`
	References     []Reference      `json:"references"`
	Affected       []AffectedPackage `json:"affected"`
	Severity       []SeverityRating `json:"severity"`
	DatabaseSpecific map[string]interface{} `json:"database_specific,omitempty"`
	SchemaVersion  string           `json:"schema_version"`
}

// Reference represents a vulnerability reference
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// AffectedPackage represents an affected package or ecosystem
type AffectedPackage struct {
	Package    Package    `json:"package"`
	Ranges     []Range    `json:"ranges"`
	Versions   []string   `json:"versions,omitempty"`
	EcosystemSpecific map[string]interface{} `json:"ecosystem_specific,omitempty"`
}

// Package represents a package identifier
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Purl      string `json:"purl,omitempty"`
}

// Range represents a version range
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event represents a version event
type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
	Limit      string `json:"limit,omitempty"`
}

// SeverityRating represents a severity score
type SeverityRating struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// QueryRequest represents a vulnerability query request
type QueryRequest struct {
	Version string `json:"version,omitempty"`
	Package Package `json:"package"`
}

// QueryResponse represents the response from OSV query
type QueryResponse struct {
	Vulns []Vulnerability `json:"vulns"`
}

// VulnerabilityInfo represents enhanced vulnerability information
type VulnerabilityInfo struct {
	CVEID       string    `json:"cve_id,omitempty"`
	GHSAID      string    `json:"ghsa_id,omitempty"`
	Summary     string    `json:"summary"`
	Severity    string    `json:"severity"`
	Score       string    `json:"score,omitempty"`
	Published   time.Time `json:"published"`
	References  []string  `json:"references"`
	Ecosystem   string    `json:"ecosystem"`
	PackageName string    `json:"package_name,omitempty"`
}

// EnhancedFinding represents a finding with vulnerability intelligence
type EnhancedFinding struct {
	rules.Finding
	VulnerabilityInfo *VulnerabilityInfo `json:"vulnerability_info,omitempty"`
	RiskScore         int                `json:"risk_score"`
	IntelligenceLevel string             `json:"intelligence_level"` // "HIGH", "MEDIUM", "LOW", "NONE"
}

// QueryVulnerability queries OSV.dev for vulnerability information
func (c *Client) QueryVulnerability(ctx context.Context, ecosystem, packageName, version string) ([]Vulnerability, error) {
	query := QueryRequest{
		Version: version,
		Package: Package{
			Ecosystem: ecosystem,
			Name:      packageName,
		},
	}

	jsonData, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/query", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Flowlyt/0.1.0 Security Scanner")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned status %d", resp.StatusCode)
	}

	var queryResp QueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&queryResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return queryResp.Vulns, nil
}

// GetVulnerabilityByID retrieves a specific vulnerability by ID
func (c *Client) GetVulnerabilityByID(ctx context.Context, vulnID string) (*Vulnerability, error) {
	url := fmt.Sprintf("%s/v1/vulns/%s", c.baseURL, vulnID)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "Flowlyt/0.1.0 Security Scanner")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // Vulnerability not found
	}
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned status %d", resp.StatusCode)
	}

	var vuln Vulnerability
	if err := json.NewDecoder(resp.Body).Decode(&vuln); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &vuln, nil
}

// EnhanceFindings adds vulnerability intelligence to security findings
func (c *Client) EnhanceFindings(ctx context.Context, findings []rules.Finding) ([]EnhancedFinding, error) {
	var enhanced []EnhancedFinding

	for _, finding := range findings {
		enhancedFinding := EnhancedFinding{
			Finding:           finding,
			VulnerabilityInfo: nil,
			RiskScore:         c.calculateBaseRiskScore(finding),
			IntelligenceLevel: "NONE",
		}

		// Try to correlate with known vulnerabilities based on evidence patterns
		vulnInfo := c.analyzeForVulnerabilities(ctx, finding)
		if vulnInfo != nil {
			enhancedFinding.VulnerabilityInfo = vulnInfo
			enhancedFinding.RiskScore = c.calculateEnhancedRiskScore(finding, vulnInfo)
			enhancedFinding.IntelligenceLevel = c.determineIntelligenceLevel(vulnInfo)
		}

		enhanced = append(enhanced, enhancedFinding)
	}

	return enhanced, nil
}

// analyzeForVulnerabilities attempts to correlate findings with known vulnerabilities
func (c *Client) analyzeForVulnerabilities(ctx context.Context, finding rules.Finding) *VulnerabilityInfo {
	// Extract package information from evidence
	packages := c.extractPackageInfo(finding.Evidence)
	
	for _, pkg := range packages {
		vulns, err := c.QueryVulnerability(ctx, pkg.Ecosystem, pkg.Name, "")
		if err != nil {
			continue // Skip on error, don't fail the entire process
		}

		// Find the most relevant vulnerability
		for _, vuln := range vulns {
			if c.isRelevantVulnerability(vuln, finding) {
				return c.convertToVulnerabilityInfo(vuln)
			}
		}
	}

	// Check for CVE/GHSA IDs directly mentioned in evidence
	cveIDs := c.extractCVEIDs(finding.Evidence)
	for _, cveID := range cveIDs {
		vuln, err := c.GetVulnerabilityByID(ctx, cveID)
		if err != nil || vuln == nil {
			continue
		}
		return c.convertToVulnerabilityInfo(*vuln)
	}

	return nil
}

// extractPackageInfo extracts package information from evidence text
func (c *Client) extractPackageInfo(evidence string) []Package {
	var packages []Package
	
	// Common GitHub Actions patterns
	if strings.Contains(evidence, "actions/") {
		// Extract GitHub Actions
		actionName := c.extractActionName(evidence)
		if actionName != "" {
			packages = append(packages, Package{
				Ecosystem: "GitHub Actions",
				Name:      actionName,
			})
		}
	}

	// Docker images
	if strings.Contains(evidence, "docker pull") || strings.Contains(evidence, "FROM ") {
		imageName := c.extractDockerImage(evidence)
		if imageName != "" {
			packages = append(packages, Package{
				Ecosystem: "Docker",
				Name:      imageName,
			})
		}
	}

	// Node.js packages
	if strings.Contains(evidence, "npm install") || strings.Contains(evidence, "yarn add") {
		npmPackages := c.extractNPMPackages(evidence)
		for _, pkg := range npmPackages {
			packages = append(packages, Package{
				Ecosystem: "npm",
				Name:      pkg,
			})
		}
	}

	// Python packages
	if strings.Contains(evidence, "pip install") {
		pypipPackages := c.extractPipPackages(evidence)
		for _, pkg := range pypipPackages {
			packages = append(packages, Package{
				Ecosystem: "PyPI",
				Name:      pkg,
			})
		}
	}

	return packages
}

// extractActionName extracts GitHub Action name from evidence
func (c *Client) extractActionName(evidence string) string {
	// Pattern: uses: owner/action@version
	lines := strings.Split(evidence, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "uses:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				action := parts[1]
				// Remove version/ref
				if idx := strings.Index(action, "@"); idx != -1 {
					action = action[:idx]
				}
				return action
			}
		}
	}
	return ""
}

// extractDockerImage extracts Docker image name from evidence
func (c *Client) extractDockerImage(evidence string) string {
	// Simple extraction for common patterns
	lines := strings.Split(evidence, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "docker pull") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				image := parts[2]
				// Remove tag
				if idx := strings.Index(image, ":"); idx != -1 {
					image = image[:idx]
				}
				return image
			}
		}
		if strings.HasPrefix(line, "FROM ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				image := parts[1]
				// Remove tag
				if idx := strings.Index(image, ":"); idx != -1 {
					image = image[:idx]
				}
				return image
			}
		}
	}
	return ""
}

// extractNPMPackages extracts npm package names from evidence
func (c *Client) extractNPMPackages(evidence string) []string {
	var packages []string
	lines := strings.Split(evidence, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "npm install") || strings.Contains(line, "yarn add") {
			// Extract package names after install command
			parts := strings.Fields(line)
			for i, part := range parts {
				if (part == "install" || part == "add") && i+1 < len(parts) {
					// Collect remaining arguments as package names
					for j := i + 1; j < len(parts); j++ {
						pkg := parts[j]
						if !strings.HasPrefix(pkg, "-") && pkg != "&&" {
							// Remove version specifiers
							if idx := strings.Index(pkg, "@"); idx != -1 {
								pkg = pkg[:idx]
							}
							packages = append(packages, pkg)
						}
					}
					break
				}
			}
		}
	}
	return packages
}

// extractPipPackages extracts pip package names from evidence
func (c *Client) extractPipPackages(evidence string) []string {
	var packages []string
	lines := strings.Split(evidence, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "pip install") {
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "install" && i+1 < len(parts) {
					// Collect remaining arguments as package names
					for j := i + 1; j < len(parts); j++ {
						pkg := parts[j]
						if !strings.HasPrefix(pkg, "-") && pkg != "&&" {
							// Remove version specifiers
							if idx := strings.Index(pkg, "=="); idx != -1 {
								pkg = pkg[:idx]
							}
							if idx := strings.Index(pkg, ">="); idx != -1 {
								pkg = pkg[:idx]
							}
							packages = append(packages, pkg)
						}
					}
					break
				}
			}
		}
	}
	return packages
}

// extractCVEIDs extracts CVE and GHSA IDs from evidence text
func (c *Client) extractCVEIDs(evidence string) []string {
	var ids []string
	
	// CVE pattern: CVE-YYYY-NNNN
	cvePattern := `CVE-\d{4}-\d{4,}`
	if matches := c.findMatches(evidence, cvePattern); len(matches) > 0 {
		ids = append(ids, matches...)
	}

	// GHSA pattern: GHSA-xxxx-xxxx-xxxx
	ghsaPattern := `GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}`
	if matches := c.findMatches(evidence, ghsaPattern); len(matches) > 0 {
		ids = append(ids, matches...)
	}

	return ids
}

// findMatches finds regex matches in text (simplified implementation)
func (c *Client) findMatches(text, pattern string) []string {
	// Simplified implementation - in real implementation, use regexp package
	var matches []string
	
	// Check for CVE pattern
	if strings.Contains(pattern, "CVE") {
		words := strings.Fields(text)
		for _, word := range words {
			if strings.HasPrefix(word, "CVE-") && len(word) >= 13 {
				matches = append(matches, word)
			}
		}
	}
	
	// Check for GHSA pattern
	if strings.Contains(pattern, "GHSA") {
		words := strings.Fields(text)
		for _, word := range words {
			if strings.HasPrefix(word, "GHSA-") && len(word) == 19 {
				matches = append(matches, word)
			}
		}
	}
	
	return matches
}

// isRelevantVulnerability checks if a vulnerability is relevant to the finding
func (c *Client) isRelevantVulnerability(vuln Vulnerability, finding rules.Finding) bool {
	// Check if vulnerability is related to the finding category
	switch finding.Category {
	case rules.MaliciousPattern:
		return strings.Contains(strings.ToLower(vuln.Summary), "malicious") ||
			   strings.Contains(strings.ToLower(vuln.Summary), "backdoor") ||
			   strings.Contains(strings.ToLower(vuln.Summary), "injection")
	case rules.SupplyChain:
		return strings.Contains(strings.ToLower(vuln.Summary), "supply") ||
			   strings.Contains(strings.ToLower(vuln.Summary), "dependency") ||
			   strings.Contains(strings.ToLower(vuln.Summary), "package")
	case rules.SecretExposure:
		return strings.Contains(strings.ToLower(vuln.Summary), "secret") ||
			   strings.Contains(strings.ToLower(vuln.Summary), "credential") ||
			   strings.Contains(strings.ToLower(vuln.Summary), "token")
	}

	// Always consider high-severity vulnerabilities relevant
	for _, severity := range vuln.Severity {
		if severity.Type == "CVSS_V3" && strings.Contains(severity.Score, "HIGH") {
			return true
		}
	}

	return false
}

// convertToVulnerabilityInfo converts OSV vulnerability to our format
func (c *Client) convertToVulnerabilityInfo(vuln Vulnerability) *VulnerabilityInfo {
	info := &VulnerabilityInfo{
		Summary:   vuln.Summary,
		Published: vuln.Published,
	}

	// Extract CVE ID from aliases
	for _, alias := range vuln.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			info.CVEID = alias
		} else if strings.HasPrefix(alias, "GHSA-") {
			info.GHSAID = alias
		}
	}

	// Extract severity information
	for _, severity := range vuln.Severity {
		if severity.Type == "CVSS_V3" {
			info.Score = severity.Score
			info.Severity = c.cvssToSeverity(severity.Score)
		}
	}

	// Extract references
	for _, ref := range vuln.References {
		info.References = append(info.References, ref.URL)
	}

	// Extract ecosystem and package info
	if len(vuln.Affected) > 0 {
		info.Ecosystem = vuln.Affected[0].Package.Ecosystem
		info.PackageName = vuln.Affected[0].Package.Name
	}

	return info
}

// cvssToSeverity converts CVSS score to severity level
func (c *Client) cvssToSeverity(score string) string {
	// Simplified CVSS to severity mapping
	if strings.Contains(score, "CRITICAL") || strings.Contains(score, "9.") || strings.Contains(score, "10.") {
		return "CRITICAL"
	}
	if strings.Contains(score, "HIGH") || strings.Contains(score, "7.") || strings.Contains(score, "8.") {
		return "HIGH"
	}
	if strings.Contains(score, "MEDIUM") || strings.Contains(score, "4.") || strings.Contains(score, "5.") || strings.Contains(score, "6.") {
		return "MEDIUM"
	}
	return "LOW"
}

// calculateBaseRiskScore calculates base risk score for a finding
func (c *Client) calculateBaseRiskScore(finding rules.Finding) int {
	score := 0
	
	switch finding.Severity {
	case rules.Critical:
		score += 40
	case rules.High:
		score += 30
	case rules.Medium:
		score += 20
	case rules.Low:
		score += 10
	case rules.Info:
		score += 5
	}

	// Category-based scoring
	switch finding.Category {
	case rules.MaliciousPattern:
		score += 20
	case rules.SecretExposure:
		score += 15
	case rules.SupplyChain:
		score += 15
	case rules.ShellObfuscation:
		score += 10
	case rules.Misconfiguration:
		score += 10
	}

	// Evidence-based scoring
	if strings.Contains(strings.ToLower(finding.Evidence), "secret") ||
	   strings.Contains(strings.ToLower(finding.Evidence), "token") ||
	   strings.Contains(strings.ToLower(finding.Evidence), "password") {
		score += 10
	}

	return score
}

// calculateEnhancedRiskScore calculates enhanced risk score with vulnerability intel
func (c *Client) calculateEnhancedRiskScore(finding rules.Finding, vulnInfo *VulnerabilityInfo) int {
	baseScore := c.calculateBaseRiskScore(finding)
	
	// Add vulnerability intelligence bonus
	switch vulnInfo.Severity {
	case "CRITICAL":
		baseScore += 30
	case "HIGH":
		baseScore += 20
	case "MEDIUM":
		baseScore += 10
	case "LOW":
		baseScore += 5
	}

	// CVE presence bonus
	if vulnInfo.CVEID != "" {
		baseScore += 15
	}

	// Recent vulnerability bonus (published within last year)
	if time.Since(vulnInfo.Published) < 365*24*time.Hour {
		baseScore += 10
	}

	// Cap at 100
	if baseScore > 100 {
		baseScore = 100
	}

	return baseScore
}

// determineIntelligenceLevel determines the intelligence level based on vulnerability info
func (c *Client) determineIntelligenceLevel(vulnInfo *VulnerabilityInfo) string {
	if vulnInfo.CVEID != "" && vulnInfo.Severity == "CRITICAL" {
		return "HIGH"
	}
	if vulnInfo.CVEID != "" || vulnInfo.Severity == "HIGH" {
		return "MEDIUM"
	}
	if vulnInfo.Summary != "" {
		return "LOW"
	}
	return "NONE"
}
