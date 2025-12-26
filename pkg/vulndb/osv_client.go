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

package vulndb

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// OSVClient provides access to the OSV.dev vulnerability database
type OSVClient struct {
	client    *http.Client
	cache     *VulnerabilityCache
	apiURL    string
	userAgent string
}

// NewOSVClient creates a new OSV.dev API client
func NewOSVClient(cacheDir string) *OSVClient {
	return &OSVClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache:     NewVulnerabilityCache(cacheDir),
		apiURL:    "https://api.osv.dev/v1",
		userAgent: "Flowlyt-Security-Scanner/1.0",
	}
}

// VulnerabilityCache manages local caching of vulnerability data
type VulnerabilityCache struct {
	cacheDir string
	ttl      time.Duration
}

// NewVulnerabilityCache creates a new vulnerability cache
func NewVulnerabilityCache(cacheDir string) *VulnerabilityCache {
	return &VulnerabilityCache{
		cacheDir: cacheDir,
		ttl:      24 * time.Hour, // Cache for 24 hours
	}
}

// Enhanced OSV structures with more detailed information
type OSVQuery struct {
	Package *OSVPackage `json:"package,omitempty"`
	Version string      `json:"version,omitempty"`
	Commit  string      `json:"commit,omitempty"`
}

type OSVPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl,omitempty"`
}

type OSVDetailedResponse struct {
	Vulns []OSVDetailedVulnerability `json:"vulns"`
}

type OSVDetailedVulnerability struct {
	SchemaVersion    string                 `json:"schema_version"`
	ID               string                 `json:"id"`
	Modified         string                 `json:"modified"`
	Published        string                 `json:"published"`
	Withdrawn        string                 `json:"withdrawn,omitempty"`
	Aliases          []string               `json:"aliases"`
	Related          []string               `json:"related"`
	Summary          string                 `json:"summary"`
	Details          string                 `json:"details"`
	Severity         []OSVSeverity          `json:"severity"`
	Affected         []OSVAffected          `json:"affected"`
	References       []OSVReference         `json:"references"`
	Credits          []OSVCredit            `json:"credits"`
	DatabaseSpecific map[string]interface{} `json:"database_specific"`
}

type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type OSVAffected struct {
	Package           OSVPackage    `json:"package"`
	Severity          []OSVSeverity `json:"severity"`
	Ranges            []OSVRange    `json:"ranges"`
	Versions          []string      `json:"versions"`
	EcosystemSpecific interface{}   `json:"ecosystem_specific"`
	DatabaseSpecific  interface{}   `json:"database_specific"`
}

type OSVRange struct {
	Type       string     `json:"type"`
	Repo       string     `json:"repo,omitempty"`
	Introduced string     `json:"introduced,omitempty"`
	Fixed      string     `json:"fixed,omitempty"`
	Events     []OSVEvent `json:"events"`
}

type OSVEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

type OSVReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type OSVCredit struct {
	Name    string   `json:"name"`
	Contact []string `json:"contact"`
	Type    string   `json:"type"`
}

// PURL (Package URL) parsing and generation
type PURL struct {
	Type       string            `json:"type"`
	Namespace  string            `json:"namespace,omitempty"`
	Name       string            `json:"name"`
	Version    string            `json:"version,omitempty"`
	Qualifiers map[string]string `json:"qualifiers,omitempty"`
	Subpath    string            `json:"subpath,omitempty"`
}

// ParseActionToPURL converts a GitHub Action reference to a PURL
func ParseActionToPURL(actionRef string) *PURL {
	// actionRef format: "owner/repo@version" or "owner/repo/path@version"
	parts := strings.Split(actionRef, "@")
	if len(parts) == 0 {
		return nil
	}

	actionPath := parts[0]
	version := ""
	if len(parts) > 1 {
		version = parts[1]
	}

	// Split action path
	pathParts := strings.Split(actionPath, "/")
	if len(pathParts) < 2 {
		return nil
	}

	namespace := pathParts[0]
	name := pathParts[1]
	subpath := ""

	if len(pathParts) > 2 {
		subpath = strings.Join(pathParts[2:], "/")
	}

	return &PURL{
		Type:      "github",
		Namespace: namespace,
		Name:      name,
		Version:   version,
		Subpath:   subpath,
	}
}

// ToPURLString converts a PURL to its string representation
func (p *PURL) ToPURLString() string {
	purl := fmt.Sprintf("pkg:%s/%s/%s", p.Type, p.Namespace, p.Name)

	if p.Version != "" {
		purl += "@" + p.Version
	}

	if p.Subpath != "" {
		purl += "#" + p.Subpath
	}

	// Add qualifiers if present
	if len(p.Qualifiers) > 0 {
		purl += "?"
		var quals []string
		for k, v := range p.Qualifiers {
			quals = append(quals, k+"="+v)
		}
		purl += strings.Join(quals, "&")
	}

	return purl
}

// QueryVulnerabilities queries OSV.dev for vulnerabilities
func (c *OSVClient) QueryVulnerabilities(actionRef string) ([]OSVDetailedVulnerability, error) {
	// Convert action to PURL for precise identification
	purl := ParseActionToPURL(actionRef)
	if purl == nil {
		return nil, fmt.Errorf("invalid action reference: %s", actionRef)
	}

	// Check cache first
	cacheKey := c.generateCacheKey(actionRef)
	if cached, found := c.cache.Get(cacheKey); found {
		return cached, nil
	}

	// Query OSV.dev API
	query := OSVQuery{
		Package: &OSVPackage{
			Ecosystem: "GitHub Actions",
			Name:      fmt.Sprintf("%s/%s", purl.Namespace, purl.Name),
			PURL:      purl.ToPURLString(),
		},
	}

	if purl.Version != "" {
		query.Version = purl.Version
	}

	vulns, err := c.queryOSVAPI(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query OSV.dev: %w", err)
	}

	// Cache the results
	c.cache.Set(cacheKey, vulns)

	return vulns, nil
}

// queryOSVAPI performs the actual API call to OSV.dev
func (c *OSVClient) queryOSVAPI(query OSVQuery) ([]OSVDetailedVulnerability, error) {
	queryJSON, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", c.apiURL+"/query", strings.NewReader(string(queryJSON)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV.dev API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var osvResp OSVDetailedResponse
	if err := json.Unmarshal(body, &osvResp); err != nil {
		return nil, err
	}

	return osvResp.Vulns, nil
}

// QueryVulnerabilityByID queries a specific vulnerability by its ID
func (c *OSVClient) QueryVulnerabilityByID(vulnID string) (*OSVDetailedVulnerability, error) {
	// Check cache first
	cacheKey := "vuln_" + vulnID
	if cached, found := c.cache.GetSingle(cacheKey); found {
		return &cached, nil
	}

	req, err := http.NewRequest("GET", c.apiURL+"/vulns/"+vulnID, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV.dev API returned status %d for vulnerability %s", resp.StatusCode, vulnID)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var vuln OSVDetailedVulnerability
	if err := json.Unmarshal(body, &vuln); err != nil {
		return nil, err
	}

	// Cache the result
	c.cache.SetSingle(cacheKey, vuln)

	return &vuln, nil
}

// Cache management methods
func (c *OSVClient) generateCacheKey(actionRef string) string {
	hash := sha256.Sum256([]byte(actionRef))
	return hex.EncodeToString(hash[:])
}

// Get retrieves cached vulnerabilities
func (vc *VulnerabilityCache) Get(key string) ([]OSVDetailedVulnerability, bool) {
	if vc.cacheDir == "" {
		return nil, false
	}

	cachePath := filepath.Join(vc.cacheDir, key+".json")

	// Check if cache file exists and is not expired
	if stat, err := os.Stat(cachePath); err != nil || time.Since(stat.ModTime()) > vc.ttl {
		return nil, false
	}

	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, false
	}

	var vulns []OSVDetailedVulnerability
	if err := json.Unmarshal(data, &vulns); err != nil {
		return nil, false
	}

	return vulns, true
}

// Set stores vulnerabilities in cache
func (vc *VulnerabilityCache) Set(key string, vulns []OSVDetailedVulnerability) {
	if vc.cacheDir == "" {
		return
	}

	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(vc.cacheDir, 0755); err != nil {
		return
	}

	cachePath := filepath.Join(vc.cacheDir, key+".json")

	data, err := json.Marshal(vulns)
	if err != nil {
		return
	}

	os.WriteFile(cachePath, data, 0644)
}

// GetSingle retrieves a single cached vulnerability
func (vc *VulnerabilityCache) GetSingle(key string) (OSVDetailedVulnerability, bool) {
	vulns, found := vc.Get(key)
	if !found || len(vulns) == 0 {
		return OSVDetailedVulnerability{}, false
	}
	return vulns[0], true
}

// SetSingle stores a single vulnerability in cache
func (vc *VulnerabilityCache) SetSingle(key string, vuln OSVDetailedVulnerability) {
	vc.Set(key, []OSVDetailedVulnerability{vuln})
}

// ClearExpired removes expired cache entries
func (vc *VulnerabilityCache) ClearExpired() error {
	if vc.cacheDir == "" {
		return nil
	}

	entries, err := os.ReadDir(vc.cacheDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			filePath := filepath.Join(vc.cacheDir, entry.Name())
			if stat, err := os.Stat(filePath); err == nil {
				if time.Since(stat.ModTime()) > vc.ttl {
					os.Remove(filePath)
				}
			}
		}
	}

	return nil
}

// Advanced vulnerability analysis methods
func (c *OSVClient) AnalyzeActionSecurity(actionRef string) (*ActionSecurityAnalysis, error) {
	vulns, err := c.QueryVulnerabilities(actionRef)
	if err != nil {
		return nil, err
	}

	analysis := &ActionSecurityAnalysis{
		ActionRef:       actionRef,
		PURL:            ParseActionToPURL(actionRef),
		Vulnerabilities: vulns,
		AnalyzedAt:      time.Now(),
	}

	// Calculate risk score
	analysis.RiskScore = c.calculateRiskScore(vulns)
	analysis.RiskLevel = c.determineRiskLevel(analysis.RiskScore)

	// Extract actionable information
	analysis.Summary = c.generateSecuritySummary(vulns)
	analysis.Recommendations = c.generateRecommendations(actionRef, vulns)

	return analysis, nil
}

type ActionSecurityAnalysis struct {
	ActionRef       string                     `json:"action_ref"`
	PURL            *PURL                      `json:"purl"`
	Vulnerabilities []OSVDetailedVulnerability `json:"vulnerabilities"`
	RiskScore       float64                    `json:"risk_score"`
	RiskLevel       string                     `json:"risk_level"`
	Summary         string                     `json:"summary"`
	Recommendations []string                   `json:"recommendations"`
	AnalyzedAt      time.Time                  `json:"analyzed_at"`
}

func (c *OSVClient) calculateRiskScore(vulns []OSVDetailedVulnerability) float64 {
	if len(vulns) == 0 {
		return 0.0
	}

	totalScore := 0.0
	for _, vuln := range vulns {
		// Parse CVSS scores if available
		for _, severity := range vuln.Severity {
			if severity.Type == "CVSS_V3" {
				if score := parseCVSSScore(severity.Score); score > 0 {
					totalScore += score
				}
			}
		}
	}

	// If no CVSS scores, use count-based scoring
	if totalScore == 0 {
		totalScore = float64(len(vulns)) * 5.0 // Default medium severity
	}

	return totalScore / float64(len(vulns))
}

func (c *OSVClient) determineRiskLevel(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "NONE"
	}
}

func (c *OSVClient) generateSecuritySummary(vulns []OSVDetailedVulnerability) string {
	if len(vulns) == 0 {
		return "No known vulnerabilities found"
	}

	if len(vulns) == 1 {
		return fmt.Sprintf("1 vulnerability found: %s", vulns[0].Summary)
	}

	return fmt.Sprintf("%d vulnerabilities found, including: %s", len(vulns), vulns[0].Summary)
}

func (c *OSVClient) generateRecommendations(actionRef string, vulns []OSVDetailedVulnerability) []string {
	var recommendations []string

	if len(vulns) == 0 {
		recommendations = append(recommendations, "Consider pinning to a specific SHA for supply chain security")
		return recommendations
	}

	recommendations = append(recommendations, "Update to the latest version of this action")
	recommendations = append(recommendations, "Review the vulnerability details and assess impact on your workflow")

	// Check if action is pinned
	if !strings.Contains(actionRef, "@") || !isValidSHA(strings.Split(actionRef, "@")[1]) {
		recommendations = append(recommendations, "Pin the action to a specific commit SHA to prevent supply chain attacks")
	}

	// Add specific recommendations based on vulnerability types
	for _, vuln := range vulns {
		if strings.Contains(strings.ToLower(vuln.Summary), "injection") {
			recommendations = append(recommendations, "Review input validation and sanitization in your workflow")
			break
		}
	}

	return recommendations
}

// Helper functions
func parseCVSSScore(cvssString string) float64 {
	// Extract numeric score from CVSS string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	re := regexp.MustCompile(`CVSS:\d+\.\d+/.*`)
	if !re.MatchString(cvssString) {
		return 0.0
	}

	// This is a simplified parser - in practice, you'd want a full CVSS calculator
	// For now, we'll estimate based on impact ratings
	highCount := strings.Count(cvssString, ":H")
	mediumCount := strings.Count(cvssString, ":M")
	lowCount := strings.Count(cvssString, ":L")

	if highCount >= 2 {
		return 8.5 // High
	} else if highCount >= 1 || mediumCount >= 2 {
		return 6.0 // Medium
	} else if mediumCount >= 1 || lowCount >= 1 {
		return 3.0 // Low
	}

	return 5.0 // Default medium
}

func isValidSHA(version string) bool {
	// Check if version looks like a git SHA (40 hex characters)
	matched, _ := regexp.MatchString(`^[a-f0-9]{40}$`, version)
	return matched
}
