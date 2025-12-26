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

package ast

import (
	"fmt"
	"regexp"
	"strings"
)

// ActionAnalyzer provides analysis capabilities for GitHub Actions
type ActionAnalyzer struct {
	knownActions     map[string]*ActionMetadata
	marketplaceCache map[string]*ActionMetadata
	customActions    map[string]*ActionMetadata
}

// ActionMetadata contains information about an action's behavior
type ActionMetadata struct {
	Name             string
	Source           string // "marketplace", "custom", "local"
	TrustedVendor    bool   // Whether this is from a trusted vendor
	DataFlowRisks    []string
	Permissions      []string
	OutputPatterns   []string
	InputPatterns    []string
	ShellAccess      bool
	NetworkAccess    bool
	FileSystemAccess bool
	Secrets          []string // Secrets this action typically uses
}

// NewActionAnalyzer creates a new action analyzer with built-in knowledge
func NewActionAnalyzer() *ActionAnalyzer {
	analyzer := &ActionAnalyzer{
		knownActions:     make(map[string]*ActionMetadata),
		marketplaceCache: make(map[string]*ActionMetadata),
		customActions:    make(map[string]*ActionMetadata),
	}

	// Initialize with known action patterns
	analyzer.initializeKnownActions()
	return analyzer
}

// initializeKnownActions sets up metadata for common GitHub Actions
func (aa *ActionAnalyzer) initializeKnownActions() {
	// GitHub official actions
	aa.knownActions["actions/checkout"] = &ActionMetadata{
		Name:             "Checkout",
		Source:           "marketplace",
		TrustedVendor:    true,
		DataFlowRisks:    []string{"repository_access"},
		Permissions:      []string{"contents:read"},
		OutputPatterns:   []string{"workspace_path"},
		FileSystemAccess: true,
		NetworkAccess:    true,
	}

	aa.knownActions["actions/setup-node"] = &ActionMetadata{
		Name:             "Setup Node.js",
		Source:           "marketplace",
		TrustedVendor:    true,
		DataFlowRisks:    []string{"package_installation"},
		Permissions:      []string{"contents:read"},
		FileSystemAccess: true,
		NetworkAccess:    true,
	}

	aa.knownActions["actions/setup-python"] = &ActionMetadata{
		Name:             "Setup Python",
		Source:           "marketplace",
		TrustedVendor:    true,
		DataFlowRisks:    []string{"package_installation"},
		Permissions:      []string{"contents:read"},
		FileSystemAccess: true,
		NetworkAccess:    true,
	}

	aa.knownActions["actions/upload-artifact"] = &ActionMetadata{
		Name:             "Upload Artifact",
		Source:           "marketplace",
		TrustedVendor:    true,
		DataFlowRisks:    []string{"artifact_upload", "data_persistence"},
		Permissions:      []string{"actions:write"},
		InputPatterns:    []string{"name", "path"},
		FileSystemAccess: true,
		NetworkAccess:    true,
	}

	aa.knownActions["actions/download-artifact"] = &ActionMetadata{
		Name:             "Download Artifact",
		Source:           "marketplace",
		TrustedVendor:    true,
		DataFlowRisks:    []string{"artifact_download", "data_retrieval"},
		Permissions:      []string{"actions:read"},
		OutputPatterns:   []string{"download-path"},
		FileSystemAccess: true,
		NetworkAccess:    true,
	}

	// Third-party but popular actions
	aa.knownActions["docker/build-push-action"] = &ActionMetadata{
		Name:             "Docker Build and Push",
		Source:           "marketplace",
		TrustedVendor:    true,
		DataFlowRisks:    []string{"docker_registry_push", "credential_exposure"},
		Permissions:      []string{"packages:write"},
		InputPatterns:    []string{"registry", "username", "password"},
		Secrets:          []string{"DOCKER_USERNAME", "DOCKER_PASSWORD"},
		NetworkAccess:    true,
		FileSystemAccess: true,
	}

	aa.knownActions["aws-actions/configure-aws-credentials"] = &ActionMetadata{
		Name:           "Configure AWS Credentials",
		Source:         "marketplace",
		TrustedVendor:  true,
		DataFlowRisks:  []string{"credential_configuration", "cloud_access"},
		InputPatterns:  []string{"aws-access-key-id", "aws-secret-access-key"},
		Secrets:        []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"},
		OutputPatterns: []string{"aws-account-id"},
		NetworkAccess:  true,
	}
}

// AnalyzeAction analyzes a specific action usage in a step
func (aa *ActionAnalyzer) AnalyzeAction(step *StepNode) (*ActionAnalysis, error) {
	if step.Uses == "" {
		return nil, fmt.Errorf("step does not use an action")
	}

	analysis := &ActionAnalysis{
		ActionName: step.Uses,
		Step:       step,
		Risks:      []string{},
		Metadata:   nil,
	}

	// Parse action reference
	actionRef, err := aa.parseActionReference(step.Uses)
	if err != nil {
		return nil, fmt.Errorf("failed to parse action reference: %w", err)
	}

	// Get or fetch action metadata
	metadata := aa.getActionMetadata(actionRef)
	analysis.Metadata = metadata

	// Analyze security risks
	risks := aa.analyzeSecurityRisks(step, metadata)
	analysis.Risks = risks

	// Analyze data flow implications
	dataFlowRisks := aa.analyzeDataFlowRisks(step, metadata)
	analysis.DataFlowRisks = dataFlowRisks

	return analysis, nil
}

// ActionReference represents a parsed action reference
type ActionReference struct {
	Owner      string
	Repository string
	Path       string // For actions in subdirectories
	Ref        string // Version, tag, or commit
	IsLocal    bool   // Whether it's a local action (./path)
	IsDocker   bool   // Whether it's a Docker action (docker://)
}

// ActionAnalysis contains the results of analyzing an action
type ActionAnalysis struct {
	ActionName    string
	Step          *StepNode
	Metadata      *ActionMetadata
	Risks         []string
	DataFlowRisks []string
}

// parseActionReference parses action references like "actions/checkout@v3"
func (aa *ActionAnalyzer) parseActionReference(uses string) (*ActionReference, error) {
	ref := &ActionReference{}

	// Handle local actions
	if strings.HasPrefix(uses, "./") {
		ref.IsLocal = true
		ref.Path = uses
		return ref, nil
	}

	// Handle Docker actions
	if strings.HasPrefix(uses, "docker://") {
		ref.IsDocker = true
		ref.Repository = uses
		return ref, nil
	}

	// Parse standard GitHub action reference
	// Format: owner/repo@ref or owner/repo/path@ref
	atIndex := strings.LastIndex(uses, "@")
	if atIndex == -1 {
		return nil, fmt.Errorf("invalid action reference format: %s", uses)
	}

	actionPath := uses[:atIndex]
	ref.Ref = uses[atIndex+1:]

	// Split owner/repo/path
	parts := strings.Split(actionPath, "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid action path format: %s", actionPath)
	}

	ref.Owner = parts[0]
	ref.Repository = parts[1]

	if len(parts) > 2 {
		ref.Path = strings.Join(parts[2:], "/")
	}

	return ref, nil
}

// getActionMetadata retrieves or creates metadata for an action
func (aa *ActionAnalyzer) getActionMetadata(ref *ActionReference) *ActionMetadata {
	actionKey := aa.getActionKey(ref)

	// Check known actions first
	if metadata, exists := aa.knownActions[actionKey]; exists {
		return metadata
	}

	// Check marketplace cache
	if metadata, exists := aa.marketplaceCache[actionKey]; exists {
		return metadata
	}

	// Create default metadata for unknown actions
	metadata := &ActionMetadata{
		Name:          ref.Owner + "/" + ref.Repository,
		Source:        aa.determineActionSource(ref),
		TrustedVendor: aa.isTrustedVendor(ref.Owner),
		DataFlowRisks: []string{"unknown_behavior"},
		// Assume potentially risky for unknown actions
		ShellAccess:      true,
		NetworkAccess:    true,
		FileSystemAccess: true,
	}

	// Cache the metadata
	aa.marketplaceCache[actionKey] = metadata

	return metadata
}

// getActionKey creates a unique key for an action
func (aa *ActionAnalyzer) getActionKey(ref *ActionReference) string {
	if ref.IsLocal {
		return ref.Path
	}

	if ref.IsDocker {
		return ref.Repository
	}

	key := ref.Owner + "/" + ref.Repository
	if ref.Path != "" {
		key += "/" + ref.Path
	}

	return key
}

// determineActionSource determines whether an action is from marketplace, custom, etc.
func (aa *ActionAnalyzer) determineActionSource(ref *ActionReference) string {
	if ref.IsLocal {
		return "local"
	}

	if ref.IsDocker {
		return "docker"
	}

	// Well-known organizations
	trustedOrgs := []string{"actions", "github", "microsoft", "azure", "aws-actions", "docker"}
	for _, org := range trustedOrgs {
		if ref.Owner == org {
			return "marketplace"
		}
	}

	return "custom"
}

// isTrustedVendor checks if an action owner is from a trusted vendor
func (aa *ActionAnalyzer) isTrustedVendor(owner string) bool {
	trustedVendors := []string{
		"actions", "github", "microsoft", "azure", "aws-actions",
		"docker", "google-github-actions", "hashicorp",
	}

	for _, vendor := range trustedVendors {
		if owner == vendor {
			return true
		}
	}

	return false
}

// analyzeSecurityRisks identifies security risks in action usage
func (aa *ActionAnalyzer) analyzeSecurityRisks(step *StepNode, metadata *ActionMetadata) []string {
	risks := []string{}

	// Untrusted vendor risk
	if !metadata.TrustedVendor {
		risks = append(risks, "untrusted_vendor")
	}

	// Version pinning risk
	if aa.hasVersionPinningRisk(step.Uses) {
		risks = append(risks, "unpinned_version")
	}

	// Credential exposure risk
	if aa.hasCredentialExposureRisk(step, metadata) {
		risks = append(risks, "credential_exposure")
	}

	// Privilege escalation risk
	if aa.hasPrivilegeEscalationRisk(step, metadata) {
		risks = append(risks, "privilege_escalation")
	}

	return risks
}

// hasVersionPinningRisk checks if the action version is not properly pinned
func (aa *ActionAnalyzer) hasVersionPinningRisk(uses string) bool {
	// Extract version part
	atIndex := strings.LastIndex(uses, "@")
	if atIndex == -1 {
		return true // No version specified
	}

	version := uses[atIndex+1:]

	// Risky version patterns
	riskyPatterns := []string{"main", "master", "latest", "dev", "development"}
	for _, pattern := range riskyPatterns {
		if version == pattern {
			return true
		}
	}

	// Check for major version only (e.g., v1, v2)
	majorVersionPattern := regexp.MustCompile(`^v\d+$`)
	if majorVersionPattern.MatchString(version) {
		return true
	}

	return false
}

// hasCredentialExposureRisk checks if credentials might be exposed
func (aa *ActionAnalyzer) hasCredentialExposureRisk(step *StepNode, metadata *ActionMetadata) bool {
	// Check for secrets in action inputs
	for key, value := range step.With {
		if aa.looksLikeSecret(key) || aa.looksLikeSecret(value) {
			return true
		}
	}

	// Check known secrets for this action
	for _, secret := range metadata.Secrets {
		if _, exists := step.With[strings.ToLower(secret)]; exists {
			return true
		}
	}

	return false
}

// hasPrivilegeEscalationRisk checks for privilege escalation risks
func (aa *ActionAnalyzer) hasPrivilegeEscalationRisk(step *StepNode, metadata *ActionMetadata) bool {
	// Docker actions have inherent privilege risks
	if strings.HasPrefix(step.Uses, "docker://") {
		return true
	}

	// Actions with shell access and unknown behavior
	if metadata.ShellAccess && metadata.Source == "custom" {
		return true
	}

	// Check for privileged permissions
	for _, permission := range metadata.Permissions {
		if strings.Contains(permission, "write") || strings.Contains(permission, "admin") {
			return true
		}
	}

	return false
}

// analyzeDataFlowRisks identifies data flow risks specific to the action
func (aa *ActionAnalyzer) analyzeDataFlowRisks(step *StepNode, metadata *ActionMetadata) []string {
	risks := []string{}

	// Add metadata risks
	risks = append(risks, metadata.DataFlowRisks...)

	// Analyze input/output patterns
	if aa.hasDataExfiltrationRisk(step, metadata) {
		risks = append(risks, "data_exfiltration")
	}

	if aa.hasArtifactRisk(step, metadata) {
		risks = append(risks, "artifact_manipulation")
	}

	return risks
}

// hasDataExfiltrationRisk checks for data exfiltration patterns
func (aa *ActionAnalyzer) hasDataExfiltrationRisk(step *StepNode, metadata *ActionMetadata) bool {
	// Network access + custom action = potential risk
	if metadata.NetworkAccess && !metadata.TrustedVendor {
		return true
	}

	// Check for external URLs in inputs
	for _, value := range step.With {
		if aa.containsExternalURL(value) {
			return true
		}
	}

	return false
}

// hasArtifactRisk checks for artifact manipulation risks
func (aa *ActionAnalyzer) hasArtifactRisk(step *StepNode, metadata *ActionMetadata) bool {
	artifactActions := []string{"upload-artifact", "download-artifact"}

	for _, action := range artifactActions {
		if strings.Contains(step.Uses, action) {
			return true
		}
	}

	return false
}

// Helper functions

// looksLikeSecret checks if a string looks like it contains secret data
func (aa *ActionAnalyzer) looksLikeSecret(value string) bool {
	secretPatterns := []string{
		"secret", "token", "key", "password", "pass", "credential",
		"auth", "api", "private", "cert", "certificate",
	}

	lowerValue := strings.ToLower(value)
	for _, pattern := range secretPatterns {
		if strings.Contains(lowerValue, pattern) {
			return true
		}
	}

	return false
}

// containsExternalURL checks if a value contains an external URL
func (aa *ActionAnalyzer) containsExternalURL(value string) bool {
	urlPattern := regexp.MustCompile(`https?://[^\s]+`)
	matches := urlPattern.FindAllString(value, -1)

	for _, match := range matches {
		// Skip trusted domains
		trustedDomains := []string{"github.com", "githubusercontent.com", "api.github.com"}
		isTrusted := false
		for _, domain := range trustedDomains {
			if strings.Contains(match, domain) {
				isTrusted = true
				break
			}
		}

		if !isTrusted {
			return true
		}
	}

	return false
}
