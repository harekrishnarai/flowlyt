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

package validation

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/constants"
	"github.com/harekrishnarai/flowlyt/pkg/errors"
)

// Validator handles input validation for the application
type Validator struct{}

// NewValidator creates a new input validator
func NewValidator() *Validator {
	return &Validator{}
}

// ValidateConfig validates configuration inputs
func (v *Validator) ValidateConfig(configPath string) error {
	if configPath == "" {
		return nil // No config path is valid
	}

	// Check if path is safe (no path traversal)
	if err := v.validatePathSafety(configPath); err != nil {
		return errors.NewConfigError("Invalid configuration path", err,
			"Use a relative path or absolute path without directory traversal sequences",
			"Avoid using '..' or other path traversal patterns",
		)
	}

	// Check if file exists if path is provided
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return errors.NewConfigError(fmt.Sprintf("Configuration file not found: %s", configPath), err,
			"Check the file path and ensure the configuration file exists",
			"Use a valid configuration file path or omit --config to use defaults",
		)
	}

	return nil
}

// ValidateRepository validates repository path inputs
func (v *Validator) ValidateRepository(repoPath string) error {
	if repoPath == "" {
		return nil // Empty path is valid for remote repos
	}

	// Check if path is safe
	if err := v.validatePathSafety(repoPath); err != nil {
		return errors.NewRepositoryError("Invalid repository path", err, repoPath,
			"Use a safe repository path without directory traversal",
			"Ensure the path doesn't contain malicious sequences",
		)
	}

	// Check if directory exists
	if stat, err := os.Stat(repoPath); err != nil {
		if os.IsNotExist(err) {
			return errors.NewRepositoryError(fmt.Sprintf("Repository directory not found: %s", repoPath), err, repoPath,
				"Ensure the repository directory exists",
				"Check the path spelling and permissions",
			)
		}
		return errors.NewRepositoryError(fmt.Sprintf("Cannot access repository directory: %s", repoPath), err, repoPath,
			"Check directory permissions",
			"Ensure the directory is readable",
		)
	} else if !stat.IsDir() {
		return errors.NewRepositoryError(fmt.Sprintf("Repository path is not a directory: %s", repoPath), nil, repoPath,
			"Provide a directory path, not a file path",
			"Use --workflow flag for single file analysis",
		)
	}

	return nil
}

// ValidateURL validates repository URL inputs
func (v *Validator) ValidateURL(repoURL string) error {
	if repoURL == "" {
		return nil // Empty URL is valid
	}

	// Parse URL
	parsedURL, err := url.Parse(repoURL)
	if err != nil {
		return errors.NewRepositoryError("Invalid repository URL format", err, "",
			"Provide a valid URL format (e.g., https://github.com/owner/repo)",
			"Check the URL syntax and protocol",
		)
	}

	// Validate scheme
	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
		return errors.NewRepositoryError(fmt.Sprintf("Unsupported URL scheme: %s", parsedURL.Scheme), nil, repoURL,
			"Use https:// or http:// URLs only",
			"Git+SSH URLs are not supported for security reasons",
		)
	}

	// Validate host (prevent localhost and private IPs for security)
	if v.isPrivateOrLocalhost(parsedURL.Host) {
		return errors.NewRepositoryError("Repository URL points to private/local address", nil, repoURL,
			"Use public repository URLs only",
			"Private network access is restricted for security",
		)
	}

	// Check for known Git hosting platforms
	if !v.isKnownGitHost(parsedURL.Host) {
		return errors.NewRepositoryError(fmt.Sprintf("Unknown or unsupported Git hosting platform: %s", parsedURL.Host), nil, repoURL,
			"Use supported platforms like github.com, gitlab.com, or gitlab instances",
			"Contact support if you need additional platform support",
		)
	}

	return nil
}

// ValidateWorkflowFile validates workflow file path inputs
func (v *Validator) ValidateWorkflowFile(workflowPath string) error {
	if workflowPath == "" {
		return nil // Empty path is valid
	}

	// Check if path is safe
	if err := v.validatePathSafety(workflowPath); err != nil {
		return errors.NewWorkflowError("Invalid workflow file path", err, workflowPath,
			"Use a safe file path without directory traversal",
			"Avoid using '..' or other path traversal patterns",
		)
	}

	// Check if file exists
	if stat, err := os.Stat(workflowPath); err != nil {
		if os.IsNotExist(err) {
			return errors.NewWorkflowError(fmt.Sprintf("Workflow file not found: %s", workflowPath), err, workflowPath,
				"Ensure the workflow file exists",
				"Check the file path spelling and permissions",
			)
		}
		return errors.NewWorkflowError(fmt.Sprintf("Cannot access workflow file: %s", workflowPath), err, workflowPath,
			"Check file permissions",
			"Ensure the file is readable",
		)
	} else if stat.IsDir() {
		return errors.NewWorkflowError(fmt.Sprintf("Workflow path is a directory, not a file: %s", workflowPath), nil, workflowPath,
			"Provide a file path, not a directory path",
			"Use --repo flag for directory analysis",
		)
	}

	// Validate file extension
	if !v.isValidWorkflowFile(workflowPath) {
		return errors.NewWorkflowError(fmt.Sprintf("Invalid workflow file extension: %s", workflowPath), nil, workflowPath,
			"Use workflow files with .yml or .yaml extensions",
			"Supported files: GitHub Actions (.yml/.yaml) and GitLab CI (.gitlab-ci.yml)",
		)
	}

	return nil
}

// ValidatePlatform validates platform input
func (v *Validator) ValidatePlatform(platform string) error {
	if platform == "" {
		return errors.NewValidationError("Platform cannot be empty", "platform", platform,
			fmt.Sprintf("Use one of: %s", strings.Join(constants.SupportedPlatforms, ", ")),
		)
	}

	// Check if platform is supported
	for _, supported := range constants.SupportedPlatforms {
		if platform == supported {
			return nil
		}
	}

	return errors.ErrUnsupportedPlatform(platform, constants.SupportedPlatforms)
}

// ValidateOutputFormat validates output format input
func (v *Validator) ValidateOutputFormat(format string) error {
	if format == "" {
		return nil // Empty format will use default
	}

	// Check if format is supported
	for _, supported := range constants.SupportedOutputFormats {
		if format == supported {
			return nil
		}
	}

	return errors.ErrInvalidOutputFormat(format, constants.SupportedOutputFormats)
}

// ValidateOutputFile validates output file path
func (v *Validator) ValidateOutputFile(outputPath string) error {
	if outputPath == "" {
		return nil // Empty path is valid (stdout)
	}

	// Check if path is safe
	if err := v.validatePathSafety(outputPath); err != nil {
		return errors.NewReportError("Invalid output file path", err, outputPath,
			"Use a safe file path without directory traversal",
			"Avoid using '..' or other path traversal patterns",
		)
	}

	// Check if directory exists (create if needed)
	dir := filepath.Dir(outputPath)
	if dir != "." && dir != "" {
		if stat, err := os.Stat(dir); err != nil {
			if os.IsNotExist(err) {
				// Try to create directory
				if err := os.MkdirAll(dir, 0755); err != nil {
					return errors.NewReportError(fmt.Sprintf("Cannot create output directory: %s", dir), err, outputPath,
						"Ensure you have write permissions",
						"Check the directory path and permissions",
					)
				}
			} else {
				return errors.NewReportError(fmt.Sprintf("Cannot access output directory: %s", dir), err, outputPath,
					"Check directory permissions",
					"Ensure the directory is accessible",
				)
			}
		} else if !stat.IsDir() {
			return errors.NewReportError(fmt.Sprintf("Output path parent is not a directory: %s", dir), nil, outputPath,
				"Ensure the parent path is a directory",
				"Check the output file path structure",
			)
		}
	}

	return nil
}

// ValidateSeverity validates severity level input
func (v *Validator) ValidateSeverity(severity string) error {
	if severity == "" {
		return nil // Empty severity will use default
	}

	// Check if severity level is valid
	if _, exists := constants.SeverityLevels[severity]; !exists {
		validSeverities := make([]string, 0, len(constants.SeverityLevels))
		for sev := range constants.SeverityLevels {
			validSeverities = append(validSeverities, sev)
		}
		return errors.NewValidationError(fmt.Sprintf("Invalid severity level: %s", severity), "severity", severity,
			fmt.Sprintf("Use one of: %s", strings.Join(validSeverities, ", ")),
		)
	}

	return nil
}

// ValidateEntropyThreshold validates entropy threshold input
func (v *Validator) ValidateEntropyThreshold(threshold float64) error {
	if threshold < 0 || threshold > 8 {
		return errors.NewValidationError("Entropy threshold out of range", "entropy-threshold", threshold,
			"Use a value between 0.0 and 8.0",
			"Typical values: 3.0-4.0 (low sensitivity), 4.0-5.0 (medium), 5.0+ (high)",
		)
	}
	return nil
}

// Helper methods

// validatePathSafety checks for path traversal and other unsafe patterns
func (v *Validator) validatePathSafety(path string) error {
	// Clean the path and check for traversal
	cleanPath := filepath.Clean(path)
	cleanPathUnix := filepath.ToSlash(cleanPath)
	isAbsolute := filepath.IsAbs(cleanPath) || strings.HasPrefix(cleanPathUnix, "/")

	// Check for directory traversal patterns
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("path contains directory traversal sequence")
	}

	// Check for absolute paths trying to access system directories
	if isAbsolute {
		// Allow certain safe absolute paths but reject system directories
		dangerousPaths := []string{"/etc", "/sys", "/proc", "/dev", "/root", "/usr", "/bin", "/sbin"}
		for _, dangerous := range dangerousPaths {
			if strings.HasPrefix(cleanPathUnix, dangerous) {
				return fmt.Errorf("path accesses restricted system directory")
			}
		}

		// Special handling for /var - allow temp directories but block others
		if strings.HasPrefix(cleanPathUnix, "/var") {
			// Allow /var/folders (macOS temp), /var/tmp, etc.
			allowedVarPaths := []string{"/var/folders", "/var/tmp"}
			allowed := false
			for _, allowedPath := range allowedVarPaths {
				if strings.HasPrefix(cleanPathUnix, allowedPath) {
					allowed = true
					break
				}
			}
			if !allowed {
				return fmt.Errorf("path accesses restricted system directory")
			}
		}
	}

	// Check for null bytes or other control characters
	if strings.ContainsAny(path, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f") {
		return fmt.Errorf("path contains invalid characters")
	}

	return nil
}

// isPrivateOrLocalhost checks if a host is private or localhost
func (v *Validator) isPrivateOrLocalhost(host string) bool {
	// Remove port if present
	if colonIndex := strings.LastIndex(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}

	// Check for localhost variants
	localhost := []string{"localhost", "127.0.0.1", "::1", "0.0.0.0"}
	for _, local := range localhost {
		if host == local {
			return true
		}
	}

	// Check for private IP ranges (simplified check)
	privatePatterns := []string{
		"10\\.", "192\\.168\\.", "172\\.(1[6-9]|2[0-9]|3[01])\\.",
		"169\\.254\\.", // Link-local
	}

	for _, pattern := range privatePatterns {
		if matched, _ := regexp.MatchString("^"+pattern, host); matched {
			return true
		}
	}

	return false
}

// isKnownGitHost checks if the host is a known Git hosting platform
func (v *Validator) isKnownGitHost(host string) bool {
	// Remove port if present
	if colonIndex := strings.LastIndex(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}

	knownHosts := []string{
		"github.com",
		"gitlab.com",
		"bitbucket.org",
		"dev.azure.com",
		"ssh.dev.azure.com",
		"source.developers.google.com",
	}

	for _, known := range knownHosts {
		if host == known {
			return true
		}
	}

	// Check for GitLab instances (common patterns)
	gitlabPatterns := []string{
		"gitlab\\.",    // gitlab.company.com
		"\\.gitlab\\.", // sub.gitlab.company.com
	}

	for _, pattern := range gitlabPatterns {
		if matched, _ := regexp.MatchString(pattern, host); matched {
			return true
		}
	}

	return false
}

// isValidWorkflowFile checks if the file has a valid workflow extension
func (v *Validator) isValidWorkflowFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))

	// Check for common workflow file patterns
	validPatterns := []string{
		".yml", ".yaml", // Generic YAML files
		".gitlab-ci.yml", // GitLab CI specific
	}

	for _, pattern := range validPatterns {
		if ext == pattern || base == pattern {
			return true
		}
	}

	return false
}
