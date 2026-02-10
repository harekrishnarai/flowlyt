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

package github

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// sanitizeGitError removes sensitive information (tokens, credentials) from git error messages
func sanitizeGitError(output []byte, err error) error {
	if err == nil {
		return nil
	}

	outputStr := string(output)

	// Remove tokens from URLs (https://TOKEN@github.com)
	sanitized := regexp.MustCompile(`https://[^@\s]+@`).ReplaceAllString(outputStr, "https://***@")

	// Remove x-access-token patterns
	sanitized = regexp.MustCompile(`x-access-token:[^@\s]+`).ReplaceAllString(sanitized, "x-access-token:***")

	// Remove any standalone tokens (40 character hex strings that look like tokens)
	sanitized = regexp.MustCompile(`\b[a-f0-9]{40}\b`).ReplaceAllString(sanitized, "***")

	// Remove GitHub personal access tokens (ghp_*, gho_*, etc.)
	sanitized = regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]+`).ReplaceAllString(sanitized, "gh*_***")

	// Truncate if too long
	if len(sanitized) > 500 {
		sanitized = sanitized[:500] + "... (truncated)"
	}

	return fmt.Errorf("git operation failed: %w\nSanitized output: %s", err, sanitized)
}

// setupGitCredentialHelper configures git to use credential helper for authentication
// This is more secure than embedding tokens in URLs
func setupGitCredentialHelper(token string) error {
	if token == "" {
		return nil
	}

	// Create a temporary credential helper script
	// This is safer than embedding tokens in clone URLs
	cmd := exec.Command("git", "config", "--global", "credential.helper", "cache --timeout=300")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to configure git credential helper: %w", err)
	}

	// Alternatively, use git credential fill
	return configureGitCredentials(token)
}

// configureGitCredentials sets up git credentials without exposing them in command line
func configureGitCredentials(token string) error {
	// Use git credential approve to store credentials securely
	cmd := exec.Command("git", "credential", "approve")

	// Build credential input
	credentialInput := fmt.Sprintf("protocol=https\nhost=github.com\nusername=x-access-token\npassword=%s\n", token)

	cmd.Stdin = strings.NewReader(credentialInput)

	// Capture output but don't log it (might contain sensitive data)
	if err := cmd.Run(); err != nil {
		// Don't include error details as they might leak credentials
		return fmt.Errorf("failed to configure git credentials")
	}

	return nil
}

// getSecureCloneURL returns a clone URL without embedded credentials
func getSecureCloneURL(owner, repo string) string {
	return fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)
}

// cleanupGitCredentials removes stored credentials after use
func cleanupGitCredentials() error {
	cmd := exec.Command("git", "credential", "reject")
	cmd.Stdin = strings.NewReader("protocol=https\nhost=github.com\n")

	// Ignore errors on cleanup
	_ = cmd.Run()
	return nil
}

// isTokenInEnvironment checks if GitHub token is available in environment
// without exposing the actual token value
func isTokenInEnvironment() bool {
	token := os.Getenv("GITHUB_TOKEN")
	return token != "" && len(token) > 0
}
