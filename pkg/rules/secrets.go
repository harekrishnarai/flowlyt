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

package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/linenum"
	"github.com/harekrishnarai/flowlyt/pkg/parser"
)

// checkHardcodedSecrets checks for potential secrets in workflow files
func checkHardcodedSecrets(workflow parser.WorkflowFile) []Finding {
	return checkHardcodedSecretsWithConfig(workflow, nil)
}

// checkHardcodedSecretsWithConfig checks for potential secrets with configuration support
func checkHardcodedSecretsWithConfig(workflow parser.WorkflowFile, config interface{}) []Finding {
	var findings []Finding

	// Enhanced secret patterns with more comprehensive detection
	secretPatterns := []*regexp.Regexp{
		// API Keys and Generic Secrets
		regexp.MustCompile(`(?i)(api[_-]?key|apikey|secret|token|password|pwd|credential|auth[_-]?key)s?\s*[:=]\s*['"]([^'"{}\s]{8,})['"]`),

		// Cloud Provider Secrets
		regexp.MustCompile(`(?i)(aws|amazon)[_-]?(access[_-]?key[_-]?id|secret[_-]?access[_-]?key|session[_-]?token)\s*[:=]\s*['"]([^'"{}\s]{16,})['"]`),
		regexp.MustCompile(`(?i)(gcp|google)[_-]?(service[_-]?account|private[_-]?key|client[_-]?email)\s*[:=]\s*['"]([^'"{}\s]{20,})['"]`),
		regexp.MustCompile(`(?i)(azure|microsoft)[_-]?(client[_-]?secret|tenant[_-]?id|subscription[_-]?id)\s*[:=]\s*['"]([^'"{}\s]{16,})['"]`),

		// GitHub and Git Platform Tokens
		regexp.MustCompile(`(?i)(github|gitlab|bitbucket)[_-]?(token|pat|access[_-]?token|personal[_-]?access[_-]?token)\s*[:=]\s*['"]([^'"{}\s]{20,})['"]`),
		regexp.MustCompile(`ghp_[A-Za-z0-9_]{36}`), // GitHub Personal Access Token
		regexp.MustCompile(`gho_[A-Za-z0-9_]{36}`), // GitHub OAuth Token
		regexp.MustCompile(`ghu_[A-Za-z0-9_]{36}`), // GitHub User-to-Server Token
		regexp.MustCompile(`ghs_[A-Za-z0-9_]{36}`), // GitHub Server-to-Server Token
		regexp.MustCompile(`ghr_[A-Za-z0-9_]{36}`), // GitHub Refresh Token

		// Database Connection Strings
		regexp.MustCompile(`(?i)(database[_-]?url|db[_-]?url|connection[_-]?string)\s*[:=]\s*['"]([^'"{}\s]{20,})['"]`),
		regexp.MustCompile(`(?i)(mongodb|postgres|mysql|redis)[_-]?(url|uri|connection)\s*[:=]\s*['"]([^'"{}\s]{15,})['"]`),

		// JWT Tokens
		regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`), // JWT Token pattern

		// Private Keys
		regexp.MustCompile(`-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----`),
		regexp.MustCompile(`-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----`),

		// OAuth and Client Secrets
		regexp.MustCompile(`(?i)(oauth[_-]?token|bearer[_-]?token|client[_-]?secret|client[_-]?id)\s*[:=]\s*['"]([^'"{}\s]{20,})['"]`),

		// Slack, Discord, Webhook URLs
		regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9+/]{44,48}`),
		regexp.MustCompile(`https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+`),

		// High-entropy strings (potential secrets)
		regexp.MustCompile(`(?i)(secret|token|key|password|pwd|credential)\s*[:=]\s*['"]([A-Za-z0-9+/]{32,})['"]`),

		// Cryptocurrency Keys
		regexp.MustCompile(`(?i)(bitcoin|btc|ethereum|eth)[_-]?(private[_-]?key|wallet[_-]?key)\s*[:=]\s*['"]([^'"{}\s]{25,})['"]`),

		// Email Service Keys
		regexp.MustCompile(`(?i)(sendgrid|mailgun|ses)[_-]?(api[_-]?key|secret)\s*[:=]\s*['"]([^'"{}\s]{20,})['"]`),

		// Generic high-entropy strings that could be secrets
		regexp.MustCompile(`['"][A-Za-z0-9+/]{40,}={0,2}['"]`), // Base64-like patterns
	}

	content := string(workflow.Content)

	// Preprocess content to handle comments in GitHub Actions workflows
	lines := strings.Split(content, "\n")
	processedLines := make([]string, len(lines))

	// Process each line to handle comments
	for i, line := range lines {
		// Check if this line has a comment
		if commentStart := strings.Index(line, "#"); commentStart >= 0 {
			// Keep everything before the comment but remove the comment part
			processedLines[i] = line[:commentStart]
		} else {
			processedLines[i] = line
		}
	}

	// Join the processed content back together
	content = strings.Join(processedLines, "\n")

	// Track found secrets to avoid duplicates
	foundSecrets := make(map[string]bool)

	for _, pattern := range secretPatterns {
		matches := pattern.FindAllStringSubmatchIndex(content, -1)
		for _, match := range matches {
			matchStr := content[match[0]:match[1]]

			// Skip if we've already found this exact secret
			if foundSecrets[matchStr] {
				continue
			}

			// Enhanced filtering for false positives
			if shouldSkipSecret(content, match[0], match[1], matchStr, workflow.Path, config) {
				continue
			}

			// Additional entropy check for generic patterns
			if isGenericPattern(pattern) && !hasHighEntropy(matchStr, 3.5) {
				continue
			}

			// Calculate line number based on character offset
			lineNumber := 1
			for i := 0; i < match[0]; i++ {
				if content[i] == '\n' {
					lineNumber++
				}
			}

			// Determine severity based on secret type
			severity := determineSecretSeverity(matchStr, pattern)

			findings = append(findings, Finding{
				RuleID:      "HARDCODED_SECRET",
				RuleName:    "Hardcoded Secret",
				Description: "Potential secret or credential found hardcoded in workflow file",
				Severity:    severity,
				Category:    SecretExposure,
				FilePath:    workflow.Path,
				JobName:     "",
				StepName:    "",
				Evidence:    maskSecret(matchStr),
				LineNumber:  lineNumber,
				Remediation: "Use repository secrets or environment variables instead of hardcoded values. Consider using GitHub's secret scanning features.",
			})

			foundSecrets[matchStr] = true
		}
	}

	return findings
}

// Enhanced helper functions for advanced secret detection

// shouldSkipSecret determines if a potential secret should be skipped based on context
func shouldSkipSecret(content string, start, end int, matchStr, filePath string, config interface{}) bool {
	// Skip if the match is a 40-char hex SHA and is used in a 'uses:' line
	if isLikelyActionSHA(content, start, end) {
		return true
	}

	// Skip if the match is a version tag (v1, v2.3.4, etc.) and is used in a 'uses:' line
	if isLikelyVersionTag(content, start, end) {
		return true
	}

	// Skip if the match is in a line with ${{ secrets.* }} or ${{ env.* }}
	if isEnvReference(content, start, end) {
		return true
	}

	lineStart := strings.LastIndex(content[:start], "\n")
	if lineStart == -1 {
		lineStart = 0
	} else {
		lineStart++
	}
	lineEnd := strings.Index(content[start:], "\n")
	if lineEnd == -1 {
		lineEnd = len(content)
	} else {
		lineEnd += start
	}
	contextLine := content[lineStart:lineEnd]
	contextLower := strings.ToLower(contextLine)

	// Skip templated or placeholder content commonly used in docs/examples
	if strings.Contains(matchStr, "{{") || strings.Contains(matchStr, "}}") || strings.Contains(matchStr, "<%") || strings.Contains(matchStr, "%>") {
		return true
	}

	skipKeywords := []string{
		"example", "placeholder", "sample", "changeme", "change-me",
		"dummy", "template", "documentation", "tutorial",
		"instructions", "replace-me", "todo",
		"insert", "configure", "fill-in", "set-your", "xxx", "yyy",
	}

	for _, keyword := range skipKeywords {
		if strings.Contains(contextLower, keyword) {
			return true
		}
	}

	if isAllUpperOrSnake(matchStr) && (strings.Contains(matchStr, "YOUR") || strings.Contains(matchStr, "PLACEHOLDER") || strings.Contains(matchStr, "EXAMPLE")) {
		return true
	}

	// Skip if the match is in a docs/examples path (prevents sample workflows from flagging)
	if looksLikeDocumentationPath(filePath) {
		return true
	}

	// Check configuration-based ignores if config is provided
	if config != nil {
		if cfg, ok := config.(interface {
			ShouldIgnoreSecret(text, context string) bool
		}); ok && cfg.ShouldIgnoreSecret(matchStr, contextLine) {
			return true
		}
	}

	// Skip common false positives - but be more specific
	commonFalsePositives := []string{
		"example", "placeholder", "YOUR_SECRET_HERE", "your-secret-here",
		"changeme", "change-me", "dummy", "test", "sample", "fake",
		"XXXXXX", "xxxxxx", "000000", "111111", "password",
		"secret", "token", "key", "admin", "user", "default",
		"localhost", "127.0.0.1", "0.0.0.0", "::1",
	}

	lowerMatch := strings.ToLower(matchStr)
	for _, fp := range commonFalsePositives {
		// Only skip if the false positive is the main part of the match, not just a substring
		if lowerMatch == strings.ToLower(fp) ||
			strings.HasPrefix(lowerMatch, strings.ToLower(fp)) ||
			strings.HasSuffix(lowerMatch, strings.ToLower(fp)) {
			return true
		}
	}

	// Skip if it's just repeated characters
	if isRepeatedChar(matchStr) {
		return true
	}

	// Skip if it's a common format string or placeholder
	if isFormatString(matchStr) {
		return true
	}

	// Skip if it's a URL without credentials
	if isURLWithoutCredentials(matchStr) {
		return true
	}

	return false
}

func isAllUpperOrSnake(s string) bool {
	if len(s) < 6 {
		return false
	}

	hasLetter := false
	for _, r := range s {
		if r >= 'a' && r <= 'z' {
			return false
		}
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			hasLetter = true
			continue
		}
		if r != '_' && r != '-' {
			return false
		}
	}

	return hasLetter
}

func looksLikeDocumentationPath(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "/docs/") ||
		strings.Contains(lower, "/doc/") ||
		strings.Contains(lower, "/examples/") ||
		strings.Contains(lower, "/samples/") ||
		strings.Contains(lower, "/test/") ||
		strings.Contains(lower, "/tests/")
}

var (
	semverReferencePattern    = regexp.MustCompile(`^v?\d+(\.\d+){0,2}$`)
	trustedActionOrgPrefixes  = []string{"actions/", "github/", "microsoft/", "azure/", "google/", "hashicorp/", "aws-actions/"}
	dockerTrustedPrefix       = "docker://"
	trustedCompositeIndicator = "/.github/"
)

func isTrustedSemverReference(uses string) bool {
	lower := strings.ToLower(uses)

	if strings.HasPrefix(lower, dockerTrustedPrefix) {
		// docker image versions are typically handled separately
		return false
	}

	parts := strings.Split(lower, "@")
	if len(parts) != 2 {
		return false
	}

	ref := parts[1]
	if !semverReferencePattern.MatchString(ref) {
		return false
	}

	// Skip composite repositories that live within .github directories (usually internal)
	if strings.Contains(parts[0], trustedCompositeIndicator) {
		return true
	}

	for _, prefix := range trustedActionOrgPrefixes {
		if strings.HasPrefix(parts[0], prefix) {
			return true
		}
	}

	return false
}

// isGenericPattern checks if a regex pattern is generic (high-entropy based)
func isGenericPattern(pattern *regexp.Regexp) bool {
	// These patterns are generic and need entropy checking
	genericPatterns := []string{
		`\['"][A-Za-z0-9+/]{40,}={0,2}['"]`, // Base64-like patterns
		`(?i)(secret|token|key|password|pwd|credential)\s*[:=]\s*['"]([A-Za-z0-9+/]{32,})['"]`,
	}

	patternStr := pattern.String()
	for _, generic := range genericPatterns {
		if strings.Contains(patternStr, generic) {
			return true
		}
	}
	return false
}

// hasHighEntropy calculates Shannon entropy to detect high-entropy strings
func hasHighEntropy(s string, threshold float64) bool {
	if len(s) < 8 {
		return false
	}

	// Calculate character frequency
	freq := make(map[rune]int)
	for _, char := range s {
		freq[char]++
	}

	// Calculate Shannon entropy
	entropy := 0.0
	length := float64(len(s))
	for _, count := range freq {
		probability := float64(count) / length
		if probability > 0 {
			entropy -= probability * (log2(probability))
		}
	}

	return entropy >= threshold
}

// log2 calculates logarithm base 2
func log2(x float64) float64 {
	return log(x) / log(2)
}

// log calculates natural logarithm
func log(x float64) float64 {
	// Simple implementation for basic cases
	if x <= 0 {
		return 0
	}
	// Use Taylor series approximation for ln(x)
	// For simplicity, we'll use a basic approximation
	// This is not production-ready but serves our purpose
	result := 0.0
	term := (x - 1) / x
	for i := 1; i <= 10; i++ {
		result += term / float64(i)
		term *= (x - 1) / x
	}
	return result
}

// determineSecretSeverity determines the severity based on the secret type
func determineSecretSeverity(secret string, pattern *regexp.Regexp) Severity {
	patternStr := pattern.String()
	secretLower := strings.ToLower(secret)

	// Critical severity for private keys and high-value tokens
	if strings.Contains(patternStr, "PRIVATE KEY") ||
		strings.Contains(secretLower, "ghp_") || // GitHub Personal Access Token
		strings.Contains(secretLower, "gho_") || // GitHub OAuth Token
		strings.Contains(secretLower, "ghu_") || // GitHub User-to-Server Token
		strings.Contains(secretLower, "ghs_") || // GitHub Server-to-Server Token
		strings.Contains(secretLower, "ghr_") || // GitHub Refresh Token
		strings.Contains(patternStr, "aws") ||
		strings.Contains(patternStr, "database") ||
		strings.Contains(patternStr, "private[_-]?key") {
		return Critical
	}

	// High severity for API keys and OAuth tokens
	if strings.Contains(patternStr, "api") ||
		strings.Contains(patternStr, "oauth") ||
		strings.Contains(patternStr, "bearer") ||
		strings.Contains(patternStr, "jwt") ||
		strings.Contains(patternStr, "client[_-]?secret") {
		return High
	}

	// Medium severity for other tokens
	if strings.Contains(patternStr, "token") ||
		strings.Contains(patternStr, "secret") {
		return Medium
	}

	// Default to medium for any detected secret
	return Medium
}

// maskSecret masks a secret for safe display
func maskSecret(secret string) string {
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}

	// Show first 4 and last 4 characters with masking in between
	prefix := secret[:4]
	suffix := secret[len(secret)-4:]
	middle := strings.Repeat("*", len(secret)-8)

	return prefix + middle + suffix
}

// isRepeatedChar checks if a string is just repeated characters
func isRepeatedChar(s string) bool {
	if len(s) == 0 {
		return false
	}

	firstChar := s[0]
	for _, char := range s {
		if char != rune(firstChar) {
			return false
		}
	}
	return true
}

// isFormatString checks if a string looks like a format string or placeholder
func isFormatString(s string) bool {
	formatPatterns := []string{
		"%s", "%d", "%v", "{}", "{{", "}}", "${", "$(", "<", ">",
		"TODO", "FIXME", "XXX", "NOTE",
	}

	lowerS := strings.ToLower(s)
	for _, pattern := range formatPatterns {
		if strings.Contains(lowerS, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// isURLWithoutCredentials checks if a string is a URL without embedded credentials
func isURLWithoutCredentials(s string) bool {
	if !strings.HasPrefix(strings.ToLower(s), "http") {
		return false
	}

	// If it's a URL but doesn't contain credentials (no @ symbol), it's likely safe
	return !strings.Contains(s, "@") || strings.Contains(s, "://")
}

// Helper functions:

// isLikelyActionSHA checks if a potential match is likely a GitHub Action SHA
func isLikelyActionSHA(content string, start, end int) bool {
	match := content[start:end]
	shaPattern := regexp.MustCompile(`^[a-f0-9]{40}$`)
	if !shaPattern.MatchString(match) {
		return false
	}
	// Check if this is in a 'uses:' line
	lineStart := strings.LastIndex(content[:start], "\n")
	if lineStart == -1 {
		lineStart = 0
	} else {
		lineStart++
	}
	lineEnd := strings.Index(content[start:], "\n")
	if lineEnd == -1 {
		lineEnd = len(content)
	} else {
		lineEnd += start
	}
	line := content[lineStart:lineEnd]
	return strings.Contains(line, "uses:") || strings.Contains(line, "@")
}

// isLikelyVersionTag checks if a potential match is likely a version tag
func isLikelyVersionTag(content string, start, end int) bool {
	match := content[start:end]
	versionPattern := regexp.MustCompile(`^v\d+(\.\d+)*$`)
	if !versionPattern.MatchString(match) {
		return false
	}
	lineStart := strings.LastIndex(content[:start], "\n")
	if lineStart == -1 {
		lineStart = 0
	} else {
		lineStart++
	}
	lineEnd := strings.Index(content[start:], "\n")
	if lineEnd == -1 {
		lineEnd = len(content)
	} else {
		lineEnd += start
	}
	line := content[lineStart:lineEnd]
	return strings.Contains(line, "uses:") || strings.Contains(line, "@")
}

// isEnvReference checks if a potential match is an environment reference
func isEnvReference(content string, start, end int) bool {
	lineStart := strings.LastIndex(content[:start], "\n")
	if lineStart == -1 {
		lineStart = 0
	} else {
		lineStart++
	}
	lineEnd := strings.Index(content[start:], "\n")
	if lineEnd == -1 {
		lineEnd = len(content)
	} else {
		lineEnd += start
	}
	line := content[lineStart:lineEnd]
	return strings.Contains(line, "${{ secrets.") || strings.Contains(line, "${{ env.")
}

// checkCredentialExfiltration checks for patterns that could lead to credential theft
func checkCredentialExfiltration(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Patterns that could exfiltrate credentials
	exfiltrationPatterns := []*regexp.Regexp{
		regexp.MustCompile(`curl.*-d.*\$\{\{\s*secrets\.`),            // POST secrets via curl
		regexp.MustCompile(`wget.*--post-data.*\$\{\{\s*secrets\.`),   // POST secrets via wget
		regexp.MustCompile(`echo.*\$\{\{\s*secrets\..*\|\s*base64`),   // Echo and encode secrets
		regexp.MustCompile(`\$\{\{\s*secrets\..*\}\}.*>\s*[^$]`),      // Redirect secrets to files
		regexp.MustCompile(`nc\s+.*\$\{\{\s*secrets\.`),               // Netcat with secrets
		regexp.MustCompile(`telnet\s+.*\$\{\{\s*secrets\.`),           // Telnet with secrets
		regexp.MustCompile(`ssh\s+.*\$\{\{\s*secrets\.`),              // SSH with secrets in command
		regexp.MustCompile(`\$\{\{\s*secrets\..*\}\}.*\|\s*mail`),     // Email secrets
		regexp.MustCompile(`\$\{\{\s*secrets\..*\}\}.*\|\s*sendmail`), // Sendmail secrets
	}

	// Also check for secrets being written to logs or outputs
	logPatterns := []*regexp.Regexp{
		regexp.MustCompile(`echo.*\$\{\{\s*secrets\.`),                             // Echo secrets (appears in logs)
		regexp.MustCompile(`printf.*\$\{\{\s*secrets\.`),                           // Printf secrets
		regexp.MustCompile(`cat.*\$\{\{\s*secrets\.`),                              // Cat secrets
		regexp.MustCompile(`\$\{\{\s*secrets\..*\}\}.*>>\s*\$GITHUB_STEP_SUMMARY`), // Write to step summary
	}

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			// Check for direct exfiltration patterns
			for _, pattern := range exfiltrationPatterns {
				if pattern.MatchString(step.Run) {
					lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
						Key:   "run",
						Value: step.Run,
					})

					lineNumber := 0
					if lineResult != nil {
						lineNumber = lineResult.LineNumber
					}

					findings = append(findings, Finding{
						RuleID:      "CREDENTIAL_EXFILTRATION",
						RuleName:    "Credential Exfiltration",
						Description: "Command pattern detected that could exfiltrate secrets or credentials to external systems",
						Severity:    Critical,
						Category:    SecretsExposure,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    step.Name,
						Evidence:    strings.TrimSpace(step.Run),
						LineNumber:  lineNumber,
						Remediation: "Avoid sending secrets to external systems. Use secure secret management practices.",
					})
				}
			}

			// Check for logging/output patterns
			for _, pattern := range logPatterns {
				if pattern.MatchString(step.Run) {
					lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
						Key:   "run",
						Value: step.Run,
					})

					lineNumber := 0
					if lineResult != nil {
						lineNumber = lineResult.LineNumber
					}

					findings = append(findings, Finding{
						RuleID:      "CREDENTIAL_EXFILTRATION",
						RuleName:    "Credential Exfiltration",
						Description: "Secrets are being written to logs or outputs where they may be exposed",
						Severity:    High,
						Category:    SecretsExposure,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    step.Name,
						Evidence:    strings.TrimSpace(step.Run),
						LineNumber:  lineNumber,
						Remediation: "Never log or output secrets. Use secure methods to handle sensitive data.",
					})
				}
			}
		}
	}

	return findings
}

// checkServicesCredentials checks for hardcoded credentials in services configuration
func checkServicesCredentials(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Patterns for detecting credentials in services config
	credentialPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)password\s*:\s*['"]\S+['"]`),
		regexp.MustCompile(`(?i)secret\s*:\s*['"]\S+['"]`),
		regexp.MustCompile(`(?i)token\s*:\s*['"]\S+['"]`),
		regexp.MustCompile(`(?i)key\s*:\s*['"]\S+['"]`),
		regexp.MustCompile(`(?i)credential\s*:\s*['"]\S+['"]`),
	}

	for jobName, job := range workflow.Workflow.Jobs {
		if job.Services != nil {
			for serviceName, serviceConfig := range job.Services {
				// Convert service config to string for pattern matching
				serviceStr := fmt.Sprintf("%v", serviceConfig)

				for _, pattern := range credentialPatterns {
					if pattern.MatchString(serviceStr) {
						lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
							Key:   "services",
							Value: serviceName,
						})

						lineNumber := 0
						if lineResult != nil {
							lineNumber = lineResult.LineNumber
						}

						findings = append(findings, Finding{
							RuleID:      "SERVICES_CREDENTIALS",
							RuleName:    "Services Configuration Credentials",
							Description: "Hardcoded credentials detected in services configuration",
							Severity:    Critical,
							Category:    SecretExposure,
							FilePath:    workflow.Path,
							JobName:     jobName,
							StepName:    serviceName,
							Evidence:    strings.TrimSpace(serviceStr),
							LineNumber:  lineNumber,
							Remediation: "Use secrets or environment variables instead of hardcoded credentials in services configuration",
						})
					}
				}
			}
		}
	}

	return findings
}

// checkSecretsInherit detects insecure secret inheritance patterns
func checkSecretsInherit(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Check for workflow_call with secrets: inherit
	if workflow.Workflow.On != nil {
		if onMap, ok := workflow.Workflow.On.(map[string]interface{}); ok {
			if workflowCall, exists := onMap["workflow_call"]; exists && workflowCall != nil {
				// Check if secrets are inherited without restrictions
				if workflowCallMap, ok := workflowCall.(map[string]interface{}); ok {
					if secretsSection, exists := workflowCallMap["secrets"]; exists {
						if secretsStr, ok := secretsSection.(string); ok && secretsStr == "inherit" {
							pattern := linenum.FindPattern{
								Key:   "secrets",
								Value: "inherit",
							}
							lineResult := lineMapper.FindLineNumber(pattern)
							lineNumber := 0
							if lineResult != nil {
								lineNumber = lineResult.LineNumber
							}

							findings = append(findings, Finding{
								RuleID:      "SECRETS_INHERIT",
								RuleName:    "Secret Inheritance Issues",
								Description: "Reusable workflow inherits all secrets without restrictions",
								Severity:    High,
								Category:    SecretsExposure,
								FilePath:    workflow.Path,
								JobName:     "workflow",
								StepName:    "workflow_call",
								Evidence:    "secrets: inherit",
								Remediation: "Explicitly define only required secrets instead of inheriting all",
								LineNumber:  lineNumber,
							})
						}
					}
				}
			}
		}
	}

	// Note: Job-level secrets inheritance would need to be checked in the job definition
	// as the parser.Job struct doesn't currently include a Secrets field
	// This could be implemented by checking raw YAML content for "secrets: inherit" patterns

	return findings
}

// checkOverprovisionedSecrets detects workflows with excessive secret access
func checkOverprovisionedSecrets(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	for jobName, job := range workflow.Workflow.Jobs {
		secretCount := 0
		var secretNames []string

		// Count environment variables that look like secrets
		if job.Env != nil {
			for key, value := range job.Env {
				valueStr := fmt.Sprintf("%v", value)
				if strings.Contains(valueStr, "secrets.") {
					secretCount++
					secretNames = append(secretNames, key)
				}
			}
		}

		// Check steps for secret usage
		usedSecrets := make(map[string]bool)
		for _, step := range job.Steps {
			if step.Env != nil {
				for _, value := range step.Env {
					valueStr := fmt.Sprintf("%v", value)
					if strings.Contains(valueStr, "secrets.") {
						re := regexp.MustCompile(`secrets\.([A-Z_]+)`)
						matches := re.FindAllStringSubmatch(valueStr, -1)
						for _, match := range matches {
							if len(match) > 1 {
								usedSecrets[match[1]] = true
							}
						}
					}
				}
			}
		}

		// If job has access to many secrets but only uses a few
		if secretCount > 5 && len(usedSecrets) < secretCount/2 {
			pattern := linenum.FindPattern{
				Key:   "env",
				Value: "",
			}
			lineResult := lineMapper.FindLineNumber(pattern)
			lineNumber := 0
			if lineResult != nil {
				lineNumber = lineResult.LineNumber
			}

			findings = append(findings, Finding{
				RuleID:      "OVERPROVISIONED_SECRETS",
				RuleName:    "Over-provisioned Secrets",
				Description: fmt.Sprintf("Job has access to %d secrets but appears to use only %d", secretCount, len(usedSecrets)),
				Severity:    Medium,
				Category:    SecretsExposure,
				FilePath:    workflow.Path,
				JobName:     jobName,
				StepName:    "job_configuration",
				Evidence:    fmt.Sprintf("Available secrets: %v", secretNames),
				Remediation: "Remove unused secret access to follow principle of least privilege",
				LineNumber:  lineNumber,
			})
		}
	}

	return findings
}

// checkUnredactedSecrets detects secrets that may be logged in plaintext
func checkUnredactedSecrets(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			stepName := step.Name
			if stepName == "" {
				stepName = fmt.Sprintf("Step %d", stepIdx+1)
			}

			// Check for patterns that might log secrets
			dangerousPatterns := []string{
				`echo.*\$\{.*secrets\.`,
				`printf.*\$\{.*secrets\.`,
				`cat.*\$\{.*secrets\.`,
				`curl.*-H.*\$\{.*secrets\.`,
				`wget.*--header.*\$\{.*secrets\.`,
				`env\s*\|.*grep`,
				`printenv`,
				`set\s*\|.*grep`,
			}

			for _, pattern := range dangerousPatterns {
				re := regexp.MustCompile(`(?i)` + pattern)
				if re.MatchString(step.Run) {
					linePattern := linenum.FindPattern{
						Key:   "run",
						Value: step.Run,
					}
					lineResult := lineMapper.FindLineNumber(linePattern)
					lineNumber := 0
					if lineResult != nil {
						lineNumber = lineResult.LineNumber
					}

					severity := Critical
					if strings.Contains(pattern, "env") || strings.Contains(pattern, "printenv") {
						severity = High // Environment dumps are high but not critical
					}

					findings = append(findings, Finding{
						RuleID:      "UNREDACTED_SECRETS",
						RuleName:    "Unredacted Secrets in Logs",
						Description: "Command may log secrets in plaintext to build logs",
						Severity:    severity,
						Category:    SecretsExposure,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    stepName,
						Evidence:    step.Run,
						Remediation: "Avoid echoing or logging secret values; use intermediate files or redaction",
						LineNumber:  lineNumber,
					})
				}
			}
		}
	}

	return findings
}
