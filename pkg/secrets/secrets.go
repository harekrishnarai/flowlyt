package secrets

import (
	"math"
	"regexp"
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/parser"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

// Detector represents a lightweight secrets detector
type Detector struct {
	// Custom patterns in addition to the defaults
	CustomPatterns []*regexp.Regexp
	// Entropy threshold for detecting high-entropy strings (likely secrets)
	EntropyThreshold float64
}

// NewDetector creates a new secrets detector
func NewDetector() *Detector {
	return &Detector{
		CustomPatterns:   []*regexp.Regexp{},
		EntropyThreshold: 4.5, // Default threshold based on empirical testing
	}
}

// AddCustomPattern adds a custom regex pattern to detect secrets
func (d *Detector) AddCustomPattern(pattern *regexp.Regexp) {
	d.CustomPatterns = append(d.CustomPatterns, pattern)
}

// SetEntropyThreshold sets the entropy threshold for detecting high-entropy strings
func (d *Detector) SetEntropyThreshold(threshold float64) {
	d.EntropyThreshold = threshold
}

// Detect scans a workflow file for potential secrets
func (d *Detector) Detect(workflow parser.WorkflowFile) []rules.Finding {
	var findings []rules.Finding

	// Get default patterns
	patterns := d.getDefaultPatterns()

	// Add custom patterns
	patterns = append(patterns, d.CustomPatterns...)

	// Convert workflow to string to search for secrets
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
	processedContent := strings.Join(processedLines, "\n")

	// Pre-analyze the file for GitHub Actions context
	isGitHubWorkflow := d.isGitHubActionsWorkflow(processedContent)

	// Regex-based detection with GitHub workflow awareness
	findings = append(findings, d.detectByPatterns(processedContent, workflow.Path, patterns, isGitHubWorkflow)...)

	// Entropy-based detection with GitHub workflow awareness
	findings = append(findings, d.detectByEntropy(processedContent, workflow.Path, isGitHubWorkflow)...)

	return findings
}

// isGitHubActionsWorkflow checks if the content is a GitHub Actions workflow file
func (d *Detector) isGitHubActionsWorkflow(content string) bool {
	// Check for key GitHub Actions YAML structure indicators
	return strings.Contains(content, "on:") &&
		(strings.Contains(content, "jobs:") || strings.Contains(content, "workflow_") ||
			strings.Contains(content, "steps:") || strings.Contains(content, "runs-on:"))
}

// getDefaultPatterns returns the default regex patterns for common secrets
func (d *Detector) getDefaultPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		// AWS Keys
		regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16})`),
		regexp.MustCompile(`(?i)aws[_-]?(access[_-]?key|secret[_-]?key|account[_-]?id)["\s]*[:=]["\s]*['"]([a-zA-Z0-9/+]{16,64})['"]`),

		// GitHub Tokens - match both PATs and OAuth
		regexp.MustCompile(`(?i)(gh[pos]_[a-zA-Z0-9_]{36,255})`),
		regexp.MustCompile(`(?i)github[_-]?(api[_-]?token|token|secret)["\s]*[:=]["\s]*['"]([a-zA-Z0-9_\-]{36,255})['"]`),

		// Google/GCP
		regexp.MustCompile(`(?i)(AIza[a-zA-Z0-9_\-]{35})`),
		regexp.MustCompile(`(?i)(ya29\.[a-zA-Z0-9_\-]+)`),

		// API Keys - generic pattern
		regexp.MustCompile(`(?i)(api[_-]?key|apikey|auth[_-]?token)["\s]*[:=]["\s]*["']([a-zA-Z0-9_\-\.=]{8,64})["']`),

		// Generic API Keys in env vars
		regexp.MustCompile(`(?i)API_KEY[\s]*:[\s]*["']([a-zA-Z0-9_\-\.=]{8,64})["']`),

		// Generic Secrets
		regexp.MustCompile(`(?i)(secret|token|password|passwd|pwd|api[_-]?key)["\s]*[:=]["\s]*['"]([a-zA-Z0-9_\-\.$+=]{8,64})['"]`),

		// Private Keys
		regexp.MustCompile(`(?i)-----BEGIN( RSA| OPENSSH| DSA| EC)? PRIVATE KEY( BLOCK)?-----`),

		// NPM tokens
		regexp.MustCompile(`(?i)(npm_[a-zA-Z0-9]{36})`),

		// Docker Hub
		regexp.MustCompile(`(?i)docker[_-]?hub[_-]?(token|password)["\s]*[:=]["\s]*['"]([a-zA-Z0-9_\-]{12,64})['"]`),

		// Database connection strings
		regexp.MustCompile(`(?i)(jdbc|mongodb(\+srv)?|postgres|postgresql|mysql|sqlserver):.*password=[^;]*`),
	}
}

// detectByPatterns detects secrets using regex patterns
func (d *Detector) detectByPatterns(content, path string, patterns []*regexp.Regexp, isGitHubWorkflow bool) []rules.Finding {
	var findings []rules.Finding

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatchIndex(content, -1)
		for _, matchIndices := range matches {
			matchStart := matchIndices[0]
			matchEnd := matchIndices[1]
			match := content[matchStart:matchEnd]

			// Skip if the pattern likely matches an environment variable reference
			if strings.Contains(match, "${{") || strings.Contains(match, "${") {
				continue
			}

			// Extract the secret value - usually in a capture group if it exists, otherwise the whole match
			secretValue := match
			if len(matchIndices) > 3 { // At least one capture group
				secretValue = content[matchIndices[2]:matchIndices[3]]
			}

			// Skip if it's a GitHub Action SHA reference in a GitHub workflow
			if isGitHubWorkflow && (isGitHubActionSHA(content, matchStart, matchEnd) || isActionReference(content, matchStart, matchEnd)) {
				continue
			}

			// Calculate line number based on character offset
			lineNumber := 1
			for i := 0; i < matchStart; i++ {
				if content[i] == '\n' {
					lineNumber++
				}
			}

			// Skip if it's part of a YAML key or YAML structure in a GitHub workflow
			if isGitHubWorkflow && isYAMLKeyOrStructure(content, matchStart, lineNumber) {
				continue
			}

			// Only report if the string looks like a secret (not too short, has some complexity)
			if len(secretValue) >= 8 && !isCommonWord(secretValue) {
				findings = append(findings, rules.Finding{
					RuleID:      "SECRET_DETECTION_PATTERN",
					RuleName:    "Hardcoded Secret Detection",
					Description: "Potential secret or credential found hardcoded in workflow file",
					Severity:    rules.Critical,
					Category:    rules.SecretExposure,
					FilePath:    path,
					Evidence:    sanitizeEvidence(match),
					LineNumber:  lineNumber,
					Remediation: "Use repository secrets or environment variables instead of hardcoded values",
				})
			}
		}
	}

	return findings
}

// detectByEntropy detects secrets using Shannon entropy
func (d *Detector) detectByEntropy(content, path string, isGitHubWorkflow bool) []rules.Finding {
	var findings []rules.Finding

	// Split content by spaces, newlines, and other separators to find high-entropy strings
	wordMatches := regexp.MustCompile(`[a-zA-Z0-9\+/=_\-\.]{16,100}`).FindAllStringIndex(content, -1)

	for _, matchIndices := range wordMatches {
		matchStart := matchIndices[0]
		matchEnd := matchIndices[1]
		word := content[matchStart:matchEnd]

		// Skip if it looks like an environment variable reference
		if strings.Contains(word, "${{") || strings.Contains(word, "${") {
			continue
		}

		// Skip if it's a GitHub Action SHA reference or version reference in a GitHub workflow
		if isGitHubWorkflow && (isGitHubActionSHA(content, matchStart, matchEnd) || isActionReference(content, matchStart, matchEnd)) {
			continue
		}

		// Skip if it's a common word or path
		if isCommonWord(word) || strings.Contains(word, "/") || strings.Count(word, ".") > 2 {
			continue
		}

		// For GitHub workflows, apply more strict filtering to reduce false positives
		if isGitHubWorkflow {
			// Skip if the word contains common GitHub-related terms
			if containsAnySubstring(word, []string{"action", "github", "workflow", "runner"}) {
				continue
			}

			// Skip if the word appears to be a hash in a commented line
			lineStart := strings.LastIndex(content[:matchStart], "\n")
			if lineStart == -1 {
				lineStart = 0
			} else {
				lineStart++
			}

			lineEnd := strings.Index(content[matchStart:], "\n")
			if lineEnd == -1 {
				lineEnd = len(content) - matchStart
			} else {
				lineEnd += matchStart
			}

			line := content[lineStart:lineEnd]
			if strings.Contains(line, "#") {
				continue
			}
		}

		// Calculate line number based on character offset
		lineNumber := 1
		for i := 0; i < matchStart; i++ {
			if content[i] == '\n' {
				lineNumber++
			}
		}

		// Calculate entropy
		entropy := calculateEntropy(word)

		// Check if entropy is high enough to be a potential secret
		if entropy > d.EntropyThreshold && len(word) >= 16 {
			findings = append(findings, rules.Finding{
				RuleID:      "SECRET_DETECTION_ENTROPY",
				RuleName:    "High-Entropy String Detection",
				Description: "High-entropy string that may be a hardcoded secret",
				Severity:    rules.High,
				Category:    rules.SecretExposure,
				FilePath:    path,
				Evidence:    sanitizeEvidence(word),
				LineNumber:  lineNumber,
				Remediation: "Verify if this is a secret. If so, use repository secrets or environment variables instead",
			})
		}
	}

	return findings
}

// containsAnySubstring checks if a string contains any of the given substrings
func containsAnySubstring(s string, substrings []string) bool {
	lowerS := strings.ToLower(s)
	for _, sub := range substrings {
		if strings.Contains(lowerS, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// calculateEntropy calculates the Shannon entropy of a string
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// Count character frequencies
	charFreq := make(map[rune]float64)
	for _, char := range s {
		charFreq[char]++
	}

	// Calculate entropy
	entropy := 0.0
	length := float64(len(s))
	for _, freq := range charFreq {
		probability := freq / length
		entropy -= probability * math.Log2(probability)
	}

	return entropy
}

// isCommonWord checks if a string is a common word or value that's likely not a secret
func isCommonWord(s string) bool {
	// List of common words or patterns that might have high entropy but aren't secrets
	commonWords := []string{
		"dockerfile", "kubernetes", "integration", "development", "production",
		"javascript", "typescript", "environment", "configuration", "dockerfile",
		"deployment", "container", "ubuntu", "debian", "alpine", "latest",
		"manifest", "workflow", "actions", "v1", "v2", "v3", "main", "master",
		"feature", "bugfix", "hotfix", "release", "develop", "http", "https",
		"checkout", "setup-node", "setup-python", "setup-java", "build",
		"pinned", "sha", "version", "node-version", "cache", "npm", "yarn",
	}

	s = strings.ToLower(s)
	for _, word := range commonWords {
		if strings.Contains(s, word) {
			return true
		}
	}

	// Check specifically for pinned SHAs in GitHub Actions
	if strings.HasPrefix(s, "actions/") && strings.Contains(s, "@") {
		return true
	}

	// Additional check for version tags
	versionPattern := regexp.MustCompile(`v\d+\.\d+\.\d+`)
	if versionPattern.MatchString(s) {
		return true
	}

	return false
}

// isGitHubActionSHA checks if a potential secret match is actually a GitHub Action SHA reference
func isGitHubActionSHA(content string, matchStart, matchEnd int) bool {
	matchedString := content[matchStart:matchEnd]

	// Pattern for a 40-character hex string (GitHub SHA)
	if matched, _ := regexp.MatchString(`^[a-f0-9]{40}$`, matchedString); matched {
		return true // Any 40-character hex string is likely a SHA
	}

	// Check surrounding context (4 lines before and after for broader context)
	contextStart := 0
	for i := 0; i < 4; i++ {
		prevNewline := strings.LastIndex(content[:matchStart], "\n")
		if prevNewline == -1 {
			break
		}
		matchStart = prevNewline
	}

	contextEnd := len(content)
	nextNewlineCount := 0
	searchPos := matchEnd
	for nextNewlineCount < 4 && searchPos < len(content) {
		nextNewline := strings.Index(content[searchPos:], "\n")
		if nextNewline == -1 {
			break
		}
		searchPos += nextNewline + 1
		nextNewlineCount++
	}
	contextEnd = searchPos

	context := content[contextStart:contextEnd]

	// Check for action-related patterns
	actionPatterns := []string{
		"uses:", "actions/", "checkout", "setup-",
		"pinned", "sha", "commit", "ref", "tag",
		"v1", "v2", "v3", "v4", "with:", "steps:",
		"workflow", "github",
	}

	for _, pattern := range actionPatterns {
		if strings.Contains(context, pattern) {
			return true
		}
	}

	return false
}

// isYAMLKeyOrStructure checks if the match is part of YAML structure rather than a value
func isYAMLKeyOrStructure(content string, matchStart int, lineNumber int) bool {
	// Get the line containing this match
	lineStartPos := 0
	currentLine := 1

	for i := 0; i < matchStart; i++ {
		if content[i] == '\n' {
			currentLine++
			if currentLine == lineNumber {
				lineStartPos = i + 1
			}
		}
	}

	lineEndPos := strings.Index(content[matchStart:], "\n")
	if lineEndPos == -1 {
		lineEndPos = len(content) - matchStart
	} else {
		lineEndPos += matchStart
	}

	line := content[lineStartPos:lineEndPos]
	trimmedLine := strings.TrimSpace(line)

	// Check if the line is a YAML structure indicator
	return strings.HasPrefix(trimmedLine, "-") ||
		strings.Contains(trimmedLine, ":") && !strings.Contains(trimmedLine, "\"") && !strings.Contains(trimmedLine, "'") ||
		strings.HasPrefix(trimmedLine, "#")
}

// isActionReference checks if the match is part of a GitHub Action reference
func isActionReference(content string, matchStart, matchEnd int) bool {
	matchedString := content[matchStart:matchEnd]

	// Check for common version patterns
	versionPatterns := []string{
		`v\d+\.\d+\.\d+`,  // v1.2.3
		`v\d+\.\d+`,       // v1.2
		`v\d+`,            // v1
		`@v\d+`,           // @v1
		`@v\d+\.\d+`,      // @v1.2
		`@v\d+\.\d+\.\d+`, // @v1.2.3
	}

	for _, pattern := range versionPatterns {
		matched, _ := regexp.MatchString(pattern, matchedString)
		if matched {
			return true
		}
	}

	// Get the surrounding line
	lineStart := strings.LastIndex(content[:matchStart], "\n")
	if lineStart == -1 {
		lineStart = 0
	} else {
		lineStart++
	}

	lineEnd := strings.Index(content[matchStart:], "\n")
	if lineEnd == -1 {
		lineEnd = len(content) - matchStart
	} else {
		lineEnd += matchStart
	}

	line := content[lineStart:lineEnd]

	// Check for GitHub Actions specific patterns
	actionsPatterns := []string{
		"uses:", "with:", "run:", "steps:", "jobs:", "workflow",
		"actions/", "github/", "docker/", "hashicorp/",
		"setup-", "checkout@", "setup-node", "setup-python",
	}

	for _, pattern := range actionsPatterns {
		if strings.Contains(line, pattern) {
			return true
		}
	}

	return false
}

// sanitizeEvidence partially masks the potential secret for safer display
func sanitizeEvidence(evidence string) string {
	// If the evidence is short, return as is
	if len(evidence) < 12 {
		return evidence
	}

	// Otherwise, mask the middle part
	visible := 4 // Number of characters to show at the beginning and end
	return evidence[:visible] + strings.Repeat("*", len(evidence)-visible*2) + evidence[len(evidence)-visible:]
}

// checkHardcodedSecrets scans a workflow file for hardcoded secrets
func checkHardcodedSecrets(workflow parser.WorkflowFile) []rules.Finding {
	var findings []rules.Finding

	// Common patterns for secrets
	secretPatterns := []*regexp.Regexp{
		// AWS Keys
		regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16})`),
		regexp.MustCompile(`(?i)aws[_-]?(access[_-]?key|secret[_-]?key|account[_-]?id)["\s]*[:=]["\s]*['"]([a-zA-Z0-9/+]{16,64})['"]`),

		// GitHub Tokens - match both PATs and OAuth
		regexp.MustCompile(`(?i)(gh[pos]_[a-zA-Z0-9_]{36,255})`),
		regexp.MustCompile(`(?i)github[_-]?(api[_-]?token|token|secret)["\s]*[:=]["\s]*['"]([a-zA-Z0-9_\-]{36,255})['"]`),

		// Google/GCP
		regexp.MustCompile(`(?i)(AIza[a-zA-Z0-9_\-]{35})`),
		regexp.MustCompile(`(?i)(ya29\.[a-zA-Z0-9_\-]+)`),

		// API Keys - generic pattern
		regexp.MustCompile(`(?i)(api[_-]?key|apikey|auth[_-]?token)["\s]*[:=]["\s]*["']([a-zA-Z0-9_\-\.=]{8,64})["']`),

		// Generic API Keys in env vars
		regexp.MustCompile(`(?i)API_KEY[\s]*:[\s]*["']([a-zA-Z0-9_\-\.=]{8,64})["']`),

		// Generic Secrets
		regexp.MustCompile(`(?i)(secret|token|password|passwd|pwd|api[_-]?key)["\s]*[:=]["\s]*['"]([a-zA-Z0-9_\-\.$+=]{8,64})['"]`),

		// Private Keys
		regexp.MustCompile(`(?i)-----BEGIN( RSA| OPENSSH| DSA| EC)? PRIVATE KEY( BLOCK)?-----`),

		// NPM tokens
		regexp.MustCompile(`(?i)(npm_[a-zA-Z0-9]{36})`),

		// Docker Hub
		regexp.MustCompile(`(?i)docker[_-]?hub[_-]?(token|password)["\s]*[:=]["\s]*['"]([a-zA-Z0-9_\-]{12,64})['"]`),

		// Database connection strings
		regexp.MustCompile(`(?i)(jdbc|mongodb(\+srv)?|postgres|postgresql|mysql|sqlserver):.*password=[^;]*`),
	}

	content := string(workflow.Content)

	for _, pattern := range secretPatterns {
		matches := pattern.FindAllStringSubmatchIndex(content, -1)
		for _, match := range matches {
			matchStr := content[match[0]:match[1]]

			// Skip if the match is a 40-char hex SHA and is used in a 'uses:' line
			if isLikelyActionSHA(content, match[0], match[1]) {
				continue
			}

			// Skip if the match is a version tag (v1, v2.3.4, etc.) and is used in a 'uses:' line
			if isLikelyVersionTag(content, match[0], match[1]) {
				continue
			}

			// Skip if the match is in a line with ${{ secrets.* }}
			if isEnvReference(content, match[0], match[1]) {
				continue
			}

			// Calculate line number based on character offset
			lineNumber := 1
			for i := 0; i < match[0]; i++ {
				if content[i] == '\n' {
					lineNumber++
				}
			}

			// Append finding
			findings = append(findings, rules.Finding{
				RuleID:      "SECRET_DETECTION_PATTERN",
				RuleName:    "Hardcoded Secret Detection",
				Description: "Potential secret or credential found hardcoded in workflow file",
				Severity:    rules.Critical,
				Category:    rules.SecretExposure,
				FilePath:    workflow.Path,
				Evidence:    sanitizeEvidence(matchStr),
				LineNumber:  lineNumber,
				Remediation: "Use repository secrets or environment variables instead of hardcoded values",
			})
		}
	}

	return findings
}

// Helper functions:
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
