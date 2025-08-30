package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/linenum"
	"github.com/harekrishnarai/flowlyt/pkg/parser"
)

// ConfigInterface defines the interface for configuration
type ConfigInterface interface {
	IsRuleEnabled(ruleID string) bool
	ShouldIgnoreForRule(ruleID, text, filePath string) bool
	ShouldIgnoreSecret(text, context string) bool
}

// RuleEngine handles rule execution with configuration support
type RuleEngine struct {
	config ConfigInterface
}

// NewRuleEngine creates a new rule engine with configuration
func NewRuleEngine(config ConfigInterface) *RuleEngine {
	return &RuleEngine{config: config}
}

// ExecuteRules runs rules against a workflow with configuration filtering
func (re *RuleEngine) ExecuteRules(workflow parser.WorkflowFile, rules []Rule) []Finding {
	var allFindings []Finding

	for _, rule := range rules {
		// Check if rule is enabled in configuration
		if re.config != nil && !re.config.IsRuleEnabled(rule.ID) {
			continue
		}

		findings := rule.Check(workflow)

		// Apply configuration-based filtering
		var filteredFindings []Finding
		for _, finding := range findings {
			if re.config == nil || !re.config.ShouldIgnoreForRule(finding.RuleID, finding.Evidence, workflow.Path) {
				filteredFindings = append(filteredFindings, finding)
			}
		}

		allFindings = append(allFindings, filteredFindings...)
	}

	return allFindings
}

// Rule represents a security rule to check in a workflow
type Rule struct {
	ID          string
	Name        string
	Description string
	Severity    Severity
	Category    Category
	Check       func(workflow parser.WorkflowFile) []Finding
}

// Severity represents the severity level of a finding
type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
	Info     Severity = "INFO"
)

// Category represents the category of a security rule
type Category string

const (
	MaliciousPattern    Category = "MALICIOUS_PATTERN"
	Misconfiguration    Category = "MISCONFIGURATION"
	SecretExposure      Category = "SECRET_EXPOSURE"
	ShellObfuscation    Category = "SHELL_OBFUSCATION"
	PolicyViolation     Category = "POLICY_VIOLATION"
	SupplyChain         Category = "SUPPLY_CHAIN"
	InjectionAttack     Category = "INJECTION_ATTACK"
	SecretsExposure     Category = "SECRETS_EXPOSURE"
	AccessControl       Category = "ACCESS_CONTROL"
	PrivilegeEscalation Category = "PRIVILEGE_ESCALATION"
	DataExposure        Category = "DATA_EXPOSURE"
)

// Finding represents a detected security issue
type Finding struct {
	RuleID      string
	RuleName    string
	Description string
	Severity    Severity
	Category    Category
	FilePath    string
	JobName     string
	StepName    string
	Evidence    string
	Remediation string
	LineNumber  int    // Line number where the issue was found
	GitHubURL   string // Direct GitHub URL to the line (for remote repositories)
}

// StandardRules returns the list of built-in security rules
func StandardRules() []Rule {
	return []Rule{
		{
			ID:          "MALICIOUS_CURL_PIPE_BASH",
			Name:        "Curl Pipe to Shell",
			Description: "Detects curl or wget piped to bash/sh/zsh, which can execute malicious code",
			Severity:    High,
			Category:    MaliciousPattern,
			Check:       checkCurlPipeToShell,
		},
		{
			ID:          "MALICIOUS_BASE64_DECODE",
			Name:        "Base64 Decode Execution",
			Description: "Detects execution of base64-decoded data, which can hide malicious code",
			Severity:    Critical,
			Category:    ShellObfuscation,
			Check:       checkBase64DecodeExecution,
		},
		{
			ID:          "MALICIOUS_DATA_EXFILTRATION",
			Name:        "Suspicious Data Exfiltration",
			Description: "Detects potential exfiltration of secrets or sensitive data to external servers",
			Severity:    Critical,
			Category:    MaliciousPattern,
			Check:       checkDataExfiltration,
		},
		{
			ID:          "INSECURE_PULL_REQUEST_TARGET",
			Name:        "Insecure pull_request_target usage",
			Description: "Detects insecure usage of pull_request_target event with code checkout",
			Severity:    Critical,
			Category:    Misconfiguration,
			Check:       checkInsecurePullRequestTarget,
		},
		{
			ID:          "UNPINNED_ACTION",
			Name:        "Unpinned GitHub Action",
			Description: "Detects usage of GitHub Actions without pinned versions (uses latest or branch)",
			Severity:    Medium,
			Category:    Misconfiguration,
			Check:       checkUnpinnedAction,
		},
		{
			ID:          "HARDCODED_SECRET",
			Name:        "Hardcoded Secret",
			Description: "Detects potential secrets hardcoded in workflow files",
			Severity:    Critical,
			Category:    SecretExposure,
			Check:       checkHardcodedSecrets,
		},
		{
			ID:          "CONTINUE_ON_ERROR_CRITICAL_JOB",
			Name:        "Continue On Error in Critical Job",
			Description: "Detects critical jobs with continue-on-error set to true",
			Severity:    Medium,
			Category:    Misconfiguration,
			Check:       checkContinueOnErrorCriticalJob,
		},
		{
			ID:          "BROAD_PERMISSIONS",
			Name:        "Overly Broad Permissions",
			Description: "Workflow uses overly broad permissions that grant unnecessary access",
			Severity:    Critical,
			Category:    Misconfiguration,
			Check:       checkBroadPermissions,
		},
	}
}

// checkCurlPipeToShell checks for curl/wget piped to shell commands
func checkCurlPipeToShell(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	// Regular expression to match curl/wget piped to bash/sh/zsh
	re := regexp.MustCompile(`(?i)(curl|wget).*\s*\|\s*(bash|sh|zsh)`)

	// Create line mapper for improved line number detection
	lineMapper := linenum.NewLineMapper(workflow.Content)

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			if re.MatchString(step.Run) {
				// Use the new line mapper to find accurate line numbers
				pattern := linenum.FindPattern{
					Key:   "run",
					Value: step.Run,
				}
				lineResult := lineMapper.FindLineNumber(pattern)

				lineNumber := 0
				if lineResult != nil {
					lineNumber = lineResult.LineNumber
				}

				findings = append(findings, Finding{
					RuleID:      "MALICIOUS_CURL_PIPE_BASH",
					RuleName:    "Curl Pipe to Shell",
					Description: "Command downloads and executes code directly from the internet, which can be a security risk",
					Severity:    High,
					Category:    MaliciousPattern,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    step.Name,
					Evidence:    step.Run,
					LineNumber:  lineNumber,
					Remediation: "Download the script first, verify its contents, and then execute it separately",
				})
			}
		}
	}

	return findings
}

// checkBase64DecodeExecution checks for base64 decode piped to shell commands
func checkBase64DecodeExecution(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	// Regular expression to match base64 decode piped to execution
	re := regexp.MustCompile(`(?i)(base64\s*-d|base64\s*--decode|base64\s*-D).*\s*\|\s*(bash|sh|zsh|eval)`)

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			if re.MatchString(step.Run) {
				// Use the helper function for line number detection
				lineNumber := findLineNumberWithMapper(workflow, step.Name, step.Run)

				findings = append(findings, Finding{
					RuleID:      "MALICIOUS_BASE64_DECODE",
					RuleName:    "Base64 Decode Execution",
					Description: "Command decodes and executes base64 encoded data, which can hide malicious code",
					Severity:    Critical,
					Category:    ShellObfuscation,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    step.Name,
					Evidence:    step.Run,
					LineNumber:  lineNumber,
					Remediation: "Avoid executing encoded commands. If necessary, decode to a file, verify content, then execute",
				})
			}
		}
	}

	return findings
}

// checkDataExfiltration checks for potential data exfiltration commands
func checkDataExfiltration(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	// Common C2 and exfiltration patterns
	exfilPatterns := []*regexp.Regexp{
		// Ngrok and other tunneling services
		regexp.MustCompile(`(?i)(ngrok|serveo|pagekite|localtunnel|expose|cloudflared)\b`),

		// Suspicious URL patterns with potential webhook/dump sites
		regexp.MustCompile(`(?i)(webhook|paste|bin|dump|collect|exfil|c2|attacker|command)\.(com|net|org|io|me)`),

		// Specific known exfiltration services
		regexp.MustCompile(`(?i)(webhook\.site|requestbin\.com|pipedream\.net|hookbin\.com|beeceptor\.com)`),

		// Suspicious POST operations, especially with secret/token/env content
		regexp.MustCompile(`(?i)curl\s+.*\-d.*(\$(?:{[A-Za-z0-9_]+}|\([A-Za-z0-9_]+\)|[A-Za-z0-9_]+)|secrets\.|env\.)`),

		// Commands piping env/secrets to external services
		regexp.MustCompile(`(?i)(env|printenv|set|secrets).*(\||>).*curl`),

		// Commands writing secrets to files and sending them
		regexp.MustCompile(`(?i)(echo|\$\{\{).*secrets.*>.*(\.txt|\.json)`),

		// Direct IP addresses, especially with unusual ports
		regexp.MustCompile(`(?i)(curl|wget|nc)\s+.*\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]{2,5})?\b`),

		// DNS/domain exfiltration techniques
		regexp.MustCompile(`(?i)(dig|nslookup|host)\s+.*(\$(?:{[A-Za-z0-9_]+}|\([A-Za-z0-9_]+\)|[A-Za-z0-9_]+)|secrets\.|env\.)`),

		// GitHub tokens or env vars being passed to scripts or commands
		regexp.MustCompile(`(?i)(\$GITHUB_TOKEN|\$\{\{ *secrets\.GITHUB_TOKEN *\}\}|\$\{\{ *secrets\.[^\}]+ *\}\}).*\|\s*(curl|wget|nc|bash)`),

		// Commands reading sensitive files and sending data
		regexp.MustCompile(`(?i)(cat|type|head|tail)\s+.*\.(npmrc|env|config|secret|token|key|pem|p12|pfx).*\|\s*(curl|wget|nc)`),

		// Script execution with environment access
		regexp.MustCompile(`(?i)(bash|sh|cmd|powershell).*\.(sh|ps1|bat|cmd).*(\$(?:{[A-Za-z0-9_]+}|\([A-Za-z0-9_]+\)|[A-Za-z0-9_]+)|secrets\.|env\.)`),

		// Base64 encoding with curl
		regexp.MustCompile(`(?i)base64.*\|\s*curl`),

		// Reverse shells
		regexp.MustCompile(`(?i)(bash -i >& |nc -e |python -c ['"]import socket,subprocess,os)`),
	}

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			// Process run commands
			for _, pattern := range exfilPatterns {
				if pattern.MatchString(step.Run) {
					// Find the line number by searching for the step in the content
					lineNumber := findLineNumberWithMapper(workflow, step.Name, step.Run)

					findings = append(findings, Finding{
						RuleID:      "MALICIOUS_DATA_EXFILTRATION",
						RuleName:    "Suspicious Data Exfiltration",
						Description: "Command potentially exfiltrates secrets or sensitive data to external servers",
						Severity:    Critical,
						Category:    MaliciousPattern,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    step.Name,
						Evidence:    step.Run,
						LineNumber:  lineNumber,
						Remediation: "Review and remove suspicious commands that may send sensitive data to external locations",
					})
					break // Only report once per step for this rule
				}
			}
		}

		// Also check env section for suspicious values
		if job.Env != nil {
			// job.Env is already map[string]string, so we can directly iterate
			for key, value := range job.Env {
				for _, pattern := range exfilPatterns {
					if pattern.MatchString(value) {
						// Find the line number for this environment variable
						lineNumber := findLineNumberWithMapper(workflow, key+":", value)

						findings = append(findings, Finding{
							RuleID:      "MALICIOUS_DATA_EXFILTRATION",
							RuleName:    "Suspicious Data Exfiltration in Environment Variable",
							Description: "Environment variable contains suspicious exfiltration pattern",
							Severity:    Critical,
							Category:    MaliciousPattern,
							FilePath:    workflow.Path,
							JobName:     jobName,
							Evidence:    key + ": " + value,
							LineNumber:  lineNumber,
							Remediation: "Review and remove suspicious environment variable values",
						})
						break
					}
				}
			}
		}
	}

	// Also check workflow-level env
	if workflow.Workflow.Env != nil {
		// workflow.Workflow.Env is already map[string]string, so we can directly iterate
		for key, value := range workflow.Workflow.Env {
			for _, pattern := range exfilPatterns {
				if pattern.MatchString(value) {
					// Find the line number for this environment variable
					lineNumber := findLineNumberWithMapper(workflow, key+":", value)

					findings = append(findings, Finding{
						RuleID:      "MALICIOUS_DATA_EXFILTRATION",
						RuleName:    "Suspicious Data Exfiltration in Workflow Environment",
						Description: "Workflow environment variable contains suspicious exfiltration pattern",
						Severity:    Critical,
						Category:    MaliciousPattern,
						FilePath:    workflow.Path,
						Evidence:    key + ": " + value,
						LineNumber:  lineNumber,
						Remediation: "Review and remove suspicious environment variable values",
					})
					break
				}
			}
		}
	}

	return findings
}

// checkInsecurePullRequestTarget checks for insecure pull_request_target usage
func checkInsecurePullRequestTarget(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	// Check if workflow uses pull_request_target event
	usesPullRequestTarget := false

	switch on := workflow.Workflow.On.(type) {
	case string:
		usesPullRequestTarget = on == "pull_request_target"
	case map[string]interface{}:
		_, usesPullRequestTarget = on["pull_request_target"]
	case []interface{}:
		for _, event := range on {
			if eventStr, ok := event.(string); ok && eventStr == "pull_request_target" {
				usesPullRequestTarget = true
				break
			}
		}
	}

	if !usesPullRequestTarget {
		return findings
	}

	// Check for code checkout in pull_request_target context
	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Uses == "" {
				continue
			}

			// Check if step uses checkout action
			if strings.HasPrefix(step.Uses, "actions/checkout@") {
				// Check if PR ref is used
				if step.With != nil {
					if ref, ok := step.With["ref"].(string); ok {
						if strings.Contains(ref, "github.event.pull_request.head.ref") ||
							strings.Contains(ref, "github.head_ref") {

							// Find the line number
							stepStr := "uses: " + step.Uses
							lineNumber := findLineNumberWithMapper(workflow, step.Name, stepStr)

							findings = append(findings, Finding{
								RuleID:      "INSECURE_PULL_REQUEST_TARGET",
								RuleName:    "Insecure pull_request_target usage",
								Description: "Workflow uses pull_request_target event and checks out PR code, which can lead to code execution",
								Severity:    Critical,
								Category:    Misconfiguration,
								FilePath:    workflow.Path,
								JobName:     jobName,
								StepName:    step.Name,
								Evidence:    "pull_request_target with checkout ref: " + ref,
								LineNumber:  lineNumber,
								Remediation: "Use pull_request event instead, or don't checkout PR code with pull_request_target",
							})
						}
					}
				}
			}
		}
	}

	return findings
}

// checkUnpinnedAction checks for GitHub Actions without pinned versions
func checkUnpinnedAction(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	content := string(workflow.Content)
	lines := strings.Split(content, "\n")

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Uses == "" {
				continue
			}

			// Skip if it's a local action (starts with ./ or ../)
			if strings.HasPrefix(step.Uses, "./") || strings.HasPrefix(step.Uses, "../") {
				continue
			}

			// Check if the action is pinned with a commit SHA (40 hex characters)
			shaPattern := regexp.MustCompile(`@[a-f0-9]{40}$`)
			if !shaPattern.MatchString(step.Uses) {
				// Find the line number by searching for the uses statement
				lineNumber := 1
				searchPattern := "uses: " + step.Uses

				for i, line := range lines {
					if strings.Contains(line, searchPattern) {
						lineNumber = i + 1
						break
					}
				}

				// Determine the type of reference being used
				evidenceType := "unpinned reference"
				if strings.Contains(step.Uses, "@v") {
					evidenceType = "version tag (not SHA)"
				} else if strings.Contains(step.Uses, "@main") || strings.Contains(step.Uses, "@master") {
					evidenceType = "branch reference"
				}

				findings = append(findings, Finding{
					RuleID:      "UNPINNED_ACTION",
					RuleName:    "Unpinned GitHub Action",
					Description: "GitHub Action is not pinned to a specific SHA commit, which may lead to supply chain attacks",
					Severity:    Medium,
					Category:    Misconfiguration,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    step.Name,
					Evidence:    fmt.Sprintf("uses: %s (%s)", step.Uses, evidenceType),
					LineNumber:  lineNumber,
					Remediation: "Pin the action to a full 40-character commit SHA instead of a version tag or branch reference. Example: uses: actions/checkout@a12a3943b4bdde767164f792f33f40b04645d846",
				})
			}
		}
	}

	return findings
}

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
			if shouldSkipSecret(content, match[0], match[1], matchStr, config) {
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
func shouldSkipSecret(content string, start, end int, matchStr string, config interface{}) bool {
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

	// Check configuration-based ignores if config is provided
	if config != nil {
		// Extract context around the match for configuration checks
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
		context := content[lineStart:lineEnd]

		// TODO: Use proper type assertion when config package is imported
		// For now, fall back to default behavior
		_ = context // Avoid unused variable warning
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

// checkContinueOnErrorCriticalJob checks for critical jobs with continue-on-error set to true
func checkContinueOnErrorCriticalJob(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	// List of critical job names (common patterns)
	criticalJobPatterns := []string{
		"deploy", "prod", "production", "release", "publish", "security", "authorization",
		"authentication", "auth", "iam", "admin", "validate", "verification",
	}

	for jobName, job := range workflow.Workflow.Jobs {
		// Check if this is a critical job
		isCritical := false
		jobNameLower := strings.ToLower(jobName)
		for _, pattern := range criticalJobPatterns {
			if strings.Contains(jobNameLower, pattern) {
				isCritical = true
				break
			}
		}

		if isCritical && job.ContinueOnError {
			// Find line number for this job using the LineMapper
			lineNumber := findLineNumberWithMapper(workflow, jobName+":", "")

			findings = append(findings, Finding{
				RuleID:      "CONTINUE_ON_ERROR_CRITICAL_JOB",
				RuleName:    "Continue On Error in Critical Job",
				Description: "Critical job has continue-on-error set to true, which may mask failures",
				Severity:    Medium,
				Category:    Misconfiguration,
				FilePath:    workflow.Path,
				JobName:     jobName,
				StepName:    "",
				Evidence:    "continue-on-error: true",
				LineNumber:  lineNumber,
				Remediation: "Remove continue-on-error from critical jobs or handle errors explicitly",
			})
		}
	}

	return findings
}

// checkBroadPermissions checks for overly broad permissions in workflows
func checkBroadPermissions(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	// Check for write-all permissions
	if workflow.Workflow.Permissions != nil {
		if permStr, ok := workflow.Workflow.Permissions.(string); ok && permStr == "write-all" {
			// Find line number for permissions
			content := string(workflow.Content)
			lines := strings.Split(content, "\n")
			lineNumber := 1

			for i, line := range lines {
				if strings.Contains(line, "permissions:") && strings.Contains(line, "write-all") {
					lineNumber = i + 1
					break
				}
			}

			findings = append(findings, Finding{
				RuleID:      "BROAD_PERMISSIONS",
				RuleName:    "Overly Broad Permissions",
				Description: "Workflow uses 'write-all' permissions, granting excessive access to all repository resources",
				Severity:    Critical,
				Category:    Misconfiguration,
				FilePath:    workflow.Path,
				JobName:     "",
				StepName:    "",
				Evidence:    "permissions: write-all",
				LineNumber:  lineNumber,
				Remediation: "Use specific permissions instead of 'write-all'. Define only the permissions your workflow actually needs.",
			})
		}
	}

	return findings
}

// findLineNumberWithMapper is a helper function that uses the new LineMapper
// for backward compatibility and easier migration
func findLineNumberWithMapper(workflow parser.WorkflowFile, key, value string) int {
	lineMapper := linenum.NewLineMapper(workflow.Content)
	pattern := linenum.FindPattern{
		Key:   key,
		Value: value,
	}

	result := lineMapper.FindLineNumber(pattern)
	if result != nil {
		return result.LineNumber
	}

	return 0
}
