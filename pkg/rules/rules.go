package rules

import (
	"regexp"
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/parser"
)

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
	MaliciousPattern Category = "MALICIOUS_PATTERN"
	Misconfiguration Category = "MISCONFIGURATION"
	SecretExposure   Category = "SECRET_EXPOSURE"
	ShellObfuscation Category = "SHELL_OBFUSCATION"
	PolicyViolation  Category = "POLICY_VIOLATION"
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
	LineNumber  int // Line number where the issue was found
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
	}
}

// checkCurlPipeToShell checks for curl/wget piped to shell commands
func checkCurlPipeToShell(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	// Regular expression to match curl/wget piped to bash/sh/zsh
	re := regexp.MustCompile(`(?i)(curl|wget).*\s*\|\s*(bash|sh|zsh)`)

	// Preprocess content to calculate line numbers
	content := string(workflow.Content)
	lines := strings.Split(content, "\n")
	lineToChar := make([]int, len(lines)+1)

	// Build a mapping of line numbers to character positions
	lineToChar[0] = 0
	for i, line := range lines {
		lineToChar[i+1] = lineToChar[i] + len(line) + 1 // +1 for the newline character
	}

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			if re.MatchString(step.Run) {
				// Find the line number by searching for the step in the content
				lineNumber := findLineNumber(content, step.Name, step.Run, lineToChar)

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

	// Preprocess content to calculate line numbers
	content := string(workflow.Content)
	lines := strings.Split(content, "\n")
	lineToChar := make([]int, len(lines)+1)

	// Build a mapping of line numbers to character positions
	lineToChar[0] = 0
	for i, line := range lines {
		lineToChar[i+1] = lineToChar[i] + len(line) + 1 // +1 for the newline character
	}

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			if re.MatchString(step.Run) {
				// Find the line number by searching for the step in the content
				lineNumber := findLineNumber(content, step.Name, step.Run, lineToChar)

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

	// Preprocess content to calculate line numbers
	content := string(workflow.Content)
	lines := strings.Split(content, "\n")
	lineToChar := make([]int, len(lines)+1)

	// Build a mapping of line numbers to character positions
	lineToChar[0] = 0
	for i, line := range lines {
		lineToChar[i+1] = lineToChar[i] + len(line) + 1 // +1 for the newline character
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
					lineNumber := findLineNumber(content, step.Name, step.Run, lineToChar)

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
						lineNumber := findLineNumber(content, key+":", value, lineToChar)

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
					lineNumber := findLineNumber(content, key+":", value, lineToChar)

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

// findLineNumber helps locate the line number for a specific pattern in the content
func findLineNumber(content, key, value string, lineToChar []int) int {
	// If we have both a key and value, try to find them together
	if key != "" && value != "" {
		// Try different formats to match key-value pairs in YAML
		searchPatterns := []string{
			key + ":" + " " + value,
			key + ":" + " '" + value + "'",
			key + ":" + " \"" + value + "\"",
			value, // Fallback to just searching for the value
		}

		for _, pattern := range searchPatterns {
			if idx := strings.Index(content, pattern); idx != -1 {
				// Find which line contains this index
				for i := 1; i < len(lineToChar); i++ {
					if lineToChar[i] > idx {
						return i // Line numbers are 1-based
					}
				}
			}
		}
	}

	// If the above didn't find anything, just search for the value
	if value != "" {
		if idx := strings.Index(content, value); idx != -1 {
			// Find which line contains this index
			for i := 1; i < len(lineToChar); i++ {
				if lineToChar[i] > idx {
					return i // Line numbers are 1-based
				}
			}
		}
	}

	// Fallback - do a more exhaustive search
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		// Try to find the key or value in the line
		if (key != "" && strings.Contains(line, key)) ||
			(value != "" && strings.Contains(line, value)) {
			return i + 1 // Line numbers are 1-based
		}
	}

	return 0 // Couldn't find the line
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

	// Preprocess content to calculate line numbers
	content := string(workflow.Content)
	lines := strings.Split(content, "\n")
	lineToChar := make([]int, len(lines)+1)

	// Build a mapping of line numbers to character positions
	lineToChar[0] = 0
	for i, line := range lines {
		lineToChar[i+1] = lineToChar[i] + len(line) + 1 // +1 for the newline character
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
							lineNumber := findLineNumber(content, step.Name, stepStr, lineToChar)

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

	// Preprocess content to calculate line numbers
	content := string(workflow.Content)
	lines := strings.Split(content, "\n")
	lineToChar := make([]int, len(lines)+1)

	// Build a mapping of line numbers to character positions
	lineToChar[0] = 0
	for i, line := range lines {
		lineToChar[i+1] = lineToChar[i] + len(line) + 1 // +1 for the newline character
	}

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Uses == "" {
				continue
			}

			// Skip if it's a local action
			if strings.HasPrefix(step.Uses, "./") {
				continue
			}

			// Check if the action is pinned with a commit SHA
			if !regexp.MustCompile(`@[0-9a-f]{40}$`).MatchString(step.Uses) {
				// Check if it's using a semver tag
				isSemver := regexp.MustCompile(`@v\d+(\.\d+)*$`).MatchString(step.Uses)

				// Flag if it's using a branch reference or unpinned
				if !isSemver {
					// Find the line number
					stepStr := "uses: " + step.Uses
					lineNumber := findLineNumber(content, step.Name, stepStr, lineToChar)

					findings = append(findings, Finding{
						RuleID:      "UNPINNED_ACTION",
						RuleName:    "Unpinned GitHub Action",
						Description: "GitHub Action is not pinned to a specific SHA commit",
						Severity:    Medium,
						Category:    Misconfiguration,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    step.Name,
						Evidence:    "Action: " + step.Uses,
						LineNumber:  lineNumber,
						Remediation: "Pin the action to a full commit SHA instead of a branch or version tag",
					})
				}
			}
		}
	}

	return findings
}

// checkHardcodedSecrets checks for potential secrets in workflow files
func checkHardcodedSecrets(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	// Common patterns for secrets
	secretPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(api[_-]?key|apikey|secret|token|password|pwd|credential)s?\s*[:=]\s*['"]([^'"]*)['"]`),
		regexp.MustCompile(`(?i)(aws|gcp|azure|github|gitlab)[_-]?(secret|token|key)s?\s*[:=]\s*['"]([^'"]*)['"]`),
		regexp.MustCompile(`[A-Za-z0-9_-]{40}`), // GitHub token pattern
		regexp.MustCompile(`(?i)(client[_-]?id|client[_-]?secret)\s*[:=]\s*['"]([^'"]*)['"]`),
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

			findings = append(findings, Finding{
				RuleID:      "HARDCODED_SECRET",
				RuleName:    "Hardcoded Secret",
				Description: "Potential secret or credential found hardcoded in workflow file",
				Severity:    Critical,
				Category:    SecretExposure,
				FilePath:    workflow.Path,
				JobName:     "",
				StepName:    "",
				Evidence:    matchStr,
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

// checkContinueOnErrorCriticalJob checks for critical jobs with continue-on-error set to true
func checkContinueOnErrorCriticalJob(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	// List of critical job names (common patterns)
	criticalJobPatterns := []string{
		"deploy", "prod", "production", "release", "publish", "security", "authorization",
		"authentication", "auth", "iam", "admin", "validate", "verification",
	}

	// Preprocess content to calculate line numbers
	content := string(workflow.Content)
	lines := strings.Split(content, "\n")
	lineToChar := make([]int, len(lines)+1)

	// Build a mapping of line numbers to character positions
	lineToChar[0] = 0
	for i, line := range lines {
		lineToChar[i+1] = lineToChar[i] + len(line) + 1 // +1 for the newline character
	}

	for jobName, job := range workflow.Workflow.Jobs {
		// Skip if continue-on-error is not set to true
		if !job.ContinueOnError {
			continue
		}

		// Check if the job name matches any critical pattern
		isCritical := false
		jobNameLower := strings.ToLower(jobName)

		for _, pattern := range criticalJobPatterns {
			if strings.Contains(jobNameLower, pattern) {
				isCritical = true
				break
			}
		}

		if isCritical {
			// Find the line number for the continue-on-error statement
			lineNumber := findLineNumber(content, jobName+":", "continue-on-error: true", lineToChar)

			findings = append(findings, Finding{
				RuleID:      "CONTINUE_ON_ERROR_CRITICAL_JOB",
				RuleName:    "Continue On Error in Critical Job",
				Description: "Critical job has continue-on-error set to true, which could bypass important failures",
				Severity:    Medium,
				Category:    Misconfiguration,
				FilePath:    workflow.Path,
				JobName:     jobName,
				Evidence:    "continue-on-error: true in job: " + jobName,
				LineNumber:  lineNumber,
				Remediation: "Remove continue-on-error: true from critical jobs, or ensure proper failure handling",
			})
		}
	}

	return findings
}
