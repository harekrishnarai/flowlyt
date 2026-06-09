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

	"github.com/harekrishnarai/flowlyt/v2/pkg/linenum"
	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
)

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

				finding := Finding{
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
				}

				// Enhance with context information
				finding = enhanceFindingWithContext(finding, workflow, job)
				findings = append(findings, finding)
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

				finding := Finding{
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
				}

				// Enhance with context information
				finding = enhanceFindingWithContext(finding, workflow, job)
				findings = append(findings, finding)
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

// checkDangerousWriteOperations checks for dangerous write operations on GitHub environment variables
func checkDangerousWriteOperations(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Patterns that indicate dangerous writes to GitHub environment variables.
	// Only flag expression interpolation (${{ ... }}) which can contain attacker-controlled
	// values from PR titles, branch names, issue bodies, etc.
	dangerousPatterns := []*regexp.Regexp{
		regexp.MustCompile(`echo\s+.*\$\{\{[^}]*\}\}.*>>\s*\$GITHUB_OUTPUT`),
		regexp.MustCompile(`echo\s+.*\$\{\{[^}]*\}\}.*>>\s*\$GITHUB_ENV`),
		regexp.MustCompile(`printf\s+.*\$\{\{[^}]*\}\}.*>>\s*\$GITHUB_OUTPUT`),
		regexp.MustCompile(`printf\s+.*\$\{\{[^}]*\}\}.*>>\s*\$GITHUB_ENV`),
	}

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			for i, pattern := range dangerousPatterns {
				if pattern.MatchString(step.Run) {
					lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
						Key:   "run",
						Value: step.Run,
					})

					lineNumber := 0
					if lineResult != nil {
						lineNumber = lineResult.LineNumber
					}

					dedupKey := fmt.Sprintf("%s:%d:%d", workflow.Path, lineNumber, i)
					if seen[dedupKey] {
						continue
					}
					seen[dedupKey] = true

					findings = append(findings, Finding{
						RuleID:      "DANGEROUS_WRITE_OPERATION",
						RuleName:    "Dangerous Write Operation",
						Description: "Direct writes to $GITHUB_OUTPUT or $GITHUB_ENV can lead to command injection vulnerabilities",
						Severity:    Critical,
						Category:    InjectionAttack,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    step.Name,
						Evidence:    strings.TrimSpace(step.Run),
						LineNumber:  lineNumber,
						Remediation: "Use GitHub's recommended secure methods: echo \"name=value\" >> $GITHUB_OUTPUT or use multiline values with EOF delimiters",
					})
				}
			}
		}
	}

	return findings
}

// checkUnsecureCommandsEnabled checks for ACTIONS_ALLOW_UNSECURE_COMMANDS environment variable
func checkUnsecureCommandsEnabled(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Check global env
	for key, value := range workflow.Workflow.Env {
		if strings.ToUpper(key) == "ACTIONS_ALLOW_UNSECURE_COMMANDS" {
			if value == "true" || value == "1" {
				lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
					Key:   key,
					Value: value,
				})

				lineNumber := 0
				if lineResult != nil {
					lineNumber = lineResult.LineNumber
				}

				findings = append(findings, Finding{
					RuleID:      "UNSECURE_COMMANDS_ENABLED",
					RuleName:    "Unsecure Commands Enabled",
					Description: "ACTIONS_ALLOW_UNSECURE_COMMANDS is deprecated and enables dangerous workflow commands",
					Severity:    High,
					Category:    Misconfiguration,
					FilePath:    workflow.Path,
					JobName:     "",
					StepName:    "",
					Evidence:    fmt.Sprintf("%s: %s", key, value),
					LineNumber:  lineNumber,
					Remediation: "Remove ACTIONS_ALLOW_UNSECURE_COMMANDS and use secure alternatives for workflow commands",
				})
			}
		}
	}

	// Check job-level env
	for jobName, job := range workflow.Workflow.Jobs {
		for key, value := range job.Env {
			if strings.ToUpper(key) == "ACTIONS_ALLOW_UNSECURE_COMMANDS" {
				if value == "true" || value == "1" {
					lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
						Key:   key,
						Value: value,
					})

					lineNumber := 0
					if lineResult != nil {
						lineNumber = lineResult.LineNumber
					}

					findings = append(findings, Finding{
						RuleID:      "UNSECURE_COMMANDS_ENABLED",
						RuleName:    "Unsecure Commands Enabled",
						Description: "ACTIONS_ALLOW_UNSECURE_COMMANDS is deprecated and enables dangerous workflow commands",
						Severity:    High,
						Category:    Misconfiguration,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    "",
						Evidence:    fmt.Sprintf("%s: %s", key, value),
						LineNumber:  lineNumber,
						Remediation: "Remove ACTIONS_ALLOW_UNSECURE_COMMANDS and use secure alternatives for workflow commands",
					})
				}
			}
		}

		// Check step-level env
		for _, step := range job.Steps {
			for key, value := range step.Env {
				if strings.ToUpper(key) == "ACTIONS_ALLOW_UNSECURE_COMMANDS" {
					if value == "true" || value == "1" {
						lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
							Key:   key,
							Value: value,
						})

						lineNumber := 0
						if lineResult != nil {
							lineNumber = lineResult.LineNumber
						}

						findings = append(findings, Finding{
							RuleID:      "UNSECURE_COMMANDS_ENABLED",
							RuleName:    "Unsecure Commands Enabled",
							Description: "ACTIONS_ALLOW_UNSECURE_COMMANDS is deprecated and enables dangerous workflow commands",
							Severity:    High,
							Category:    Misconfiguration,
							FilePath:    workflow.Path,
							JobName:     jobName,
							StepName:    step.Name,
							Evidence:    fmt.Sprintf("%s: %s", key, value),
							LineNumber:  lineNumber,
							Remediation: "Remove ACTIONS_ALLOW_UNSECURE_COMMANDS and use secure alternatives for workflow commands",
						})
					}
				}
			}
		}
	}

	return findings
}

// unquotedVarRe matches bare $VAR references (not ${VAR} or ${{ expr }}).
// Double-quote wrapping is checked separately for file-op commands via fileOpCmdRe.
var unquotedVarRe = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)(?:[^}A-Za-z0-9_]|$)`)

// dangerousCmdRe matches commands where unquoted variables cause real harm.
var dangerousCmdRe = regexp.MustCompile(
	`^\s*(?:sudo\s+)?(rm|cp|mv|mkdir|chmod|chown|ln|find|rsync|tar|zip|unzip|eval|curl|wget)\b`)

// fileOpCmdRe matches file-operation commands where double-quoting a $VAR provides
// actual safety (prevents word splitting/glob expansion). Does NOT include exec or
// network commands (eval, curl, wget, bash -c) where quoting is insufficient.
// find is intentionally excluded: its -exec/-delete sub-commands mean a single
// quoted path argument does not fully contain the risk.
var fileOpCmdRe = regexp.MustCompile(
	`^\s*(?:sudo\s+)?(rm|cp|mv|mkdir|chmod|chown|ln|rsync|tar|zip|unzip)\b`)

// safeCmdRe matches commands where word splitting is harmless.
var safeCmdRe = regexp.MustCompile(`^\s*(echo|printf|cat)\b`)

// knownBotRe matches known official GitHub service bot identities used in
// git config user.name/email commands. Findings for these are downgraded to LOW.
var knownBotRe = regexp.MustCompile(
	`user\.(name|email)\s+["']?(github-actions(?:\[bot\])?|dependabot\[bot\])["']?`)

// checkShellScriptIssues performs basic shellcheck-like analysis on run commands
func checkShellScriptIssues(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Common shell script security issues (shellcheck-like patterns)
	shellIssues := []struct {
		pattern     *regexp.Regexp
		description string
		remediation string
		severity    Severity
	}{
		{
			pattern:     regexp.MustCompile(`rm\s+-rf\s+/`), // Dangerous rm commands
			description: "Dangerous rm -rf command targeting root directory",
			remediation: "Avoid using rm -rf on absolute paths, especially root directory",
			severity:    Critical,
		},
		{
			pattern:     regexp.MustCompile(`eval\s+`), // Eval usage
			description: "Use of eval can lead to code injection vulnerabilities",
			remediation: "Avoid using eval; use safer alternatives for dynamic command execution",
			severity:    High,
		},
		{
			pattern:     regexp.MustCompile(`\|\s*(sh|bash|zsh)\s*$`), // Pipe to shell
			description: "Piping to shell can execute arbitrary commands",
			remediation: "Avoid piping untrusted input to shell interpreters",
			severity:    High,
		},
		{
			pattern:     regexp.MustCompile(`wget\s+[^|]*\s*\|\s*sudo`), // wget pipe to sudo
			description: "Downloading and executing content with sudo privileges is dangerous",
			remediation: "Download files first, verify their integrity, then execute with minimal privileges",
			severity:    Critical,
		},
		{
			pattern:     regexp.MustCompile(`curl\s+[^|]*\s*\|\s*sudo`), // curl pipe to sudo
			description: "Downloading and executing content with sudo privileges is dangerous",
			remediation: "Download files first, verify their integrity, then execute with minimal privileges",
			severity:    Critical,
		},
	}

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			for _, issue := range shellIssues {
				if issue.pattern.MatchString(step.Run) {
					// For multi-line run blocks the generic `run: |` fallback
					// always resolves to the first such key in the file,
					// misattributing findings to the wrong step.  Use the first
					// non-empty content line instead so each step maps to its
					// own location in the file.
					runPattern := linenum.FindPattern{Key: "run", Value: step.Run}
					if strings.Contains(step.Run, "\n") {
						for _, l := range strings.Split(step.Run, "\n") {
							if trimmed := strings.TrimSpace(l); trimmed != "" {
								runPattern = linenum.FindPattern{Value: trimmed}
								break
							}
						}
					}
					lineResult := lineMapper.FindLineNumber(runPattern)

					lineNumber := 0
					if lineResult != nil {
						lineNumber = lineResult.LineNumber
					}

					findings = append(findings, Finding{
						RuleID:      "SHELL_SCRIPT_ISSUES",
						RuleName:    "Shell Script Security Issues",
						Description: issue.description,
						Severity:    issue.severity,
						Category:    MaliciousPattern,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    step.Name,
						Evidence:    strings.TrimSpace(step.Run),
						LineNumber:  lineNumber,
						Remediation: issue.remediation,
					})
				}
			}

			// --- Dedicated unquoted-variable check ---
			// Suppression is position-based: safe commands (echo, printf, cat) are
			// never flagged; dangerous commands (rm, cp, curl, etc.) are always flagged
			// regardless of whether the variable was locally assigned. A locally-assigned
			// variable in a dangerous position (e.g. rm -rf $DIR) is still a real risk.

			// Scan per-line for unquoted vars in dangerous positions.
			for _, line := range strings.Split(step.Run, "\n") {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" || strings.HasPrefix(trimmed, "#") {
					continue // skip blank lines and comments
				}
				// Skip lines where the command is safe (echo, printf, cat).
				if safeCmdRe.MatchString(trimmed) {
					continue
				}
				// Only flag if the line is in a dangerous command position.
				isDangerous := dangerousCmdRe.MatchString(trimmed) ||
					strings.Contains(trimmed, "eval ") ||
					strings.Contains(trimmed, "bash -c") ||
					strings.Contains(trimmed, "sh -c")
				if !isDangerous {
					continue
				}
				// Find unquoted $VAR references on this line using byte-position form
				// so we can check whether each '$' is immediately preceded by '"'.
				isFileOp := fileOpCmdRe.MatchString(trimmed)
				idxPairs := unquotedVarRe.FindAllStringSubmatchIndex(trimmed, -1)
				for _, pair := range idxPairs {
					if len(pair) < 2 {
						continue
					}
					start := pair[0] // byte offset of '$' in trimmed
					// If this is a file-op command and '$' is immediately preceded by '"',
					// the variable is properly quoted — word splitting cannot occur.
					// Known limitation: variables preceded by literal text inside double
					// quotes (e.g. "prefix$VAR") are not suppressed by this heuristic.
					if isFileOp && start > 0 && trimmed[start-1] == '"' {
						continue
					}
					// Emit finding — use the actual line for accurate attribution.
					lineResult := lineMapper.FindLineNumber(linenum.FindPattern{Value: trimmed})
					lineNumber := 0
					if lineResult != nil {
						lineNumber = lineResult.LineNumber
					}
					findings = append(findings, Finding{
						RuleID:      "SHELL_SCRIPT_ISSUES",
						RuleName:    "Shell Script Security Issues",
						Description: "Unquoted variable usage may lead to word splitting and pathname expansion",
						Severity:    Medium,
						Category:    MaliciousPattern,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    step.Name,
						Evidence:    trimmed,
						LineNumber:  lineNumber,
						Remediation: "Quote variables: \"$VAR\" instead of $VAR",
					})
					break // one finding per dangerous line is sufficient
				}
			}
		}
	}

	return findings
}

// checkObfuscationDetection detects obfuscated code patterns
func checkObfuscationDetection(workflow parser.WorkflowFile) []Finding {
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

			// Check for various obfuscation patterns
			obfuscationPatterns := []struct {
				pattern     string
				description string
				severity    Severity
			}{
				{`\$\{[^}]*\[.*\*.*\].*\}`, "Variable expansion with wildcards", High},
				{`eval\s*\$\(.*base64.*\)`, "Base64 decoded eval", Critical},
				{`\$\(\$\(.*\)\)`, "Nested command substitution", Medium},
				// Removed: Non-printable characters - too many false positives with GitHub Actions syntax
				{`\\x[0-9a-f]{2}`, "Hex-encoded characters", Medium},
				// More specific pattern for potentially dangerous parameter expansion
				{`\$\{[^}]*#[^}]*\$\{\{[^}]*\}\}[^}]*\}`, "Parameter expansion with user input pattern removal", High},
				{`\|\s*xxd\s*-r`, "Hex decode pipeline", High},
				{`printf.*\\[0-9]{3}`, "Octal escape sequences", Medium},
			}

			for _, obfPattern := range obfuscationPatterns {
				re := regexp.MustCompile(`(?i)` + obfPattern.pattern)
				if re.MatchString(step.Run) {
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
						RuleID:      "OBFUSCATION_DETECTION",
						RuleName:    "Code Obfuscation Detection",
						Description: fmt.Sprintf("Detected obfuscation pattern: %s", obfPattern.description),
						Severity:    obfPattern.severity,
						Category:    ShellObfuscation,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    stepName,
						Evidence:    step.Run,
						Remediation: "Review obfuscated code for malicious intent; use clear, readable commands",
						LineNumber:  lineNumber,
					})
				}
			}
		}
	}

	return findings
}
