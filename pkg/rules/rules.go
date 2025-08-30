package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/constants"
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

// Platform represents the CI/CD platform a rule applies to
type Platform string

const (
	PlatformAll    Platform = "ALL"    // Rule applies to all platforms
	PlatformGitHub Platform = "GITHUB" // Rule applies only to GitHub Actions
	PlatformGitLab Platform = "GITLAB" // Rule applies only to GitLab CI
)

// Rule represents a security rule to check in a workflow
type Rule struct {
	ID          string
	Name        string
	Description string
	Severity    Severity
	Category    Category
	Platform    Platform // Platform compatibility for this rule
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
	GitLabURL   string // Direct GitLab URL to the line (for remote repositories)
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
			Platform:    PlatformAll, // Shell commands apply to all platforms
			Check:       checkCurlPipeToShell,
		},
		{
			ID:          "MALICIOUS_BASE64_DECODE",
			Name:        "Base64 Decode Execution",
			Description: "Detects execution of base64-decoded data, which can hide malicious code",
			Severity:    Critical,
			Category:    ShellObfuscation,
			Platform:    PlatformAll, // Shell commands apply to all platforms
			Check:       checkBase64DecodeExecution,
		},
		{
			ID:          "MALICIOUS_DATA_EXFILTRATION",
			Name:        "Suspicious Data Exfiltration",
			Description: "Detects potential exfiltration of secrets or sensitive data to external servers",
			Severity:    Critical,
			Category:    MaliciousPattern,
			Platform:    PlatformAll, // Data exfiltration applies to all platforms
			Check:       checkDataExfiltration,
		},
		{
			ID:          "INSECURE_PULL_REQUEST_TARGET",
			Name:        "Insecure pull_request_target usage",
			Description: "Detects insecure usage of pull_request_target event with code checkout",
			Severity:    Critical,
			Category:    Misconfiguration,
			Platform:    PlatformGitHub, // GitHub Actions specific event
			Check:       checkInsecurePullRequestTarget,
		},
		{
			ID:          "UNPINNED_ACTION",
			Name:        "Unpinned GitHub Action",
			Description: "Detects usage of GitHub Actions without pinned versions (uses latest or branch)",
			Severity:    Medium,
			Category:    Misconfiguration,
			Platform:    PlatformGitHub, // GitHub Actions specific (uses: syntax)
			Check:       checkUnpinnedAction,
		},
		{
			ID:          "HARDCODED_SECRET",
			Name:        "Hardcoded Secret",
			Description: "Detects potential secrets hardcoded in workflow files",
			Severity:    Critical,
			Category:    SecretExposure,
			Platform:    PlatformAll, // Secrets apply to all platforms
			Check:       checkHardcodedSecrets,
		},
		{
			ID:          "CONTINUE_ON_ERROR_CRITICAL_JOB",
			Name:        "Continue On Error in Critical Job",
			Description: "Detects critical jobs with continue-on-error set to true",
			Severity:    Medium,
			Category:    Misconfiguration,
			Platform:    PlatformGitHub, // GitHub Actions specific syntax
			Check:       checkContinueOnErrorCriticalJob,
		},
		{
			ID:          "BROAD_PERMISSIONS",
			Name:        "Overly Broad Permissions",
			Description: "Workflow uses overly broad permissions that grant unnecessary access",
			Severity:    Critical,
			Category:    Misconfiguration,
			Platform:    PlatformGitHub, // GitHub Actions specific permissions model
			Check:       checkBroadPermissions,
		},
		{
			ID:          "INJECTION_VULNERABILITY",
			Name:        "Code Injection from User Input",
			Description: "Detects injection vulnerabilities where user-controlled input is directly interpolated into commands",
			Severity:    Critical,
			Category:    InjectionAttack,
			Platform:    PlatformAll, // Injection applies to all platforms
			Check:       checkInjectionVulnerabilities,
		},
		{
			ID:          "UNTRUSTED_CHECKOUT_EXECUTION",
			Name:        "Code Execution After Untrusted Checkout",
			Description: "Detects execution of commands after checking out untrusted code that could contain malicious scripts",
			Severity:    Critical,
			Category:    InjectionAttack,
			Platform:    PlatformGitHub, // GitHub Actions specific checkout patterns
			Check:       checkUntrustedCheckoutExecution,
		},
		{
			ID:          "SHELL_INJECTION",
			Name:        "Shell Injection Vulnerability",
			Description: "Detects shell injection vulnerabilities where user input is executed directly in shell context",
			Severity:    Critical,
			Category:    InjectionAttack,
			Platform:    PlatformAll, // Shell injection applies to all platforms
			Check:       checkShellInjectionVulnerabilities,
		},
		{
			ID:          "SCRIPT_INJECTION",
			Name:        "Script Injection Vulnerability",
			Description: "Detects script injection vulnerabilities in github-script actions and PowerShell scripts",
			Severity:    Critical,
			Category:    InjectionAttack,
			Platform:    PlatformGitHub, // GitHub Actions specific (github-script)
			Check:       checkScriptInjectionVulnerabilities,
		},
		{
			ID:          "SELF_HOSTED_RUNNER_SECURITY",
			Name:        "Self-Hosted Runner Security Risk",
			Description: "Detects security risks with self-hosted runners, especially in pull request workflows",
			Severity:    Critical,
			Category:    AccessControl,
			Platform:    PlatformGitHub, // GitHub Actions specific runners
			Check:       checkSelfHostedRunnerSecurity,
		},
		{
			ID:          "KNOWN_VULNERABLE_ACTION",
			Name:        "Known Vulnerable Action",
			Description: "Detects usage of GitHub Actions with known security vulnerabilities",
			Severity:    Critical,
			Category:    SupplyChain,
			Platform:    PlatformGitHub, // GitHub Actions specific
			Check:       checkKnownVulnerableActions,
		},
		{
			ID:          "UNPINNABLE_ACTION",
			Name:        "Unpinnable Action",
			Description: "Detects actions that cannot be pinned to specific versions",
			Severity:    Medium,
			Category:    SupplyChain,
			Platform:    PlatformGitHub, // GitHub Actions specific
			Check:       checkUnpinnableActions,
		},
		{
			ID:          "TYPOSQUATTING_ACTION",
			Name:        "Potential Typosquatting Action",
			Description: "Detects action names that might be typosquatting attempts",
			Severity:    High,
			Category:    SupplyChain,
			Platform:    PlatformGitHub, // GitHub Actions specific
			Check:       checkTyposquattingActions,
		},
		{
			ID:          "UNTRUSTED_ACTION_SOURCE",
			Name:        "Untrusted Action Source",
			Description: "Detects actions from untrusted or unknown publishers",
			Severity:    Medium,
			Category:    SupplyChain,
			Platform:    PlatformGitHub, // GitHub Actions specific
			Check:       checkUntrustedActionSources,
		},
		{
			ID:          "DEPRECATED_ACTION",
			Name:        "Deprecated Action",
			Description: "Detects usage of deprecated action versions",
			Severity:    Medium,
			Category:    SupplyChain,
			Platform:    PlatformGitHub, // GitHub Actions specific
			Check:       checkDeprecatedActions,
		},
		{
			ID:          "DANGEROUS_WRITE_OPERATION",
			Name:        "Dangerous Write Operation",
			Description: "Detects dangerous write operations on $GITHUB_OUTPUT or $GITHUB_ENV that could lead to command injection",
			Severity:    Critical,
			Category:    InjectionAttack,
			Platform:    PlatformGitHub, // GitHub Actions specific environment variables
			Check:       checkDangerousWriteOperations,
		},
		{
			ID:          "LOCAL_ACTION_USAGE",
			Name:        "Local Action Usage",
			Description: "Detects usage of local actions which may pose security risks",
			Severity:    Medium,
			Category:    Misconfiguration,
			Platform:    PlatformGitHub, // GitHub Actions specific
			Check:       checkLocalActionUsage,
		},
		{
			ID:          "UNSECURE_COMMANDS_ENABLED",
			Name:        "Unsecure Commands Enabled",
			Description: "Detects workflows with ACTIONS_ALLOW_UNSECURE_COMMANDS enabled, which is deprecated and dangerous",
			Severity:    High,
			Category:    Misconfiguration,
			Platform:    PlatformGitHub, // GitHub Actions specific
			Check:       checkUnsecureCommandsEnabled,
		},
		{
			ID:          "SHELL_SCRIPT_ISSUES",
			Name:        "Shell Script Security Issues",
			Description: "Detects common shell script security issues in run commands using basic shellcheck-like analysis",
			Severity:    Medium,
			Category:    MaliciousPattern,
			Platform:    PlatformAll, // Shell scripts apply to all platforms
			Check:       checkShellScriptIssues,
		},
		{
			ID:          "PR_TARGET_ABUSE",
			Name:        "Pull Request Target Abuse",
			Description: "Detects dangerous usage of pull_request_target trigger with write permissions",
			Severity:    Critical,
			Category:    InjectionAttack,
			Platform:    PlatformGitHub,
			Check:       checkPRTargetAbuse,
		},
		{
			ID:          "CREDENTIAL_EXFILTRATION",
			Name:        "Credential Exfiltration",
			Description: "Detects patterns that could lead to secret or credential theft",
			Severity:    Critical,
			Category:    InjectionAttack,
			Platform:    PlatformGitHub,
			Check:       checkCredentialExfiltration,
		},
		{
			ID:          "ARTIFACT_POISONING",
			Name:        "Artifact Poisoning",
			Description: "Detects potentially malicious artifact upload/download patterns",
			Severity:    High,
			Category:    SupplyChain,
			Platform:    PlatformGitHub,
			Check:       checkArtifactPoisoning,
		},
		{
			ID:          "MATRIX_INJECTION",
			Name:        "Matrix Strategy Injection",
			Description: "Detects injection vulnerabilities through matrix strategy inputs",
			Severity:    High,
			Category:    InjectionAttack,
			Platform:    PlatformGitHub,
			Check:       checkMatrixInjection,
		},
		{
			ID:          "SERVICES_CREDENTIALS",
			Name:        "Services Configuration Credentials",
			Description: "Detects hardcoded credentials in services configuration",
			Severity:    Critical,
			Category:    SecretExposure,
			Platform:    PlatformAll,
			Check:       checkServicesCredentials,
		},
		{
			ID:          "RUNNER_LABEL_VALIDATION",
			Name:        "Runner Label Validation",
			Description: "Validates GitHub-hosted and self-hosted runner labels in runs-on configuration",
			Severity:    Medium,
			Category:    Misconfiguration,
			Platform:    PlatformGitHub,
			Check:       checkRunnerLabels,
		},
		{
			ID:          "BOT_IDENTITY_CHECK",
			Name:        "Bot Identity Check",
			Description: "Detects if statements based on bot identity that could be exploited",
			Severity:    Medium,
			Category:    AccessControl,
			Platform:    PlatformGitHub,
			Check:       checkBotIdentity,
		},
		{
			ID:          "EXTERNAL_TRIGGER_DEBUG",
			Name:        "External Trigger Debug",
			Description: "Detects workflows that can be externally triggered with potential security risks",
			Severity:    High,
			Category:    AccessControl,
			Platform:    PlatformAll,
			Check:       checkExternalTrigger,
		},
		{
			ID:          "REPO_JACKING_VULNERABILITY",
			Name:        "Repository Jacking Vulnerability",
			Description: "Verifies external actions point to valid GitHub users/organizations",
			Severity:    High,
			Category:    SupplyChain,
			Platform:    PlatformGitHub,
			Check:       checkRepoJacking,
		},
		{
			ID:          "DEBUG_ARTIFACTS_UPLOAD",
			Name:        "Debug Artifacts Upload",
			Description: "Detects workflows that upload artifacts for debugging purposes",
			Severity:    Info,
			Category:    DataExposure,
			Platform:    PlatformGitHub, // GitHub Actions artifacts
			Check:       checkDebugArtifacts,
		},
		{
			ID:          "DEBUG_JS_EXECUTION",
			Name:        "Debug JavaScript Execution",
			Description: "Detects workflows that execute system commands in JavaScript scripts",
			Severity:    Medium,
			Category:    InjectionAttack,
			Platform:    PlatformAll, // JavaScript execution applies to all platforms
			Check:       checkDebugJsExecution,
		},
		{
			ID:          "DEBUG_OIDC_ACTIONS",
			Name:        "Debug OIDC Actions",
			Description: "Detects workflows that use OIDC token authentication",
			Severity:    Info,
			Category:    AccessControl,
			Platform:    PlatformGitHub, // GitHub OIDC tokens
			Check:       checkDebugOidcActions,
		},
	}
}

// FilterRulesByPlatform filters rules based on target platform compatibility
func FilterRulesByPlatform(rules []Rule, targetPlatform Platform) []Rule {
	var filteredRules []Rule

	for _, rule := range rules {
		// Include rules that apply to all platforms or match the target platform
		if rule.Platform == PlatformAll || rule.Platform == targetPlatform {
			filteredRules = append(filteredRules, rule)
		}
	}

	return filteredRules
}

// StringToPlatform converts platform string constants to Platform enum
func StringToPlatform(platformStr string) Platform {
	switch platformStr {
	case constants.PlatformGitHub:
		return PlatformGitHub
	case constants.PlatformGitLab:
		return PlatformGitLab
	default:
		return PlatformAll // Default to all if unknown
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

// CheckAllRules runs all security rule checks
func CheckAllRules(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	// Injection vulnerabilities
	findings = append(findings, CheckInjectionVulnerabilities(workflow)...)

	// Shell injection vulnerabilities
	findings = append(findings, CheckShellInjectionVulnerabilities(workflow)...)

	// Supply chain vulnerabilities (includes advanced intelligence)
	findings = append(findings, CheckSupplyChainVulnerabilities(workflow)...)

	// Phase 3: Self-hosted runner security and advanced privilege analysis
	findings = append(findings, CheckSelfHostedRunnerSecurity(workflow)...)
	findings = append(findings, CheckAdvancedPrivilegeAnalysis(workflow)...)

	return findings
}

// checkDangerousWriteOperations checks for dangerous write operations on GitHub environment variables
func checkDangerousWriteOperations(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Patterns that indicate dangerous writes to GitHub environment variables
	dangerousPatterns := []*regexp.Regexp{
		regexp.MustCompile(`echo\s+.*>>\s*\$GITHUB_OUTPUT`),   // Direct echo to GITHUB_OUTPUT
		regexp.MustCompile(`echo\s+.*>>\s*\$GITHUB_ENV`),      // Direct echo to GITHUB_ENV
		regexp.MustCompile(`printf\s+.*>>\s*\$GITHUB_OUTPUT`), // Printf to GITHUB_OUTPUT
		regexp.MustCompile(`printf\s+.*>>\s*\$GITHUB_ENV`),    // Printf to GITHUB_ENV
		regexp.MustCompile(`>>\s*\$GITHUB_OUTPUT`),            // Any redirect to GITHUB_OUTPUT
		regexp.MustCompile(`>>\s*\$GITHUB_ENV`),               // Any redirect to GITHUB_ENV
	}

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			for _, pattern := range dangerousPatterns {
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

// checkLocalActionUsage checks for usage of local actions which may pose security risks
func checkLocalActionUsage(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Uses == "" {
				continue
			}

			// Check for local action patterns (relative paths)
			if strings.HasPrefix(step.Uses, "./") || strings.HasPrefix(step.Uses, "../") ||
				(!strings.Contains(step.Uses, "/") && !strings.Contains(step.Uses, "@")) {

				lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
					Key:   "uses",
					Value: step.Uses,
				})

				lineNumber := 0
				if lineResult != nil {
					lineNumber = lineResult.LineNumber
				}

				findings = append(findings, Finding{
					RuleID:      "LOCAL_ACTION_USAGE",
					RuleName:    "Local Action Usage",
					Description: "Usage of local actions may pose security risks as they are not version-controlled externally",
					Severity:    Medium,
					Category:    Misconfiguration,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    step.Name,
					Evidence:    fmt.Sprintf("uses: %s", step.Uses),
					LineNumber:  lineNumber,
					Remediation: "Consider using versioned actions from GitHub Marketplace or pin local actions to specific commits",
				})
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
			pattern:     regexp.MustCompile(`\$[A-Za-z_][A-Za-z0-9_]*[^}]`), // Unquoted variables (simplified)
			description: "Unquoted variable usage may lead to word splitting and pathname expansion",
			remediation: "Quote variables: \"$VAR\" instead of $VAR",
			severity:    Medium,
		},
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
					lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
						Key:   "run",
						Value: step.Run,
					})

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
		}
	}

	return findings
}

// checkPRTargetAbuse checks for dangerous usage of pull_request_target trigger
func checkPRTargetAbuse(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Check if pull_request_target is used (handle different On types)
	hasPRTarget := false
	switch on := workflow.Workflow.On.(type) {
	case string:
		hasPRTarget = on == "pull_request_target"
	case map[string]interface{}:
		_, hasPRTarget = on["pull_request_target"]
	case []interface{}:
		for _, event := range on {
			if eventStr, ok := event.(string); ok && eventStr == "pull_request_target" {
				hasPRTarget = true
				break
			}
		}
	}

	if !hasPRTarget {
		return findings // No pull_request_target trigger found
	}

	// Check for dangerous patterns with pull_request_target
	for jobName, job := range workflow.Workflow.Jobs {
		// Check for write permissions
		if job.Permissions != nil {
			if perms, ok := job.Permissions.(map[string]interface{}); ok {
				for permission, levelInterface := range perms {
					if level, ok := levelInterface.(string); ok {
						if (permission == "contents" || permission == "actions" || permission == "packages") && level == "write" {
							lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
								Key:   permission,
								Value: level,
							})

							lineNumber := 0
							if lineResult != nil {
								lineNumber = lineResult.LineNumber
							}

							findings = append(findings, Finding{
								RuleID:      "PR_TARGET_ABUSE",
								RuleName:    "Pull Request Target Abuse",
								Description: "pull_request_target with write permissions allows untrusted code to access secrets and write to repository",
								Severity:    Critical,
								Category:    AccessControl,
								FilePath:    workflow.Path,
								JobName:     jobName,
								StepName:    "",
								Evidence:    fmt.Sprintf("pull_request_target trigger with %s: %s permission", permission, level),
								LineNumber:  lineNumber,
								Remediation: "Use pull_request trigger instead, or implement proper security controls before accessing secrets",
							})
						}
					}
				}
			}
		}

		// Check for secret usage in steps
		for _, step := range job.Steps {
			if step.With != nil {
				for key, valueInterface := range step.With {
					if value, ok := valueInterface.(string); ok {
						if strings.Contains(value, "${{ secrets.") {
							lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
								Key:   key,
								Value: value,
							})

							lineNumber := 0
							if lineResult != nil {
								lineNumber = lineResult.LineNumber
							}

							findings = append(findings, Finding{
								RuleID:      "PR_TARGET_ABUSE",
								RuleName:    "Pull Request Target Abuse",
								Description: "pull_request_target trigger with secret access allows untrusted pull requests to access sensitive data",
								Severity:    Critical,
								Category:    AccessControl,
								FilePath:    workflow.Path,
								JobName:     jobName,
								StepName:    step.Name,
								Evidence:    fmt.Sprintf("Secret access in pull_request_target: %s", value),
								LineNumber:  lineNumber,
								Remediation: "Use pull_request trigger or implement proper authorization checks before accessing secrets",
							})
						}
					}
				}
			}

			// Check for secret usage in environment variables
			for envKey, envValue := range step.Env {
				if strings.Contains(envValue, "${{ secrets.") {
					lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
						Key:   envKey,
						Value: envValue,
					})

					lineNumber := 0
					if lineResult != nil {
						lineNumber = lineResult.LineNumber
					}

					findings = append(findings, Finding{
						RuleID:      "PR_TARGET_ABUSE",
						RuleName:    "Pull Request Target Abuse",
						Description: "pull_request_target trigger with secret access in environment variables",
						Severity:    Critical,
						Category:    AccessControl,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    step.Name,
						Evidence:    fmt.Sprintf("Secret in env var: %s = %s", envKey, envValue),
						LineNumber:  lineNumber,
						Remediation: "Use pull_request trigger or implement proper authorization checks before accessing secrets",
					})
				}
			}
		}
	}

	return findings
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

// checkArtifactPoisoning checks for potentially malicious artifact patterns
func checkArtifactPoisoning(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			// Check for artifact upload actions
			if step.Uses != "" && strings.Contains(step.Uses, "actions/upload-artifact") {
				// Check for suspicious artifact patterns
				if step.With != nil {
					if pathInterface, exists := step.With["path"]; exists {
						if path, ok := pathInterface.(string); ok {
							// Check for dangerous paths
							dangerousPaths := []string{
								"/", "/*", "~", "~/", "$HOME",
								"/etc", "/usr", "/bin", "/sbin",
								"C:\\", "C:\\Windows", "C:\\Program Files",
							}

							for _, dangerousPath := range dangerousPaths {
								if strings.Contains(path, dangerousPath) {
									lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
										Key:   "path",
										Value: path,
									})

									lineNumber := 0
									if lineResult != nil {
										lineNumber = lineResult.LineNumber
									}

									findings = append(findings, Finding{
										RuleID:      "ARTIFACT_POISONING",
										RuleName:    "Artifact Poisoning",
										Description: "Artifact upload includes dangerous system paths that could expose sensitive files",
										Severity:    High,
										Category:    SupplyChain,
										FilePath:    workflow.Path,
										JobName:     jobName,
										StepName:    step.Name,
										Evidence:    fmt.Sprintf("Dangerous artifact path: %s", path),
										LineNumber:  lineNumber,
										Remediation: "Restrict artifact uploads to specific, safe directories only",
									})
								}
							}

							// Check for overly broad patterns
							broadPatterns := []string{"*", "**", "**/*", "."}
							for _, pattern := range broadPatterns {
								if path == pattern {
									lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
										Key:   "path",
										Value: path,
									})

									lineNumber := 0
									if lineResult != nil {
										lineNumber = lineResult.LineNumber
									}

									findings = append(findings, Finding{
										RuleID:      "ARTIFACT_POISONING",
										RuleName:    "Artifact Poisoning",
										Description: "Artifact upload uses overly broad patterns that may include sensitive files",
										Severity:    Medium,
										Category:    SupplyChain,
										FilePath:    workflow.Path,
										JobName:     jobName,
										StepName:    step.Name,
										Evidence:    fmt.Sprintf("Broad artifact pattern: %s", path),
										LineNumber:  lineNumber,
										Remediation: "Use specific file patterns instead of broad wildcards for artifact uploads",
									})
								}
							}
						}
					}
				}
			}

			// Check for artifact download actions
			if step.Uses != "" && strings.Contains(step.Uses, "actions/download-artifact") {
				// Check for unsafe download patterns
				if step.With != nil {
					if nameInterface, exists := step.With["name"]; exists {
						if name, ok := nameInterface.(string); ok {
							// Check for user-controlled artifact names
							if strings.Contains(name, "${{ github.event.") || strings.Contains(name, "${{ inputs.") {
								lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
									Key:   "name",
									Value: name,
								})

								lineNumber := 0
								if lineResult != nil {
									lineNumber = lineResult.LineNumber
								}

								findings = append(findings, Finding{
									RuleID:      "ARTIFACT_POISONING",
									RuleName:    "Artifact Poisoning",
									Description: "Artifact download uses user-controlled input for artifact name, which could lead to path traversal",
									Severity:    High,
									Category:    SupplyChain,
									FilePath:    workflow.Path,
									JobName:     jobName,
									StepName:    step.Name,
									Evidence:    fmt.Sprintf("User-controlled artifact name: %s", name),
									LineNumber:  lineNumber,
									Remediation: "Validate and sanitize artifact names, or use predefined artifact names only",
								})
							}
						}
					}
				}
			}
		}
	}

	return findings
}

// checkMatrixInjection checks for injection vulnerabilities through matrix strategy
func checkMatrixInjection(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	for jobName, job := range workflow.Workflow.Jobs {
		if job.Strategy != nil {
			// Check if matrix strategy is defined
			if matrix, exists := job.Strategy["matrix"]; exists && matrix != nil {
				// Check for matrix values used in shell commands
				for _, step := range job.Steps {
					if step.Run == "" {
						continue
					}

					// Look for matrix variable usage in shell commands
					matrixVarPattern := regexp.MustCompile(`\$\{\{\s*matrix\.([^}]+)\}\}`)
					matches := matrixVarPattern.FindAllStringSubmatch(step.Run, -1)

					for _, match := range matches {
						if len(match) > 1 {
							matrixVar := match[1]

							// Check if the matrix variable is used in dangerous contexts
							dangerousPatterns := []*regexp.Regexp{
								regexp.MustCompile(`\$\{\{\s*matrix\.` + regexp.QuoteMeta(matrixVar) + `\s*\}\}.*\|\s*(sh|bash|zsh)`), // Pipe to shell
								regexp.MustCompile(`eval.*\$\{\{\s*matrix\.` + regexp.QuoteMeta(matrixVar) + `\s*\}\}`),               // Eval with matrix
								regexp.MustCompile(`\$\{\{\s*matrix\.` + regexp.QuoteMeta(matrixVar) + `\s*\}\}.*>>`),                 // Redirect to file
								regexp.MustCompile(`curl.*\$\{\{\s*matrix\.` + regexp.QuoteMeta(matrixVar) + `\s*\}\}`),               // Curl with matrix
								regexp.MustCompile(`wget.*\$\{\{\s*matrix\.` + regexp.QuoteMeta(matrixVar) + `\s*\}\}`),               // Wget with matrix
							}

							for _, pattern := range dangerousPatterns {
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
										RuleID:      "MATRIX_INJECTION",
										RuleName:    "Matrix Strategy Injection",
										Description: "Matrix variable used in dangerous shell context without proper validation",
										Severity:    High,
										Category:    InjectionAttack,
										FilePath:    workflow.Path,
										JobName:     jobName,
										StepName:    step.Name,
										Evidence:    fmt.Sprintf("Matrix variable '%s' used in: %s", matrixVar, strings.TrimSpace(step.Run)),
										LineNumber:  lineNumber,
										Remediation: "Validate and sanitize matrix variables before using in shell commands, or use safer alternatives",
									})
								}
							}

							// Check for unquoted matrix variables (simpler check)
							unquotedPattern := regexp.MustCompile(`[^"']\$\{\{\s*matrix\.` + regexp.QuoteMeta(matrixVar) + `\s*\}\}[^"']`)
							if unquotedPattern.MatchString(step.Run) {
								lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
									Key:   "run",
									Value: step.Run,
								})

								lineNumber := 0
								if lineResult != nil {
									lineNumber = lineResult.LineNumber
								}

								findings = append(findings, Finding{
									RuleID:      "MATRIX_INJECTION",
									RuleName:    "Matrix Strategy Injection",
									Description: "Unquoted matrix variable usage may lead to command injection",
									Severity:    Medium,
									Category:    InjectionAttack,
									FilePath:    workflow.Path,
									JobName:     jobName,
									StepName:    step.Name,
									Evidence:    fmt.Sprintf("Unquoted matrix variable '%s' in: %s", matrixVar, strings.TrimSpace(step.Run)),
									LineNumber:  lineNumber,
									Remediation: "Always quote matrix variables in shell commands: \"${{ matrix.var }}\"",
								})
							}
						}
					}
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

// checkRunnerLabels validates GitHub-hosted and self-hosted runner labels
func checkRunnerLabels(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Known GitHub-hosted runner labels
	githubHostedRunners := map[string]bool{
		"ubuntu-latest":  true,
		"ubuntu-22.04":   true,
		"ubuntu-20.04":   true,
		"windows-latest": true,
		"windows-2022":   true,
		"windows-2019":   true,
		"macos-latest":   true,
		"macos-13":       true,
		"macos-12":       true,
		"macos-11":       true,
	}

	for jobName, job := range workflow.Workflow.Jobs {
		runsOnStr := ""

		// Handle both string and array formats for runs-on
		switch runsOn := job.RunsOn.(type) {
		case string:
			runsOnStr = runsOn
		case []interface{}:
			if len(runsOn) > 0 {
				if str, ok := runsOn[0].(string); ok {
					runsOnStr = str
				}
			}
		}

		if runsOnStr != "" {
			// Check for suspicious self-hosted runner patterns
			suspiciousPatterns := []*regexp.Regexp{
				regexp.MustCompile(`(?i)self-hosted.*production`),
				regexp.MustCompile(`(?i)self-hosted.*internal`),
				regexp.MustCompile(`(?i)self-hosted.*private`),
				regexp.MustCompile(`(?i)runner-\d+`), // Generic numbered runners
			}

			for _, pattern := range suspiciousPatterns {
				if pattern.MatchString(runsOnStr) {
					lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
						Key:   "runs-on",
						Value: runsOnStr,
					})

					lineNumber := 0
					if lineResult != nil {
						lineNumber = lineResult.LineNumber
					}

					findings = append(findings, Finding{
						RuleID:      "RUNNER_LABEL_VALIDATION",
						RuleName:    "Runner Label Validation",
						Description: "Potentially insecure self-hosted runner configuration detected",
						Severity:    Medium,
						Category:    Misconfiguration,
						FilePath:    workflow.Path,
						JobName:     jobName,
						Evidence:    runsOnStr,
						LineNumber:  lineNumber,
						Remediation: "Use specific, well-managed self-hosted runner labels or GitHub-hosted runners",
					})
				}
			}

			// Check for unknown runner labels (not GitHub-hosted and not self-hosted format)
			if !githubHostedRunners[runsOnStr] && !strings.Contains(runsOnStr, "self-hosted") {
				lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
					Key:   "runs-on",
					Value: runsOnStr,
				})

				lineNumber := 0
				if lineResult != nil {
					lineNumber = lineResult.LineNumber
				}

				findings = append(findings, Finding{
					RuleID:      "RUNNER_LABEL_VALIDATION",
					RuleName:    "Runner Label Validation",
					Description: "Unknown runner label that may not exist or be misconfigured",
					Severity:    Low,
					Category:    Misconfiguration,
					FilePath:    workflow.Path,
					JobName:     jobName,
					Evidence:    runsOnStr,
					LineNumber:  lineNumber,
					Remediation: "Verify runner label exists and is properly configured",
				})
			}
		}
	}

	return findings
}

// checkBotIdentity checks for if statements based on bot identity
func checkBotIdentity(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Patterns for bot identity checks that could be exploited
	botPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)github\.actor\s*==\s*['"]dependabot\[bot\]['"]`),
		regexp.MustCompile(`(?i)github\.actor\s*==\s*['"]renovate\[bot\]['"]`),
		regexp.MustCompile(`(?i)github\.actor\s*!=\s*['"]dependabot\[bot\]['"]`),
		regexp.MustCompile(`(?i)github\.actor\s*!=\s*['"]renovate\[bot\]['"]`),
		regexp.MustCompile(`(?i)contains\(github\.actor,\s*['"]bot['"]`),
		regexp.MustCompile(`(?i)endswith\(github\.actor,\s*['"]\[bot\]['"]`),
	}

	for jobName, job := range workflow.Workflow.Jobs {
		// Check job-level if conditions
		if job.If != "" {
			for _, pattern := range botPatterns {
				if pattern.MatchString(job.If) {
					lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
						Key:   "if",
						Value: job.If,
					})

					lineNumber := 0
					if lineResult != nil {
						lineNumber = lineResult.LineNumber
					}

					findings = append(findings, Finding{
						RuleID:      "BOT_IDENTITY_CHECK",
						RuleName:    "Bot Identity Check",
						Description: "Bot identity check in if statement may be exploitable by attackers",
						Severity:    Medium,
						Category:    AccessControl,
						FilePath:    workflow.Path,
						JobName:     jobName,
						Evidence:    strings.TrimSpace(job.If),
						LineNumber:  lineNumber,
						Remediation: "Use more specific conditions or validate bot identity through other means",
					})
				}
			}
		}

		// Check step-level if conditions
		for _, step := range job.Steps {
			if step.If != "" {
				for _, pattern := range botPatterns {
					if pattern.MatchString(step.If) {
						lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
							Key:   "if",
							Value: step.If,
						})

						lineNumber := 0
						if lineResult != nil {
							lineNumber = lineResult.LineNumber
						}

						findings = append(findings, Finding{
							RuleID:      "BOT_IDENTITY_CHECK",
							RuleName:    "Bot Identity Check",
							Description: "Bot identity check in step if condition may be exploitable",
							Severity:    Medium,
							Category:    AccessControl,
							FilePath:    workflow.Path,
							JobName:     jobName,
							StepName:    step.Name,
							Evidence:    strings.TrimSpace(step.If),
							LineNumber:  lineNumber,
							Remediation: "Use more specific conditions or validate bot identity through other means",
						})
					}
				}
			}
		}
	}

	return findings
}

// checkExternalTrigger checks for workflows that can be externally triggered
func checkExternalTrigger(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Get the trigger events
	var triggerEvents []string

	switch on := workflow.Workflow.On.(type) {
	case string:
		triggerEvents = []string{on}
	case []interface{}:
		for _, event := range on {
			if str, ok := event.(string); ok {
				triggerEvents = append(triggerEvents, str)
			}
		}
	case map[string]interface{}:
		for event := range on {
			triggerEvents = append(triggerEvents, event)
		}
	}

	// Check for dangerous external triggers
	dangerousTriggers := map[string]string{
		"issue_comment":       "Can be triggered by anyone who can comment on issues",
		"pull_request_target": "Can be triggered by external pull requests with elevated permissions",
		"workflow_run":        "Can be triggered by completion of other workflows",
		"repository_dispatch": "Can be triggered via API by repository collaborators",
		"workflow_dispatch":   "Can be manually triggered with potential for abuse",
	}

	for _, trigger := range triggerEvents {
		if risk, isDangerous := dangerousTriggers[trigger]; isDangerous {
			lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
				Key:   "on",
				Value: trigger,
			})

			lineNumber := 0
			if lineResult != nil {
				lineNumber = lineResult.LineNumber
			}

			findings = append(findings, Finding{
				RuleID:      "EXTERNAL_TRIGGER_DEBUG",
				RuleName:    "External Trigger Debug",
				Description: fmt.Sprintf("Workflow uses external trigger '%s': %s", trigger, risk),
				Severity:    High,
				Category:    AccessControl,
				FilePath:    workflow.Path,
				Evidence:    trigger,
				LineNumber:  lineNumber,
				Remediation: "Review trigger necessity and add appropriate security controls",
			})
		}
	}

	return findings
}

// checkRepoJacking verifies external actions point to valid repositories
func checkRepoJacking(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Pattern to match action references
	actionPattern := regexp.MustCompile(`^([^/]+)/([^@]+)@(.+)$`)

	// Known trusted organizations
	trustedOrgs := map[string]bool{
		"actions":     true,
		"github":      true,
		"microsoft":   true,
		"azure":       true,
		"docker":      true,
		"aws-actions": true,
	}

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Uses != "" {
				matches := actionPattern.FindStringSubmatch(step.Uses)
				if len(matches) == 4 {
					org := matches[1]
					repo := matches[2]
					ref := matches[3]

					// Check for potential repo-jacking indicators
					suspiciousPatterns := []*regexp.Regexp{
						regexp.MustCompile(`^\d+$`),                   // Numeric usernames
						regexp.MustCompile(`^[a-zA-Z]+\d+$`),          // Username with trailing numbers
						regexp.MustCompile(`(?i)(test|demo|example)`), // Test/demo repos
						regexp.MustCompile(`^.{1,2}$`),                // Very short usernames
					}

					var isSuspicious bool
					var suspiciousReason string

					// Check if organization is trusted
					if !trustedOrgs[org] {
						// Check for suspicious patterns
						for _, pattern := range suspiciousPatterns {
							if pattern.MatchString(org) {
								isSuspicious = true
								suspiciousReason = fmt.Sprintf("Suspicious organization name pattern: %s", org)
								break
							}
							if pattern.MatchString(repo) {
								isSuspicious = true
								suspiciousReason = fmt.Sprintf("Suspicious repository name pattern: %s", repo)
								break
							}
						}

						// Check for unpinned references to untrusted sources
						if ref == "main" || ref == "master" || regexp.MustCompile(`^v\d+$`).MatchString(ref) {
							isSuspicious = true
							suspiciousReason = fmt.Sprintf("Unpinned reference to untrusted source: %s@%s", org, ref)
						}
					}

					if isSuspicious {
						lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
							Key:   "uses",
							Value: step.Uses,
						})

						lineNumber := 0
						if lineResult != nil {
							lineNumber = lineResult.LineNumber
						}

						findings = append(findings, Finding{
							RuleID:      "REPO_JACKING_VULNERABILITY",
							RuleName:    "Repository Jacking Vulnerability",
							Description: suspiciousReason,
							Severity:    High,
							Category:    SupplyChain,
							FilePath:    workflow.Path,
							JobName:     jobName,
							StepName:    step.Name,
							Evidence:    step.Uses,
							LineNumber:  lineNumber,
							Remediation: "Verify the action source is legitimate and pin to specific SHA for security",
						})
					}
				}
			}
		}
	}

	return findings
}

// checkDebugArtifacts detects workflows that upload artifacts
func checkDebugArtifacts(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Look for artifact upload actions
	artifactActions := []string{
		"actions/upload-artifact",
		"actions/download-artifact",
	}

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Uses != "" {
				for _, action := range artifactActions {
					if strings.Contains(step.Uses, action) {
						lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
							Key:   "uses",
							Value: step.Uses,
						})

						lineNumber := 0
						if lineResult != nil {
							lineNumber = lineResult.LineNumber
						}

						findings = append(findings, Finding{
							RuleID:      "DEBUG_ARTIFACTS_UPLOAD",
							RuleName:    "Debug Artifacts Upload",
							Description: "Workflow uploads or downloads artifacts which may contain sensitive data",
							Severity:    Info,
							Category:    DataExposure,
							FilePath:    workflow.Path,
							JobName:     jobName,
							StepName:    step.Name,
							Evidence:    step.Uses,
							LineNumber:  lineNumber,
							Remediation: "Review artifact contents to ensure no sensitive data is exposed",
						})
					}
				}
			}
		}
	}

	return findings
}

// checkDebugJsExecution detects JavaScript execution of system commands
func checkDebugJsExecution(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Patterns for JavaScript system command execution
	jsExecPatterns := []*regexp.Regexp{
		regexp.MustCompile(`require\(['"]child_process['"]\)`),
		regexp.MustCompile(`\.exec\(`),
		regexp.MustCompile(`\.spawn\(`),
		regexp.MustCompile(`\.execSync\(`),
		regexp.MustCompile(`\.spawnSync\(`),
		regexp.MustCompile(`process\.exec`),
		regexp.MustCompile(`import.*child_process`),
		regexp.MustCompile(`from.*child_process`),
	}

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			// Check JavaScript actions (actions that use JavaScript)
			if step.Uses != "" && strings.Contains(step.Uses, "actions/github-script") {
				// Check the script content for system command execution
				if step.With != nil {
					if script, exists := step.With["script"]; exists {
						scriptStr := fmt.Sprintf("%v", script)

						for _, pattern := range jsExecPatterns {
							if pattern.MatchString(scriptStr) {
								lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
									Key:   "script",
									Value: scriptStr,
								})

								lineNumber := 0
								if lineResult != nil {
									lineNumber = lineResult.LineNumber
								}

								findings = append(findings, Finding{
									RuleID:      "DEBUG_JS_EXECUTION",
									RuleName:    "Debug JavaScript Execution",
									Description: "JavaScript script executes system commands which may be dangerous",
									Severity:    Medium,
									Category:    InjectionAttack,
									FilePath:    workflow.Path,
									JobName:     jobName,
									StepName:    step.Name,
									Evidence:    strings.TrimSpace(scriptStr),
									LineNumber:  lineNumber,
									Remediation: "Avoid executing system commands in JavaScript scripts, use safer alternatives",
								})
							}
						}
					}
				}
			}

			// Also check run commands that might contain JavaScript execution
			if step.Run != "" {
				for _, pattern := range jsExecPatterns {
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
							RuleID:      "DEBUG_JS_EXECUTION",
							RuleName:    "Debug JavaScript Execution",
							Description: "Script contains JavaScript system command execution patterns",
							Severity:    Medium,
							Category:    InjectionAttack,
							FilePath:    workflow.Path,
							JobName:     jobName,
							StepName:    step.Name,
							Evidence:    strings.TrimSpace(step.Run),
							LineNumber:  lineNumber,
							Remediation: "Review JavaScript system command usage for potential security risks",
						})
					}
				}
			}
		}
	}

	return findings
}

// checkDebugOidcActions detects workflows that use OIDC token authentication
func checkDebugOidcActions(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// OIDC-related patterns
	oidcPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)id-token:\s*write`),
		regexp.MustCompile(`(?i)ACTIONS_ID_TOKEN_REQUEST_TOKEN`),
		regexp.MustCompile(`(?i)ACTIONS_ID_TOKEN_REQUEST_URL`),
		regexp.MustCompile(`(?i)aws-actions/configure-aws-credentials`),
		regexp.MustCompile(`(?i)azure/login`),
		regexp.MustCompile(`(?i)google-github-actions/auth`),
	}

	// Check job permissions for id-token
	for jobName, job := range workflow.Workflow.Jobs {
		if job.Permissions != nil {
			if permMap, ok := job.Permissions.(map[string]interface{}); ok {
				if idTokenValue, exists := permMap["id-token"]; exists {
					if idToken, ok := idTokenValue.(string); ok && idToken == "write" {
						lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
							Key:   "id-token",
							Value: "write",
						})

						lineNumber := 0
						if lineResult != nil {
							lineNumber = lineResult.LineNumber
						}

						findings = append(findings, Finding{
							RuleID:      "DEBUG_OIDC_ACTIONS",
							RuleName:    "Debug OIDC Actions",
							Description: "Workflow uses OIDC token authentication with id-token: write permission",
							Severity:    Info,
							Category:    AccessControl,
							FilePath:    workflow.Path,
							JobName:     jobName,
							Evidence:    "id-token: write",
							LineNumber:  lineNumber,
							Remediation: "Ensure OIDC token usage is properly scoped and necessary",
						})
					}
				}
			}
		}

		// Check steps for OIDC-related actions and environment variables
		for _, step := range job.Steps {
			if step.Uses != "" {
				for _, pattern := range oidcPatterns {
					if pattern.MatchString(step.Uses) {
						lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
							Key:   "uses",
							Value: step.Uses,
						})

						lineNumber := 0
						if lineResult != nil {
							lineNumber = lineResult.LineNumber
						}

						findings = append(findings, Finding{
							RuleID:      "DEBUG_OIDC_ACTIONS",
							RuleName:    "Debug OIDC Actions",
							Description: "Workflow uses OIDC-enabled action for cloud authentication",
							Severity:    Info,
							Category:    AccessControl,
							FilePath:    workflow.Path,
							JobName:     jobName,
							StepName:    step.Name,
							Evidence:    step.Uses,
							LineNumber:  lineNumber,
							Remediation: "Verify OIDC configuration is secure and follows best practices",
						})
					}
				}
			}

			// Check environment variables for OIDC tokens
			if step.Env != nil {
				for envKey := range step.Env {
					for _, pattern := range oidcPatterns {
						if pattern.MatchString(envKey) {
							lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
								Key:   envKey,
								Value: "",
							})

							lineNumber := 0
							if lineResult != nil {
								lineNumber = lineResult.LineNumber
							}

							findings = append(findings, Finding{
								RuleID:      "DEBUG_OIDC_ACTIONS",
								RuleName:    "Debug OIDC Actions",
								Description: "Workflow references OIDC token environment variables",
								Severity:    Info,
								Category:    AccessControl,
								FilePath:    workflow.Path,
								JobName:     jobName,
								StepName:    step.Name,
								Evidence:    envKey,
								LineNumber:  lineNumber,
								Remediation: "Ensure OIDC token environment variables are used securely",
							})
						}
					}
				}
			}
		}
	}

	// Check workflow-level permissions
	if workflow.Workflow.Permissions != nil {
		if permMap, ok := workflow.Workflow.Permissions.(map[string]interface{}); ok {
			if idTokenValue, exists := permMap["id-token"]; exists {
				if idToken, ok := idTokenValue.(string); ok && idToken == "write" {
					lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
						Key:   "id-token",
						Value: "write",
					})

					lineNumber := 0
					if lineResult != nil {
						lineNumber = lineResult.LineNumber
					}

					findings = append(findings, Finding{
						RuleID:      "DEBUG_OIDC_ACTIONS",
						RuleName:    "Debug OIDC Actions",
						Description: "Workflow has global id-token: write permission for OIDC authentication",
						Severity:    Info,
						Category:    AccessControl,
						FilePath:    workflow.Path,
						Evidence:    "id-token: write (global)",
						LineNumber:  lineNumber,
						Remediation: "Consider limiting id-token permissions to specific jobs that need OIDC",
					})
				}
			}
		}
	}

	return findings
}
