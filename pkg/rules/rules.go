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
	"strings"

	"github.com/harekrishnarai/flowlyt/v2/pkg/analysis/context"
	"github.com/harekrishnarai/flowlyt/v2/pkg/constants"
	"github.com/harekrishnarai/flowlyt/v2/pkg/linenum"
	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
)

// ConfigInterface defines the interface for configuration
type ConfigInterface interface {
	IsRuleEnabled(ruleID string) bool
	ShouldIgnoreForRule(ruleID, text, filePath string) bool
	ShouldIgnoreSecret(text, context string) bool
}

// RuleEngine handles rule execution with configuration support
type RuleEngine struct {
	config          ConfigInterface
	contextAnalyzer *context.ContextAnalyzer
	contextAware    bool
}

// NewRuleEngine creates a new rule engine with configuration
func NewRuleEngine(config ConfigInterface) *RuleEngine {
	return &RuleEngine{
		config:          config,
		contextAnalyzer: context.NewContextAnalyzer(),
		contextAware:    true, // Enable context-aware analysis by default
	}
}

// SetContextAware enables or disables context-aware analysis
func (re *RuleEngine) SetContextAware(enabled bool) {
	re.contextAware = enabled
}

// ExecuteRules runs rules against a workflow with configuration filtering
func (re *RuleEngine) ExecuteRules(workflow parser.WorkflowFile, rules []Rule) []Finding {
	var allFindings []Finding

	// Analyze workflow context once for all rules
	var ctx *context.WorkflowContext
	if re.contextAware {
		ctx = re.contextAnalyzer.Analyze(&workflow.Workflow)
	}

	for _, rule := range rules {
		// Check if rule is enabled in configuration
		if re.config != nil && !re.config.IsRuleEnabled(rule.ID) {
			continue
		}

		findings := rule.Check(workflow)

		// Apply configuration-based filtering and context-aware adjustments
		var filteredFindings []Finding
		for _, finding := range findings {
			// Check if should be ignored by configuration
			if re.config != nil && re.config.ShouldIgnoreForRule(finding.RuleID, finding.Evidence, workflow.Path) {
				continue
			}

			// Apply context-aware analysis
			if re.contextAware && ctx != nil {
				// Check if finding should be suppressed
				if re.contextAnalyzer.ShouldSuppress(finding.RuleID, ctx) {
					continue
				}

				// Adjust severity based on context
				originalSeverity := string(finding.Severity)
				adjustedSeverity := re.contextAnalyzer.AdjustSeverity(finding.RuleID, originalSeverity, ctx)
				finding.Severity = Severity(adjustedSeverity)

				// Add context information to evidence
				if originalSeverity != adjustedSeverity {
					finding.Evidence = fmt.Sprintf("[Context-adjusted from %s to %s] %s", originalSeverity, adjustedSeverity, finding.Evidence)
				}
			}

			filteredFindings = append(filteredFindings, finding)
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

	// Context fields for better AI analysis
	Trigger     string `json:"trigger,omitempty"`      // Workflow trigger (e.g., "push", "pull_request", "workflow_dispatch")
	RunnerType  string `json:"runner_type,omitempty"`  // Runner type (e.g., "ubuntu-latest", "self-hosted", "windows-latest")
	FileContext string `json:"file_context,omitempty"` // File context (e.g., "production", "test", "example", "template")

	// AI verification fields
	AIVerified            bool    `json:"ai_verified,omitempty"`              // Whether AI analysis was performed
	AILikelyFalsePositive *bool   `json:"ai_likely_false_positive,omitempty"` // AI assessment (nil if not analyzed)
	AIConfidence          float64 `json:"ai_confidence,omitempty"`            // AI confidence level (0.0 to 1.0)
	AIReasoning           string  `json:"ai_reasoning,omitempty"`             // AI explanation
	AISuggestedSeverity   string  `json:"ai_suggested_severity,omitempty"`    // AI suggested severity if different
	AIError               string  `json:"ai_error,omitempty"`                 // AI analysis error if any
	AISkipped             bool    `json:"ai_skipped,omitempty"`               // Whether AI analysis was skipped
	AISkipReason          string  `json:"ai_skip_reason,omitempty"`           // Reason AI analysis was skipped
	AIRemediation         string  `json:"ai_remediation,omitempty"`           // AI-suggested remediation steps
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
			ID:          "UNTRUSTED_TRIGGER",
			Name:        "Untrusted Workflow Trigger",
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

		// Cache poisoning rules (CP-001 and CP-002 — each entry calls a distinct function)
		{
			ID:          "CACHE_RESTORE_KEYS_TOO_BROAD",
			Name:        "Cache restore-keys Too Broad",
			Description: "Broad restore-keys without content hash enables cache poisoning from PR branches",
			Severity:    Medium,
			Category:    SupplyChain,
			Platform:    PlatformGitHub,
			Check:       checkBroadRestoreKeys,
		},
		{
			ID:          "CACHE_WRITE_IN_PR_WORKFLOW",
			Name:        "Cache Write in Pull Request Workflow",
			Description: "Writing to the cache from a pull_request workflow can allow untrusted code to poison the cache for future runs",
			Severity:    Low,
			Category:    SupplyChain,
			Platform:    PlatformGitHub,
			Check:       checkCacheWriteInPR,
		},
		{
			ID:          "REF_CONFUSION",
			Name:        "Git Reference Confusion",
			Description: "Detects potential git reference confusion vulnerabilities",
			Severity:    High,
			Category:    SupplyChain,
			Platform:    PlatformAll,
			Check:       checkRefConfusion,
		},
		{
			ID:          "IMPOSTOR_COMMIT",
			Name:        "Impostor Commit Detection",
			Description: "Detects commits that may be impersonating legitimate authors",
			Severity:    Critical,
			Category:    SupplyChain,
			Platform:    PlatformAll,
			Check:       checkImpostorCommit,
		},
		{
			ID:          "STALE_ACTION_REFS",
			Name:        "Stale Action References",
			Description: "Detects actions referenced by outdated or non-existent versions",
			Severity:    Medium,
			Category:    SupplyChain,
			Platform:    PlatformAll,
			Check:       checkStaleActionRefs,
		},
		{
			ID:          "SECRETS_INHERIT",
			Name:        "Secret Inheritance Issues",
			Description: "Detects insecure secret inheritance patterns in reusable workflows",
			Severity:    High,
			Category:    SecretsExposure,
			Platform:    PlatformGitHub,
			Check:       checkSecretsInherit,
		},
		{
			ID:          "OVERPROVISIONED_SECRETS",
			Name:        "Over-provisioned Secrets",
			Description: "Detects workflows with excessive secret access beyond requirements",
			Severity:    Medium,
			Category:    SecretsExposure,
			Platform:    PlatformAll,
			Check:       checkOverprovisionedSecrets,
		},
		{
			ID:          "UNREDACTED_SECRETS",
			Name:        "Unredacted Secrets in Logs",
			Description: "Detects secrets that may be logged in plaintext during execution",
			Severity:    Critical,
			Category:    SecretsExposure,
			Platform:    PlatformAll,
			Check:       checkUnredactedSecrets,
		},
		{
			ID:          "UNSOUND_CONDITION",
			Name:        "Unsound Condition Logic",
			Description: "Detects logic vulnerabilities in workflow conditional statements",
			Severity:    High,
			Category:    InjectionAttack,
			Platform:    PlatformAll,
			Check:       checkUnsoundCondition,
		},
		{
			ID:          "UNSOUND_CONTAINS",
			Name:        "Unsound Contains Logic",
			Description: "Detects vulnerable contains() expressions that can be bypassed",
			Severity:    High,
			Category:    InjectionAttack,
			Platform:    PlatformGitHub,
			Check:       checkUnsoundContains,
		},
		{
			ID:          "USE_TRUSTED_PUBLISHING",
			Name:        "Missing Trusted Publishing",
			Description: "Detects PyPI publishing without trusted publishing (OIDC)",
			Severity:    Medium,
			Category:    SupplyChain,
			Platform:    PlatformGitHub,
			Check:       checkUseTrustedPublishing,
		},
		{
			ID:          "OBFUSCATION_DETECTION",
			Name:        "Code Obfuscation Detection",
			Description: "Detects obfuscated code patterns that may hide malicious behavior",
			Severity:    High,
			Category:    ShellObfuscation,
			Platform:    PlatformAll,
			Check:       checkObfuscationDetection,
		},
		{
			ID:          "ARTIPACKED_VULNERABILITY",
			Name:        "Artifact Packing Vulnerability",
			Description: "Detects vulnerabilities in artifact creation and packaging processes",
			Severity:    Medium,
			Category:    SupplyChain,
			Platform:    PlatformAll,
			Check:       checkArtipackedVulnerability,
		},
		{
			ID:          "WORKFLOW_RUN_ARTIFACT_UNTRUSTED",
			Name:        "Untrusted Artifact Download in workflow_run",
			Description: "workflow_run downloads artifacts without constraining run_id, enabling supply chain attacks (CVE-2025-30066 pattern)",
			Severity:    Critical,
			Category:    SupplyChain,
			Platform:    PlatformGitHub,
			Check:       CheckWorkflowRunTrust,
		},
		{
			ID:          "OIDC_WORKFLOW_LEVEL_PERMISSION",
			Name:        "OIDC id-token:write at Workflow Level",
			Description: "id-token: write at workflow level exposes all jobs to OIDC token access, enabling privilege escalation via expression injection",
			Severity:    High,
			Category:    PrivilegeEscalation,
			Platform:    PlatformGitHub,
			Check:       CheckOIDCAbuse,
		},
		// EI-001/002/003: injection sub-rules registered independently so they
		// can be enabled/disabled without affecting INJECTION_VULNERABILITY.
		{
			ID:          "GITHUB_ENV_UNTRUSTED_WRITE",
			Name:        "Untrusted Expression Written to GITHUB_ENV",
			Description: "User-controlled data written to $GITHUB_ENV enables arbitrary env-var injection into subsequent steps",
			Severity:    Critical,
			Category:    InjectionAttack,
			Platform:    PlatformGitHub,
			Check:       checkGithubEnvUntrustedWrite,
		},
		{
			ID:          "MEMDUMP_EXFILTRATION_SIGNATURE",
			Name:        "Process Memory Dump / Exfiltration Signature",
			Description: "Detects memdump.py and similar process-memory exfiltration tools used to steal runner secrets",
			Severity:    Critical,
			Category:    InjectionAttack,
			Platform:    PlatformAll,
			Check:       checkMemdumpExfiltration,
		},
		{
			ID:          "INDIRECT_PPE_BUILD_TOOL",
			Name:        "Indirect Poisoned Pipeline Execution via Build Tool",
			Description: "Workflow checks out untrusted PR code and runs a build tool that processes attacker-controlled manifests",
			Severity:    High,
			Category:    InjectionAttack,
			Platform:    PlatformAll,
			Check:       checkIndirectPPEBuildTool,
		},
		{
			ID:          "DOCKER_EXEC_WITH_SECRETS_ON_FORK_CODE",
			Name:        "Docker Container Runs Fork Code With Secrets (No Network Isolation)",
			Description: "A pull_request_target workflow runs a Docker container or reusable agent workflow with secrets forwarded while processing fork code without network isolation",
			Severity:    Critical,
			Category:    SecretExposure,
			Platform:    PlatformGitHub,
			Check:       CheckDockerAgentExposure,
		},
		{
			ID:          "AI_AGENT_ON_UNTRUSTED_CODE",
			Name:        "AI Agent Processes Untrusted Fork Code With Secrets",
			Description: "An AI agent/bot processes fork-controlled code in a pull_request_target workflow with secrets available, enabling indirect prompt injection to exfiltrate secrets",
			Severity:    High,
			Category:    SecretExposure,
			Platform:    PlatformGitHub,
			Check:       checkAIAgentOnUntrustedCode,
		},
		{
			ID:          "AI_AGENT_COMMENT_TRIGGERED",
			Name:        "AI Agent Triggered by External Comment Without Actor Gate",
			Description: "An AI agent runs in response to issue/PR comments from any user without author_association gating, enabling prompt injection (with secrets) or denial-of-wallet (without secrets) attacks",
			Severity:    High,
			Category:    SecretExposure,
			Platform:    PlatformGitHub,
			Check:       CheckAIAgentCommentTriggered,
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

// Helper functions for extracting context information

// extractTriggerInfo extracts the trigger information from a workflow
func extractTriggerInfo(workflow parser.WorkflowFile) string {
	if workflow.Workflow.On == nil {
		return "unknown"
	}

	// Handle different trigger formats
	switch v := workflow.Workflow.On.(type) {
	case string:
		return v
	case []interface{}:
		if len(v) > 0 {
			if str, ok := v[0].(string); ok {
				return str
			}
		}
		return "multiple"
	case map[interface{}]interface{}:
		// Extract the first trigger name
		for key := range v {
			if str, ok := key.(string); ok {
				return str
			}
		}
		return "complex"
	case map[string]interface{}:
		// Extract the first trigger name
		for key := range v {
			return key
		}
		return "complex"
	default:
		return "unknown"
	}
}

// extractRunnerType extracts the runner type from a job
func extractRunnerType(job parser.Job) string {
	if job.RunsOn == nil {
		return "unknown"
	}

	switch v := job.RunsOn.(type) {
	case string:
		return v
	case []interface{}:
		if len(v) > 0 {
			if str, ok := v[0].(string); ok {
				return str
			}
		}
		return "matrix"
	case map[interface{}]interface{}:
		return "matrix"
	case map[string]interface{}:
		return "matrix"
	default:
		return "unknown"
	}
}

// extractFileContext determines the context of the file based on path and content
func extractFileContext(workflow parser.WorkflowFile) string {
	path := strings.ToLower(workflow.Path)

	// Check for common patterns in file names and paths
	if strings.Contains(path, "test") || strings.Contains(path, "spec") {
		return "test"
	}
	if strings.Contains(path, "example") || strings.Contains(path, "sample") || strings.Contains(path, "demo") {
		return "example"
	}
	if strings.Contains(path, "template") || strings.Contains(path, ".template") {
		return "template"
	}
	if strings.Contains(path, "dev") || strings.Contains(path, "develop") {
		return "development"
	}
	if strings.Contains(path, "prod") || strings.Contains(path, "production") {
		return "production"
	}
	if strings.Contains(path, "staging") || strings.Contains(path, "stage") {
		return "staging"
	}

	// Check workflow name for context clues
	workflowName := strings.ToLower(workflow.Workflow.Name)
	if strings.Contains(workflowName, "test") || strings.Contains(workflowName, "spec") {
		return "test"
	}
	if strings.Contains(workflowName, "build") || strings.Contains(workflowName, "ci") {
		return "ci"
	}
	if strings.Contains(workflowName, "deploy") || strings.Contains(workflowName, "cd") {
		return "deployment"
	}
	if strings.Contains(workflowName, "release") {
		return "release"
	}

	return "production" // Default to production context for safety
}

// enhanceFindingWithContext adds context information to a finding
func enhanceFindingWithContext(finding Finding, workflow parser.WorkflowFile, job parser.Job) Finding {
	finding.Trigger = extractTriggerInfo(workflow)
	finding.RunnerType = extractRunnerType(job)
	finding.FileContext = extractFileContext(workflow)
	return finding
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

	// Phase 4: Docker agent exposure (AI agents on fork code with secrets)
	findings = append(findings, CheckDockerAgentExposure(workflow)...)
	findings = append(findings, checkAIAgentOnUntrustedCode(workflow)...)
	findings = append(findings, CheckAIAgentCommentTriggered(workflow)...)

	return findings
}
