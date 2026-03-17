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

	"github.com/harekrishnarai/flowlyt/pkg/analysis/ast"
	"github.com/harekrishnarai/flowlyt/pkg/linenum"
	"github.com/harekrishnarai/flowlyt/pkg/parser"
)

// memdumpPatterns are compiled once at package level for efficiency.
var memdumpPatterns = []*regexp.Regexp{
	regexp.MustCompile(`nikitastupin.*memdump\.py`),
	regexp.MustCompile(`(?m)curl[^\n]+\|\s*sudo\s+python3?\s*$`),
	regexp.MustCompile(`/proc/[0-9*/]+/mem`),
	regexp.MustCompile(`ptrace.*PTRACE_PEEKDATA`),
}

// CheckInjectionVulnerabilities is the main entry point for injection vulnerability checks
func CheckInjectionVulnerabilities(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	findings = append(findings, checkInjectionVulnerabilities(workflow)...)
	findings = append(findings, checkUntrustedCheckoutExecution(workflow)...)
	findings = append(findings, checkGithubEnvUntrustedWrite(workflow)...)
	findings = append(findings, checkMemdumpExfiltration(workflow)...)
	findings = append(findings, checkIndirectPPEBuildTool(workflow)...)

	return findings
}

// checkGithubEnvUntrustedWrite detects untrusted ${{ }} expressions or LD_PRELOAD written to $GITHUB_ENV (EI-001)
func checkGithubEnvUntrustedWrite(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	ldPreloadRe := regexp.MustCompile(`LD_PRELOAD\s*=`)

	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			// Check if the step writes to $GITHUB_ENV
			writesToGithubEnv := strings.Contains(step.Run, ">> $GITHUB_ENV") ||
				strings.Contains(step.Run, ">>$GITHUB_ENV") ||
				strings.Contains(step.Run, `>> "$GITHUB_ENV"`)

			if !writesToGithubEnv {
				continue
			}

			// Flag if it also contains an untrusted ${{ }} expression or LD_PRELOAD
			if !strings.Contains(step.Run, "${{") && !ldPreloadRe.MatchString(step.Run) {
				continue
			}

			stepName := step.Name
			if stepName == "" {
				stepName = fmt.Sprintf("Step %d", stepIdx+1)
			}

			pat := linenum.FindPattern{Key: "run", Value: step.Run}
			lineResult := lineMapper.FindLineNumber(pat)
			lineNumber := 0
			if lineResult != nil {
				lineNumber = lineResult.LineNumber
			}

			findings = append(findings, Finding{
				RuleID:      "GITHUB_ENV_UNTRUSTED_WRITE",
				RuleName:    "Untrusted Expression Written to GITHUB_ENV",
				Description: "User-controlled data is written directly to $GITHUB_ENV. An attacker can inject arbitrary environment variables including LD_PRELOAD, enabling code execution in all subsequent steps.",
				Severity:    Critical,
				Category:    InjectionAttack,
				FilePath:    workflow.Path,
				JobName:     jobName,
				StepName:    stepName,
				Evidence:    step.Run,
				Remediation: "Validate and sanitize all data before writing to $GITHUB_ENV. Never write untrusted ${{ }} expressions directly to $GITHUB_ENV.",
				LineNumber:  lineNumber,
			})
		}
	}

	return findings
}

// checkMemdumpExfiltration detects signatures of the memdump.py technique (CVE-2025-30066) (EI-002)
func checkMemdumpExfiltration(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			for _, re := range memdumpPatterns {
				if re.MatchString(step.Run) {
					stepName := step.Name
					if stepName == "" {
						stepName = fmt.Sprintf("Step %d", stepIdx+1)
					}

					pat := linenum.FindPattern{Key: "run", Value: step.Run}
					lineResult := lineMapper.FindLineNumber(pat)
					lineNumber := 0
					if lineResult != nil {
						lineNumber = lineResult.LineNumber
					}

					findings = append(findings, Finding{
						RuleID:      "MEMDUMP_EXFILTRATION_SIGNATURE",
						RuleName:    "Process Memory Dump Exfiltration Signature",
						Description: "Workflow contains patterns matching the memdump.py technique used in the March 2025 supply chain attack (CVE-2025-30066) to dump GitHub Actions runner memory and exfiltrate all secrets.",
						Severity:    Critical,
						Category:    MaliciousPattern,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    stepName,
						Evidence:    step.Run,
						Remediation: "Remove this step immediately. This pattern is associated with known supply chain attacks targeting GitHub Actions secrets.",
						LineNumber:  lineNumber,
					})
					break // one finding per step is enough
				}
			}
		}
	}

	return findings
}

// checkIndirectPPEBuildTool detects Indirect Poisoned Pipeline Execution via build tools (EI-003)
func checkIndirectPPEBuildTool(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	untrustedHeadRefs := []string{
		"${{ github.event.pull_request.head.sha }}",
		"${{ github.event.pull_request.head.ref }}",
		"${{ github.head_ref }}",
	}

	buildToolPatterns := []string{
		"npm install",
		"npm ci",
		"pip install -e",
		"make ",
		"mvn ",
		"gradle ",
		"yarn install",
		"pnpm install",
		"poetry install",
		"bundle install",
		"cargo build",
	}

	for jobName, job := range workflow.Workflow.Jobs {
		seenUntrustedCheckout := false

		for stepIdx, step := range job.Steps {
			// Check for untrusted-head checkout
			if strings.HasPrefix(step.Uses, "actions/checkout") {
				if step.With != nil {
					if ref, ok := step.With["ref"].(string); ok {
						for _, untrusted := range untrustedHeadRefs {
							if strings.Contains(ref, untrusted) {
								seenUntrustedCheckout = true
								break
							}
						}
					}
				}
				continue
			}

			if !seenUntrustedCheckout || step.Run == "" {
				continue
			}

			// Check if any build tool pattern is present
			for _, tool := range buildToolPatterns {
				match := strings.Contains(step.Run, tool)
				// "make " is a substring of "cmake"; skip cmake invocations.
				if tool == "make " && strings.Contains(step.Run, "cmake") {
					match = false
				}
				if match {
					stepName := step.Name
					if stepName == "" {
						stepName = fmt.Sprintf("Step %d", stepIdx+1)
					}

					pat := linenum.FindPattern{Key: "run", Value: step.Run}
					lineResult := lineMapper.FindLineNumber(pat)
					lineNumber := 0
					if lineResult != nil {
						lineNumber = lineResult.LineNumber
					}

					findings = append(findings, Finding{
						RuleID:      "INDIRECT_PPE_BUILD_TOOL",
						RuleName:    "Indirect Poisoned Pipeline Execution via Build Tool",
						Description: "Workflow checks out untrusted PR code and then runs a build tool that processes attacker-controlled manifests (npm preinstall hooks, setup.py, Makefile targets). An attacker can execute arbitrary code without modifying workflow YAML.",
						Severity:    High,
						Category:    InjectionAttack,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    stepName,
						Evidence:    tool,
						Remediation: "Use the two-workflow architecture: an unprivileged pull_request workflow builds artifacts only; a privileged workflow_run workflow accesses secrets but never executes untrusted code.",
						LineNumber:  lineNumber,
					})
					break // one finding per step
				}
			}
		}
	}

	return findings
}

// InjectionPatterns contains regex patterns for detecting injection vulnerabilities
type InjectionPatterns struct {
	GitHub []string
	GitLab []string
	Azure  []string
	Tekton []string
}

// GetInjectionPatterns returns patterns for detecting user-controlled input injection
func GetInjectionPatterns() InjectionPatterns {
	return InjectionPatterns{
		GitHub: []string{
			// User-controlled GitHub context variables that can contain malicious input
			`\$\{\{\s*(github\.head_ref|github\.event\.workflow_run\.(head_branch|head_repository\.description|head_repository\.owner\.email|pull_requests[^}]+?(head\.ref|head\.repo\.name)))\s*\}\}`,
			`\$\{\{\s*github\.event\.(issue\.(title|body)|pull_request\.(title|body)|comment\.body|review\.body|review_comment\.body|pages\.[^}]+?\.page_name|head_commit\.message|head_commit\.author\.(email|name)|commits[^}]+?\.author\.(email|name)|pull_request\.head\.(ref|label)|pull_request\.head\.repo\.default_branch|(inputs|client_payload)[^}]+?)\s*\}\}`,
			// Additional untrusted sources: release, discussion, PR head repo, workflow_run commit info
			`\$\{\{\s*github\.event\.(release\.(body|name)|discussion\.(body|title)|pull_request\.head\.repo\.full_name|workflow_run\.head_commit\.(message|author\.(email|name)))\s*\}\}`,
		},
		GitLab: []string{
			// GitLab CI variables with expand_vars that can be dangerous
			`\$\[\[\s*?[^\]]*?(inputs\.[a-zA-Z0-9_-]+)[^\]]*?expand_vars[^\]]*?\s*?\]\]`,
		},
		Azure: []string{
			// Azure DevOps variables that contain user input
			`\$\((Build\.(SourceBranchName|SourceBranch|SourceVersionMessage)|System\.PullRequest\.SourceBranch)\)`,
		},
		Tekton: []string{
			// Tekton Pipeline as Code variables from PR data
			`\{\{\s*(body\.pull_request\.(title|user\.email|body)|source_branch)\s*\}\}`,
		},
	}
}

// checkInjectionVulnerabilities detects injection vulnerabilities from user-controlled input
func checkInjectionVulnerabilities(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	patterns := GetInjectionPatterns()

	// Compile regex patterns
	var compiledPatterns []*regexp.Regexp
	allPatterns := append(patterns.GitHub, patterns.GitLab...)
	allPatterns = append(allPatterns, patterns.Azure...)
	allPatterns = append(allPatterns, patterns.Tekton...)

	for _, pattern := range allPatterns {
		if compiled, err := regexp.Compile(pattern); err == nil {
			compiledPatterns = append(compiledPatterns, compiled)
		}
	}

	// Check GitHub Actions workflow (all workflows are GitHub Actions in our parser)
	findings = append(findings, checkGitHubInjection(workflow, compiledPatterns)...)

	return findings
}

// checkGitHubInjection checks for injection vulnerabilities in GitHub Actions workflows
func checkGitHubInjection(workflow parser.WorkflowFile, patterns []*regexp.Regexp) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Check each job
	for jobName, job := range workflow.Workflow.Jobs {
		// Check steps
		for stepIdx, step := range job.Steps {
			stepName := step.Name
			if stepName == "" {
				stepName = fmt.Sprintf("Step %d", stepIdx+1)
			}

			// Check 'run' field for shell injection
			if step.Run != "" {
				// Skip if expressions are safely routed through the env: block (env-var indirection)
				if isSafeViaEnvIndirection(step.Run, step.Env) {
					continue
				}
				if injections := findInjections(step.Run, patterns); len(injections) > 0 {
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
						RuleID:      "INJECTION_VULNERABILITY",
						RuleName:    "Code Injection from User Input",
						Description: "The workflow contains injection vulnerability where user-controlled input is directly interpolated into shell commands",
						Severity:    Critical,
						Category:    InjectionAttack,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    stepName,
						Evidence:    step.Run,
						Remediation: "Use environment variables instead of direct interpolation: assign the value to an environment variable and reference it in the script",
						LineNumber:  lineNumber,
					})
				}
			}

			// Check github-script action for JavaScript injection
			if strings.HasPrefix(step.Uses, "actions/github-script@") {
				if step.With != nil {
					if script, ok := step.With["script"].(string); ok {
						if injections := findInjections(script, patterns); len(injections) > 0 {
							pattern := linenum.FindPattern{
								Key:   "script",
								Value: script,
							}
							lineResult := lineMapper.FindLineNumber(pattern)
							lineNumber := 0
							if lineResult != nil {
								lineNumber = lineResult.LineNumber
							}

							findings = append(findings, Finding{
								RuleID:      "INJECTION_VULNERABILITY",
								RuleName:    "JavaScript Injection in github-script",
								Description: "The github-script action contains injection vulnerability where user-controlled input is directly interpolated into JavaScript code",
								Severity:    Critical,
								Category:    InjectionAttack,
								FilePath:    workflow.Path,
								JobName:     jobName,
								StepName:    stepName,
								Evidence:    script,
								Remediation: "Use context variables and proper escaping instead of direct interpolation in github-script",
								LineNumber:  lineNumber,
							})
						}
					}
				}
			}
		}
	}

	return findings
}

// findInjections searches for injection patterns in the given text
func findInjections(text string, patterns []*regexp.Regexp) []string {
	var injections []string
	seen := make(map[string]bool)

	// Check if the text contains input validation patterns
	validationPatterns := []string{
		`if\s*\[\[\s*"[^"]*"\s*=~\s*\^[^$]+\$\s*\]\]`, // Regex validation pattern
		`^\s*#.*validate.*input`,                      // Comments about validation
		`exit\s+1`,                                    // Error handling with exit
		`echo\s+".*Invalid.*format"`,                  // Validation error messages
	}

	hasValidation := false
	for _, pattern := range validationPatterns {
		if matched, _ := regexp.MatchString(pattern, text); matched {
			hasValidation = true
			break
		}
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(text, -1)
		for _, match := range matches {
			if len(match) > 0 {
				injection := match[0]
				if !seen[injection] {
					// If input validation is present, reduce the confidence
					// We still report it but at lower severity or skip borderline cases
					if hasValidation {
						// Skip common validated input patterns
						if strings.Contains(injection, "github.event.inputs.version") &&
							strings.Contains(text, "=~") &&
							strings.Contains(text, "exit 1") {
							continue // Skip validated version inputs
						}
					}

					injections = append(injections, injection)
					seen[injection] = true
				}
			}
		}
	}

	return injections
}

// checkUntrustedCheckoutExecution detects execution of commands after checking out untrusted code
func checkUntrustedCheckoutExecution(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Only check workflows triggered by potentially untrusted events
	if !hasUntrustedTriggers(workflow) {
		return findings
	}

	// Check each job for checkout followed by risky execution
	for jobName, job := range workflow.Workflow.Jobs {
		var hasCheckout bool
		var checkoutStepIdx int

		// Find checkout steps
		for stepIdx, step := range job.Steps {
			if strings.HasPrefix(step.Uses, "actions/checkout@") {
				hasCheckout = true
				checkoutStepIdx = stepIdx

				// Check if checkout uses untrusted ref
				if isUntrustedCheckout(step) {
					// Look for risky execution after this checkout
					riskySteps := findRiskyExecutionAfterCheckout(job.Steps, stepIdx+1)
					for _, riskyStep := range riskySteps {
						stepName := riskyStep.step.Name
						if stepName == "" {
							stepName = "Step " + string(rune('1'+riskyStep.index))
						}

						pattern := linenum.FindPattern{
							Key:   "run",
							Value: getStepContent(riskyStep.step),
						}
						lineResult := lineMapper.FindLineNumber(pattern)
						lineNumber := 0
						if lineResult != nil {
							lineNumber = lineResult.LineNumber
						}

						findings = append(findings, Finding{
							RuleID:      "UNTRUSTED_CHECKOUT_EXECUTION",
							RuleName:    "Code Execution After Untrusted Checkout",
							Description: "The workflow checks out untrusted code and then executes commands that could run malicious code from the checkout",
							Severity:    Critical,
							Category:    InjectionAttack,
							FilePath:    workflow.Path,
							JobName:     jobName,
							StepName:    stepName,
							Evidence:    getStepContent(riskyStep.step),
							Remediation: "Use a trusted checkout reference (like a specific commit SHA) or run risky commands before checkout",
							LineNumber:  lineNumber,
						})
					}
				}
			}
		}

		// Also check for implicit checkout risks
		if hasCheckout {
			implicitRisks := findImplicitExecutionRisks(job.Steps, checkoutStepIdx)
			for _, risk := range implicitRisks {
				stepName := risk.step.Name
				if stepName == "" {
					stepName = "Step " + string(rune('1'+risk.index))
				}

				pattern := linenum.FindPattern{
					Key:   "uses",
					Value: getStepContent(risk.step),
				}
				lineResult := lineMapper.FindLineNumber(pattern)
				lineNumber := 0
				if lineResult != nil {
					lineNumber = lineResult.LineNumber
				}

				findings = append(findings, Finding{
					RuleID:      "UNTRUSTED_CHECKOUT_EXECUTION",
					RuleName:    "Potential Code Execution After Checkout",
					Description: "The workflow uses actions or commands that might execute code from the checked out repository",
					Severity:    High,
					Category:    InjectionAttack,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    stepName,
					Evidence:    getStepContent(risk.step),
					Remediation: "Verify that the action or command does not execute untrusted code from the repository",
					LineNumber:  lineNumber,
				})
			}
		}
	}

	return findings
}

// hasUntrustedTriggers checks if workflow is triggered by events that can include untrusted code
func hasUntrustedTriggers(workflow parser.WorkflowFile) bool {
	untrustedEvents := []string{
		"pull_request_target",
		"issues",
		"issue_comment",
		"workflow_call",
		"pull_request", // Can be risky in public repos
	}

	if workflow.Workflow.On == nil {
		return false
	}

	// Handle different types of 'on' field
	switch on := workflow.Workflow.On.(type) {
	case string:
		// Single event as string
		for _, event := range untrustedEvents {
			if on == event {
				return true
			}
		}
	case []interface{}:
		// Array of events
		for _, eventInterface := range on {
			if eventStr, ok := eventInterface.(string); ok {
				for _, event := range untrustedEvents {
					if eventStr == event {
						return true
					}
				}
			}
		}
	case map[interface{}]interface{}:
		// Map of events with configuration
		for eventInterface := range on {
			if eventStr, ok := eventInterface.(string); ok {
				for _, event := range untrustedEvents {
					if eventStr == event {
						return true
					}
				}
			}
		}
	case map[string]interface{}:
		// Map of events with configuration (alternative format)
		for eventStr := range on {
			for _, event := range untrustedEvents {
				if eventStr == event {
					return true
				}
			}
		}
	}

	return false
}

// isUntrustedCheckout determines if a checkout step uses untrusted references
func isUntrustedCheckout(step parser.Step) bool {
	if step.With != nil {
		// Check for explicit untrusted refs
		if ref, ok := step.With["ref"].(string); ok {
			untrustedRefs := []string{
				"${{ github.head_ref }}",
				"${{ github.event.pull_request.head.ref }}",
				"${{ github.event.pull_request.head.sha }}",
			}
			for _, untrustedRef := range untrustedRefs {
				if strings.Contains(ref, untrustedRef) {
					return true
				}
			}
		}

		// Check for repository parameter (might checkout different repo)
		if repo, ok := step.With["repository"].(string); ok {
			if strings.Contains(repo, "${{") {
				return true
			}
		}
	}

	return false
}

type riskyStep struct {
	step  parser.Step
	index int
}

// findRiskyExecutionAfterCheckout finds steps that could execute checked out code
func findRiskyExecutionAfterCheckout(steps []parser.Step, startIdx int) []riskyStep {
	var riskySteps []riskyStep

	buildActions := map[string]bool{
		"actions/setup-node":   true,
		"actions/setup-python": true,
		"actions/setup-go":     true,
		"actions/setup-java":   true,
		"ruby/setup-ruby":      true,
	}

	riskyCommands := []string{
		`npm\s+(run|start|test|ci|install)`,
		`yarn\s+(run|start|test|install)`,
		`pip\s+install`,
		`python\s+setup\.py`,
		`go\s+(run|build|test)`,
		`make\s+`,
		`mvn\s+`,
		`gradle\s+`,
		`cargo\s+(run|build|test)`,
		`bundle\s+(exec|install)`,
		`\./[a-zA-Z0-9_-]+\.(sh|py|rb|js)`,
		`chmod\s+.*\+x`,
	}

	for i := startIdx; i < len(steps); i++ {
		step := steps[i]

		// Check for risky actions
		if step.Uses != "" {
			actionName := strings.Split(step.Uses, "@")[0]
			if buildActions[actionName] {
				riskySteps = append(riskySteps, riskyStep{step, i})
			}
		}

		// Check for risky run commands
		if step.Run != "" {
			for _, pattern := range riskyCommands {
				if matched, _ := regexp.MatchString(pattern, step.Run); matched {
					riskySteps = append(riskySteps, riskyStep{step, i})
					break
				}
			}
		}
	}

	return riskySteps
}

// findImplicitExecutionRisks finds steps that might implicitly execute code
func findImplicitExecutionRisks(steps []parser.Step, checkoutIdx int) []riskyStep {
	var riskySteps []riskyStep

	// Actions that might execute code from the repo
	implicitlyRiskyActions := []string{
		"docker/build-push-action",
		"docker/setup-buildx-action",
		"github/super-linter",
		"reviewdog/action-",
		"codecov/codecov-action",
	}

	for i := checkoutIdx + 1; i < len(steps); i++ {
		step := steps[i]

		if step.Uses != "" {
			for _, riskyAction := range implicitlyRiskyActions {
				if strings.Contains(step.Uses, riskyAction) {
					riskySteps = append(riskySteps, riskyStep{step, i})
					break
				}
			}
		}
	}

	return riskySteps
}

// isSafeViaEnvIndirection returns true when all untrusted ${{ }} expressions
// in the run block are safely routed through the step's env: block.
// This prevents false positives for GitHub's recommended safe pattern:
//
//	env:
//	  TITLE: ${{ github.event.pull_request.title }}
//	run: echo "$TITLE"
func isSafeViaEnvIndirection(run string, env map[string]string) bool {
	tracker := ast.NewExprTaintTracker()
	paths, err := tracker.PathsForStep(run, env)
	if err != nil {
		return false
	}
	return !ast.HasUnsafePaths(paths)
}

// Helper functions
func getStepContent(step parser.Step) string {
	if step.Run != "" {
		return step.Run
	}
	if step.Uses != "" {
		return step.Uses
	}
	return "Unknown step content"
}
