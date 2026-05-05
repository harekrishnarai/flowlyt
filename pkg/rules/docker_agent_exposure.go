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
	"regexp"
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/linenum"
	"github.com/harekrishnarai/flowlyt/pkg/parser"
)

// CheckDockerAgentExposure detects pull_request_target workflows that run
// Docker containers or reusable agent workflows with secrets on fork code.
func CheckDockerAgentExposure(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	if !hasPullRequestTargetTrigger(workflow) {
		return findings
	}

	findings = append(findings, checkDockerExecWithSecrets(workflow)...)
	findings = append(findings, checkReusableWorkflowAgentExposure(workflow)...)

	return findings
}

// checkReusableWorkflowAgentExposure detects job-level reusable workflow calls
// that pass secrets to agent/review/bot workflows under pull_request_target.
func checkReusableWorkflowAgentExposure(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	agentWorkflowPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)review.*pull.*request`),
		regexp.MustCompile(`(?i)review-pr`),
		regexp.MustCompile(`(?i)agent`),
		regexp.MustCompile(`(?i)bot.*respond`),
		regexp.MustCompile(`(?i)ai.*review`),
		regexp.MustCompile(`(?i)code.*review`),
		regexp.MustCompile(`(?i)auto.*review`),
		regexp.MustCompile(`(?i)respond.*comment`),
		regexp.MustCompile(`(?i)triage.*issue`),
	}

	for jobName, job := range workflow.Workflow.Jobs {
		if job.Uses == "" {
			continue
		}

		if !strings.Contains(job.Uses, ".github/workflows/") {
			continue
		}

		isAgentWorkflow := false
		for _, pattern := range agentWorkflowPatterns {
			if pattern.MatchString(job.Uses) {
				isAgentWorkflow = true
				break
			}
		}
		if !isAgentWorkflow {
			continue
		}

		hasSecrets := false
		if job.Secrets != nil {
			switch s := job.Secrets.(type) {
			case string:
				if s == "inherit" {
					hasSecrets = true
				}
			case map[string]interface{}:
				if len(s) > 0 {
					hasSecrets = true
				}
			case map[interface{}]interface{}:
				if len(s) > 0 {
					hasSecrets = true
				}
			}
		}

		if !hasSecrets {
			continue
		}

		severity := Medium
		if job.Secrets != nil {
			switch s := job.Secrets.(type) {
			case string:
				if s == "inherit" {
					severity = High
				}
			}
		}

		lineNumber := 1
		linePattern := linenum.FindPattern{
			Key:   "uses",
			Value: job.Uses,
		}
		lineResult := lineMapper.FindLineNumber(linePattern)
		if lineResult != nil {
			lineNumber = lineResult.LineNumber
		}

		finding := Finding{
			RuleID:      "DOCKER_EXEC_WITH_SECRETS_ON_FORK_CODE",
			RuleName:    "Reusable Agent Workflow Called With Secrets on pull_request_target",
			Description: "A pull_request_target workflow calls a reusable workflow that appears to run an AI agent or automated review, passing secrets. Verify whether the called workflow checks out the PR head ref — if it does, fork code runs in a container with secrets available, enabling exfiltration.",
			Severity:    severity,
			Category:    SecretExposure,
			FilePath:    workflow.Path,
			JobName:     jobName,
			StepName:    "",
			Evidence:    "uses: " + job.Uses,
			Remediation: "Ensure downstream Docker containers use --network=none. Do not forward secrets into containers processing fork code. Require a maintainer label before running agents on fork PRs.",
			LineNumber:  lineNumber,
		}
		findings = append(findings, finding)
	}

	return findings
}

// checkDockerExecWithSecrets detects direct docker run commands that forward
// secrets via -e/--env while operating on fork code without network isolation.
// Only flags when the job checks out untrusted PR head code.
func checkDockerExecWithSecrets(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	dockerRunWithEnv := []*regexp.Regexp{
		regexp.MustCompile(`docker\s+run\b[^;|&]*\s-e\s`),
		regexp.MustCompile(`docker\s+run\b[^;|&]*\s--env\s`),
		regexp.MustCompile(`docker\s+run\b[^;|&]*\s--env-file\s`),
	}

	secretEnvPatterns := []*regexp.Regexp{
		regexp.MustCompile(`-e\s+\w*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)\w*`),
		regexp.MustCompile(`--env\s+\w*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)\w*`),
		regexp.MustCompile(`-e\s+\$\{\{\s*secrets\.\w+\s*\}\}`),
		regexp.MustCompile(`-e\s+\w+=\$\{\{\s*secrets\.\w+\s*\}\}`),
		regexp.MustCompile(`--env\s+\w+=\$\{\{\s*secrets\.\w+\s*\}\}`),
	}

	networkNone := regexp.MustCompile(`--network[=\s]+none`)

	for jobName, job := range workflow.Workflow.Jobs {
		// Only flag if the job checks out untrusted PR head code
		if !jobCheckoutsUntrustedCode(job) {
			continue
		}

		for stepIdx, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			hasDockerEnv := false
			for _, pattern := range dockerRunWithEnv {
				if pattern.MatchString(step.Run) {
					hasDockerEnv = true
					break
				}
			}
			if !hasDockerEnv {
				continue
			}

			if networkNone.MatchString(step.Run) {
				continue
			}

			hasSecretForward := false
			for _, pattern := range secretEnvPatterns {
				if pattern.MatchString(step.Run) {
					hasSecretForward = true
					break
				}
			}

			if !hasSecretForward && job.Env != nil {
				for key, value := range job.Env {
					if strings.Contains(value, "secrets.") {
						keyUpper := strings.ToUpper(key)
						if strings.Contains(keyUpper, "KEY") || strings.Contains(keyUpper, "TOKEN") ||
							strings.Contains(keyUpper, "SECRET") || strings.Contains(keyUpper, "PASSWORD") {
							// Only flag if the docker run command actually forwards this env var
							if strings.Contains(step.Run, "-e "+key) || strings.Contains(step.Run, "--env "+key) ||
								strings.Contains(step.Run, "-e $"+key) || strings.Contains(step.Run, "--env $"+key) ||
								strings.Contains(step.Run, "-e ${"+key+"}") || strings.Contains(step.Run, "--env ${"+key+"}") {
								hasSecretForward = true
								break
							}
						}
					}
				}
			}

			if !hasSecretForward && step.Env != nil {
				for key, value := range step.Env {
					if strings.Contains(value, "secrets.") {
						if strings.Contains(step.Run, "-e "+key) || strings.Contains(step.Run, "--env "+key) ||
							strings.Contains(step.Run, "-e $"+key) || strings.Contains(step.Run, "--env $"+key) ||
							strings.Contains(step.Run, "-e ${"+key+"}") || strings.Contains(step.Run, "--env ${"+key+"}") {
							hasSecretForward = true
							break
						}
					}
				}
			}

			if !hasSecretForward {
				continue
			}

			stepName := step.Name
			if stepName == "" {
				stepName = "Step " + string(rune('1'+stepIdx))
			}

			linePattern := linenum.FindPattern{
				Key:   "run",
				Value: step.Run,
			}
			lineResult := lineMapper.FindLineNumber(linePattern)
			lineNumber := 1
			if lineResult != nil {
				lineNumber = lineResult.LineNumber
			}

			finding := Finding{
				RuleID:      "DOCKER_EXEC_WITH_SECRETS_ON_FORK_CODE",
				RuleName:    "Docker Container Runs Fork Code With Secrets",
				Description: "A pull_request_target workflow runs a Docker container with secrets forwarded via -e/--env while operating on fork code without --network=none isolation. An external attacker can exfiltrate secrets by opening a PR with malicious files.",
				Severity:    Critical,
				Category:    SecretExposure,
				FilePath:    workflow.Path,
				JobName:     jobName,
				StepName:    stepName,
				Evidence:    step.Run,
				Remediation: "Add --network=none to docker run to prevent network exfiltration. Remove unnecessary secrets from the container environment.",
				LineNumber:  lineNumber,
			}
			findings = append(findings, finding)
		}
	}

	findings = append(findings, checkIndirectDockerWithSecrets(workflow, lineMapper)...)

	return findings
}

// checkIndirectDockerWithSecrets detects step-level composite action calls
// that pass secrets to agent/review workflows under pull_request_target.
// Note: Reusable workflows (.github/workflows/) are job-level only;
// step-level uses only valid for composite actions.
func checkIndirectDockerWithSecrets(workflow parser.WorkflowFile, lineMapper *linenum.LineMapper) []Finding {
	var findings []Finding

	agentWorkflowPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)review.*pull.*request`),
		regexp.MustCompile(`(?i)agent`),
		regexp.MustCompile(`(?i)bot.*respond`),
		regexp.MustCompile(`(?i)ai.*review`),
		regexp.MustCompile(`(?i)code.*review`),
		regexp.MustCompile(`(?i)auto.*review`),
	}

	for jobName, job := range workflow.Workflow.Jobs {
		// Only flag if the job checks out untrusted PR head code
		if !jobCheckoutsUntrustedCode(job) {
			continue
		}

		for stepIdx, step := range job.Steps {
			if step.Uses == "" {
				continue
			}

			// Step-level uses: only composite actions are valid here
			if !strings.Contains(step.Uses, ".github/actions/") {
				continue
			}

			isAgentWorkflow := false
			for _, pattern := range agentWorkflowPatterns {
				if pattern.MatchString(step.Uses) {
					isAgentWorkflow = true
					break
				}
			}
			if !isAgentWorkflow {
				continue
			}

			hasSecrets := false
			if step.With != nil {
				for key, value := range step.With {
					if valueStr, ok := value.(string); ok {
						if strings.Contains(valueStr, "secrets.") ||
							strings.Contains(strings.ToLower(key), "token") ||
							strings.Contains(strings.ToLower(key), "key") {
							hasSecrets = true
							break
						}
					}
				}
			}

			if !hasSecrets {
				// Check job-level secrets field (for reusable workflow calls in same job)
				if job.Secrets != nil {
					switch s := job.Secrets.(type) {
					case string:
						if s == "inherit" {
							hasSecrets = true
						}
					}
				}
			}

			if !hasSecrets {
				continue
			}

			stepName := step.Name
			if stepName == "" {
				stepName = "Step " + string(rune('1'+stepIdx))
			}

			lineNumber := 1
			if step.Uses != "" {
				linePattern := linenum.FindPattern{
					Key:   "uses",
					Value: step.Uses,
				}
				lineResult := lineMapper.FindLineNumber(linePattern)
				if lineResult != nil {
					lineNumber = lineResult.LineNumber
				}
			}

			finding := Finding{
				RuleID:      "DOCKER_EXEC_WITH_SECRETS_ON_FORK_CODE",
				RuleName:    "Reusable Workflow Runs Agent on Fork Code With Secrets",
				Description: "A pull_request_target workflow passes secrets to a reusable workflow that runs an AI agent or automated review on fork code. If the downstream container lacks network isolation, an external attacker can exfiltrate secrets via malicious PR files.",
				Severity:    High,
				Category:    SecretExposure,
				FilePath:    workflow.Path,
				JobName:     jobName,
				StepName:    stepName,
				Evidence:    "uses: " + step.Uses,
				Remediation: "Audit the reusable workflow to ensure Docker containers use --network=none and secrets are not forwarded into containers processing fork code.",
				LineNumber:  lineNumber,
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// checkAIAgentOnUntrustedCode detects AI agent invocations that process
// untrusted fork code with secrets available, enabling indirect prompt injection.
func checkAIAgentOnUntrustedCode(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	if !hasPullRequestTargetTrigger(workflow) {
		return findings
	}

	lineMapper := linenum.NewLineMapper(workflow.Content)

	aiAgentPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(oz|claude|copilot|gpt|openai|anthropic)\s+(agent|run|review)`),
		regexp.MustCompile(`(?i)\bagent\s+run\b`),
		regexp.MustCompile(`(?i)\bclaude\s+(-p|--prompt|code)\b`),
		regexp.MustCompile(`(?i)docker\s+run\b[^;|&]*(agent|review|bot|ai)[^;|&]*`),
		regexp.MustCompile(`(?i)\b(aider|cursor|continue|cody|devin|sweep)\b.*\b(run|start|review)\b`),
	}

	aiStepNamePatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(ai|agent|bot|llm|gpt|claude|copilot).*(review|analyze|respond|triage)`),
		regexp.MustCompile(`(?i)(review|analyze|respond|triage).*(ai|agent|bot|llm|gpt|claude|copilot)`),
		regexp.MustCompile(`(?i)auto.*review`),
		regexp.MustCompile(`(?i)code.*review.*bot`),
	}

	aiActionPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(oz-agent|ai-review|code-review-bot|pr-review|auto-review)`),
		regexp.MustCompile(`(?i)(anthropic|openai|claude|copilot).*action`),
	}

	networkNonePattern := regexp.MustCompile(`--network[=\s]+none`)

	for jobName, job := range workflow.Workflow.Jobs {
		// Only flag if the job checks out untrusted PR head code
		if !jobCheckoutsUntrustedCode(job) {
			continue
		}

		for stepIdx, step := range job.Steps {
			isAIStep := false
			evidence := ""

			if step.Run != "" {
				for _, pattern := range aiAgentPatterns {
					if pattern.MatchString(step.Run) {
						isAIStep = true
						evidence = step.Run
						break
					}
				}
				// If this is a docker run with --network=none, it's mitigated
				if isAIStep && networkNonePattern.MatchString(step.Run) {
					continue
				}
			}

			if !isAIStep && step.Name != "" {
				for _, pattern := range aiStepNamePatterns {
					if pattern.MatchString(step.Name) {
						isAIStep = true
						evidence = "step name: " + step.Name
						break
					}
				}
			}

			if !isAIStep && step.Uses != "" {
				for _, pattern := range aiActionPatterns {
					if pattern.MatchString(step.Uses) {
						isAIStep = true
						evidence = "uses: " + step.Uses
						break
					}
				}
			}

			if !isAIStep {
				continue
			}

			hasSecrets := hasSecretsAccess(step)
			if !hasSecrets && job.Env != nil {
				for _, value := range job.Env {
					if strings.Contains(value, "secrets.") {
						hasSecrets = true
						break
					}
				}
			}
			if !hasSecrets && step.Env != nil {
				for _, value := range step.Env {
					if strings.Contains(strings.ToUpper(value), "KEY") ||
						strings.Contains(strings.ToUpper(value), "TOKEN") {
						hasSecrets = true
						break
					}
				}
			}

			severity := High
			if !hasSecrets {
				severity = Medium
			}

			stepName := step.Name
			if stepName == "" {
				stepName = "Step " + string(rune('1'+stepIdx))
			}

			lineNumber := 1
			if step.Run != "" {
				linePattern := linenum.FindPattern{
					Key:   "run",
					Value: step.Run,
				}
				lineResult := lineMapper.FindLineNumber(linePattern)
				if lineResult != nil {
					lineNumber = lineResult.LineNumber
				}
			} else if step.Uses != "" {
				linePattern := linenum.FindPattern{
					Key:   "uses",
					Value: step.Uses,
				}
				lineResult := lineMapper.FindLineNumber(linePattern)
				if lineResult != nil {
					lineNumber = lineResult.LineNumber
				}
			}

			finding := Finding{
				RuleID:      "AI_AGENT_ON_UNTRUSTED_CODE",
				RuleName:    "AI Agent Processes Untrusted Fork Code With Secrets",
				Description: "A pull_request_target workflow runs an AI agent that processes fork-controlled code with secrets in its environment and network access. Attacker-controlled files can contain indirect prompt injection payloads that trick the agent into exfiltrating secrets.",
				Severity:    severity,
				Category:    SecretExposure,
				FilePath:    workflow.Path,
				JobName:     jobName,
				StepName:    stepName,
				Evidence:    evidence,
				Remediation: "Add --network=none to agent containers. Treat all file contents as untrusted in agent prompts. Remove secrets from the agent environment if not needed. Require a maintainer label before running agents on fork PRs.",
				LineNumber:  lineNumber,
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// jobCheckoutsUntrustedCode returns true if a job contains a checkout step
// that references the PR head (untrusted code). Checks for:
// - actions/checkout with ref containing head.sha, head.ref, or head_ref
// - git checkout/fetch commands referencing PR refs
func jobCheckoutsUntrustedCode(job parser.Job) bool {
	untrustedRefPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)pull_request\.head\.sha`),
		regexp.MustCompile(`(?i)pull_request\.head\.ref`),
		regexp.MustCompile(`(?i)github\.head_ref`),
		regexp.MustCompile(`(?i)event\.pull_request\.head`),
		regexp.MustCompile(`(?i)refs/pull/`),
	}

	for _, step := range job.Steps {
		// Check actions/checkout with untrusted ref
		if strings.Contains(step.Uses, "actions/checkout") {
			if step.With != nil {
				if ref, ok := step.With["ref"]; ok {
					refStr, _ := ref.(string)
					for _, pattern := range untrustedRefPatterns {
						if pattern.MatchString(refStr) {
							return true
						}
					}
				}
			}
		}

		// Check run steps for git commands fetching PR refs
		if step.Run != "" {
			for _, pattern := range untrustedRefPatterns {
				if pattern.MatchString(step.Run) {
					return true
				}
			}
		}
	}

	return false
}

// CheckAIAgentCommentTriggered detects AI agent workflows triggered by
// issue_comment or pull_request_review_comment that process attacker-controlled
// input (comment body) with secrets available. This enables prompt injection
// attacks where any external user can @mention the agent and craft payloads
// to exfiltrate secrets or abuse write permissions.
func CheckAIAgentCommentTriggered(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	// Must be triggered by comment events
	hasCommentTrigger := false
	switch on := workflow.Workflow.On.(type) {
	case string:
		if on == "issue_comment" || on == "pull_request_review_comment" {
			hasCommentTrigger = true
		}
	case []interface{}:
		for _, trigger := range on {
			if t, ok := trigger.(string); ok {
				if t == "issue_comment" || t == "pull_request_review_comment" {
					hasCommentTrigger = true
					break
				}
			}
		}
	case map[string]interface{}:
		if _, ok := on["issue_comment"]; ok {
			hasCommentTrigger = true
		}
		if _, ok := on["pull_request_review_comment"]; ok {
			hasCommentTrigger = true
		}
	}

	if !hasCommentTrigger {
		return findings
	}

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Known AI agent actions (comment-triggered code review / chat agents)
	aiAgentActions := []*regexp.Regexp{
		regexp.MustCompile(`(?i)anthropics?/claude[-_]code[-_]action`),
		regexp.MustCompile(`(?i)google[-_]gemini/code[-_]assist[-_]action`),
		regexp.MustCompile(`(?i)github/copilot[-_]action`),
		regexp.MustCompile(`(?i)openai/chatgpt[-_]action`),
		regexp.MustCompile(`(?i)coderabbit`),
		regexp.MustCompile(`(?i)sourcery[-_]ai`),
		regexp.MustCompile(`(?i)sweep[-_]ai`),
		regexp.MustCompile(`(?i)aider[-_]action`),
		regexp.MustCompile(`(?i)devin[-_]action`),
		regexp.MustCompile(`(?i)qodo/`),
		regexp.MustCompile(`(?i)cursor[-_]action`),
	}

	// AI agent CLI patterns in run steps
	aiRunPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bclaude\s+(code|--prompt|-p)\b`),
		regexp.MustCompile(`(?i)\bgemini\s+(run|review|respond)\b`),
		regexp.MustCompile(`(?i)\baider\b.*\b(run|--message)\b`),
		regexp.MustCompile(`(?i)\bcody\b.*\b(chat|respond)\b`),
		regexp.MustCompile(`(?i)\bcopilot\b.*\b(review|respond)\b`),
	}

	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			isAIAgent := false
			evidence := ""

			// Check uses: for known AI agent actions
			if step.Uses != "" {
				for _, pattern := range aiAgentActions {
					if pattern.MatchString(step.Uses) {
						isAIAgent = true
						evidence = "uses: " + step.Uses
						break
					}
				}
			}

			// Check run: for AI CLI invocations
			if !isAIAgent && step.Run != "" {
				for _, pattern := range aiRunPatterns {
					if pattern.MatchString(step.Run) {
						isAIAgent = true
						evidence = step.Run
						break
					}
				}
			}

			if !isAIAgent {
				continue
			}

			// Check if author_association is already gated to trusted actors
			hasActorGate := false
			actorGatePattern := regexp.MustCompile(`author_association\s*==\s*'(MEMBER|OWNER|COLLABORATOR)'`)
			if job.If != "" && actorGatePattern.MatchString(job.If) {
				hasActorGate = true
			}
			if step.If != "" && actorGatePattern.MatchString(step.If) {
				hasActorGate = true
			}

			if hasActorGate {
				continue
			}

			// Determine what secrets are exposed
			hasSecrets := false
			secretEvidence := []string{}

			if step.With != nil {
				for key, value := range step.With {
					if valueStr, ok := value.(string); ok {
						if strings.Contains(valueStr, "secrets.") {
							hasSecrets = true
							secretEvidence = append(secretEvidence, key+"="+valueStr)
						}
					}
				}
			}

			if step.Env != nil {
				for key, value := range step.Env {
					if strings.Contains(value, "secrets.") {
						hasSecrets = true
						secretEvidence = append(secretEvidence, key+"="+value)
					}
				}
			}

			if job.Env != nil {
				for _, value := range job.Env {
					if strings.Contains(value, "secrets.") {
						hasSecrets = true
						break
					}
				}
			}

			stepName := step.Name
			if stepName == "" {
				stepName = "Step " + string(rune('1'+stepIdx))
			}

			lineNumber := 1
			if step.Uses != "" {
				linePattern := linenum.FindPattern{
					Key:   "uses",
					Value: step.Uses,
				}
				lineResult := lineMapper.FindLineNumber(linePattern)
				if lineResult != nil {
					lineNumber = lineResult.LineNumber
				}
			} else if step.Run != "" {
				linePattern := linenum.FindPattern{
					Key:   "run",
					Value: step.Run,
				}
				lineResult := lineMapper.FindLineNumber(linePattern)
				if lineResult != nil {
					lineNumber = lineResult.LineNumber
				}
			}

			// Determine severity and description based on exposure
			var severity Severity
			var description string
			var ruleCategory Category

			if hasSecrets {
				ruleCategory = SecretExposure
				severity = High
				// If the job effectively has write permissions, severity is Critical.
				// Job-level permissions inherit from workflow-level when nil.
				effectivePermissions := job.Permissions
				if effectivePermissions == nil {
					effectivePermissions = workflow.Workflow.Permissions
				}
				if permsImplyWrite(effectivePermissions) {
					severity = Critical
				}
				secretInfo := ""
				if len(secretEvidence) > 0 {
					secretInfo = " Secrets passed: " + strings.Join(secretEvidence, ", ")
				}
				description = "A workflow runs an AI agent in response to issue comments or PR review comments " +
					"without restricting to trusted actors (author_association). " +
					"Any user who can comment (including external contributors on public repos) can trigger the agent " +
					"and control its input via the comment body. With secrets available, an attacker can craft prompt " +
					"injection payloads to exfiltrate API keys or abuse write permissions." + secretInfo
			} else {
				// Denial-of-wallet: no secrets but still burns API credits
				ruleCategory = AccessControl
				severity = Medium
				description = "A workflow runs an AI agent in response to issue comments or PR review comments " +
					"without restricting to trusted actors (author_association). " +
					"Any user who can comment on public repos can trigger the agent, causing unbounded API cost. " +
					"An attacker can spam mentions to inflict denial-of-wallet by exhausting the API budget."
			}

			finding := Finding{
				RuleID:      "AI_AGENT_COMMENT_TRIGGERED",
				RuleName:    "AI Agent Triggered by External Comment Without Actor Gate",
				Description: description,
				Severity:    severity,
				Category:    ruleCategory,
				FilePath:    workflow.Path,
				JobName:     jobName,
				StepName:    stepName,
				Evidence:    evidence,
				Remediation: "Restrict trigger to trusted actors: add `if: github.event.comment.author_association == 'MEMBER' || github.event.comment.author_association == 'OWNER'`. For cost control, add rate limiting or require a maintainer label. Never pass secrets directly to agent actions processing external input.",
				LineNumber:  lineNumber,
			}
			findings = append(findings, finding)
		}
	}

	return findings
}
