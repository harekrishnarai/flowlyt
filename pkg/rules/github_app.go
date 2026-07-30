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

	"github.com/harekrishnarai/flowlyt/v2/pkg/linenum"
	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
)

// CheckGitHubAppTokenMisuse is the public entry point for the
// GITHUB_APP_TOKEN_MISUSE rule.
func CheckGitHubAppTokenMisuse(workflow parser.WorkflowFile) []Finding {
	return checkGitHubAppTokenMisuse(workflow)
}

// appTokenActions are actions that mint a GitHub App installation token.
var appTokenActions = []string{
	"actions/create-github-app-token",
	"tibdex/github-app-token",
	"getsentry/action-github-app-token",
	"peter-murray/workflow-application-token-action",
}

// isAppTokenAction reports whether a `uses:` clause mints an App installation
// token, ignoring any version or digest suffix.
func isAppTokenAction(uses string) bool {
	name := uses
	if idx := strings.Index(name, "@"); idx != -1 {
		name = name[:idx]
	}
	name = strings.ToLower(strings.TrimSpace(name))

	for _, candidate := range appTokenActions {
		if name == candidate {
			return true
		}
	}
	return false
}

// appTokenIssue describes one way a token request is over-scoped.
type appTokenIssue struct {
	// inputKey is the `with:` key that anchors the finding to a line.
	inputKey    string
	inputValue  string
	summary     string
	remediation string
	severity    Severity
}

// checkGitHubAppTokenMisuse detects over-scoped GitHub App installation tokens.
//
// App installation tokens are a legitimate and often preferable alternative to
// the default GITHUB_TOKEN, so their use is not itself a finding. The risk lies
// in how they are requested:
//
//   - Disabling revocation leaves a valid credential alive after the job ends,
//     extending the window in which a leaked token is useful to an attacker.
//   - Requesting an owner-wide token grants access to every repository in the
//     installation, so a compromise in one workflow reaches the entire org.
//   - Omitting `permissions` yields a token carrying every permission the App
//     was granted at install time, which is routinely far broader than the job
//     needs.
func checkGitHubAppTokenMisuse(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)
	seen := make(map[string]bool)

	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			if step.Uses == "" || !isAppTokenAction(step.Uses) {
				continue
			}

			stepName := step.Name
			if stepName == "" {
				stepName = fmt.Sprintf("Step %d", stepIdx+1)
			}

			for _, issue := range appTokenIssues(step.With) {
				lineNumber := 0
				pattern := linenum.FindPattern{Key: "uses", Value: step.Uses}
				if issue.inputKey != "" {
					pattern = linenum.FindPattern{Key: issue.inputKey, Value: issue.inputValue}
				}
				if result := lineMapper.FindLineNumber(pattern); result != nil {
					lineNumber = result.LineNumber
				}

				dedupKey := fmt.Sprintf("%s|%s|%d", jobName, issue.summary, lineNumber)
				if seen[dedupKey] {
					continue
				}
				seen[dedupKey] = true

				findings = append(findings, Finding{
					RuleID:      "GITHUB_APP_TOKEN_MISUSE",
					RuleName:    "Over-scoped GitHub App Token",
					Description: "GitHub App installation token is requested with broader scope or lifetime than the job requires",
					Severity:    issue.severity,
					Category:    PrivilegeEscalation,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    stepName,
					Evidence:    fmt.Sprintf("%s: %s", step.Uses, issue.summary),
					Remediation: issue.remediation,
					LineNumber:  lineNumber,
				})
			}
		}
	}

	return findings
}

// appTokenIssues inspects the inputs of a token-minting step.
func appTokenIssues(with map[string]interface{}) []appTokenIssue {
	var issues []appTokenIssue

	stringInput := func(key string) (string, bool) {
		raw, ok := with[key]
		if !ok || raw == nil {
			return "", false
		}
		switch v := raw.(type) {
		case string:
			return v, true
		case bool:
			return fmt.Sprintf("%t", v), true
		}
		return "", false
	}

	// Revocation disabled.
	if value, ok := stringInput("skip-token-revoke"); ok && isTruthyInput(value) {
		issues = append(issues, appTokenIssue{
			inputKey:    "skip-token-revoke",
			inputValue:  value,
			summary:     "token revocation is disabled via `skip-token-revoke`, so the credential stays valid after the job ends",
			remediation: "Remove `skip-token-revoke` (or set it to false) so the token is revoked in the post-run step",
			severity:    Medium,
		})
	}

	// Owner-wide token: `owner` set without narrowing to `repositories`.
	owner, hasOwner := stringInput("owner")
	if _, hasRepositories := stringInput("repositories"); hasOwner && !hasRepositories {
		issues = append(issues, appTokenIssue{
			inputKey:    "owner",
			inputValue:  owner,
			summary:     fmt.Sprintf("`owner: %s` is set without `repositories:`, producing a token valid for every repository in the installation", owner),
			remediation: "Add `repositories:` listing only the repositories the job needs, so the token cannot reach the rest of the organization",
			severity:    High,
		})
	}

	// No explicit permission narrowing. The action namespaces these inputs as
	// `permission-<scope>`, so the absence of every such key means the token
	// inherits all of the App's granted permissions.
	if !hasPermissionNarrowing(with) {
		issues = append(issues, appTokenIssue{
			summary:     "no `permission-*` inputs are set, so the token carries every permission granted to the App at install time",
			remediation: "Restrict the token with explicit `permission-*` inputs, e.g. `permission-contents: read`, granting only what the job needs",
			severity:    Medium,
		})
	}

	return issues
}

// hasPermissionNarrowing reports whether any permission-scoping input is set.
func hasPermissionNarrowing(with map[string]interface{}) bool {
	for key := range with {
		if strings.HasPrefix(strings.ToLower(key), "permission") {
			return true
		}
	}
	return false
}

// isTruthyInput interprets a workflow input as a boolean. Values driven by an
// expression are treated as deliberate and are not flagged.
func isTruthyInput(value string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	if strings.Contains(trimmed, "${{") {
		return false
	}
	return trimmed == "true" || trimmed == "yes" || trimmed == "1"
}
