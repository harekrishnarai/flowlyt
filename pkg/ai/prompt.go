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

package ai

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/harekrishnarai/flowlyt/v2/pkg/rules"
)

// categoryToClass maps a Finding.Category to one of the 4 specialist prompt
// classes, or "generic" for everything else.
func categoryToClass(cat rules.Category) string {
	switch cat {
	case rules.PrivilegeEscalation, rules.AccessControl:
		return "escalation"
	case rules.InjectionAttack:
		return "injection"
	case rules.SecretExposure:
		return "secrets_context"
	case rules.SupplyChain:
		return "supply_chain_trust"
	default:
		return "generic"
	}
}

// ContextualFinding pairs a finding with the workflow evidence needed to judge
// it. Findings are never sent to a model without this.
type ContextualFinding struct {
	Finding rules.Finding
	Context FindingContext
}

// composeBatchPrompt returns (systemPrompt, userPrompt) for a batch of findings
// of the same class. The user prompt encodes findings as a JSON array with an
// echoed index field so responses can be attributed correctly even if the model
// omits entries.
func composeBatchPrompt(class string, findings []ContextualFinding) (string, string) {
	system := systemPromptForClass(class)

	type batchItem struct {
		Index    int    `json:"index"`
		RuleID   string `json:"rule_id"`
		RuleName string `json:"rule_name"`
		Severity string `json:"static_severity"`

		// Workflow-level facts that determine who can reach this code.
		Triggers            []string `json:"workflow_triggers,omitempty"`
		WorkflowPermissions string   `json:"workflow_permissions,omitempty"`

		// Job-level facts that determine what credentials are in scope.
		Job            string   `json:"job,omitempty"`
		JobPermissions string   `json:"job_permissions,omitempty"`
		JobNeeds       []string `json:"job_depends_on,omitempty"`
		Runner         string   `json:"runner,omitempty"`

		// The step itself, in full rather than as a truncated fragment.
		Step     string `json:"step,omitempty"`
		StepUses string `json:"step_uses,omitempty"`
		StepRun  string `json:"step_run,omitempty"`

		FileContext string `json:"file_context,omitempty"`
		Evidence    string `json:"matched_evidence"`
		Snippet     string `json:"workflow_snippet,omitempty"`
	}

	items := make([]batchItem, len(findings))
	for i, cf := range findings {
		f, c := cf.Finding, cf.Context
		items[i] = batchItem{
			Index:               i,
			RuleID:              f.RuleID,
			RuleName:            f.RuleName,
			Severity:            string(f.Severity),
			Triggers:            c.WorkflowTriggers,
			WorkflowPermissions: c.WorkflowPermissions,
			Job:                 safePromptValue(f.JobName, ""),
			JobPermissions:      c.JobPermissions,
			JobNeeds:            c.JobNeeds,
			Runner:              safePromptValue(c.JobRunsOn, safePromptValue(f.RunnerType, "")),
			Step:                safePromptValue(f.StepName, ""),
			StepUses:            c.StepUses,
			StepRun:             trimEvidence(c.StepRun),
			FileContext:         safePromptValue(f.FileContext, ""),
			Evidence:            trimEvidence(safePromptValue(strings.TrimSpace(f.Evidence), "not provided")),
			Snippet:             c.Snippet,
		}
	}

	raw, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		raw = []byte("[]")
	}
	user := fmt.Sprintf(
		"Analyze each finding below. Each includes the workflow triggers, the workflow- and job-level "+
			"permissions, the full step definition, and a numbered source snippet centered on the "+
			"reported line (marked with `>`).\n\n"+
			"Base your judgement only on the evidence provided. If the evidence is insufficient to "+
			"decide, say so in the reasoning and return a confidence at or below 0.5.\n\n"+
			"Reply ONLY with a JSON array, one object per finding, echoing the index.\n\n"+
			"Required fields per object: index (int), is_likely_false_positive (bool), confidence (0.0-1.0), "+
			"reasoning (string, 1-2 sentences citing a specific token, permission, or line number from the evidence), "+
			"suggested_severity (CRITICAL|HIGH|MEDIUM|LOW|INFO), remediation (string, one concrete fix).\n\n"+
			"Findings:\n%s", string(raw))

	return system, user
}

// composeFindingPrompt is retained for the single-finding fallback path.
func composeFindingPrompt(f rules.Finding) string {
	return fmt.Sprintf(sharedPromptTemplate,
		safePromptValue(f.Trigger, "unknown"),
		safePromptValue(f.RunnerType, "unknown"),
		safePromptValue(f.FileContext, "unknown"),
		safePromptValue(f.RuleName, f.RuleID),
		safePromptValue(f.RuleID, "N/A"),
		f.Severity,
		f.Category,
		safePromptValue(f.FilePath, "N/A"),
		safePromptValue(f.JobName, "N/A"),
		safePromptValue(f.StepName, "N/A"),
		trimEvidence(safePromptValue(strings.TrimSpace(f.Evidence), "not provided")),
	)
}

func systemPromptForClass(class string) string {
	switch class {
	case "escalation":
		return escalationSystemPrompt
	case "injection":
		return injectionSystemPrompt
	case "secrets_context":
		return secretsContextSystemPrompt
	case "supply_chain_trust":
		return supplyChainSystemPrompt
	default:
		return genericSystemPrompt
	}
}

const escalationSystemPrompt = `You are a CI/CD security expert specialising in privilege escalation.

You are given, for each finding: the workflow triggers, the workflow- and job-level permissions, the job's dependencies and runner, the full step definition, and a numbered source snippet.

Evaluate the escalation chain formed by the COMBINATION of trigger × permissions × step. A finding is a TRUE POSITIVE when an unprivileged actor (e.g. a fork PR contributor) can reach a job that holds write permissions AND executes attacker-controlled code. A finding is a FALSE POSITIVE when the triggers cannot be fired by an untrusted actor, or when the permissions in scope are read-only or empty.

Note that 'not set' permissions inherit the repository default, which may be write; treat that as unknown-but-possibly-privileged rather than as safe.

Reply ONLY with a JSON array. Per item: index, is_likely_false_positive, confidence (0-1), reasoning (1-2 sentences, name the trigger+permission+step combination), suggested_severity, remediation (one concrete fix).`

const injectionSystemPrompt = `You are a CI/CD security expert specialising in expression injection.

You are given, for each finding: the workflow triggers, the full 'run' script and 'uses' clause of the step, and a numbered source snippet.

Evaluate whether user-controlled data reaches a dangerous sink. Sources: github.event.pull_request.title, github.event.issue.body, github.head_ref, github.event.comment.body, and any other user-supplied event payload. Sinks: interpolation into a 'run' script, action inputs that are later executed, env vars consumed by a script. A finding is a TRUE POSITIVE when an untrusted source reaches a sink without sanitisation. A finding is a FALSE POSITIVE when the expression is not attacker-controlled (github.sha, github.repository, matrix values), when it is passed via 'env:' and referenced as a shell variable, or when the triggers cannot be fired by an untrusted actor.

Reply ONLY with a JSON array. Per item: index, is_likely_false_positive, confidence (0-1), reasoning (1-2 sentences, name the source and sink), suggested_severity, remediation (one concrete fix).`

const secretsContextSystemPrompt = `You are a CI/CD security expert specialising in secrets exposure.

You are given, for each finding: the matched evidence, the full step definition, the file context, and a numbered source snippet.

Distinguish live credentials from placeholders, references, and test fixtures. A finding is a TRUE POSITIVE when the evidence contains a credential with real structure (high entropy, or a known token prefix such as ghp_, sk-, AKIA). A finding is a FALSE POSITIVE when the evidence is a ${{ secrets.X }} reference, an environment variable lookup, a clearly labeled placeholder ("your-api-key-here", "<TOKEN>"), a value in a test or example file, or a commented-out line in the snippet.

Reply ONLY with a JSON array. Per item: index, is_likely_false_positive, confidence (0-1), reasoning (1-2 sentences, cite the specific token or pattern), suggested_severity, remediation (one concrete fix).`

const supplyChainSystemPrompt = `You are a CI/CD security expert specialising in supply chain security.

You are given, for each finding: the job-level permissions, the workflow triggers, the step's 'uses' clause and 'run' script, and a numbered source snippet.

Evaluate third-party action trust beyond SHA pinning, which static analysis already covers. Focus on: (1) Do the job permissions shown grant write access or secret exposure to this action? (2) Is the publisher well-known or suspicious? (3) Does the snippet show a downloaded artifact or binary being executed without verification? A finding is a TRUE POSITIVE when an unverified third-party component runs with write permissions or secret access. A finding is a FALSE POSITIVE when the action is from a verified publisher (actions/, github/) or the job permissions shown are read-only or empty.

Reply ONLY with a JSON array. Per item: index, is_likely_false_positive, confidence (0-1), reasoning (1-2 sentences, name the action and the trust concern), suggested_severity, remediation (one concrete fix).`

// sharedPromptTemplate is kept for the single-finding fallback path (composeFindingPrompt).
const sharedPromptTemplate = `You are a CI/CD security reviewer. Analyze this finding in context.

Context: trigger=%s | runner=%s | file=%s
Rule: %s (%s) | severity=%s | category=%s
Location: file=%s job=%s step=%s
Evidence: %s

Reply ONLY with JSON: {"is_likely_false_positive":bool,"confidence":0-1,"reasoning":"1-2 sentences citing evidence","suggested_severity":"CRITICAL|HIGH|MEDIUM|LOW|INFO","remediation":"one concrete fix"}`

const genericSystemPrompt = `You are a CI/CD security reviewer. Each finding includes the workflow triggers, the workflow- and job-level permissions, the full step definition, and a numbered source snippet. Assess whether it is a true positive or a false positive using only that evidence; if it is insufficient, say so and return a confidence at or below 0.5. Reply ONLY with a JSON array. Per item: index, is_likely_false_positive, confidence (0-1), reasoning (1-2 sentences citing specific evidence), suggested_severity (CRITICAL|HIGH|MEDIUM|LOW|INFO), remediation (one concrete fix).`

func safePromptValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func trimEvidence(e string) string {
	const maxEvidenceLen = 600
	if len(e) <= maxEvidenceLen {
		return e
	}
	// Prefer keeping the start; indicate truncation
	return e[:maxEvidenceLen] + " \u2026[truncated]"
}

// parseBatchResponse parses a JSON array of BatchVerificationResult from the
// model's text response. It fills in an Error for any missing index.
// Shared by all providers — defined here so only one copy exists in the package.
func parseBatchResponse(content string, count int) ([]BatchVerificationResult, error) {
	// Extract JSON array from response (model may wrap in markdown)
	start := strings.Index(content, "[")
	end := strings.LastIndex(content, "]")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON array in batch response")
	}
	raw := content[start : end+1]

	type wireResult struct {
		Index                 int     `json:"index"`
		IsLikelyFalsePositive bool    `json:"is_likely_false_positive"`
		Confidence            float64 `json:"confidence"`
		Reasoning             string  `json:"reasoning"`
		SuggestedSeverity     string  `json:"suggested_severity"`
		Remediation           string  `json:"remediation"`
		Error                 string  `json:"error,omitempty"`
	}

	var wire []wireResult
	if err := json.Unmarshal([]byte(raw), &wire); err != nil {
		return nil, fmt.Errorf("failed to parse batch JSON: %w", err)
	}

	byIndex := make(map[int]*VerificationResult, len(wire))
	for _, w := range wire {
		if w.Error != "" {
			continue
		}
		conf := w.Confidence
		if conf < 0 {
			conf = 0
		}
		if conf > 1 {
			conf = 1
		}
		byIndex[w.Index] = &VerificationResult{
			IsLikelyFalsePositive: w.IsLikelyFalsePositive,
			Confidence:            conf,
			Reasoning:             w.Reasoning,
			Severity:              w.SuggestedSeverity,
			Remediation:           w.Remediation,
		}
	}

	out := make([]BatchVerificationResult, count)
	for i := range out {
		out[i].Index = i
		if r, ok := byIndex[i]; ok {
			out[i].Result = r
		} else {
			out[i].Error = "missing from batch response"
		}
	}
	return out, nil
}
