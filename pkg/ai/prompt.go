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

	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

// categoryToClass maps a Finding.Category to one of the 4 specialist prompt
// classes, or "generic" for everything else.
func categoryToClass(cat rules.Category) string {
	switch cat {
	case rules.PrivilegeEscalation, rules.AccessControl:
		return "escalation"
	case rules.InjectionAttack:
		return "injection"
	case rules.SecretExposure, rules.SecretsExposure:
		return "secrets_context"
	case rules.SupplyChain:
		return "supply_chain_trust"
	default:
		return "generic"
	}
}

// composeBatchPrompt returns (systemPrompt, userPrompt) for a batch of findings
// of the same class. The user prompt encodes findings as a JSON array with an
// echoed index field so responses can be attributed correctly even if the model
// omits entries.
func composeBatchPrompt(class string, findings []rules.Finding) (string, string) {
	system := systemPromptForClass(class)

	type batchItem struct {
		Index       int    `json:"index"`
		RuleID      string `json:"rule_id"`
		RuleName    string `json:"rule_name"`
		Severity    string `json:"severity"`
		Trigger     string `json:"trigger,omitempty"`
		Runner      string `json:"runner,omitempty"`
		Job         string `json:"job,omitempty"`
		Step        string `json:"step,omitempty"`
		FileContext string `json:"file_context,omitempty"`
		Evidence    string `json:"evidence"`
	}

	items := make([]batchItem, len(findings))
	for i, f := range findings {
		items[i] = batchItem{
			Index:       i,
			RuleID:      f.RuleID,
			RuleName:    f.RuleName,
			Severity:    string(f.Severity),
			Trigger:     safePromptValue(f.Trigger, ""),
			Runner:      safePromptValue(f.RunnerType, ""),
			Job:         safePromptValue(f.JobName, ""),
			Step:        safePromptValue(f.StepName, ""),
			FileContext: safePromptValue(f.FileContext, ""),
			Evidence:    trimEvidence(safePromptValue(strings.TrimSpace(f.Evidence), "not provided")),
		}
	}

	raw, _ := json.MarshalIndent(items, "", "  ")
	user := fmt.Sprintf(
		"Analyse each finding below. Reply ONLY with a JSON array, one object per finding, echoing the index.\n\n"+
			"Required fields per object: index (int), is_likely_false_positive (bool), confidence (0.0-1.0), "+
			"reasoning (string, 1-2 sentences citing the specific evidence token), "+
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

Evaluate findings for escalation chains formed by the COMBINATION of: workflow trigger × job permissions × step actions. A finding is a TRUE POSITIVE when an unprivileged actor (e.g. PR contributor) can trigger a workflow that has write permissions AND executes attacker-controlled code (checkout of PR head, run with user-supplied env). A finding is a FALSE POSITIVE when the trigger is restricted (push to protected branch, workflow_dispatch with approval) OR the write permissions are never exercised by steps that touch attacker input.

Reply ONLY with a JSON array. Per item: index, is_likely_false_positive, confidence (0-1), reasoning (1-2 sentences, name the trigger+permission+step combination), suggested_severity, remediation (one concrete fix).`

const injectionSystemPrompt = `You are a CI/CD security expert specialising in expression injection.

Evaluate whether user-controlled data flows into a dangerous sink. Sources: github.event.pull_request.title, github.event.issue.body, github.head_ref, github.event.comment.body, and any other user-supplied event payload. Sinks: run: steps (shell injection), action inputs passed to run, env vars consumed in run. A finding is a TRUE POSITIVE when an untrusted source reaches a sink without sanitisation. A finding is a FALSE POSITIVE when the source is from a protected branch trigger or the value is used only in a non-execution context (e.g. as an artifact name with no shell evaluation).

Reply ONLY with a JSON array. Per item: index, is_likely_false_positive, confidence (0-1), reasoning (1-2 sentences, name the source and sink), suggested_severity, remediation (one concrete fix).`

const secretsContextSystemPrompt = `You are a CI/CD security expert specialising in secrets exposure.

Distinguish live credentials from placeholders, references, and test fixtures. A finding is a TRUE POSITIVE when the evidence contains a credential with real structure (high entropy, known token prefix such as ghp_, sk-, AKIA, or a format matching a specific service). A finding is a FALSE POSITIVE when the evidence is a ${{ secrets.X }} reference, an environment variable lookup, a clearly labelled example/placeholder ("your-api-key-here", "<TOKEN>"), a value in a test fixture directory, or a comment.

Reply ONLY with a JSON array. Per item: index, is_likely_false_positive, confidence (0-1), reasoning (1-2 sentences, cite the specific token or pattern), suggested_severity, remediation (one concrete fix).`

const supplyChainSystemPrompt = `You are a CI/CD security expert specialising in supply chain security.

Evaluate third-party action trust beyond simple SHA pinning (static analysis already handles that). Focus on: (1) Is this action used in a privileged job (write permissions, access to secrets)? (2) Is the action publisher well-known or suspicious? (3) Does an artifact produced in one step get consumed unsafely in a later step (e.g. downloaded binary executed without checksum)? A finding is a TRUE POSITIVE when an unverified third-party component has access to secrets or write permissions. A finding is a FALSE POSITIVE when the action is from a verified publisher (actions/, github/) or is isolated in a read-only context.

Reply ONLY with a JSON array. Per item: index, is_likely_false_positive, confidence (0-1), reasoning (1-2 sentences, name the action and the trust concern), suggested_severity, remediation (one concrete fix).`

// sharedPromptTemplate is kept for the single-finding fallback path (composeFindingPrompt).
const sharedPromptTemplate = `You are a CI/CD security reviewer. Analyse this finding in context.

Context: trigger=%s | runner=%s | file=%s
Rule: %s (%s) | severity=%s | category=%s
Location: file=%s job=%s step=%s
Evidence: %s

Reply ONLY with JSON: {"is_likely_false_positive":bool,"confidence":0-1,"reasoning":"1-2 sentences citing evidence","suggested_severity":"CRITICAL|HIGH|MEDIUM|LOW|INFO","remediation":"one concrete fix"}`

const genericSystemPrompt = `You are a CI/CD security reviewer. For each finding, assess whether it is a true positive or false positive, considering the workflow context. Reply ONLY with a JSON array. Per item: index, is_likely_false_positive, confidence (0-1), reasoning (1-2 sentences citing specific evidence), suggested_severity (CRITICAL|HIGH|MEDIUM|LOW|INFO), remediation (one concrete fix).`

func safePromptValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func trimEvidence(e string) string {
	const max = 600
	if len(e) <= max {
		return e
	}
	// Prefer keeping the start; indicate truncation
	return e[:max] + " \u2026[truncated]"
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
