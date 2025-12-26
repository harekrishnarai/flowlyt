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
	"fmt"
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

const sharedPromptTemplate = `Flowlyt Security Review

Context
- Trigger: %s | Runner: %s | File scope: %s
- Rule: %s (%s) | Severity: %s | Category: %s
- Location: file=%s | job=%s | step=%s
- Evidence (trimmed): %s

Task
Reply only with JSON exactly as:
{"is_likely_false_positive":bool,"confidence":0-1,"reasoning":"...", "suggested_severity":"CRITICAL|HIGH|MEDIUM|LOW|INFO"}

Security lenses
1) Actions hardening (pinning, permissions, secrets, triggers)
2) Supply-chain exposure (dependency confusion, third-party trust, artifact integrity)
3) Runner attack surface (self-hosted isolation, persistence, credential theft or privilege escalation)
4) Pipeline context (legitimate CI/CD usage? severity still appropriate? '/tmp' paths refer to Flowlyt's temporary working directory)

Severity cues
CRITICAL=code execution/credential exposure; HIGH=privilege escalation or supply-chain compromise; MEDIUM=misconfiguration that aids attackers; LOW=minor hygiene gap; INFO=best-practice reminder. When uncertain, err on caution.`

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
	return e[:max] + " …[truncated]"
}
