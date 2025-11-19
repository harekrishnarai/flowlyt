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
