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

// CheckMisfeatures is the public entry point for the MISFEATURE rule.
func CheckMisfeatures(workflow parser.WorkflowFile) []Finding {
	return checkMisfeatures(workflow)
}

// misfeature describes a platform feature that is permitted by GitHub Actions
// but is dangerous enough that its use should be deliberate and reviewed.
type misfeature struct {
	// key is the step input or workflow setting that enables the feature.
	key         string
	summary     string
	remediation string
	severity    Severity
}

// checkoutMisfeatures are inputs to actions/checkout that weaken the isolation
// of the checked-out source.
var checkoutMisfeatures = map[string]misfeature{
	"submodules": {
		key:         "submodules",
		summary:     "checkout fetches git submodules, which pull in code from repositories outside this one",
		remediation: "Only enable `submodules` when the build genuinely needs them, and ensure every submodule points at a trusted, pinned commit",
		severity:    Low,
	},
	"ssh-key": {
		key:         "ssh-key",
		summary:     "checkout is configured with a private SSH key, which is written to the runner's filesystem for the duration of the job",
		remediation: "Prefer a scoped token over a deploy key where possible, and confirm the key has read-only access to only the repositories required",
		severity:    Medium,
	},
}

// checkMisfeatures detects dangerous-but-legal GitHub Actions configurations.
//
// Each pattern here is permitted by the platform and has legitimate uses, so
// none is inherently a vulnerability. They are surfaced because each one
// meaningfully widens the blast radius of a compromise and is easy to enable
// without appreciating the consequences.
func checkMisfeatures(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)
	seen := make(map[string]bool)

	add := func(jobName, stepName string, mf misfeature, lineNumber int) {
		dedupKey := fmt.Sprintf("%s|%s|%d", jobName, mf.key, lineNumber)
		if seen[dedupKey] {
			return
		}
		seen[dedupKey] = true

		findings = append(findings, Finding{
			RuleID:      "MISFEATURE",
			RuleName:    "Dangerous Workflow Misfeature",
			Description: "Workflow enables a permitted but hazardous platform feature that widens the impact of a compromise",
			Severity:    mf.severity,
			Category:    Misconfiguration,
			FilePath:    workflow.Path,
			JobName:     jobName,
			StepName:    stepName,
			Evidence:    mf.summary,
			Remediation: mf.remediation,
			LineNumber:  lineNumber,
		})
	}

	for jobName, job := range workflow.Workflow.Jobs {
		// `secrets: inherit` on a reusable workflow call forwards every secret
		// the caller holds, rather than the specific ones the callee needs.
		if isSecretsInherit(job.Secrets) && job.Uses != "" {
			lineNumber := 0
			if result := lineMapper.FindLineNumber(linenum.FindPattern{Key: "secrets", Value: "inherit"}); result != nil {
				lineNumber = result.LineNumber
			}
			add(jobName, "", misfeature{
				key:         "secrets-inherit",
				summary:     fmt.Sprintf("job calls `%s` with `secrets: inherit`, forwarding every secret available to this workflow", job.Uses),
				remediation: "Replace `secrets: inherit` with an explicit `secrets:` mapping listing only the secrets the called workflow requires",
				severity:    Medium,
			}, lineNumber)
		}

		for stepIdx, step := range job.Steps {
			stepName := step.Name
			if stepName == "" {
				stepName = fmt.Sprintf("Step %d", stepIdx+1)
			}

			if !isCheckoutAction(step.Uses) {
				continue
			}

			for key, mf := range checkoutMisfeatures {
				raw, ok := step.With[key]
				if !ok || raw == nil {
					continue
				}
				value := fmt.Sprintf("%v", raw)
				// `submodules: false` is the default and is not a misfeature.
				if key == "submodules" && !isTruthyInput(value) && !strings.EqualFold(value, "recursive") {
					continue
				}
				if strings.TrimSpace(value) == "" {
					continue
				}

				lineNumber := 0
				if result := lineMapper.FindLineNumber(linenum.FindPattern{Key: key, Value: value}); result != nil {
					lineNumber = result.LineNumber
				}
				add(jobName, stepName, mf, lineNumber)
			}
		}
	}

	return findings
}

// isCheckoutAction reports whether a `uses:` clause invokes actions/checkout.
func isCheckoutAction(uses string) bool {
	name := uses
	if idx := strings.Index(name, "@"); idx != -1 {
		name = name[:idx]
	}
	return strings.EqualFold(strings.TrimSpace(name), "actions/checkout")
}

// isSecretsInherit reports whether a job forwards all secrets to a called
// reusable workflow.
func isSecretsInherit(secrets interface{}) bool {
	s, ok := secrets.(string)
	return ok && strings.EqualFold(strings.TrimSpace(s), "inherit")
}
