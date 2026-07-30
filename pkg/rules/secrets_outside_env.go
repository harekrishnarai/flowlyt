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

	"github.com/harekrishnarai/flowlyt/v2/pkg/linenum"
	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
)

// CheckSecretsOutsideEnv is the public entry point for the SECRETS_OUTSIDE_ENV
// rule.
func CheckSecretsOutsideEnv(workflow parser.WorkflowFile) []Finding {
	return checkSecretsOutsideEnv(workflow)
}

// secretExpressionPattern matches a secrets context reference, capturing the
// secret name.
var secretExpressionPattern = regexp.MustCompile(`\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}`)

// checkSecretsOutsideEnv detects secrets interpolated directly into a `run:`
// script instead of being passed through the step's `env:` block.
//
// A `${{ secrets.X }}` expression inside `run:` is substituted into the script
// text *before* the shell ever sees it. Two consequences follow:
//
//   - The secret's literal value becomes part of the command line, where it can
//     surface in process listings, shell traces (`set -x`), and error messages
//     that echo the failing command. GitHub's log redaction does not reliably
//     cover values mangled by shell processing.
//   - If the secret contains shell metacharacters, the substituted text is
//     parsed as code, which can break the script or enable injection.
//
// Passing the secret via `env:` avoids both: the value is handed to the process
// through the environment and referenced as an ordinary shell variable, so it
// never appears in the script source.
func checkSecretsOutsideEnv(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)
	seen := make(map[string]bool)

	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			matches := secretExpressionPattern.FindAllStringSubmatch(step.Run, -1)
			if len(matches) == 0 {
				continue
			}

			stepName := step.Name
			if stepName == "" {
				stepName = fmt.Sprintf("Step %d", stepIdx+1)
			}

			// GITHUB_TOKEN is the one secret routinely passed inline to `gh`,
			// which reads it from the command environment; flagging it would
			// bury the genuine findings.
			for _, match := range matches {
				secretName := match[1]
				if strings.EqualFold(secretName, "GITHUB_TOKEN") {
					continue
				}

				lineNumber := 0
				if result := lineMapper.FindLineNumber(linenum.FindPattern{
					Key:   "run",
					Value: firstNonEmptyLine(step.Run),
				}); result != nil {
					lineNumber = result.LineNumber
				}

				dedupKey := fmt.Sprintf("%s|%s|%d", jobName, secretName, lineNumber)
				if seen[dedupKey] {
					continue
				}
				seen[dedupKey] = true

				findings = append(findings, Finding{
					RuleID:      "SECRETS_OUTSIDE_ENV",
					RuleName:    "Secret Interpolated Outside env Block",
					Description: "Secret is substituted directly into a run script instead of being passed through env, exposing it to the command line",
					Severity:    Medium,
					Category:    SecretExposure,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    stepName,
					Evidence:    fmt.Sprintf("`${{ secrets.%s }}` is interpolated directly into the run script", secretName),
					Remediation: fmt.Sprintf("Pass the secret via the step's env block and reference it as a shell variable:\nenv:\n  %s: ${{ secrets.%s }}\nthen use \"$%s\" in the script", secretName, secretName, secretName),
					LineNumber:  lineNumber,
				})
			}
		}
	}

	return findings
}
