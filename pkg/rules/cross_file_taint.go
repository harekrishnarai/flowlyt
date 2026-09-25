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
	"sort"

	"github.com/harekrishnarai/flowlyt/v2/pkg/analysis/jobgraph"
	"github.com/harekrishnarai/flowlyt/v2/pkg/analysis/resolve"
	"github.com/harekrishnarai/flowlyt/v2/pkg/linenum"
	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
)

// CheckCrossFileTaint is the public entry point for the CROSS_FILE_TAINT rule.
func CheckCrossFileTaint(workflow parser.WorkflowFile) []Finding {
	return checkCrossFileTaint(workflow)
}

// checkCrossFileTaint detects attacker-controlled data passed into a local
// composite action or reusable workflow that executes it.
//
// Analysis that stops at the file boundary cannot see this: the calling
// workflow looks clean because it only passes a parameter, and the callee looks
// clean because it only uses its own declared input. The vulnerability is the
// composition of the two.
//
// Only repository-local targets are followed. Resolving a remote action would
// require fetching another repository, which is a network operation with its
// own trust questions; the supply chain rules cover those instead.
func checkCrossFileTaint(workflow parser.WorkflowFile) []Finding {
	root := resolve.RepoRootFor(workflow.Path)
	if root == "" {
		// The workflow is not laid out as <root>/.github/workflows/<file>, so
		// there is no repository tree to resolve against.
		return nil
	}

	repo := resolve.NewRepo(root)
	lineMapper := linenum.NewLineMapper(workflow.Content)
	seen := make(map[string]bool)

	var findings []Finding

	add := func(callerJob, callerStep, uses string, taintedInput, taintExpr string, def *resolve.Definition, use resolve.InputUse) {
		lineNumber := 0
		if res := lineMapper.FindLineNumber(linenum.FindPattern{Key: taintedInput, Value: taintExpr}); res != nil {
			lineNumber = res.LineNumber
		} else if res := lineMapper.FindLineNumber(linenum.FindPattern{Key: "uses", Value: uses}); res != nil {
			lineNumber = res.LineNumber
		}

		kind := "composite action"
		if def.Kind == resolve.KindReusableWorkflow {
			kind = "reusable workflow"
		}

		dedupKey := fmt.Sprintf("%s|%s|%s|%d", callerJob, uses, taintedInput, lineNumber)
		if seen[dedupKey] {
			return
		}
		seen[dedupKey] = true

		findings = append(findings, Finding{
			RuleID:      "CROSS_FILE_TAINT",
			RuleName:    "Untrusted Input Executed by Local Action",
			Description: "Attacker-controlled data is passed into a local composite action or reusable workflow that executes it, so neither file appears dangerous on its own",
			Severity:    Critical,
			Category:    InjectionAttack,
			FilePath:    workflow.Path,
			JobName:     callerJob,
			StepName:    callerStep,
			Evidence: fmt.Sprintf(
				"input `%s` receives untrusted `%s` and is executed by the %s %s (%s:%d, %s)",
				taintedInput, taintExpr, kind, def.RelPath, def.RelPath, use.Line, use.SinkKind,
			),
			Remediation: fmt.Sprintf(
				"Either sanitize the value before passing it, or change %s so that input `%s` is "+
					"consumed through an `env:` variable and referenced as a quoted shell variable "+
					"rather than interpolated into the script.",
				def.RelPath, taintedInput,
			),
			LineNumber: lineNumber,
		})
	}

	// Reusable workflow calls appear at job level; composite actions at step level.
	for _, jobName := range sortedKeys(workflow.Workflow.Jobs) {
		job := workflow.Workflow.Jobs[jobName]

		if job.Uses != "" {
			if def, ok := repo.ResolveUses(job.Uses); ok {
				executed := indexExecutedInputs(def)
				for _, inputName := range sortedKeys(job.With) {
					value, isStr := job.With[inputName].(string)
					if !isStr || !jobgraph.HasUntrustedExpression(value) {
						continue
					}
					if use, hit := executed[inputName]; hit {
						add(jobName, "", job.Uses, inputName, value, def, use)
					}
				}
			}
		}

		for stepIdx, step := range job.Steps {
			if step.Uses == "" || !resolve.IsLocal(step.Uses) {
				continue
			}
			def, ok := repo.ResolveUses(step.Uses)
			if !ok {
				continue
			}

			stepName := step.Name
			if stepName == "" {
				stepName = fmt.Sprintf("Step %d", stepIdx+1)
			}

			executed := indexExecutedInputs(def)
			for _, inputName := range sortedKeys(step.With) {
				value, isStr := step.With[inputName].(string)
				if !isStr || !jobgraph.HasUntrustedExpression(value) {
					continue
				}
				if use, hit := executed[inputName]; hit {
					add(jobName, stepName, step.Uses, inputName, value, def, use)
				}
			}
		}
	}

	return findings
}

// indexExecutedInputs maps each executed input name to its first use, so the
// caller side can be checked in constant time per input.
func indexExecutedInputs(def *resolve.Definition) map[string]resolve.InputUse {
	out := map[string]resolve.InputUse{}
	for _, use := range def.ExecutedInputs() {
		if _, exists := out[use.Input]; !exists {
			out[use.Input] = use
		}
	}
	return out
}

// sortedKeys returns map keys in a deterministic order.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
