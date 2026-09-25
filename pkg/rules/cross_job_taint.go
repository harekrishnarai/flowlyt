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

	"github.com/harekrishnarai/flowlyt/v2/pkg/analysis/jobgraph"
	"github.com/harekrishnarai/flowlyt/v2/pkg/linenum"
	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
)

// CheckCrossJobTaint is the public entry point for the CROSS_JOB_TAINT rule.
func CheckCrossJobTaint(workflow parser.WorkflowFile) []Finding {
	return checkCrossJobTaint(workflow)
}

// checkCrossJobTaint detects attacker-controlled data that crosses a job
// boundary and is then executed.
//
// Every other rule in the engine examines a single step or a single job. That
// misses a real attack shape: one job captures attacker-controlled text into a
// job output, and a dependent job — often a more privileged one — consumes it
// and executes it. Neither job is dangerous in isolation, so a per-job analysis
// sees nothing. The vulnerability lives in the edge between them.
//
// Jobs form a DAG via `needs:`, and data flows only from a dependency to its
// dependents, so the analysis visits jobs in topological order and resolves
// each in a single pass.
func checkCrossJobTaint(workflow parser.WorkflowFile) []Finding {
	if len(workflow.Workflow.Jobs) < 2 {
		// A cross-job flow needs at least two jobs.
		return nil
	}

	graph := jobgraph.Build(workflow.Workflow)
	flows := jobgraph.NewAnalyzer(graph).Analyze()
	if len(flows) == 0 {
		return nil
	}

	lineMapper := linenum.NewLineMapper(workflow.Content)
	seen := make(map[string]bool)

	var findings []Finding
	for _, flow := range flows {
		// Point at the consuming expression, which is where the fix belongs.
		lineNumber := 0
		if res := lineMapper.FindLineNumber(linenum.FindPattern{Value: flow.SinkExpression}); res != nil {
			lineNumber = res.LineNumber
		}

		dedupKey := fmt.Sprintf("%s|%s|%d", flow.SinkJob, flow.SinkExpression, lineNumber)
		if seen[dedupKey] {
			continue
		}
		seen[dedupKey] = true

		findings = append(findings, Finding{
			RuleID:      "CROSS_JOB_TAINT",
			RuleName:    "Attacker-Controlled Data Crosses Job Boundary",
			Description: "Attacker-controlled data is written to a job output and executed by a dependent job, so neither job appears dangerous on its own",
			Severity:    Critical,
			Category:    InjectionAttack,
			FilePath:    workflow.Path,
			JobName:     flow.SinkJob,
			StepName:    flow.SinkStep,
			Evidence: fmt.Sprintf(
				"`%s` (from %s in job `%s`) reaches the %s of job `%s` via %s",
				flow.SinkExpression,
				flow.Origin.Expression,
				flow.Origin.JobID,
				flow.SinkKind,
				flow.SinkJob,
				strings.Join(flow.Path, " → "),
			),
			Remediation: fmt.Sprintf(
				"Do not carry untrusted input through job outputs into an execution context. "+
					"Pass `%s` via the consuming step's `env:` block and reference it as a quoted shell "+
					"variable, or sanitize it in job `%s` before writing the output.",
				flow.SinkExpression, flow.Origin.JobID,
			),
			LineNumber: lineNumber,
		})
	}

	return findings
}
