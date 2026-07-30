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
	"strings"

	"github.com/harekrishnarai/flowlyt/v2/pkg/linenum"
	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
)

// CheckConcurrencyLimits is the public entry point for the
// CONCURRENCY_LIMITS_MISSING rule.
func CheckConcurrencyLimits(workflow parser.WorkflowFile) []Finding {
	return checkConcurrencyLimits(workflow)
}

// rapidRetriggerTriggers are the events that can be fired repeatedly in quick
// succession by an external party (e.g. by pushing more commits to an open
// pull request). Only these make missing concurrency limits a practical
// resource-exhaustion vector, so the rule is scoped to them to avoid noise on
// schedule-only or manually dispatched workflows.
var rapidRetriggerTriggers = []string{
	"push",
	"pull_request",
	"pull_request_target",
}

// hasRapidRetriggerTrigger reports whether the workflow responds to at least one
// event that an external party can fire repeatedly in quick succession.
func hasRapidRetriggerTrigger(workflow parser.WorkflowFile) bool {
	for _, trigger := range extractTriggerNames(workflow.Workflow.On) {
		for _, candidate := range rapidRetriggerTriggers {
			if trigger == candidate {
				return true
			}
		}
	}
	return false
}

// extractTriggerNames normalises the polymorphic `on:` field into a flat list of
// trigger names. GitHub Actions permits `on: push`, `on: [push, pull_request]`
// and the mapping form, and YAML decoding may yield either
// map[string]interface{} or map[interface{}]interface{}.
func extractTriggerNames(on interface{}) []string {
	var names []string

	switch v := on.(type) {
	case string:
		names = append(names, v)
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				names = append(names, s)
			}
		}
	case map[string]interface{}:
		for key := range v {
			names = append(names, key)
		}
	case map[interface{}]interface{}:
		for key := range v {
			if s, ok := key.(string); ok {
				names = append(names, s)
			}
		}
	}

	return names
}

// concurrencyState describes how a `concurrency:` block is configured.
type concurrencyState int

const (
	// concurrencyAbsent means no concurrency block is declared at all.
	concurrencyAbsent concurrencyState = iota
	// concurrencyNoCancel means a group is declared but superseded runs are
	// not cancelled (either the shorthand string form, or an explicit
	// cancel-in-progress: false).
	concurrencyNoCancel
	// concurrencyCancels means superseded runs are cancelled, either
	// unconditionally or via an expression.
	concurrencyCancels
)

// classifyConcurrency inspects a `concurrency:` value and reports whether it
// cancels superseded runs.
//
// The shorthand string form (`concurrency: my-group`) is equivalent to
// cancel-in-progress: false, so it still queues redundant runs.
func classifyConcurrency(concurrency interface{}) concurrencyState {
	if concurrency == nil {
		return concurrencyAbsent
	}

	switch v := concurrency.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return concurrencyAbsent
		}
		// Shorthand form: a group with no cancellation.
		return concurrencyNoCancel

	case map[string]interface{}:
		return classifyCancelInProgress(v["cancel-in-progress"])

	case map[interface{}]interface{}:
		for key, value := range v {
			if s, ok := key.(string); ok && s == "cancel-in-progress" {
				return classifyCancelInProgress(value)
			}
		}
		return concurrencyNoCancel
	}

	return concurrencyAbsent
}

// classifyCancelInProgress interprets the cancel-in-progress value, which may be
// a bool or a `${{ }}` expression that is evaluated at runtime.
func classifyCancelInProgress(value interface{}) concurrencyState {
	switch v := value.(type) {
	case nil:
		// Key omitted; GitHub defaults to false.
		return concurrencyNoCancel
	case bool:
		if v {
			return concurrencyCancels
		}
		return concurrencyNoCancel
	case string:
		trimmed := strings.TrimSpace(v)
		switch strings.ToLower(trimmed) {
		case "true":
			return concurrencyCancels
		case "false":
			return concurrencyNoCancel
		}
		// An expression such as ${{ github.ref != 'refs/heads/main' }} is a
		// deliberate, context-sensitive choice — treat it as configured.
		if strings.Contains(trimmed, "${{") {
			return concurrencyCancels
		}
		return concurrencyNoCancel
	}

	return concurrencyNoCancel
}

// checkConcurrencyLimits detects workflows that permit redundant concurrent runs.
//
// By default GitHub Actions runs every trigger of a workflow to completion, even
// when a newer run fully supersedes an older one. On externally triggerable
// events this lets an attacker burn runner minutes (a real cost on billed or
// self-hosted runners) simply by pushing repeatedly, and it introduces race
// conditions for any logic that locates artifacts by workflow/job name rather
// than run ID.
//
// A finding is reported only when neither the workflow nor any of its jobs
// configures cancellation, since a job-level setting is a legitimate way to
// scope the limit more narrowly.
func checkConcurrencyLimits(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	if !hasRapidRetriggerTrigger(workflow) {
		return findings
	}

	workflowState := classifyConcurrency(workflow.Workflow.Concurrency)
	if workflowState == concurrencyCancels {
		return findings
	}

	// A job-level concurrency block that cancels is sufficient protection for
	// the expensive part of the workflow, so don't report in that case.
	for _, job := range workflow.Workflow.Jobs {
		if classifyConcurrency(job.Concurrency) == concurrencyCancels {
			return findings
		}
	}

	lineMapper := linenum.NewLineMapper(workflow.Content)

	var evidence, remediation string
	var severity Severity

	if workflowState == concurrencyAbsent {
		evidence = "Workflow declares no `concurrency:` block, so superseded runs continue to completion"
		remediation = "Add a workflow-level concurrency block, e.g.\n" +
			"concurrency:\n" +
			"  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}\n" +
			"  cancel-in-progress: true"
		severity = Low
	} else {
		evidence = "Workflow declares `concurrency:` without cancel-in-progress, so superseded runs queue instead of being cancelled"
		remediation = "Set `cancel-in-progress: true` on the existing concurrency block so that re-triggering the workflow cancels the in-flight run"
		severity = Low
	}

	lineNumber := 0
	if workflowState == concurrencyNoCancel {
		if result := lineMapper.FindLineNumber(linenum.FindPattern{Key: "concurrency"}); result != nil {
			lineNumber = result.LineNumber
		}
	}

	findings = append(findings, Finding{
		RuleID:      "CONCURRENCY_LIMITS_MISSING",
		RuleName:    "Missing Workflow Concurrency Limits",
		Description: "Workflow allows redundant concurrent runs, enabling runner resource exhaustion and artifact race conditions",
		Severity:    severity,
		Category:    Misconfiguration,
		FilePath:    workflow.Path,
		Evidence:    evidence,
		Remediation: remediation,
		LineNumber:  lineNumber,
	})

	return findings
}
