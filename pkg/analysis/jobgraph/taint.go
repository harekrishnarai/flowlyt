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

package jobgraph

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
)

// Taint tracks attacker-controlled data as it moves between jobs.
//
// The unit of tracking is a named slot that can hold a value across a step or
// job boundary:
//
//	step:<job>.<stepID>.<output>   a step output, written via $GITHUB_OUTPUT
//	job:<job>.<output>             a job output, readable as needs.<job>.outputs.<name>
//
// A slot becomes tainted when an untrusted expression reaches it, and taint
// propagates forward along the DAG. Because data only ever flows from a
// dependency to its dependents, visiting jobs in topological order means every
// slot a job reads has already been decided, so one pass is sufficient.

// Origin records where a tainted value entered the workflow.
type Origin struct {
	// JobID and StepName locate the step that introduced the taint.
	JobID    string
	StepName string
	// Expression is the untrusted expression, e.g. github.event.issue.title.
	Expression string
}

// Slot identifies a value that can carry taint between steps or jobs.
type Slot struct {
	Kind   string // "step" or "job"
	JobID  string
	Name   string // step output name, or job output name
	StepID string // set for Kind == "step"
}

func (s Slot) String() string {
	if s.Kind == "step" {
		return fmt.Sprintf("step:%s.%s.%s", s.JobID, s.StepID, s.Name)
	}
	return fmt.Sprintf("job:%s.%s", s.JobID, s.Name)
}

// Flow is one confirmed path from an untrusted source to a dangerous sink that
// crosses a job boundary.
type Flow struct {
	// Origin is where the data became untrusted.
	Origin Origin
	// Carrier is the job output that transported it across the boundary.
	Carrier Slot
	// SinkJob and SinkStep are where it was consumed.
	SinkJob  string
	SinkStep string
	// SinkKind describes how it was consumed, e.g. "run script".
	SinkKind string
	// SinkExpression is the reference that consumed it, e.g.
	// needs.build.outputs.version.
	SinkExpression string
	// Path is the job chain from origin to sink, for explaining the finding.
	Path []string
}

// untrustedContextPattern matches expressions an external actor can influence.
//
// This is deliberately a allowlist of known-attacker-controlled contexts rather
// than "anything under github.event": fields such as github.event.repository.name
// are not attacker-controlled, and treating them as tainted would bury the real
// findings.
var untrustedContextPattern = regexp.MustCompile(`(?i)github\.(?:` +
	`event\.(?:issue|pull_request|comment|discussion|review|head_commit|commits|inputs)\b[\w.\[\]'"-]*` +
	`|head_ref` +
	`|event\.workflow_run\.(?:head_branch|head_commit|display_title)` +
	`)`)

// expressionPattern matches a GitHub Actions expression.
var expressionPattern = regexp.MustCompile(`\$\{\{([^}]*)\}\}`)

// needsOutputPattern matches a reference to an upstream job's output.
var needsOutputPattern = regexp.MustCompile(`needs\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)`)

// stepOutputPattern matches a reference to an earlier step's output.
var stepOutputPattern = regexp.MustCompile(`steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)`)

// githubOutputWritePattern matches a shell line appending to $GITHUB_OUTPUT,
// capturing the output name being written.
var githubOutputWritePattern = regexp.MustCompile(`([A-Za-z0-9_-]+)\s*=.*>>\s*"?\$\{?GITHUB_OUTPUT`)

// Analyzer performs cross-job taint propagation over a job graph.
type Analyzer struct {
	graph *Graph
	// tainted maps a slot key to the origin that tainted it.
	tainted map[string]Origin
}

// NewAnalyzer prepares an analyzer for a workflow's job graph.
func NewAnalyzer(g *Graph) *Analyzer {
	return &Analyzer{graph: g, tainted: map[string]Origin{}}
}

// Analyze propagates taint across the graph and returns the flows that reach a
// dangerous sink in a different job from where they originated.
//
// Complexity is O(V + E + T), where T is the total size of the expressions and
// scripts in the workflow: each job is visited once, in topological order.
func (a *Analyzer) Analyze() []Flow {
	var flows []Flow

	for _, jobID := range a.graph.TopologicalOrder() {
		node := a.graph.Nodes[jobID]
		flows = append(flows, a.analyzeJob(node)...)
		a.recordJobOutputs(node)
	}

	// Jobs in a dependency cycle are skipped by the topological order. They
	// cannot run on GitHub either, so there is nothing to report for them.

	sort.SliceStable(flows, func(i, j int) bool {
		if flows[i].SinkJob != flows[j].SinkJob {
			return flows[i].SinkJob < flows[j].SinkJob
		}
		return flows[i].SinkExpression < flows[j].SinkExpression
	})
	return flows
}

// analyzeJob examines one job: it records taint introduced by its own steps,
// and reports where taint arriving from an upstream job reaches a sink.
func (a *Analyzer) analyzeJob(node *Node) []Flow {
	var flows []Flow

	for stepIdx, step := range node.Job.Steps {
		stepName := step.Name
		if stepName == "" {
			stepName = fmt.Sprintf("Step %d", stepIdx+1)
		}

		// Every text the step evaluates: the script, its action inputs, and its
		// environment.
		texts := stepTexts(step)

		// 1. Does this step consume taint that arrived from an upstream job?
		for _, text := range texts.sinkTexts {
			for _, ref := range needsOutputPattern.FindAllStringSubmatch(text.value, -1) {
				slot := Slot{Kind: "job", JobID: ref[1], Name: ref[2]}
				origin, ok := a.tainted[slot.String()]
				if !ok {
					continue
				}
				flows = append(flows, Flow{
					Origin:         origin,
					Carrier:        slot,
					SinkJob:        node.ID,
					SinkStep:       stepName,
					SinkKind:       text.kind,
					SinkExpression: ref[0],
					Path:           append(a.graph.Ancestors(node.ID), node.ID),
				})
			}
		}

		// 2. Does this step introduce taint into a step output?
		a.recordStepOutputs(node.ID, stepName, step, texts)
	}

	return flows
}

// recordStepOutputs marks step outputs written from untrusted data, so the
// taint can be picked up by the job's outputs block.
func (a *Analyzer) recordStepOutputs(jobID, stepName string, step parser.Step, texts stepText) {
	if step.ID == "" || step.Run == "" {
		return
	}

	for _, line := range strings.Split(step.Run, "\n") {
		m := githubOutputWritePattern.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		outputName := m[1]

		// The written value is tainted if the line interpolates an untrusted
		// expression, or if it reuses a value already known to be tainted.
		origin, tainted := a.taintOfText(jobID, stepName, line)
		if !tainted {
			continue
		}
		slot := Slot{Kind: "step", JobID: jobID, StepID: step.ID, Name: outputName}
		a.tainted[slot.String()] = origin
	}

	// A step that passes untrusted data through an action which sets outputs is
	// not modelled: without the action's own definition there is no way to know
	// which output carries the value. Resolving composite actions would close
	// this gap.
	_ = texts
}

// recordJobOutputs promotes tainted step outputs into job outputs, which is how
// data becomes visible to dependent jobs.
func (a *Analyzer) recordJobOutputs(node *Node) {
	for name, expr := range node.Job.Outputs {
		origin, tainted := a.taintOfText(node.ID, "outputs", expr)
		if !tainted {
			continue
		}
		slot := Slot{Kind: "job", JobID: node.ID, Name: name}
		a.tainted[slot.String()] = origin
	}
}

// taintOfText reports whether a text is tainted, either because it interpolates
// an untrusted context directly or because it references an already-tainted
// step or job output.
func (a *Analyzer) taintOfText(jobID, stepName, text string) (Origin, bool) {
	if m := untrustedContextPattern.FindString(text); m != "" {
		return Origin{JobID: jobID, StepName: stepName, Expression: m}, true
	}

	for _, ref := range stepOutputPattern.FindAllStringSubmatch(text, -1) {
		slot := Slot{Kind: "step", JobID: jobID, StepID: ref[1], Name: ref[2]}
		if origin, ok := a.tainted[slot.String()]; ok {
			return origin, true
		}
	}

	for _, ref := range needsOutputPattern.FindAllStringSubmatch(text, -1) {
		slot := Slot{Kind: "job", JobID: ref[1], Name: ref[2]}
		if origin, ok := a.tainted[slot.String()]; ok {
			return origin, true
		}
	}

	return Origin{}, false
}

// stepText groups the texts of a step by how the value would be used.
type stepText struct {
	sinkTexts []taggedText
}

type taggedText struct {
	kind  string
	value string
}

// stepTexts collects the parts of a step where an interpolated value would be
// evaluated.
//
// A value referenced in `env:` is only dangerous once the script uses it, and
// the script is scanned anyway, so env is not treated as a sink on its own —
// that is the documented safe way to pass untrusted data.
func stepTexts(step parser.Step) stepText {
	var st stepText

	if step.Run != "" {
		st.sinkTexts = append(st.sinkTexts, taggedText{kind: "run script", value: step.Run})
	}
	for name, raw := range step.With {
		if s, ok := raw.(string); ok && s != "" {
			st.sinkTexts = append(st.sinkTexts, taggedText{
				kind:  fmt.Sprintf("action input `%s`", name),
				value: s,
			})
		}
	}
	if step.If != "" {
		st.sinkTexts = append(st.sinkTexts, taggedText{kind: "condition", value: step.If})
	}

	sort.SliceStable(st.sinkTexts, func(i, j int) bool { return st.sinkTexts[i].kind < st.sinkTexts[j].kind })
	return st
}

// HasUntrustedExpression reports whether a text interpolates an
// attacker-controllable context. Exported for reuse by rules.
func HasUntrustedExpression(text string) bool {
	return untrustedContextPattern.MatchString(text)
}

// ExpressionsIn returns the inner text of every ${{ }} expression, for callers
// that need to inspect them individually.
func ExpressionsIn(text string) []string {
	var out []string
	for _, m := range expressionPattern.FindAllStringSubmatch(text, -1) {
		out = append(out, strings.TrimSpace(m[1]))
	}
	return out
}
