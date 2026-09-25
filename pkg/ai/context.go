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
	"sort"
	"strings"

	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
	"github.com/harekrishnarai/flowlyt/v2/pkg/rules"
)

// FindingContext is the workflow evidence a model needs in order to judge a
// finding.
//
// Without it a model is asked, for example, whether an action runs "in a
// privileged job" while being told nothing about the job's permissions. It can
// only guess, and a guessing model that is also asked for a confidence score
// produces confident fabrication. Every field here exists because one of the
// prompts depends on it.
type FindingContext struct {
	// Snippet is the workflow source around the finding, with line numbers.
	Snippet string
	// WorkflowTriggers lists the events that can start this workflow, which
	// determines whether an untrusted actor can reach the finding at all.
	WorkflowTriggers []string
	// WorkflowPermissions and JobPermissions describe the credentials in scope.
	// "not set" and "default" are meaningfully different, so both are rendered
	// explicitly rather than left empty.
	WorkflowPermissions string
	JobPermissions      string
	// JobNeeds records upstream jobs, since data can arrive through them.
	JobNeeds []string
	// JobRunsOn distinguishes hosted from self-hosted runners.
	JobRunsOn string
	// StepUses and StepRun are the full step definition, not the truncated
	// evidence fragment.
	StepUses string
	StepRun  string
}

// ContextProvider resolves findings back to the workflow they came from.
type ContextProvider struct {
	byPath map[string]*parser.WorkflowFile
}

// NewContextProvider indexes the scanned workflows for lookup by path.
func NewContextProvider(files []parser.WorkflowFile) *ContextProvider {
	p := &ContextProvider{byPath: make(map[string]*parser.WorkflowFile, len(files))}
	for i := range files {
		p.byPath[files[i].Path] = &files[i]
		// Findings are reported with repository-relative paths while the
		// scanned file may be absolute, so index the base name as a fallback.
		if base := baseName(files[i].Path); base != files[i].Path {
			if _, exists := p.byPath[base]; !exists {
				p.byPath[base] = &files[i]
			}
		}
	}
	return p
}

// snippetRadius is the number of source lines included either side of a
// finding. Wide enough to show a step in full and its immediate neighbors,
// narrow enough to keep many findings within one request.
const snippetRadius = 12

// maxSnippetBytes caps a snippet so that one enormous step cannot crowd out the
// rest of a batch.
const maxSnippetBytes = 2500

// For returns the context for a finding. A finding whose workflow cannot be
// resolved yields a zero context rather than an error: the analysis should
// still run, just with less evidence.
func (p *ContextProvider) For(f rules.Finding) FindingContext {
	if p == nil {
		return FindingContext{}
	}

	wf, ok := p.byPath[f.FilePath]
	if !ok {
		wf, ok = p.byPath[baseName(f.FilePath)]
	}
	if !ok {
		return FindingContext{}
	}

	ctx := FindingContext{
		Snippet:             snippetAround(string(wf.Content), f.LineNumber),
		WorkflowTriggers:    triggerNames(wf.Workflow.On),
		WorkflowPermissions: renderPermissions(wf.Workflow.Permissions),
	}

	job, found := wf.Workflow.Jobs[f.JobName]
	if !found {
		return ctx
	}

	ctx.JobPermissions = renderPermissions(job.Permissions)
	ctx.JobNeeds = stringList(job.Needs)
	ctx.JobRunsOn = renderScalar(job.RunsOn)

	if step, ok := findStep(job, f.StepName); ok {
		ctx.StepUses = step.Uses
		ctx.StepRun = step.Run
	}

	return ctx
}

// findStep locates a step by its reported name, tolerating the synthetic
// "Step N" names used when a step has no name of its own.
func findStep(job parser.Job, stepName string) (parser.Step, bool) {
	if stepName == "" {
		return parser.Step{}, false
	}

	for _, s := range job.Steps {
		if s.Name == stepName {
			return s, true
		}
	}

	// Synthetic name produced by the rules when a step is unnamed.
	var idx int
	if _, err := fmt.Sscanf(stepName, "Step %d", &idx); err == nil && idx >= 1 && idx <= len(job.Steps) {
		return job.Steps[idx-1], true
	}

	return parser.Step{}, false
}

// snippetAround renders the source around a line with line numbers, so the
// model can refer to concrete locations rather than guessing at structure.
func snippetAround(content string, line int) string {
	if content == "" || line <= 0 {
		return ""
	}

	lines := strings.Split(content, "\n")
	if line > len(lines) {
		return ""
	}

	start := line - snippetRadius
	if start < 1 {
		start = 1
	}
	end := line + snippetRadius
	if end > len(lines) {
		end = len(lines)
	}

	var b strings.Builder
	for n := start; n <= end; n++ {
		marker := "  "
		if n == line {
			marker = "> " // the line the finding points at
		}
		fmt.Fprintf(&b, "%s%4d | %s\n", marker, n, lines[n-1])
		if b.Len() > maxSnippetBytes {
			b.WriteString("  ... [truncated]\n")
			break
		}
	}

	return b.String()
}

// renderPermissions turns the polymorphic permissions field into a compact,
// unambiguous description.
//
// The distinction between "absent" and "explicitly empty" is security-relevant:
// an absent block inherits potentially broad repository defaults, while
// `permissions: {}` grants nothing. Collapsing both to an empty string would
// hide that.
func renderPermissions(perms interface{}) string {
	switch v := perms.(type) {
	case nil:
		return "not set (inherits repository default, which may be write)"
	case string:
		if strings.TrimSpace(v) == "" {
			return "not set (inherits repository default, which may be write)"
		}
		return v
	case map[string]interface{}:
		return renderPermissionMap(toStringMap(v))
	case map[interface{}]interface{}:
		return renderPermissionMap(toStringMap(v))
	}
	return fmt.Sprintf("%v", perms)
}

func renderPermissionMap(m map[string]string) string {
	if len(m) == 0 {
		return "{} (no permissions granted)"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+": "+m[k])
	}
	return strings.Join(parts, ", ")
}

// toStringMap normalises either YAML mapping representation.
func toStringMap(v interface{}) map[string]string {
	out := map[string]string{}
	switch m := v.(type) {
	case map[string]interface{}:
		for k, val := range m {
			out[k] = fmt.Sprintf("%v", val)
		}
	case map[interface{}]interface{}:
		for k, val := range m {
			if ks, ok := k.(string); ok {
				out[ks] = fmt.Sprintf("%v", val)
			}
		}
	}
	return out
}

// triggerNames flattens the polymorphic `on:` field into trigger names.
func triggerNames(on interface{}) []string {
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
		for k := range v {
			names = append(names, k)
		}
	case map[interface{}]interface{}:
		for k := range v {
			if s, ok := k.(string); ok {
				names = append(names, s)
			}
		}
	}
	sort.Strings(names)
	return names
}

// stringList normalises a scalar-or-list YAML field.
func stringList(v interface{}) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []interface{}:
		var out []string
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// renderScalar renders a scalar-or-list field as a readable string.
func renderScalar(v interface{}) string {
	if list := stringList(v); len(list) > 0 {
		return strings.Join(list, ", ")
	}
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

// baseName returns the final path element, without importing path/filepath
// semantics that differ per platform for the forward-slash paths used here.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		return p[i+1:]
	}
	return p
}
