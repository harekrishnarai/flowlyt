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

package resolve

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
)

// InputUse records a place inside a resolved definition where a declared input
// reaches an execution sink.
type InputUse struct {
	// Input is the declared input name that is used.
	Input string
	// StepName identifies the step inside the definition.
	StepName string
	// SinkKind describes how the value is used, e.g. "run script".
	SinkKind string
	// Line is the line within the definition file, for reporting.
	Line int
	// Snippet is the offending line.
	Snippet string
}

// inputRefPattern matches a reference to a declared input from inside a
// definition. Composite actions and reusable workflows both expose them as
// `inputs.<name>`.
var inputRefPattern = regexp.MustCompile(`inputs\.([A-Za-z0-9_-]+)`)

// ExecutedInputs returns the declared inputs that reach an execution sink
// inside the definition.
//
// A definition that merely echoes an input into a file, or passes it to an
// action that does not execute it, is not reported: the point is to identify
// inputs whose value becomes code.
func (d *Definition) ExecutedInputs() []InputUse {
	var uses []InputUse

	switch d.Kind {
	case KindCompositeAction:
		uses = append(uses, executedInputsInSteps(d, d.Steps, "")...)
	case KindReusableWorkflow:
		// Job IDs are visited in a stable order so results do not depend on map
		// iteration order.
		for _, jobID := range sortedJobIDs(d.Jobs) {
			uses = append(uses, executedInputsInSteps(d, d.Jobs[jobID].Steps, jobID)...)
		}
	}

	return uses
}

// executedInputsInSteps scans a step list for inputs used in a sink.
func executedInputsInSteps(d *Definition, steps []parser.Step, jobID string) []InputUse {
	var uses []InputUse
	seen := map[string]bool{}

	for idx, step := range steps {
		stepName := step.Name
		if stepName == "" {
			stepName = fmt.Sprintf("Step %d", idx+1)
		}
		if jobID != "" {
			stepName = jobID + " / " + stepName
		}

		// A `run:` script is the primary execution sink: an interpolated input
		// is substituted into the script text before the shell parses it.
		if step.Run != "" {
			for _, line := range strings.Split(step.Run, "\n") {
				for _, m := range inputRefPattern.FindAllStringSubmatch(line, -1) {
					name := m[1]
					if !d.Inputs[name] {
						continue // not a declared input of this definition
					}
					key := name + "|" + stepName
					if seen[key] {
						continue
					}
					seen[key] = true
					uses = append(uses, InputUse{
						Input:    name,
						StepName: stepName,
						SinkKind: "run script",
						Line:     lineOf(d.Content, strings.TrimSpace(line)),
						Snippet:  strings.TrimSpace(line),
					})
				}
			}
		}

		// An input forwarded into a script-executing action is a sink too.
		for inputName, raw := range step.With {
			value, ok := raw.(string)
			if !ok || !executesItsInput(step.Uses, inputName) {
				continue
			}
			for _, m := range inputRefPattern.FindAllStringSubmatch(value, -1) {
				name := m[1]
				if !d.Inputs[name] {
					continue
				}
				key := name + "|" + stepName + "|" + inputName
				if seen[key] {
					continue
				}
				seen[key] = true
				uses = append(uses, InputUse{
					Input:    name,
					StepName: stepName,
					SinkKind: fmt.Sprintf("input `%s` of %s", inputName, step.Uses),
					Line:     lineOf(d.Content, strings.TrimSpace(value)),
					Snippet:  strings.TrimSpace(value),
				})
			}
		}
	}

	return uses
}

// executesItsInput reports whether an action treats the named input as code.
//
// Kept to a small, well-known list rather than guessing: a wrong entry here
// turns a data-handling action into a false positive.
func executesItsInput(uses, input string) bool {
	name := uses
	if i := strings.Index(name, "@"); i != -1 {
		name = name[:i]
	}
	name = strings.ToLower(strings.TrimSpace(name))

	switch name {
	case "actions/github-script":
		return input == "script"
	case "azure/cli", "azure/powershell":
		return input == "inlineScript"
	}
	return false
}

// lineOf finds the 1-based line of a snippet within the definition's source.
func lineOf(content []byte, snippet string) int {
	if snippet == "" {
		return 0
	}
	for i, line := range strings.Split(string(content), "\n") {
		if strings.Contains(line, snippet) {
			return i + 1
		}
	}
	return 0
}

// sortedJobIDs returns job IDs in a deterministic order.
func sortedJobIDs(jobs map[string]parser.Job) []string {
	ids := make([]string, 0, len(jobs))
	for id := range jobs {
		ids = append(ids, id)
	}
	// Simple insertion sort keeps this dependency-free and the input is tiny.
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && ids[j] < ids[j-1]; j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
	return ids
}
