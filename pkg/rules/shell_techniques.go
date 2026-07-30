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

// shellTechnique describes one attacker technique that is detectable inside a
// `run:` block.
//
// Techniques are declared as data rather than as bespoke scanning loops, so
// that covering a newly observed technique is a single table entry. The shared
// scanner below handles the parts that are easy to get wrong and must be
// consistent across every rule: skipping comments, pinpointing the offending
// line, resolving its line number, and deduplicating findings.
type shellTechnique struct {
	ID          string
	Name        string
	Severity    Severity
	Category    Category
	Description string
	Remediation string

	// MatchLine reports whether a single shell line exhibits the technique.
	// Use this for techniques contained within one command.
	MatchLine func(line string) bool

	// MatchScript inspects an entire run block and returns the offending line,
	// or "" when the technique is absent. Use this for techniques that span
	// several commands, such as writing a file in one and executing it in
	// another.
	//
	// Exactly one of MatchLine or MatchScript must be set.
	MatchScript func(lines []string) string
}

// scanShellTechniques applies every technique to every `run:` block in the
// workflow.
//
// At most one finding is produced per technique per step: a single malicious
// command frequently matches several patterns within the same technique, and
// reporting each match separately would bury the signal.
func scanShellTechniques(workflow parser.WorkflowFile, techniques []shellTechnique) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)
	seen := make(map[string]bool)

	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			stepName := step.Name
			if stepName == "" {
				stepName = fmt.Sprintf("Step %d", stepIdx+1)
			}

			lines := significantShellLines(step.Run)
			if len(lines) == 0 {
				continue
			}

			for _, tech := range techniques {
				offending := matchTechnique(tech, lines)
				if offending == "" {
					continue
				}

				lineNumber := resolveRunLine(lineMapper, step.Run, offending)

				dedupKey := fmt.Sprintf("%s|%s|%d", tech.ID, workflow.Path, lineNumber)
				if seen[dedupKey] {
					continue
				}
				seen[dedupKey] = true

				findings = append(findings, Finding{
					RuleID:      tech.ID,
					RuleName:    tech.Name,
					Description: tech.Description,
					Severity:    tech.Severity,
					Category:    tech.Category,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    stepName,
					Evidence:    truncate(offending, 200),
					Remediation: tech.Remediation,
					LineNumber:  lineNumber,
				})
			}
		}
	}

	return findings
}

// matchTechnique dispatches to whichever matcher the technique defines.
func matchTechnique(tech shellTechnique, lines []string) string {
	if tech.MatchScript != nil {
		return tech.MatchScript(lines)
	}
	if tech.MatchLine == nil {
		return ""
	}
	for _, line := range lines {
		if tech.MatchLine(line) {
			return line
		}
	}
	return ""
}

// significantShellLines splits a run block into non-empty, non-comment lines.
//
// Comments are stripped so that a commented-out example does not produce a
// finding, and line continuations are joined so a command split across physical
// lines is evaluated as a whole.
func significantShellLines(script string) []string {
	joined := strings.ReplaceAll(script, "\\\n", " ")

	var out []string
	for _, raw := range strings.Split(joined, "\n") {
		line := strings.TrimSpace(stripShellComment(raw))
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// locateRunBlock returns the file line holding the first content line of the
// given `run:` script, or 0 when it cannot be located.
//
// Matching on the first line alone is not enough: identical commands appear in
// many workflows, and a bare expression such as `${{ github.event.issue.body }}`
// may occur in several steps. Candidate positions are therefore verified by
// checking that the script's subsequent lines also line up, which
// disambiguates steps that merely start the same way.
func locateRunBlock(mapper *linenum.LineMapper, script string) int {
	raw := strings.Split(script, "\n")

	first := -1
	for i, l := range raw {
		if strings.TrimSpace(l) != "" {
			first = i
			break
		}
	}
	if first < 0 {
		return 0
	}

	firstTrimmed := strings.TrimSpace(raw[first])
	total := mapper.TotalLines()
	fallback := 0

	for n := 1; n <= total; n++ {
		if !strings.Contains(mapper.GetLine(n), firstTrimmed) {
			continue
		}
		if fallback == 0 {
			fallback = n
		}

		// Verify the remaining content lines follow consecutively.
		fileLine, aligned := n, true
		for i := first + 1; i < len(raw); i++ {
			t := strings.TrimSpace(raw[i])
			if t == "" {
				continue
			}
			fileLine++
			if fileLine > total || !strings.Contains(mapper.GetLine(fileLine), t) {
				aligned = false
				break
			}
		}
		if aligned {
			return n
		}
	}

	return fallback
}

// resolveRunLine locates the offending line within the workflow file.
//
// The search is scoped to the enclosing `run:` block rather than spanning the
// whole file. An offending line is often a short, generic fragment that occurs
// in several steps, and an unscoped search would attribute the finding to
// whichever step happens to appear first.
func resolveRunLine(mapper *linenum.LineMapper, script, offending string) int {
	start := locateRunBlock(mapper, script)
	target := strings.TrimSpace(offending)

	if start == 0 || target == "" {
		return start
	}

	// The block cannot extend beyond its own line count; the margin absorbs
	// blank lines within the block.
	limit := start + len(strings.Split(script, "\n")) + 1
	if total := mapper.TotalLines(); limit > total {
		limit = total
	}

	for n := start; n <= limit; n++ {
		if strings.Contains(mapper.GetLine(n), target) {
			return n
		}
	}

	// The offending text could not be matched verbatim, for example after
	// continuation joining. The block start remains the best available answer.
	return start
}

// selectTechniques returns the techniques whose ID appears in ids.
//
// Rules select by ID rather than by slice position so that reordering a
// technique table can never silently repoint a registered rule at the wrong
// detector.
func selectTechniques(all []shellTechnique, ids ...string) []shellTechnique {
	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		wanted[id] = true
	}

	var out []shellTechnique
	for _, tech := range all {
		if wanted[tech.ID] {
			out = append(out, tech)
		}
	}
	return out
}

// anyPattern builds a MatchLine matcher that reports whether a line matches any
// of the supplied patterns.
func anyPattern(patterns ...*regexp.Regexp) func(string) bool {
	return func(line string) bool {
		for _, p := range patterns {
			if p.MatchString(line) {
				return true
			}
		}
		return false
	}
}

// untrustedExpressionPattern matches a GitHub Actions expression. Not every
// expression is attacker-controlled, but its presence inside a shell command is
// the precondition for the injection techniques below.
var untrustedExpressionPattern = regexp.MustCompile(`\$\{\{[^}]+\}\}`)

// containsExpression reports whether a line interpolates a workflow expression.
func containsExpression(line string) bool {
	return untrustedExpressionPattern.MatchString(line)
}
