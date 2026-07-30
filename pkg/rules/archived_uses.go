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

	"github.com/harekrishnarai/flowlyt/v2/pkg/github"
	"github.com/harekrishnarai/flowlyt/v2/pkg/linenum"
	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
)

// CheckArchivedActionSource is the public entry point for the
// ARCHIVED_ACTION_SOURCE rule.
func CheckArchivedActionSource(workflow parser.WorkflowFile) []Finding {
	return checkArchivedActionSource(workflow)
}

// actionReference identifies the repository backing a `uses:` clause.
type actionReference struct {
	owner    string
	repo     string
	fullName string
	uses     string
	jobName  string
	stepName string
}

// collectExternalActionReferences returns every third-party action referenced by
// the workflow, excluding local actions and Docker image references.
func collectExternalActionReferences(workflow parser.WorkflowFile) []actionReference {
	var refs []actionReference

	for jobName, job := range workflow.Workflow.Jobs {
		// A job may call a reusable workflow directly.
		if job.Uses != "" {
			if ref, ok := parseActionReference(job.Uses, jobName, ""); ok {
				refs = append(refs, ref)
			}
		}

		for stepIdx, step := range job.Steps {
			if step.Uses == "" {
				continue
			}
			stepName := step.Name
			if stepName == "" {
				stepName = fmt.Sprintf("Step %d", stepIdx+1)
			}
			if ref, ok := parseActionReference(step.Uses, jobName, stepName); ok {
				refs = append(refs, ref)
			}
		}
	}

	return refs
}

// parseActionReference extracts owner/repo from a `uses:` clause.
func parseActionReference(uses, jobName, stepName string) (actionReference, bool) {
	trimmed := strings.TrimSpace(uses)

	// Local actions live in this repository and Docker references are images,
	// not repositories.
	if trimmed == "" ||
		strings.HasPrefix(trimmed, "./") ||
		strings.HasPrefix(trimmed, "../") ||
		strings.HasPrefix(trimmed, "docker://") {
		return actionReference{}, false
	}

	name := trimmed
	if idx := strings.Index(name, "@"); idx != -1 {
		name = name[:idx]
	}

	parts := strings.Split(name, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return actionReference{}, false
	}

	return actionReference{
		owner:    parts[0],
		repo:     parts[1],
		fullName: parts[0] + "/" + parts[1],
		uses:     trimmed,
		jobName:  jobName,
		stepName: stepName,
	}, true
}

// checkArchivedActionSource detects actions sourced from archived repositories.
//
// Archiving makes a repository read-only and signals that it is no longer
// maintained. Depending on one is a supply chain risk in two directions: any
// vulnerability found in the action itself can never be patched, and vendored
// JavaScript dependencies inside the action continue to age without updates.
//
// Resolution requires GitHub API access. References that cannot be resolved
// (private repositories, rate limiting, deleted repositories) are skipped
// rather than reported, so the rule never asserts a claim it cannot verify.
func checkArchivedActionSource(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	refs := collectExternalActionReferences(workflow)
	if len(refs) == 0 {
		return findings
	}

	ghClient := github.NewClient()
	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Repository status is network-bound and the same action commonly recurs
	// across jobs, so results are memoised for the duration of this workflow.
	archivedStatus := make(map[string]bool)
	unresolvable := make(map[string]bool)
	seen := make(map[string]bool)

	for _, ref := range refs {
		if unresolvable[ref.fullName] {
			continue
		}

		archived, cached := archivedStatus[ref.fullName]
		if !cached {
			result, err := ghClient.IsRepositoryArchived(ref.owner, ref.repo)
			if err != nil {
				unresolvable[ref.fullName] = true
				continue
			}
			archived = result
			archivedStatus[ref.fullName] = archived
		}

		if !archived {
			continue
		}

		lineNumber := 0
		if result := lineMapper.FindLineNumber(linenum.FindPattern{
			Key:   "uses",
			Value: ref.uses,
		}); result != nil {
			lineNumber = result.LineNumber
		}

		dedupKey := fmt.Sprintf("%s|%d", ref.uses, lineNumber)
		if seen[dedupKey] {
			continue
		}
		seen[dedupKey] = true

		findings = append(findings, Finding{
			RuleID:      "ARCHIVED_ACTION_SOURCE",
			RuleName:    "Action From Archived Repository",
			Description: "Workflow depends on an action whose repository is archived and therefore can no longer receive security fixes",
			Severity:    Medium,
			Category:    SupplyChain,
			FilePath:    workflow.Path,
			JobName:     ref.jobName,
			StepName:    ref.stepName,
			Evidence:    fmt.Sprintf("%s is archived (read-only) on GitHub", ref.fullName),
			Remediation: fmt.Sprintf("Replace %s with a maintained alternative, or inline its behaviour in a `run:` step (many wrapper actions can be replaced by a `gh` CLI call)", ref.fullName),
			LineNumber:  lineNumber,
		})
	}

	return findings
}
