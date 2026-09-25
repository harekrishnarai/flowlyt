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

// CheckDefinitionHygiene runs the workflow-readability checks.
func CheckDefinitionHygiene(workflow parser.WorkflowFile) []Finding {
	findings := make([]Finding, 0, 2)
	findings = append(findings, checkAnonymousDefinition(workflow)...)
	findings = append(findings, checkUndocumentedPermissions(workflow)...)
	return findings
}

// checkAnonymousDefinition detects workflows that omit a top-level `name:`.
//
// This has no direct security impact. It matters because an unnamed workflow is
// rendered by its filename in the Actions UI, checks list, and required-status
// settings, which makes it materially harder to tell at a glance which workflow
// produced a given run — a real obstacle during incident response, and a
// condition an attacker adding a lookalike workflow benefits from.
func checkAnonymousDefinition(workflow parser.WorkflowFile) []Finding {
	if strings.TrimSpace(workflow.Workflow.Name) != "" {
		return nil
	}

	// A workflow with no jobs is almost certainly a fragment or template rather
	// than a real definition.
	if len(workflow.Workflow.Jobs) == 0 {
		return nil
	}

	return []Finding{{
		RuleID:      "ANONYMOUS_DEFINITION",
		RuleName:    "Unnamed Workflow Definition",
		Description: "Workflow omits a top-level name, so it is identified only by filename in the Actions UI",
		Severity:    Info,
		Category:    Misconfiguration,
		FilePath:    workflow.Path,
		Evidence:    "Workflow has no top-level `name:` field",
		Remediation: "Add a descriptive `name:` at the top of the workflow, e.g. `name: CI`",
		LineNumber:  1,
	}}
}

// permissionsBlockPattern locates a `permissions:` key and captures its
// indentation so the extent of the block can be determined.
var permissionsBlockPattern = regexp.MustCompile(`^(\s*)permissions:\s*(.*)$`)

// checkUndocumentedPermissions detects granted write permissions that carry no
// explanatory comment.
//
// Write scopes are the credentials an attacker inherits if any step in the job
// is compromised, and they are routinely copied between workflows without
// anyone re-checking whether they are still needed. Requiring a brief comment
// on each granted write scope keeps the justification next to the grant, so
// reviewers can tell an intentional permission from a vestigial one.
//
// Read-only scopes and `permissions: {}` are not reported: neither confers
// meaningful authority, so demanding a rationale would be noise.
func checkUndocumentedPermissions(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)
	total := lineMapper.TotalLines()
	seen := make(map[int]bool)

	for lineNum := 1; lineNum <= total; lineNum++ {
		line := lineMapper.GetLine(lineNum)

		match := permissionsBlockPattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}

		indent := len(match[1])
		inline := strings.TrimSpace(match[2])

		// Inline forms such as `permissions: read-all` or `permissions: {}`
		// have no per-scope grants to document.
		if inline != "" {
			continue
		}

		// Walk the block's entries, which are indented further than the key.
		for entryNum := lineNum + 1; entryNum <= total; entryNum++ {
			entry := lineMapper.GetLine(entryNum)

			if strings.TrimSpace(entry) == "" {
				continue
			}

			entryIndent := len(entry) - len(strings.TrimLeft(entry, " \t"))
			if entryIndent <= indent {
				// Dedented back out of the permissions block.
				break
			}

			scope, value, comment, ok := parsePermissionEntry(entry)
			if !ok {
				continue
			}

			// Only write-capable scopes confer authority worth justifying.
			if !strings.EqualFold(value, "write") {
				continue
			}
			if comment != "" {
				continue
			}
			if seen[entryNum] {
				continue
			}
			seen[entryNum] = true

			findings = append(findings, Finding{
				RuleID:      "UNDOCUMENTED_PERMISSIONS",
				RuleName:    "Undocumented Write Permission",
				Description: "A write permission is granted without an explanatory comment, making it hard to tell whether it is still required",
				Severity:    Info,
				Category:    AccessControl,
				FilePath:    workflow.Path,
				Evidence:    fmt.Sprintf("`%s: write` is granted with no comment explaining why it is needed", scope),
				Remediation: fmt.Sprintf("Add a short trailing comment justifying the grant, e.g. `%s: write # needed to publish release assets`, or remove the scope if it is unused", scope),
				LineNumber:  entryNum,
			})
		}
	}

	return findings
}

// permissionEntryPattern matches a single `scope: value` line within a
// permissions block, along with any trailing comment.
var permissionEntryPattern = regexp.MustCompile(`^\s*([a-z-]+):\s*([a-z-]+)\s*(?:#\s*(.*))?$`)

// parsePermissionEntry extracts the scope, value, and trailing comment from a
// permissions block entry.
func parsePermissionEntry(line string) (scope, value, comment string, ok bool) {
	match := permissionEntryPattern.FindStringSubmatch(line)
	if match == nil {
		return "", "", "", false
	}
	return match[1], match[2], strings.TrimSpace(match[3]), true
}
