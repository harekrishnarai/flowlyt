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

	"github.com/harekrishnarai/flowlyt/v2/pkg/linenum"
	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
)

// NewForbiddenUsesRule builds the opt-in FORBIDDEN_USES rule from an allowlist
// and a denylist.
//
// The rule is policy enforcement rather than vulnerability detection: it lets an
// organization mechanically enforce which third-party actions may appear in its
// workflows. Because there is no universally correct policy, the rule does
// nothing until configured, and returns nil when both lists are empty so it is
// never registered as a no-op.
//
// Allow and Deny are mutually exclusive; if both are supplied, Allow wins, since
// an allowlist is the strictly stronger control.
//
// Note that this inspects `uses:` clauses as written. It cannot see actions
// pulled in indirectly — via a `git clone` in a `run:` step, or by a permitted
// action that itself calls a forbidden one — so it complements rather than
// replaces the other supply chain rules.
func NewForbiddenUsesRule(allow, deny []string) *Rule {
	allow = nonEmptyPatterns(allow)
	deny = nonEmptyPatterns(deny)

	if len(allow) == 0 && len(deny) == 0 {
		return nil
	}

	allowMode := len(allow) > 0
	patterns := deny
	if allowMode {
		patterns = allow
	}

	description := "Action is explicitly denied by the configured `uses:` policy"
	if allowMode {
		description = "Action is not on the configured `uses:` allowlist"
	}

	return &Rule{
		ID:          "FORBIDDEN_USES",
		Name:        "Forbidden Action Usage",
		Description: description,
		Severity:    High,
		Category:    PolicyViolation,
		Platform:    PlatformGitHub,
		Check: func(workflow parser.WorkflowFile) []Finding {
			return checkForbiddenUses(workflow, patterns, allowMode)
		},
	}
}

// nonEmptyPatterns strips blank entries so that a commented-out or partially
// filled configuration block does not silently enable the rule.
func nonEmptyPatterns(patterns []string) []string {
	var out []string
	for _, p := range patterns {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// checkForbiddenUses evaluates every external action against the policy.
func checkForbiddenUses(workflow parser.WorkflowFile, patterns []string, allowMode bool) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)
	seen := make(map[string]bool)

	for _, ref := range collectExternalActionReferences(workflow) {
		matched := matchesAnyRepositoryPattern(ref.fullName, patterns)

		// Allowlist mode reports non-matches; denylist mode reports matches.
		if matched == allowMode {
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

		var evidence, remediation string
		if allowMode {
			evidence = fmt.Sprintf("%s is not permitted by the configured allowlist", ref.fullName)
			remediation = fmt.Sprintf("Remove the action, replace it with an allowlisted equivalent, or add `%s` to rules.forbidden_uses.allow in your configuration", ref.fullName)
		} else {
			evidence = fmt.Sprintf("%s is explicitly denied by the configured policy", ref.fullName)
			remediation = fmt.Sprintf("Remove %s and replace it with an approved alternative", ref.fullName)
		}

		findings = append(findings, Finding{
			RuleID:      "FORBIDDEN_USES",
			RuleName:    "Forbidden Action Usage",
			Description: "Action usage violates the configured `uses:` policy",
			Severity:    High,
			Category:    PolicyViolation,
			FilePath:    workflow.Path,
			JobName:     ref.jobName,
			StepName:    ref.stepName,
			Evidence:    evidence,
			Remediation: remediation,
			LineNumber:  lineNumber,
		})
	}

	return findings
}

// matchesAnyRepositoryPattern reports whether an `owner/repo` name matches any
// configured pattern.
func matchesAnyRepositoryPattern(fullName string, patterns []string) bool {
	for _, pattern := range patterns {
		if matchesRepositoryPattern(fullName, pattern) {
			return true
		}
	}
	return false
}

// matchesRepositoryPattern matches a repository name against a single pattern.
//
// Supported forms:
//
//   - — matches everything
//     owner/*      — matches every repository under owner
//     owner/repo   — matches exactly that repository
//
// Matching is case-insensitive, since GitHub treats owner and repository names
// case-insensitively.
func matchesRepositoryPattern(fullName, pattern string) bool {
	fullName = strings.ToLower(strings.TrimSpace(fullName))
	pattern = strings.ToLower(strings.TrimSpace(pattern))

	if pattern == "*" {
		return true
	}

	// Tolerate a pattern written with a version suffix.
	if idx := strings.Index(pattern, "@"); idx != -1 {
		pattern = pattern[:idx]
	}

	// An owner-only pattern (no slash) matches every repository under it.
	if !strings.Contains(pattern, "/") {
		owner, _, found := strings.Cut(fullName, "/")
		return found && owner == pattern
	}

	patternOwner, patternRepo, _ := strings.Cut(pattern, "/")
	nameOwner, nameRepo, _ := strings.Cut(fullName, "/")

	if patternOwner != nameOwner {
		return false
	}

	// `owner/*` matches any repository under the owner. A trailing `/*` on a
	// subdirectory pattern (e.g. `github/codeql-action/*`) is normalised away
	// by the owner/repo split above.
	if patternRepo == "*" {
		return true
	}

	// Strip any subdirectory component from the pattern's repo segment.
	patternRepo, _, _ = strings.Cut(patternRepo, "/")

	return patternRepo == nameRepo
}
