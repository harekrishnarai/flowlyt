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

	"github.com/harekrishnarai/flowlyt/v2/pkg/github"
	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
)

// CheckRefVersionMismatch is the public entry point for the
// REF_VERSION_MISMATCH rule.
func CheckRefVersionMismatch(workflow parser.WorkflowFile) []Finding {
	return checkRefVersionMismatch(workflow)
}

// pinnedUsesWithCommentPattern matches a SHA-pinned action reference carrying a
// trailing version comment, which is the conventional way to keep a pinned
// workflow readable:
//
//	uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v5.0.0
//
// Comments are discarded during YAML parsing, so this operates on raw content.
var pinnedUsesWithCommentPattern = regexp.MustCompile(
	`(?m)^\s*-?\s*uses:\s*["']?([A-Za-z0-9._-]+/[A-Za-z0-9._/-]+)@([0-9a-fA-F]{40})["']?\s*#\s*(\S+)`,
)

// versionCommentPattern identifies comments that actually assert a version,
// e.g. "v5", "v5.0.0", "1.2.3". Comments such as "# pin to fork" make no
// verifiable claim and are ignored.
var versionCommentPattern = regexp.MustCompile(`^v?\d+(\.\d+)*$`)

// refVersionClaim is a single "this SHA is version X" assertion extracted from
// the workflow source.
type refVersionClaim struct {
	action string
	sha    string
	// claimedTag is the version string as written in the comment.
	claimedTag string
	lineNumber int
	rawLine    string
}

// extractRefVersionClaims parses the raw workflow content for SHA pins that
// carry a version comment.
func extractRefVersionClaims(content []byte) []refVersionClaim {
	var claims []refVersionClaim

	text := string(content)
	matches := pinnedUsesWithCommentPattern.FindAllStringSubmatchIndex(text, -1)

	for _, loc := range matches {
		groups := make([]string, 0, 4)
		for i := 0; i < 4; i++ {
			start, end := loc[2*i], loc[2*i+1]
			if start == -1 {
				groups = append(groups, "")
				continue
			}
			groups = append(groups, text[start:end])
		}

		action := groups[1]
		sha := strings.ToLower(groups[2])
		comment := strings.TrimSpace(groups[3])

		if !versionCommentPattern.MatchString(comment) {
			continue
		}

		// Line numbers are 1-based; count newlines preceding the match start.
		lineNumber := strings.Count(text[:loc[0]], "\n") + 1

		claims = append(claims, refVersionClaim{
			action:     action,
			sha:        sha,
			claimedTag: comment,
			lineNumber: lineNumber,
			rawLine:    strings.TrimSpace(groups[0]),
		})
	}

	return claims
}

// candidateTagNames returns the tag spellings to try for a version comment.
// Repositories are inconsistent about the leading "v", so both forms are
// attempted before concluding the tag does not exist.
func candidateTagNames(claimedTag string) []string {
	if strings.HasPrefix(claimedTag, "v") {
		return []string{claimedTag, strings.TrimPrefix(claimedTag, "v")}
	}
	return []string{"v" + claimedTag, claimedTag}
}

// checkRefVersionMismatch verifies that a SHA-pinned action actually
// corresponds to the version its trailing comment claims.
//
// Pinning by commit SHA is the recommended defence against tag mutation, but
// reviewers rely almost entirely on the adjacent `# v1.2.3` comment to judge
// what is being pinned. A SHA that does not match the claimed tag is therefore
// a potent social-engineering vector: a malicious pull request can point at an
// attacker-controlled commit while displaying a trusted version number. The
// same mismatch also arises benignly when a version bump updates the comment
// but not the SHA, which silently leaves the workflow on old, potentially
// vulnerable code.
//
// This check requires GitHub API access to resolve tags. Any reference that
// cannot be resolved (private repositories, deleted tags, rate limiting) is
// skipped rather than reported, so the rule never produces findings it cannot
// substantiate.
func checkRefVersionMismatch(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	claims := extractRefVersionClaims(workflow.Content)
	if len(claims) == 0 {
		return findings
	}

	ghClient := github.NewClient()

	// Tag resolution is network-bound and the same action/version pair recurs
	// across jobs and matrix entries, so results are memoised per workflow.
	resolved := make(map[string]string)
	unresolvable := make(map[string]bool)
	seen := make(map[string]bool)

	for _, claim := range claims {
		owner, repo, ok := splitActionOwnerRepo(claim.action)
		if !ok {
			continue
		}

		cacheKey := claim.action + "@" + claim.claimedTag
		if unresolvable[cacheKey] {
			continue
		}

		tagSHA, cached := resolved[cacheKey]
		if !cached {
			for _, tag := range candidateTagNames(claim.claimedTag) {
				sha, err := ghClient.ResolveRefSHA(owner, repo, tag)
				if err == nil && sha != "" {
					tagSHA = strings.ToLower(sha)
					break
				}
			}

			if tagSHA == "" {
				// Cannot substantiate a claim about a tag we cannot see.
				unresolvable[cacheKey] = true
				continue
			}
			resolved[cacheKey] = tagSHA
		}

		if tagSHA == claim.sha {
			continue
		}

		dedupKey := fmt.Sprintf("%s|%d", cacheKey, claim.lineNumber)
		if seen[dedupKey] {
			continue
		}
		seen[dedupKey] = true

		findings = append(findings, Finding{
			RuleID:      "REF_VERSION_MISMATCH",
			RuleName:    "Action Ref Version Mismatch",
			Description: "SHA-pinned action does not point at the version claimed by its adjacent comment",
			Severity:    High,
			Category:    SupplyChain,
			FilePath:    workflow.Path,
			Evidence: fmt.Sprintf(
				"%s is pinned to %s but the comment claims %s, which actually resolves to %s",
				claim.action, shortSHA(claim.sha), claim.claimedTag, shortSHA(tagSHA),
			),
			Remediation: fmt.Sprintf(
				"Verify the intended version, then either repin to the correct commit (`uses: %s@%s # %s`) or correct the comment to describe the commit that is actually pinned",
				claim.action, tagSHA, claim.claimedTag,
			),
			LineNumber: claim.lineNumber,
		})
	}

	return findings
}

// splitActionOwnerRepo extracts the owner and repository from an action
// reference, tolerating subdirectory paths such as github/codeql-action/init.
func splitActionOwnerRepo(action string) (owner, repo string, ok bool) {
	parts := strings.Split(action, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// shortSHA abbreviates a commit SHA for readable finding output.
func shortSHA(sha string) string {
	const shortLen = 12
	if len(sha) <= shortLen {
		return sha
	}
	return sha[:shortLen]
}
