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

package ast

import (
	"fmt"
	"regexp"
	"strings"
)

// TaintCategory classifies the origin of untrusted data.
type TaintCategory int

const (
	TaintPRContent      TaintCategory = iota // PR title, body, branch name
	TaintIssueContent                        // issue title, body, comment body
	TaintCommitContent                       // commit message, author email/name
	TaintReleaseContent                      // release body, tag name
	TaintDiscussion                          // discussion title, body
	TaintWorkflowRun                         // workflow_run head_branch, commit info
	TaintArtifact                            // downloaded artifact content
	TaintCacheRestore                        // restored cache content
	TaintUnknown                             // cannot classify — treat as unsafe
)

// SinkType classifies where tainted data lands.
type SinkType int

const (
	SinkShellInterpolation SinkType = iota // ${{ ... }} directly in run:
	SinkGitHubEnv                          // >> $GITHUB_ENV
	SinkGitHubOutput                       // >> $GITHUB_OUTPUT
	SinkGitHubPath                         // >> $GITHUB_PATH
	SinkScriptExecution                    // eval, bash -c, etc.
)

// TaintTransform describes what happens between source and sink.
type TaintTransform int

const (
	TransformNone      TaintTransform = iota // direct interpolation — UNSAFE
	TransformEnvVar                          // assigned to env: block first — SAFE
	TransformSanitized                       // passed through known sanitizer — SAFE
	TransformUnknown                         // unclear — treat as unsafe
)

// TaintSource describes the origin of untrusted data.
type TaintSource struct {
	Expression string
	Category   TaintCategory
}

// TaintSink describes where tainted data lands.
type TaintSink struct {
	Type     SinkType
	Location string
}

// TaintPath represents a complete data-flow path from source to sink.
type TaintPath struct {
	Source    TaintSource
	Transform TaintTransform
	Sink      TaintSink
	Safe      bool   // true if transform makes it safe
	Evidence  string // the raw text containing the tainted expression
}

// UntrustedExpressions is the full 2024-2025 research-backed list of GitHub
// Actions context expressions whose values are controlled by external actors.
var UntrustedExpressions = []string{
	// PR content
	"github.event.pull_request.title",
	"github.event.pull_request.body",
	"github.event.pull_request.head.ref",
	"github.event.pull_request.head.label",
	"github.event.pull_request.head.repo.full_name",
	"github.head_ref",
	// Issue / comment content
	"github.event.issue.title",
	"github.event.issue.body",
	"github.event.comment.body",
	"github.event.review.body",
	"github.event.review_comment.body",
	// Commit content — expand array sub-expressions so regex matches them
	"github.event.commits[0].message",
	"github.event.commits[0].author.email",
	"github.event.commits[0].author.name",
	"github.event.head_commit.message",
	"github.event.head_commit.author.email",
	"github.event.head_commit.author.name",
	// Release content (added 2024-2025)
	"github.event.release.body",
	"github.event.release.name",
	// Discussion content (added 2024-2025)
	"github.event.discussion.body",
	"github.event.discussion.title",
	// workflow_run context (added 2024-2025)
	"github.event.workflow_run.head_branch",
	"github.event.workflow_run.head_commit.message",
	"github.event.workflow_run.head_commit.author.email",
	"github.event.workflow_run.head_commit.author.name",
}

// untrustedExprRe is compiled once at package init from UntrustedExpressions.
// It matches ${{ <expr> }} where <expr> is one of the known untrusted paths,
// with optional surrounding whitespace inside the delimiters.
var untrustedExprRe *regexp.Regexp

func init() {
	parts := make([]string, len(UntrustedExpressions))
	for i, expr := range UntrustedExpressions {
		parts[i] = regexp.QuoteMeta(expr)
	}
	// Use [^}]* instead of \s* to allow minor expression variants (e.g. array
	// index suffixes) while still requiring the closing }}.
	pattern := `\$\{\{\s*(?:` + strings.Join(parts, "|") + `)[^}]*\}\}`
	untrustedExprRe = regexp.MustCompile(pattern)
}

// ExprTaintTracker is a lightweight expression taint tracker that classifies
// step expressions as safe or unsafe based on data-flow from untrusted
// sources to dangerous sinks.
type ExprTaintTracker struct{}

// NewExprTaintTracker creates a new ExprTaintTracker.
func NewExprTaintTracker() *ExprTaintTracker {
	return &ExprTaintTracker{}
}

// PathsForStep returns all taint paths found in a step.
//
// stepRun is the step's run: block content.
// stepEnv is the step's env: block (key → value map).
//
// Safety rule:
//   - UNSAFE: ${{ untrusted_expr }} appears directly in stepRun.
//   - SAFE:   ${{ untrusted_expr }} appears ONLY in stepEnv values, NOT in
//     stepRun directly (env-var indirection).
//
// On error callers should fall back to legacy regex matching.
func (t *ExprTaintTracker) PathsForStep(stepRun string, stepEnv map[string]string) ([]TaintPath, error) {
	if stepRun == "" && len(stepEnv) == 0 {
		return nil, nil
	}

	var paths []TaintPath

	// --- Direct interpolation in run: (always unsafe) ---
	// Collect run-block matches first so we can reference them for dedup below.
	var runMatches []string
	if stepRun != "" {
		locs := untrustedExprRe.FindAllStringIndex(stepRun, -1)
		lines := strings.Split(stepRun, "\n")
		for _, loc := range locs {
			rawExpr := stepRun[loc[0]:loc[1]]
			runMatches = append(runMatches, rawExpr)
			inner := extractInner(rawExpr)
			category := classifyExpression(inner)

			// Detect $GITHUB_ENV sink: check only the specific line the match
			// is on, not the whole run block, to avoid polluting unrelated lines.
			sinkType := SinkShellInterpolation
			// Determine which line offset loc[0] falls on.
			offset := 0
			for _, line := range lines {
				lineEnd := offset + len(line)
				if loc[0] >= offset && loc[0] <= lineEnd {
					if strings.Contains(line, ">> $GITHUB_ENV") || strings.Contains(line, ">>$GITHUB_ENV") {
						sinkType = SinkGitHubEnv
					}
					break
				}
				offset = lineEnd + 1 // +1 for the '\n' consumed by Split
			}

			paths = append(paths, TaintPath{
				Source: TaintSource{
					Expression: inner,
					Category:   category,
				},
				Transform: TransformNone,
				Sink: TaintSink{
					Type:     sinkType,
					Location: fmt.Sprintf("run block at offset %d", loc[0]),
				},
				Safe:     false,
				Evidence: rawExpr,
			})
		}
	}

	// --- Expressions only in env: block (safe via env-var indirection) ---
	for _, val := range stepEnv {
		matches := untrustedExprRe.FindAllString(val, -1)
		for _, rawExpr := range matches {
			inner := extractInner(rawExpr)
			// If the same inner expression is already captured as an unsafe
			// run-block path, skip emitting a redundant safe path.  Compare
			// inner expressions (whitespace-normalised via extractInner) rather
			// than raw strings to avoid false mismatches caused by spacing
			// differences between the env value and the run block.
			alreadyUnsafe := false
			for _, runRaw := range runMatches {
				if extractInner(runRaw) == inner {
					alreadyUnsafe = true
					break
				}
			}
			if alreadyUnsafe {
				continue
			}
			category := classifyExpression(inner)
			paths = append(paths, TaintPath{
				Source: TaintSource{
					Expression: inner,
					Category:   category,
				},
				Transform: TransformEnvVar,
				Sink: TaintSink{
					Type:     SinkShellInterpolation,
					Location: "env block",
				},
				Safe:     true,
				Evidence: rawExpr,
			})
		}
	}

	return paths, nil
}

// HasUnsafePaths returns true if any path in the slice is unsafe.
func HasUnsafePaths(paths []TaintPath) bool {
	for _, p := range paths {
		if !p.Safe {
			return true
		}
	}
	return false
}

// UnsafePaths returns only the unsafe paths from the slice.
func UnsafePaths(paths []TaintPath) []TaintPath {
	var out []TaintPath
	for _, p := range paths {
		if !p.Safe {
			out = append(out, p)
		}
	}
	return out
}

// classifyExpression maps an expression string to a TaintCategory based on
// keywords it contains.
func classifyExpression(expr string) TaintCategory {
	switch {
	case strings.Contains(expr, "pull_request") ||
		strings.Contains(expr, "head_ref"):
		return TaintPRContent
	case strings.Contains(expr, "issue") ||
		strings.Contains(expr, "comment") ||
		strings.Contains(expr, "review"):
		return TaintIssueContent
	case strings.Contains(expr, "workflow_run"):
		// Must precede "commit" — workflow_run.head_commit.* contains "commit"
		// but belongs to the workflow_run category.
		return TaintWorkflowRun
	case strings.Contains(expr, "commit"):
		return TaintCommitContent
	case strings.Contains(expr, "release"):
		return TaintReleaseContent
	case strings.Contains(expr, "discussion"):
		return TaintDiscussion
	default:
		return TaintUnknown
	}
}

// extractInner strips the ${{ }} delimiters and surrounding whitespace from a
// matched expression string, returning the inner expression text.
func extractInner(raw string) string {
	// raw has the form ${{ expr }}
	s := strings.TrimPrefix(raw, "${{")
	s = strings.TrimSuffix(s, "}}")
	return strings.TrimSpace(s)
}
