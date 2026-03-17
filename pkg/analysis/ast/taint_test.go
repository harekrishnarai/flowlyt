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
	"testing"
)

// TestExprTaintTracker_PathsForStep covers the main PathsForStep scenarios.
func TestExprTaintTracker_PathsForStep(t *testing.T) {
	tracker := NewExprTaintTracker()

	tests := []struct {
		name       string
		stepRun    string
		stepEnv    map[string]string
		wantUnsafe bool
		wantCount  int // minimum number of paths (0 = don't check)
	}{
		{
			name:       "direct PR title interpolation is unsafe",
			stepRun:    `echo "${{ github.event.pull_request.title }}"`,
			stepEnv:    nil,
			wantUnsafe: true,
		},
		{
			name:    "PR title in env block only is safe (env-var indirection)",
			stepRun: `echo "$TITLE"`,
			stepEnv: map[string]string{
				"TITLE": "${{ github.event.pull_request.title }}",
			},
			wantUnsafe: false,
		},
		{
			name:       "PR title written to GITHUB_ENV has SinkGitHubEnv sink",
			stepRun:    `echo "VAL=${{ github.event.pull_request.title }}" >> $GITHUB_ENV`,
			stepEnv:    nil,
			wantUnsafe: true,
		},
		{
			name:       "release body (2024-2025 source) is unsafe",
			stepRun:    `echo "${{ github.event.release.body }}"`,
			stepEnv:    nil,
			wantUnsafe: true,
		},
		{
			name:       "discussion title (2024-2025 source) is unsafe",
			stepRun:    `echo "${{ github.event.discussion.title }}"`,
			stepEnv:    nil,
			wantUnsafe: true,
		},
		{
			name:       "workflow_run head_branch (2024-2025 source) is unsafe",
			stepRun:    `git checkout ${{ github.event.workflow_run.head_branch }}`,
			stepEnv:    nil,
			wantUnsafe: true,
		},
		{
			name:       "workflow_run head_commit.message (2024-2025 source) is unsafe",
			stepRun:    `echo "${{ github.event.workflow_run.head_commit.message }}"`,
			stepEnv:    nil,
			wantUnsafe: true,
		},
		{
			name:       "PR head repo full name (2024-2025 source) is unsafe",
			stepRun:    `echo "${{ github.event.pull_request.head.repo.full_name }}"`,
			stepEnv:    nil,
			wantUnsafe: true,
		},
		{
			name:       "safe static string produces no unsafe paths",
			stepRun:    `echo "hello world"`,
			stepEnv:    nil,
			wantUnsafe: false,
		},
		{
			name:       "empty stepRun with nil env produces no paths",
			stepRun:    "",
			stepEnv:    nil,
			wantUnsafe: false,
			wantCount:  0,
		},
		{
			name:       "issue body is unsafe",
			stepRun:    `echo "${{ github.event.issue.body }}"`,
			stepEnv:    nil,
			wantUnsafe: true,
		},
		{
			name:       "comment body is unsafe",
			stepRun:    `echo "${{ github.event.comment.body }}"`,
			stepEnv:    nil,
			wantUnsafe: true,
		},
		{
			name:       "github.head_ref is unsafe",
			stepRun:    `git checkout ${{ github.head_ref }}`,
			stepEnv:    nil,
			wantUnsafe: true,
		},
		{
			name:       "indexed commits form is unsafe",
			stepRun:    `echo "${{ github.event.commits[0].message }}"`,
			stepEnv:    nil,
			wantUnsafe: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			paths, err := tracker.PathsForStep(tc.stepRun, tc.stepEnv)
			if err != nil {
				t.Fatalf("PathsForStep returned unexpected error: %v", err)
			}

			got := HasUnsafePaths(paths)
			if got != tc.wantUnsafe {
				t.Errorf("HasUnsafePaths = %v, want %v (paths: %+v)", got, tc.wantUnsafe, paths)
			}

			if tc.wantCount > 0 && len(paths) < tc.wantCount {
				t.Errorf("len(paths) = %d, want at least %d", len(paths), tc.wantCount)
			}
		})
	}
}

// TestExprTaintTracker_GithubEnvSink verifies that the SinkGitHubEnv sink is
// only assigned when the tainted expression and >> $GITHUB_ENV appear on the
// SAME line, not when they appear on different lines.
func TestExprTaintTracker_GithubEnvSink(t *testing.T) {
	tracker := NewExprTaintTracker()

	t.Run("same line: tainted expr and GITHUB_ENV write → SinkGitHubEnv", func(t *testing.T) {
		run := `echo "VAL=${{ github.event.pull_request.title }}" >> $GITHUB_ENV`
		paths, err := tracker.PathsForStep(run, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		unsafe := UnsafePaths(paths)
		if len(unsafe) == 0 {
			t.Fatal("expected at least one unsafe path, got none")
		}
		found := false
		for _, p := range unsafe {
			if p.Sink.Type == SinkGitHubEnv {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected SinkGitHubEnv in unsafe paths, got: %+v", unsafe)
		}
	})

	t.Run("different lines: GITHUB_ENV write is unrelated to tainted expr → SinkShellInterpolation", func(t *testing.T) {
		// The GITHUB_ENV write is on the first line; the tainted expression is on the second line.
		run := "echo \"safe\" >> $GITHUB_ENV\necho \"${{ github.event.pull_request.title }}\""
		paths, err := tracker.PathsForStep(run, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		unsafe := UnsafePaths(paths)
		if len(unsafe) == 0 {
			t.Fatal("expected at least one unsafe path, got none")
		}
		for _, p := range unsafe {
			if p.Sink.Type != SinkShellInterpolation {
				t.Errorf("expected SinkShellInterpolation for tainted expr on separate line, got %v (path: %+v)", p.Sink.Type, p)
			}
		}
	})
}

// TestHasUnsafePaths verifies the HasUnsafePaths helper.
func TestHasUnsafePaths(t *testing.T) {
	t.Run("empty slice returns false", func(t *testing.T) {
		if HasUnsafePaths(nil) {
			t.Error("HasUnsafePaths(nil) should be false")
		}
		if HasUnsafePaths([]TaintPath{}) {
			t.Error("HasUnsafePaths([]) should be false")
		}
	})

	t.Run("all safe paths returns false", func(t *testing.T) {
		paths := []TaintPath{
			{Safe: true},
			{Safe: true},
		}
		if HasUnsafePaths(paths) {
			t.Error("all-safe paths should return false")
		}
	})

	t.Run("mix of safe and unsafe returns true", func(t *testing.T) {
		paths := []TaintPath{
			{Safe: true},
			{Safe: false},
		}
		if !HasUnsafePaths(paths) {
			t.Error("mix of safe/unsafe should return true")
		}
	})

	t.Run("all unsafe returns true", func(t *testing.T) {
		paths := []TaintPath{
			{Safe: false},
			{Safe: false},
		}
		if !HasUnsafePaths(paths) {
			t.Error("all-unsafe paths should return true")
		}
	})
}

// TestUnsafePaths verifies the UnsafePaths helper.
func TestUnsafePaths(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		if got := UnsafePaths(nil); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("filters out safe paths", func(t *testing.T) {
		paths := []TaintPath{
			{Safe: true, Evidence: "safe1"},
			{Safe: false, Evidence: "unsafe1"},
			{Safe: true, Evidence: "safe2"},
			{Safe: false, Evidence: "unsafe2"},
		}
		got := UnsafePaths(paths)
		if len(got) != 2 {
			t.Fatalf("expected 2 unsafe paths, got %d: %+v", len(got), got)
		}
		for _, p := range got {
			if p.Safe {
				t.Errorf("UnsafePaths returned a safe path: %+v", p)
			}
		}
	})

	t.Run("all safe returns nil/empty", func(t *testing.T) {
		paths := []TaintPath{{Safe: true}, {Safe: true}}
		got := UnsafePaths(paths)
		if len(got) != 0 {
			t.Errorf("expected empty result, got %v", got)
		}
	})
}

// TestClassifyExpression_ViaPathsForStep tests classifyExpression indirectly
// by inspecting the Source.Category field of paths returned by PathsForStep.
func TestClassifyExpression_ViaPathsForStep(t *testing.T) {
	tracker := NewExprTaintTracker()

	tests := []struct {
		name         string
		run          string
		wantCategory TaintCategory
	}{
		{
			name:         "pull_request.title → TaintPRContent",
			run:          `echo "${{ github.event.pull_request.title }}"`,
			wantCategory: TaintPRContent,
		},
		{
			name:         "issue.body → TaintIssueContent",
			run:          `echo "${{ github.event.issue.body }}"`,
			wantCategory: TaintIssueContent,
		},
		{
			name:         "head_commit.message → TaintCommitContent",
			run:          `echo "${{ github.event.head_commit.message }}"`,
			wantCategory: TaintCommitContent,
		},
		{
			name:         "release.body → TaintReleaseContent",
			run:          `echo "${{ github.event.release.body }}"`,
			wantCategory: TaintReleaseContent,
		},
		{
			name:         "discussion.title → TaintDiscussion",
			run:          `echo "${{ github.event.discussion.title }}"`,
			wantCategory: TaintDiscussion,
		},
		{
			name:         "workflow_run.head_branch → TaintWorkflowRun",
			run:          `git checkout ${{ github.event.workflow_run.head_branch }}`,
			wantCategory: TaintWorkflowRun,
		},
		{
			name:         "github.head_ref → TaintPRContent (not TaintUnknown)",
			run:          `git checkout ${{ github.head_ref }}`,
			wantCategory: TaintPRContent,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			paths, err := tracker.PathsForStep(tc.run, nil)
			if err != nil {
				t.Fatalf("PathsForStep returned error: %v", err)
			}
			if len(paths) == 0 {
				t.Fatalf("expected at least one taint path for %q, got none", tc.run)
			}
			// Find the first unsafe path (direct interpolation)
			var found *TaintPath
			for i := range paths {
				if !paths[i].Safe {
					found = &paths[i]
					break
				}
			}
			if found == nil {
				t.Fatalf("no unsafe path found among %d paths", len(paths))
			}
			if found.Source.Category != tc.wantCategory {
				t.Errorf("Category = %v, want %v (expression: %q)",
					found.Source.Category, tc.wantCategory, found.Source.Expression)
			}
		})
	}
}
