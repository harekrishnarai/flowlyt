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
	"testing"

	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
)

// The rule's tag-resolution step requires GitHub API access, so these tests
// cover the offline half: extracting version claims from raw workflow source.

func TestExtractRefVersionClaims_BasicPinWithComment(t *testing.T) {
	content := []byte(`name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v5.0.0
`)

	claims := extractRefVersionClaims(content)
	if len(claims) != 1 {
		t.Fatalf("expected 1 claim, got %d", len(claims))
	}

	claim := claims[0]
	if claim.action != "actions/checkout" {
		t.Errorf("action = %q, want actions/checkout", claim.action)
	}
	if claim.sha != "11bd71901bbe5b1630ceea73d27597364c9af683" {
		t.Errorf("sha = %q, unexpected", claim.sha)
	}
	if claim.claimedTag != "v5.0.0" {
		t.Errorf("claimedTag = %q, want v5.0.0", claim.claimedTag)
	}
	if claim.lineNumber != 7 {
		t.Errorf("lineNumber = %d, want 7", claim.lineNumber)
	}
}

// A pin without a version comment makes no verifiable claim.
func TestExtractRefVersionClaims_NoComment(t *testing.T) {
	content := []byte(`      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
`)

	if claims := extractRefVersionClaims(content); len(claims) != 0 {
		t.Fatalf("expected 0 claims for uncommented pin, got %d", len(claims))
	}
}

// Free-form comments assert nothing about a version and must be ignored.
func TestExtractRefVersionClaims_NonVersionComment(t *testing.T) {
	content := []byte(`      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # pinned-to-fork
`)

	if claims := extractRefVersionClaims(content); len(claims) != 0 {
		t.Fatalf("expected 0 claims for non-version comment, got %d", len(claims))
	}
}

// Tag-pinned (non-SHA) references are the concern of the unpinned-action rule.
func TestExtractRefVersionClaims_TagPinIgnored(t *testing.T) {
	content := []byte(`      - uses: actions/checkout@v4 # v4
`)

	if claims := extractRefVersionClaims(content); len(claims) != 0 {
		t.Fatalf("expected 0 claims for tag-pinned action, got %d", len(claims))
	}
}

func TestExtractRefVersionClaims_SubdirectoryAction(t *testing.T) {
	content := []byte(`      - uses: github/codeql-action/init@1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e # v3.1.0
`)

	claims := extractRefVersionClaims(content)
	if len(claims) != 1 {
		t.Fatalf("expected 1 claim, got %d", len(claims))
	}
	if claims[0].action != "github/codeql-action/init" {
		t.Errorf("action = %q, want github/codeql-action/init", claims[0].action)
	}

	owner, repo, ok := splitActionOwnerRepo(claims[0].action)
	if !ok || owner != "github" || repo != "codeql-action" {
		t.Errorf("splitActionOwnerRepo = (%q, %q, %v), want (github, codeql-action, true)", owner, repo, ok)
	}
}

func TestExtractRefVersionClaims_MultipleClaims(t *testing.T) {
	content := []byte(`jobs:
  build:
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v5.0.0
      - uses: actions/setup-go@0aaccfd150d50ccaeb58ebd88d36e91967a5f35b # v5.1.0
`)

	claims := extractRefVersionClaims(content)
	if len(claims) != 2 {
		t.Fatalf("expected 2 claims, got %d", len(claims))
	}
	if claims[0].lineNumber != 4 || claims[1].lineNumber != 5 {
		t.Errorf("line numbers = %d, %d; want 4, 5", claims[0].lineNumber, claims[1].lineNumber)
	}
}

// Bare major-version comments such as "# v4" are a common convention.
func TestExtractRefVersionClaims_MajorOnlyComment(t *testing.T) {
	content := []byte(`      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4
`)

	claims := extractRefVersionClaims(content)
	if len(claims) != 1 {
		t.Fatalf("expected 1 claim for major-only comment, got %d", len(claims))
	}
	if claims[0].claimedTag != "v4" {
		t.Errorf("claimedTag = %q, want v4", claims[0].claimedTag)
	}
}

// Repositories disagree on the leading "v", so both spellings are attempted.
func TestCandidateTagNames(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"v1.2.3", []string{"v1.2.3", "1.2.3"}},
		{"1.2.3", []string{"v1.2.3", "1.2.3"}},
	}

	for _, tt := range tests {
		got := candidateTagNames(tt.input)
		if len(got) != len(tt.want) {
			t.Fatalf("candidateTagNames(%q) length = %d, want %d", tt.input, len(got), len(tt.want))
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("candidateTagNames(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

func TestShortSHA(t *testing.T) {
	if got := shortSHA("11bd71901bbe5b1630ceea73d27597364c9af683"); got != "11bd71901bbe" {
		t.Errorf("shortSHA = %q, want 11bd71901bbe", got)
	}
	if got := shortSHA("abc"); got != "abc" {
		t.Errorf("shortSHA of short input = %q, want abc", got)
	}
}

// A workflow containing no SHA pins must return early without any network calls.
func TestCheckRefVersionMismatch_NoClaimsReturnsEarly(t *testing.T) {
	wf := parser.WorkflowFile{
		Path: "test.yml",
		Name: "test.yml",
		Content: []byte(`name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make build
`),
	}

	if findings := checkRefVersionMismatch(wf); len(findings) != 0 {
		t.Fatalf("expected no findings when no SHA pins carry version comments, got %d", len(findings))
	}
}
