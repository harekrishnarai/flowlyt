package rules_test

import (
	"strings"
	"testing"

	"github.com/harekrishnarai/flowlyt/v2/pkg/rules"
)

func TestCrossJobTaint_ReportsExecutionOfUpstreamUntrustedOutput(t *testing.T) {
	findings := findingsFor(t, "CROSS_JOB_TAINT", `
name: Triage
on: issue_comment
jobs:
  collect:
    runs-on: ubuntu-latest
    outputs:
      title: ${{ steps.grab.outputs.title }}
    steps:
      - id: grab
        run: echo "title=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT
  publish:
    needs: [collect]
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - name: announce
        run: echo "${{ needs.collect.outputs.title }}"
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 cross-job finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != rules.Critical {
		t.Errorf("severity = %s, want CRITICAL", f.Severity)
	}
	if f.JobName != "publish" {
		t.Errorf("finding should be attributed to the consuming job, got %q", f.JobName)
	}
	if !strings.Contains(f.Evidence, "collect → publish") {
		t.Errorf("evidence should show the job path, got: %q", f.Evidence)
	}
	if !strings.Contains(f.Evidence, "github.event.issue.title") {
		t.Errorf("evidence should name the untrusted origin, got: %q", f.Evidence)
	}
	if f.LineNumber == 0 {
		t.Error("finding should resolve to the consuming line")
	}
}

func TestCrossJobTaint_TrustedDataIsClean(t *testing.T) {
	findings := findingsFor(t, "CROSS_JOB_TAINT", `
name: Build
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      sha: ${{ steps.s.outputs.sha }}
    steps:
      - id: s
        run: echo "sha=${{ github.sha }}" >> $GITHUB_OUTPUT
  deploy:
    needs: [build]
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ needs.build.outputs.sha }}"
`)
	if len(findings) != 0 {
		t.Fatalf("trusted data must not be reported, got %d", len(findings))
	}
}

// Passing the value through env: is the documented mitigation and must not be
// reported, or the rule would have no actionable fix.
func TestCrossJobTaint_EnvIndirectionIsClean(t *testing.T) {
	findings := findingsFor(t, "CROSS_JOB_TAINT", `
name: Triage
on: issue_comment
jobs:
  collect:
    runs-on: ubuntu-latest
    outputs:
      title: ${{ steps.grab.outputs.title }}
    steps:
      - id: grab
        run: echo "title=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT
  publish:
    needs: [collect]
    runs-on: ubuntu-latest
    steps:
      - name: announce
        run: echo "$TITLE"
        env:
          TITLE: ${{ needs.collect.outputs.title }}
`)
	if len(findings) != 0 {
		t.Fatalf("env indirection is the recommended fix and must be clean, got %d: %+v", len(findings), findings)
	}
}

// Single-job workflows are the existing rules' territory; this rule must not
// duplicate them.
func TestCrossJobTaint_SingleJobIsClean(t *testing.T) {
	findings := findingsFor(t, "CROSS_JOB_TAINT", `
name: Solo
on: issues
jobs:
  only:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
`)
	if len(findings) != 0 {
		t.Fatalf("single-job workflows are out of scope, got %d", len(findings))
	}
}
