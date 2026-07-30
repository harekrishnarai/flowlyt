package rules_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
	"github.com/harekrishnarai/flowlyt/v2/pkg/rules"
)

// buildRepo writes a repository tree and returns the parsed caller workflow,
// with the absolute Path a real scan would produce.
func buildRepo(t *testing.T, files map[string]string, callerRel string) parser.WorkflowFile {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	full := filepath.Join(root, filepath.FromSlash(callerRel))
	content, err := os.ReadFile(full)
	if err != nil {
		t.Fatal(err)
	}
	wf := parser.WorkflowFile{Path: full, Name: filepath.Base(full), Content: content}
	if err := parser.ParseWorkflowYAML(&wf); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return wf
}

func crossFileFindings(t *testing.T, wf parser.WorkflowFile) []rules.Finding {
	t.Helper()
	var out []rules.Finding
	for _, f := range rules.CheckCrossFileTaint(wf) {
		if f.RuleID == "CROSS_FILE_TAINT" {
			out = append(out, f)
		}
	}
	return out
}

// The caller only passes a parameter and the action only uses its own declared
// input; the vulnerability is the composition of the two.
func TestCrossFileTaint_UntrustedInputExecutedByCompositeAction(t *testing.T) {
	wf := buildRepo(t, map[string]string{
		".github/actions/greet/action.yml": `
inputs:
  message: {description: shown}
runs:
  using: composite
  steps:
    - run: echo "${{ inputs.message }}"
      shell: bash
`,
		".github/workflows/ci.yml": `
name: CI
on: issue_comment
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - name: say hello
        uses: ./.github/actions/greet
        with:
          message: ${{ github.event.comment.body }}
`,
	}, ".github/workflows/ci.yml")

	findings := crossFileFindings(t, wf)
	if len(findings) != 1 {
		t.Fatalf("expected 1 cross-file finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != rules.Critical {
		t.Errorf("severity = %s, want CRITICAL", f.Severity)
	}
	if !strings.Contains(f.Evidence, "github.event.comment.body") {
		t.Errorf("evidence should name the untrusted source: %q", f.Evidence)
	}
	if !strings.Contains(f.Evidence, "actions/greet/action.yml") {
		t.Errorf("evidence should name the resolved file: %q", f.Evidence)
	}
	if f.LineNumber == 0 {
		t.Error("finding should resolve to a line in the caller")
	}
}

// An input the action never executes is not a vulnerability.
func TestCrossFileTaint_NonExecutedInputIsClean(t *testing.T) {
	wf := buildRepo(t, map[string]string{
		".github/actions/label/action.yml": `
inputs:
  name: {description: artifact name}
runs:
  using: composite
  steps:
    - uses: actions/upload-artifact@v4
      with:
        name: ${{ inputs.name }}
`,
		".github/workflows/ci.yml": `
name: CI
on: issue_comment
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/label
        with:
          name: ${{ github.event.comment.body }}
`,
	}, ".github/workflows/ci.yml")

	if findings := crossFileFindings(t, wf); len(findings) != 0 {
		t.Fatalf("an input that is never executed must be clean, got %+v", findings)
	}
}

// Trusted data passed to an executing input is not a vulnerability.
func TestCrossFileTaint_TrustedInputIsClean(t *testing.T) {
	wf := buildRepo(t, map[string]string{
		".github/actions/greet/action.yml": `
inputs:
  message: {description: shown}
runs:
  using: composite
  steps:
    - run: echo "${{ inputs.message }}"
      shell: bash
`,
		".github/workflows/ci.yml": `
name: CI
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/greet
        with:
          message: ${{ github.sha }}
`,
	}, ".github/workflows/ci.yml")

	if findings := crossFileFindings(t, wf); len(findings) != 0 {
		t.Fatalf("github.sha is not attacker-controlled, got %+v", findings)
	}
}

// Reusable workflows are called at job level and carry the same risk.
func TestCrossFileTaint_ReusableWorkflowCall(t *testing.T) {
	wf := buildRepo(t, map[string]string{
		".github/workflows/deploy.yml": `
name: deploy
on:
  workflow_call:
    inputs:
      target: {type: string}
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh "${{ inputs.target }}"
`,
		".github/workflows/ci.yml": `
name: CI
on: issues
jobs:
  call:
    uses: ./.github/workflows/deploy.yml
    with:
      target: ${{ github.event.issue.title }}
`,
	}, ".github/workflows/ci.yml")

	findings := crossFileFindings(t, wf)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for the reusable workflow call, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Evidence, "reusable workflow") {
		t.Errorf("evidence should identify the target kind: %q", findings[0].Evidence)
	}
}

// Remote actions cannot be resolved from the working tree and must not be
// guessed at.
func TestCrossFileTaint_RemoteActionIsIgnored(t *testing.T) {
	wf := buildRepo(t, map[string]string{
		".github/workflows/ci.yml": `
name: CI
on: issue_comment
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: some/remote-action@v1
        with:
          message: ${{ github.event.comment.body }}
`,
	}, ".github/workflows/ci.yml")

	if findings := crossFileFindings(t, wf); len(findings) != 0 {
		t.Fatalf("remote actions are out of scope here, got %+v", findings)
	}
}

// A workflow outside the expected layout has no repository tree to resolve
// against and must degrade quietly rather than error.
func TestCrossFileTaint_NoRepoRootIsClean(t *testing.T) {
	wf := makeWorkflow(t, `
name: CI
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/x
        with:
          message: ${{ github.event.issue.title }}
`)
	if findings := crossFileFindings(t, wf); len(findings) != 0 {
		t.Fatalf("expected no findings without a resolvable root, got %+v", findings)
	}
}
