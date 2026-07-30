package resolve

import (
	"os"
	"path/filepath"
	"testing"
)

// scaffold builds a repository tree and returns its root.
func scaffold(t *testing.T, files map[string]string) string {
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
	return root
}

func TestRepoRootFor(t *testing.T) {
	if got := RepoRootFor("/repo/.github/workflows/ci.yml"); got != "/repo" {
		t.Errorf("got %q, want /repo", got)
	}
	// Anything not laid out as <root>/.github/workflows/<file> yields no root,
	// so no local resolution is attempted.
	for _, p := range []string{"/repo/ci.yml", "/repo/.github/ci.yml", "ci.yml"} {
		if got := RepoRootFor(p); got != "" {
			t.Errorf("RepoRootFor(%q) = %q, want empty", p, got)
		}
	}
}

// A `uses:` value is repository data and must never be trusted to stay inside
// the tree, or the analyzer could be made to read arbitrary files.
func TestResolveUses_RefusesPathTraversal(t *testing.T) {
	root := scaffold(t, map[string]string{
		".github/actions/ok/action.yml": "runs:\n  using: composite\n  steps: []\n",
	})
	// A file that exists outside the repository root.
	outside := filepath.Join(filepath.Dir(root), "outside-action")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "action.yml"),
		[]byte("runs:\n  using: composite\n  steps: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := NewRepo(root)
	for _, escape := range []string{
		"./../outside-action",
		"./../../etc",
		"./.github/../../outside-action",
	} {
		if _, ok := r.ResolveUses(escape); ok {
			t.Errorf("resolver escaped the repository root via %q", escape)
		}
	}

	// The legitimate reference still resolves.
	if _, ok := r.ResolveUses("./.github/actions/ok"); !ok {
		t.Error("expected the in-tree action to resolve")
	}
}

func TestResolveUses_IgnoresRemoteReferences(t *testing.T) {
	r := NewRepo(scaffold(t, map[string]string{}))
	for _, remote := range []string{"actions/checkout@v4", "docker://alpine", "owner/repo/.github/workflows/x.yml@main"} {
		if _, ok := r.ResolveUses(remote); ok {
			t.Errorf("%q is remote and must not resolve locally", remote)
		}
	}
}

// JavaScript and Docker actions execute code this analysis cannot read, so they
// are deliberately not resolved.
func TestResolveUses_OnlyCompositeActions(t *testing.T) {
	root := scaffold(t, map[string]string{
		".github/actions/js/action.yml": "runs:\n  using: node20\n  main: index.js\n",
		".github/actions/comp/action.yml": `
inputs:
  cmd: {description: c}
runs:
  using: composite
  steps:
    - run: echo "${{ inputs.cmd }}"
      shell: bash
`,
	})
	r := NewRepo(root)

	if _, ok := r.ResolveUses("./.github/actions/js"); ok {
		t.Error("a JavaScript action must not resolve")
	}
	def, ok := r.ResolveUses("./.github/actions/comp")
	if !ok {
		t.Fatal("expected the composite action to resolve")
	}
	if def.Kind != KindCompositeAction {
		t.Errorf("kind = %v, want composite", def.Kind)
	}
	if !def.Inputs["cmd"] {
		t.Errorf("declared inputs not captured: %v", def.Inputs)
	}
}

func TestExecutedInputs_CompositeAction(t *testing.T) {
	root := scaffold(t, map[string]string{
		".github/actions/a/action.yml": `
inputs:
  cmd: {description: executed}
  label: {description: not executed}
runs:
  using: composite
  steps:
    - run: echo "${{ inputs.cmd }}"
      shell: bash
    - uses: actions/upload-artifact@v4
      with:
        name: ${{ inputs.label }}
`,
	})
	def, ok := NewRepo(root).ResolveUses("./.github/actions/a")
	if !ok {
		t.Fatal("resolve failed")
	}

	uses := def.ExecutedInputs()
	if len(uses) != 1 {
		t.Fatalf("expected only the executed input, got %d: %+v", len(uses), uses)
	}
	if uses[0].Input != "cmd" {
		t.Errorf("input = %q, want cmd", uses[0].Input)
	}
	if uses[0].Line == 0 {
		t.Error("expected a line number within the action file")
	}
}

// An input referenced but not declared belongs to some other scope and must not
// be treated as this definition's.
func TestExecutedInputs_IgnoresUndeclaredInputs(t *testing.T) {
	root := scaffold(t, map[string]string{
		".github/actions/a/action.yml": `
inputs:
  known: {description: d}
runs:
  using: composite
  steps:
    - run: echo "${{ inputs.unknown }}"
      shell: bash
`,
	})
	def, _ := NewRepo(root).ResolveUses("./.github/actions/a")
	if uses := def.ExecutedInputs(); len(uses) != 0 {
		t.Errorf("undeclared input must be ignored, got %+v", uses)
	}
}

func TestResolveUses_ReusableWorkflow(t *testing.T) {
	root := scaffold(t, map[string]string{
		".github/workflows/reusable.yml": `
name: reusable
on:
  workflow_call:
    inputs:
      target: {type: string}
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - run: deploy.sh "${{ inputs.target }}"
`,
	})
	def, ok := NewRepo(root).ResolveUses("./.github/workflows/reusable.yml")
	if !ok {
		t.Fatal("expected the reusable workflow to resolve")
	}
	if def.Kind != KindReusableWorkflow {
		t.Errorf("kind = %v, want reusable workflow", def.Kind)
	}
	if !def.Inputs["target"] {
		t.Errorf("workflow_call inputs not captured: %v", def.Inputs)
	}
	uses := def.ExecutedInputs()
	if len(uses) != 1 || uses[0].Input != "target" {
		t.Errorf("expected target to be executed, got %+v", uses)
	}
}

// The same action is commonly used by many workflows; parsing must be cached.
func TestResolveUses_CachesAndRemembersMisses(t *testing.T) {
	root := scaffold(t, map[string]string{
		".github/actions/a/action.yml": "runs:\n  using: composite\n  steps: []\n",
	})
	r := NewRepo(root)

	first, ok1 := r.ResolveUses("./.github/actions/a")
	second, ok2 := r.ResolveUses("./.github/actions/a")
	if !ok1 || !ok2 || first != second {
		t.Error("expected the same cached definition instance")
	}

	if _, ok := r.ResolveUses("./.github/actions/missing"); ok {
		t.Error("missing action must not resolve")
	}
	if !r.misses[mustAbs(t, filepath.Join(root, ".github/actions/missing"))] {
		t.Error("expected the miss to be recorded")
	}
}

func mustAbs(t *testing.T, p string) string {
	t.Helper()
	a, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
