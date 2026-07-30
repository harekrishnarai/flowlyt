package ai

import (
	"strings"
	"testing"

	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
	"github.com/harekrishnarai/flowlyt/v2/pkg/rules"
)

const ctxWorkflow = `name: Deploy
on:
  pull_request_target:
    types: [opened]
  push:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    needs: [prepare]
    permissions:
      contents: write
      id-token: write
    steps:
      - name: checkout
        uses: actions/checkout@v4
      - name: risky
        run: echo "${{ github.event.pull_request.title }}"
  prepare:
    runs-on: self-hosted
    steps:
      - run: make prep
`

func ctxProvider(t *testing.T) *ContextProvider {
	t.Helper()
	wf := parser.WorkflowFile{Path: ".github/workflows/deploy.yml", Name: "deploy.yml", Content: []byte(ctxWorkflow)}
	if err := parser.ParseWorkflowYAML(&wf); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return NewContextProvider([]parser.WorkflowFile{wf})
}

// The whole point of the context provider is that the model receives the facts
// the prompts ask about. Permissions in particular were never sent before.
func TestContextProvider_SuppliesPermissionsAndTriggers(t *testing.T) {
	p := ctxProvider(t)
	got := p.For(rules.Finding{
		FilePath: ".github/workflows/deploy.yml",
		JobName:  "build",
		StepName: "risky",
		// Line of the `run:` inside the risky step.
		LineNumber: 19,
	})

	if got.JobPermissions == "" || !strings.Contains(got.JobPermissions, "contents: write") {
		t.Errorf("job permissions missing or wrong: %q", got.JobPermissions)
	}
	if !strings.Contains(got.JobPermissions, "id-token: write") {
		t.Errorf("expected id-token in job permissions, got %q", got.JobPermissions)
	}
	if !strings.Contains(got.WorkflowPermissions, "contents: read") {
		t.Errorf("workflow permissions wrong: %q", got.WorkflowPermissions)
	}

	joined := strings.Join(got.WorkflowTriggers, ",")
	if !strings.Contains(joined, "pull_request_target") || !strings.Contains(joined, "push") {
		t.Errorf("triggers wrong: %v", got.WorkflowTriggers)
	}
	if len(got.JobNeeds) != 1 || got.JobNeeds[0] != "prepare" {
		t.Errorf("job needs wrong: %v", got.JobNeeds)
	}
	if got.JobRunsOn != "ubuntu-latest" {
		t.Errorf("runner wrong: %q", got.JobRunsOn)
	}
	if !strings.Contains(got.StepRun, "github.event.pull_request.title") {
		t.Errorf("step run not captured: %q", got.StepRun)
	}
}

// Absent permissions must not be rendered as empty: inheriting the repository
// default is materially different from granting nothing.
func TestContextProvider_DistinguishesAbsentFromEmptyPermissions(t *testing.T) {
	p := ctxProvider(t)
	got := p.For(rules.Finding{
		FilePath:   ".github/workflows/deploy.yml",
		JobName:    "prepare",
		LineNumber: 23,
	})
	if !strings.Contains(got.JobPermissions, "not set") {
		t.Errorf("absent job permissions should say so, got %q", got.JobPermissions)
	}

	if empty := renderPermissions(map[string]interface{}{}); !strings.Contains(empty, "no permissions") {
		t.Errorf("empty permissions should be explicit, got %q", empty)
	}
}

func TestContextProvider_SnippetMarksTheFindingLine(t *testing.T) {
	p := ctxProvider(t)
	got := p.For(rules.Finding{
		FilePath:   ".github/workflows/deploy.yml",
		JobName:    "build",
		StepName:   "risky",
		LineNumber: 19,
	})

	if got.Snippet == "" {
		t.Fatal("expected a snippet")
	}
	var marked string
	for _, line := range strings.Split(got.Snippet, "\n") {
		if strings.HasPrefix(line, "> ") {
			marked = line
		}
	}
	if marked == "" {
		t.Fatal("snippet must mark the finding line with '>'")
	}
	if !strings.Contains(marked, "19") {
		t.Errorf("marked line should be 19, got %q", marked)
	}
}

// An unresolvable finding must degrade gracefully, not panic or error.
func TestContextProvider_UnknownFileYieldsEmptyContext(t *testing.T) {
	p := ctxProvider(t)
	got := p.For(rules.Finding{FilePath: "nope.yml", JobName: "build"})
	if got.Snippet != "" || got.JobPermissions != "" {
		t.Errorf("expected empty context for an unknown file, got %+v", got)
	}

	var nilProvider *ContextProvider
	if c := nilProvider.For(rules.Finding{}); c.Snippet != "" {
		t.Error("a nil provider must return an empty context")
	}
}

// Unnamed steps are reported as "Step N"; the provider must resolve those.
func TestContextProvider_ResolvesSyntheticStepNames(t *testing.T) {
	p := ctxProvider(t)
	got := p.For(rules.Finding{
		FilePath: ".github/workflows/deploy.yml",
		JobName:  "prepare",
		StepName: "Step 1",
	})
	if !strings.Contains(got.StepRun, "make prep") {
		t.Errorf("synthetic step name not resolved, got %q", got.StepRun)
	}
}

// The prompt must actually carry the context; this guards against the payload
// and the prompt text drifting apart again.
func TestComposeBatchPrompt_IncludesRealContext(t *testing.T) {
	p := ctxProvider(t)
	f := rules.Finding{
		RuleID:     "INJECTION_VULNERABILITY",
		FilePath:   ".github/workflows/deploy.yml",
		JobName:    "build",
		StepName:   "risky",
		LineNumber: 19,
		Evidence:   `echo "${{ github.event.pull_request.title }}"`,
		Category:   rules.InjectionAttack,
	}
	_, user := composeBatchPrompt("injection", []ContextualFinding{{Finding: f, Context: p.For(f)}})

	for _, want := range []string{
		"workflow_triggers", "pull_request_target",
		"job_permissions", "contents: write",
		"workflow_snippet", "step_run",
	} {
		if !strings.Contains(user, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
}
