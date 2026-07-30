package jobgraph

import (
	"strings"
	"testing"

	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
)

func parse(t *testing.T, yaml string) parser.Workflow {
	t.Helper()
	wf := parser.WorkflowFile{Path: "t.yml", Name: "t.yml", Content: []byte(yaml)}
	if err := parser.ParseWorkflowYAML(&wf); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return wf.Workflow
}

func TestBuild_TopologicalOrderRespectsDependencies(t *testing.T) {
	g := Build(parse(t, `
name: t
on: push
jobs:
  deploy:
    needs: [build, test]
    runs-on: ubuntu-latest
    steps: [{run: echo deploy}]
  build:
    needs: prepare
    runs-on: ubuntu-latest
    steps: [{run: echo build}]
  test:
    needs: prepare
    runs-on: ubuntu-latest
    steps: [{run: echo test}]
  prepare:
    runs-on: ubuntu-latest
    steps: [{run: echo prep}]
`))

	order := g.TopologicalOrder()
	if len(order) != 4 {
		t.Fatalf("expected 4 jobs in order, got %d: %v", len(order), order)
	}

	pos := map[string]int{}
	for i, id := range order {
		pos[id] = i
	}
	for _, edge := range [][2]string{{"prepare", "build"}, {"prepare", "test"}, {"build", "deploy"}, {"test", "deploy"}} {
		if pos[edge[0]] >= pos[edge[1]] {
			t.Errorf("%s must come before %s; order was %v", edge[0], edge[1], order)
		}
	}
	if len(g.Cyclic()) != 0 {
		t.Errorf("expected no cycles, got %v", g.Cyclic())
	}
}

// Order must not depend on Go's randomised map iteration, or findings would
// shuffle between runs.
func TestBuild_OrderIsDeterministic(t *testing.T) {
	src := `
name: t
on: push
jobs:
  a: {runs-on: ubuntu-latest, steps: [{run: x}]}
  b: {runs-on: ubuntu-latest, steps: [{run: x}]}
  c: {runs-on: ubuntu-latest, steps: [{run: x}]}
  d: {needs: [a, b, c], runs-on: ubuntu-latest, steps: [{run: x}]}
  e: {needs: [a], runs-on: ubuntu-latest, steps: [{run: x}]}
`
	first := strings.Join(Build(parse(t, src)).TopologicalOrder(), ",")
	for i := 0; i < 20; i++ {
		if got := strings.Join(Build(parse(t, src)).TopologicalOrder(), ","); got != first {
			t.Fatalf("run %d differed: %s vs %s", i, got, first)
		}
	}
}

// GitHub rejects cyclic needs, but a file on disk can still contain one and the
// analyzer must terminate rather than hang.
func TestBuild_DetectsCycle(t *testing.T) {
	g := Build(parse(t, `
name: t
on: push
jobs:
  a: {needs: [c], runs-on: ubuntu-latest, steps: [{run: x}]}
  b: {needs: [a], runs-on: ubuntu-latest, steps: [{run: x}]}
  c: {needs: [b], runs-on: ubuntu-latest, steps: [{run: x}]}
  standalone: {runs-on: ubuntu-latest, steps: [{run: x}]}
`))

	if len(g.TopologicalOrder()) != 1 || g.TopologicalOrder()[0] != "standalone" {
		t.Errorf("only the acyclic job should be ordered, got %v", g.TopologicalOrder())
	}
	cyc := strings.Join(g.Cyclic(), ",")
	if cyc != "a,b,c" {
		t.Errorf("expected a,b,c in the cycle, got %q", cyc)
	}
}

// A needs: entry naming a nonexistent job is invalid but must not break the
// rest of the analysis.
func TestBuild_IgnoresDanglingDependency(t *testing.T) {
	g := Build(parse(t, `
name: t
on: push
jobs:
  a: {needs: [ghost], runs-on: ubuntu-latest, steps: [{run: x}]}
`))
	if len(g.TopologicalOrder()) != 1 {
		t.Errorf("expected the job to still be ordered, got %v", g.TopologicalOrder())
	}
	if len(g.Nodes["a"].Needs) != 0 {
		t.Errorf("dangling dependency should be dropped, got %v", g.Nodes["a"].Needs)
	}
}

func TestBuild_ScalarNeeds(t *testing.T) {
	g := Build(parse(t, `
name: t
on: push
jobs:
  a: {runs-on: ubuntu-latest, steps: [{run: x}]}
  b: {needs: a, runs-on: ubuntu-latest, steps: [{run: x}]}
`))
	if len(g.Nodes["b"].Needs) != 1 || g.Nodes["b"].Needs[0] != "a" {
		t.Errorf("scalar needs not handled: %v", g.Nodes["b"].Needs)
	}
}

func TestAncestors(t *testing.T) {
	g := Build(parse(t, `
name: t
on: push
jobs:
  a: {runs-on: ubuntu-latest, steps: [{run: x}]}
  b: {needs: [a], runs-on: ubuntu-latest, steps: [{run: x}]}
  c: {needs: [b], runs-on: ubuntu-latest, steps: [{run: x}]}
`))
	got := strings.Join(g.Ancestors("c"), ",")
	if got != "a,b" {
		t.Errorf("Ancestors(c) = %q, want a,b", got)
	}
	if len(g.Ancestors("a")) != 0 {
		t.Errorf("Ancestors(a) should be empty, got %v", g.Ancestors("a"))
	}
}
