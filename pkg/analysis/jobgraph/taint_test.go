package jobgraph

import (
	"strings"
	"testing"
	"time"
)

func analyze(t *testing.T, yaml string) []Flow {
	t.Helper()
	return NewAnalyzer(Build(parse(t, yaml))).Analyze()
}

// The attack this engine exists for: an unprivileged job captures
// attacker-controlled text into a job output, and a downstream job executes it.
// Neither job is dangerous alone.
func TestAnalyze_CrossJobTaintReachesRunScript(t *testing.T) {
	flows := analyze(t, `
name: t
on: issue_comment
jobs:
  collect:
    runs-on: ubuntu-latest
    outputs:
      title: ${{ steps.grab.outputs.title }}
    steps:
      - id: grab
        run: echo "title=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT
  deploy:
    needs: [collect]
    runs-on: ubuntu-latest
    steps:
      - name: use it
        run: echo "${{ needs.collect.outputs.title }}"
`)

	if len(flows) != 1 {
		t.Fatalf("expected exactly 1 cross-job flow, got %d: %+v", len(flows), flows)
	}
	f := flows[0]
	if f.Origin.JobID != "collect" {
		t.Errorf("origin job = %q, want collect", f.Origin.JobID)
	}
	if !strings.Contains(f.Origin.Expression, "github.event.issue.title") {
		t.Errorf("origin expression = %q", f.Origin.Expression)
	}
	if f.SinkJob != "deploy" || f.SinkStep != "use it" {
		t.Errorf("sink = %s/%s, want deploy/use it", f.SinkJob, f.SinkStep)
	}
	if f.SinkKind != "run script" {
		t.Errorf("sink kind = %q", f.SinkKind)
	}
	if strings.Join(f.Path, ",") != "collect,deploy" {
		t.Errorf("path = %v, want collect,deploy", f.Path)
	}
}

// Taint must survive an intermediate job that merely forwards the value.
func TestAnalyze_TaintPropagatesThroughIntermediateJob(t *testing.T) {
	flows := analyze(t, `
name: t
on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    outputs:
      v: ${{ steps.s.outputs.v }}
    steps:
      - id: s
        run: echo "v=${{ github.event.issue.body }}" >> $GITHUB_OUTPUT
  b:
    needs: [a]
    runs-on: ubuntu-latest
    outputs:
      v: ${{ needs.a.outputs.v }}
    steps:
      - run: echo forwarding
  c:
    needs: [b]
    runs-on: ubuntu-latest
    steps:
      - run: bash -c "${{ needs.b.outputs.v }}"
`)

	if len(flows) != 1 {
		t.Fatalf("expected 1 flow through the chain, got %d: %+v", len(flows), flows)
	}
	if flows[0].SinkJob != "c" {
		t.Errorf("sink job = %q, want c", flows[0].SinkJob)
	}
	if flows[0].Origin.JobID != "a" {
		t.Errorf("origin should be traced back to a, got %q", flows[0].Origin.JobID)
	}
}

// A job output carrying a trusted value must not be reported.
func TestAnalyze_TrustedOutputIsClean(t *testing.T) {
	flows := analyze(t, `
name: t
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
	if len(flows) != 0 {
		t.Fatalf("github.sha is not attacker-controlled; got %d flows: %+v", len(flows), flows)
	}
}

// Fields under github.event that an attacker does not control must not taint.
func TestAnalyze_NonAttackerControlledEventFieldIsClean(t *testing.T) {
	flows := analyze(t, `
name: t
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    outputs:
      r: ${{ steps.s.outputs.r }}
    steps:
      - id: s
        run: echo "r=${{ github.event.repository.name }}" >> $GITHUB_OUTPUT
  b:
    needs: [a]
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ needs.a.outputs.r }}"
`)
	if len(flows) != 0 {
		t.Fatalf("repository name is not attacker-controlled; got %+v", flows)
	}
}

// Taint confined to one job is the existing rules' job, not this engine's.
func TestAnalyze_SameJobTaintIsNotReported(t *testing.T) {
	flows := analyze(t, `
name: t
on: issues
jobs:
  solo:
    runs-on: ubuntu-latest
    steps:
      - id: s
        run: echo "v=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT
      - run: echo "${{ steps.s.outputs.v }}"
`)
	if len(flows) != 0 {
		t.Fatalf("single-job flows are out of scope here, got %+v", flows)
	}
}

// Consumption through an action input is a sink too.
func TestAnalyze_ActionInputSink(t *testing.T) {
	flows := analyze(t, `
name: t
on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    outputs:
      v: ${{ steps.s.outputs.v }}
    steps:
      - id: s
        run: echo "v=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT
  b:
    needs: [a]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: console.log("${{ needs.a.outputs.v }}")
`)
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow into an action input, got %d", len(flows))
	}
	if !strings.Contains(flows[0].SinkKind, "action input") {
		t.Errorf("sink kind = %q, want an action input", flows[0].SinkKind)
	}
}

// A job output that is never consumed downstream is not a vulnerability.
func TestAnalyze_UnconsumedTaintedOutputIsClean(t *testing.T) {
	flows := analyze(t, `
name: t
on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    outputs:
      v: ${{ steps.s.outputs.v }}
    steps:
      - id: s
        run: echo "v=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT
  b:
    needs: [a]
    runs-on: ubuntu-latest
    steps:
      - run: echo unrelated
`)
	if len(flows) != 0 {
		t.Fatalf("an unconsumed output is not a flow, got %+v", flows)
	}
}

// Cyclic jobs cannot run on GitHub; the analyzer must terminate and report
// nothing for them rather than looping.
func TestAnalyze_CyclicJobsTerminate(t *testing.T) {
	done := make(chan []Flow, 1)
	go func() {
		done <- analyze(t, `
name: t
on: push
jobs:
  a: {needs: [b], runs-on: ubuntu-latest, steps: [{run: x}]}
  b: {needs: [a], runs-on: ubuntu-latest, steps: [{run: x}]}
`)
	}()
	select {
	case flows := <-done:
		if len(flows) != 0 {
			t.Errorf("expected no flows for cyclic jobs, got %+v", flows)
		}
	case <-timeoutAfterSeconds(5):
		t.Fatal("analysis did not terminate on a cyclic graph")
	}
}

func timeoutAfterSeconds(n int) <-chan time.Time {
	return time.After(time.Duration(n) * time.Second)
}
