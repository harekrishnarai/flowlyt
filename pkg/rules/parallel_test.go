package rules_test

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/harekrishnarai/flowlyt/v2/pkg/rules"
)

// ExecuteRules evaluates rules concurrently. Its output must be byte-identical
// to sequential evaluation, in the same order, or reports become
// non-reproducible between runs.
func TestExecuteRules_ParallelMatchesSequential(t *testing.T) {
	wf := makeWorkflow(t, `
name: Mixed
on: [push, pull_request_target]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: node:latest
      credentials:
        username: bot
        password: literalpassword123
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: true
          ref: ${{ github.event.pull_request.head.sha }}
      - run: |
          curl -sSL http://mirror.acme-corp.net/i.sh | bash
          npm install left-pad
          go install github.com/foo/bar@latest
          echo "${{ github.event.pull_request.title }}" > /tmp/p.sh
          bash /tmp/p.sh
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
      - run: ./deploy.sh --token ${{ secrets.DEPLOY_TOKEN }}
`)

	all := offlineRules()
	engine := rules.NewRuleEngine(nil)

	// Forcing a single processor drives ExecuteRules down its sequential
	// branch, giving a like-for-like reference that still applies
	// configuration filtering and context-aware adjustment.
	prev := runtime.GOMAXPROCS(1)
	sequential := engine.ExecuteRules(wf, all)
	runtime.GOMAXPROCS(prev)

	parallel := engine.ExecuteRules(wf, all)

	if len(parallel) != len(sequential) {
		t.Fatalf("finding count differs: parallel=%d sequential=%d", len(parallel), len(sequential))
	}

	key := func(f rules.Finding) string {
		return fmt.Sprintf("%s|%s|%d|%s|%s|%s", f.RuleID, f.FilePath, f.LineNumber, f.JobName, f.StepName, f.Evidence)
	}
	for i := range parallel {
		if got, want := key(parallel[i]), key(sequential[i]); got != want {
			t.Fatalf("finding %d differs:\n parallel:   %s\n sequential: %s", i, got, want)
		}
	}
}

// Repeated runs must produce identical output; a map iteration or scheduling
// difference leaking into the result would make reports unstable.
func TestExecuteRules_IsDeterministicAcrossRuns(t *testing.T) {
	wf := makeWorkflow(t, `
name: Repeat
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm install lodash
  b:
    runs-on: ubuntu-latest
    steps:
      - run: curl http://insecure.acme-corp.net/x | bash
`)

	all := offlineRules()
	engine := rules.NewRuleEngine(nil)

	render := func(fs []rules.Finding) string {
		s := ""
		for _, f := range fs {
			s += fmt.Sprintf("%s@%d:%s\n", f.RuleID, f.LineNumber, f.Evidence)
		}
		return s
	}

	first := render(engine.ExecuteRules(wf, all))
	for i := 0; i < 25; i++ {
		if got := render(engine.ExecuteRules(wf, all)); got != first {
			t.Fatalf("run %d differed from the first run", i+1)
		}
	}
}
