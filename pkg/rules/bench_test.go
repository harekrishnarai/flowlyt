package rules_test

import (
	"fmt"
	"testing"

	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
	"github.com/harekrishnarai/flowlyt/v2/pkg/rules"
)

// benchWorkflowYAML builds a workflow of realistic size: several jobs, each
// with a mix of action and run steps.
func benchWorkflowYAML(jobs, steps int) string {
	s := "name: Bench\non: [push, pull_request]\npermissions:\n  contents: read\njobs:\n"
	for j := 0; j < jobs; j++ {
		s += fmt.Sprintf("  job%d:\n    runs-on: ubuntu-latest\n    steps:\n", j)
		for k := 0; k < steps; k++ {
			s += fmt.Sprintf("      - uses: actions/checkout@v4\n")
			s += fmt.Sprintf("      - name: build %d\n        run: |\n          npm ci\n          make build TARGET=%d\n          echo \"done ${{ github.sha }}\"\n", k, k)
		}
	}
	return s
}

func benchWorkflow(b *testing.B, jobs, steps int) parser.WorkflowFile {
	b.Helper()
	wf := parser.WorkflowFile{Path: ".github/workflows/bench.yml", Name: "bench.yml", Content: []byte(benchWorkflowYAML(jobs, steps))}
	if err := parser.ParseWorkflowYAML(&wf); err != nil {
		b.Fatal(err)
	}
	return wf
}

// onlineRuleIDs make GitHub API calls; excluding them keeps the benchmark
// measuring CPU work rather than network latency.
var onlineRuleIDs = map[string]bool{
	"STALE_ACTION_REFS":          true,
	"ARCHIVED_ACTION_SOURCE":     true,
	"REF_VERSION_MISMATCH":       true,
	"ADVANCED_VULNERABLE_ACTION": true,
	"REPO_JACKING_VULNERABILITY": true,
}

func offlineRules() []rules.Rule {
	var out []rules.Rule
	for _, r := range rules.StandardRules() {
		if !onlineRuleIDs[r.ID] {
			out = append(out, r)
		}
	}
	return out
}

// BenchmarkStandardRules measures a full rule-set pass over one workflow.
func BenchmarkStandardRules(b *testing.B) {
	for _, sz := range []struct {
		name        string
		jobs, steps int
	}{
		{"small_2x3", 2, 3},
		{"medium_5x10", 5, 10},
		{"large_10x20", 10, 20},
	} {
		b.Run(sz.name, func(b *testing.B) {
			wf := benchWorkflow(b, sz.jobs, sz.steps)
			all := offlineRules()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, r := range all {
					_ = r.Check(wf)
				}
			}
		})
	}
}

// BenchmarkRuleEngine measures the path the CLI actually uses, including
// configuration filtering and context-aware adjustment.
func BenchmarkRuleEngine(b *testing.B) {
	for _, sz := range []struct {
		name        string
		jobs, steps int
	}{
		{"small_2x3", 2, 3},
		{"large_10x20", 10, 20},
	} {
		b.Run(sz.name, func(b *testing.B) {
			wf := benchWorkflow(b, sz.jobs, sz.steps)
			all := offlineRules()
			engine := rules.NewRuleEngine(nil)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = engine.ExecuteRules(wf, all)
			}
		})
	}
}
