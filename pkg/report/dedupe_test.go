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

package report

import (
	"testing"

	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

// TestDeduplicateFindings guards the fix where the summary count was computed on
// the pre-deduplication list while the JSON/SARIF output deduplicated, so the
// headline issue count could exceed the number of findings actually reported.
// CalculateSummary now runs on the deduplicated list returned here.
func TestDeduplicateFindings(t *testing.T) {
	dup := rules.Finding{
		RuleID:     "R1",
		FilePath:   "ci.yml",
		JobName:    "build",
		StepName:   "checkout",
		LineNumber: 10,
		Severity:   rules.Medium,
	}
	other := rules.Finding{
		RuleID:     "R2",
		FilePath:   "ci.yml",
		JobName:    "build",
		StepName:   "test",
		LineNumber: 20,
		Severity:   rules.High,
	}

	in := []rules.Finding{dup, dup, other, dup}
	out := DeduplicateFindings(in)

	if len(out) != 2 {
		t.Fatalf("expected 2 unique findings, got %d", len(out))
	}

	// The summary must agree with the deduplicated set.
	summary := CalculateSummary(out)
	if summary.Total != 2 {
		t.Errorf("summary.Total = %d, want 2 (must match deduplicated findings)", summary.Total)
	}
	if summary.Medium != 1 || summary.High != 1 {
		t.Errorf("severity counts off: medium=%d high=%d", summary.Medium, summary.High)
	}
}
