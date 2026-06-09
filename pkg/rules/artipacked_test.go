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

package rules_test

import (
	"testing"

	"github.com/harekrishnarai/flowlyt/v2/pkg/rules"
)

// checkoutFindingSeverity returns the severity of the "Credential Persistence
// Risk" (checkout) finding, or fatally fails if none is present.
func checkoutFindingSeverity(t *testing.T, findings []rules.Finding) rules.Severity {
	t.Helper()
	for _, f := range findings {
		if f.RuleName == "Credential Persistence Risk" {
			return f.Severity
		}
	}
	t.Fatalf("no checkout credential-persistence finding among %d findings", len(findings))
	return ""
}

// TestArtipackedSeverityGating verifies the ArtiPACKED accuracy fix: a checkout
// missing persist-credentials:false is only HIGH when the job also uploads an
// artifact that can include the .git directory; otherwise it is a LOW hardening
// note (preventing a HIGH finding on essentially every workflow).
func TestArtipackedSeverityGating(t *testing.T) {
	rule := findRule(t, "ARTIPACKED_VULNERABILITY")

	tests := []struct {
		name string
		yaml string
		want rules.Severity
	}{
		{
			name: "checkout only, no artifact upload -> LOW",
			yaml: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: go test ./...
`,
			want: rules.Low,
		},
		{
			name: "checkout + upload repo root (.git included) -> HIGH",
			yaml: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/upload-artifact@v4
        with:
          path: .
`,
			want: rules.High,
		},
		{
			name: "checkout + upload narrow path (no .git) -> LOW",
			yaml: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/upload-artifact@v4
        with:
          path: dist/
`,
			want: rules.Low,
		},
		{
			name: "upload-artifact in a different job does not raise the checkout severity",
			yaml: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: go build ./...
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@v4
        with:
          path: .
`,
			want: rules.Low,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wf := makeWorkflow(t, tt.yaml)
			if got := checkoutFindingSeverity(t, rule.Check(wf)); got != tt.want {
				t.Errorf("checkout severity = %s, want %s", got, tt.want)
			}
		})
	}
}
