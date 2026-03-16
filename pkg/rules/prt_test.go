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

	"github.com/harekrishnarai/flowlyt/pkg/parser"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
	"gopkg.in/yaml.v3"
)

// buildPRTWorkflowFile parses a YAML string into a parser.WorkflowFile for PRT rule tests.
func buildPRTWorkflowFile(t *testing.T, content string) parser.WorkflowFile {
	t.Helper()
	var wf parser.Workflow
	if err := yaml.Unmarshal([]byte(content), &wf); err != nil {
		t.Fatalf("failed to parse workflow YAML: %v", err)
	}
	return parser.WorkflowFile{
		Path:     "test.yml",
		Name:     "test.yml",
		Content:  []byte(content),
		Workflow: wf,
	}
}

// prtFindingsForRule returns all INSECURE_PULL_REQUEST_TARGET findings from CheckAll.
func prtFindingsForRule(wf parser.WorkflowFile) []rules.Finding {
	var result []rules.Finding
	for _, r := range rules.StandardRules() {
		if r.ID == "INSECURE_PULL_REQUEST_TARGET" {
			result = append(result, r.Check(wf)...)
		}
	}
	return result
}

// TestPRT_CriticalForHeadCheckout verifies that pull_request_target + checkout with
// ref: ${{ github.event.pull_request.head.sha }} yields a CRITICAL finding.
func TestPRT_CriticalForHeadCheckout(t *testing.T) {
	wf := buildPRTWorkflowFile(t, `
name: PR Head Checkout
on: pull_request_target

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR head
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Build
        run: make build
`)

	findings := prtFindingsForRule(wf)

	if len(findings) == 0 {
		t.Fatal("expected at least one INSECURE_PULL_REQUEST_TARGET finding, got none")
	}
	for _, f := range findings {
		if f.Severity != rules.Critical {
			t.Errorf("expected CRITICAL severity for head.sha checkout, got %s (evidence: %s)", f.Severity, f.Evidence)
		}
	}
}

// TestPRT_CriticalForHeadRef verifies that checkout with ref: ${{ github.event.pull_request.head.ref }}
// also yields CRITICAL.
func TestPRT_CriticalForHeadRef(t *testing.T) {
	wf := buildPRTWorkflowFile(t, `
name: PR Head Ref Checkout
on: pull_request_target

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR head ref
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
`)

	findings := prtFindingsForRule(wf)

	if len(findings) == 0 {
		t.Fatal("expected at least one INSECURE_PULL_REQUEST_TARGET finding, got none")
	}
	for _, f := range findings {
		if f.Severity != rules.Critical {
			t.Errorf("expected CRITICAL severity for head.ref checkout, got %s", f.Severity)
		}
	}
}

// TestPRT_CriticalForGithubHeadRef verifies that checkout with ref: ${{ github.head_ref }}
// also yields CRITICAL.
func TestPRT_CriticalForGithubHeadRef(t *testing.T) {
	wf := buildPRTWorkflowFile(t, `
name: Github Head Ref Checkout
on: pull_request_target

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
`)

	findings := prtFindingsForRule(wf)

	if len(findings) == 0 {
		t.Fatal("expected INSECURE_PULL_REQUEST_TARGET finding, got none")
	}
	for _, f := range findings {
		if f.Severity != rules.Critical {
			t.Errorf("expected CRITICAL for github.head_ref checkout, got %s", f.Severity)
		}
	}
}

// TestPRT_MediumForBaseCheckout verifies that pull_request_target + checkout without a ref
// (defaults to base branch) yields a MEDIUM finding.
func TestPRT_MediumForBaseCheckout(t *testing.T) {
	wf := buildPRTWorkflowFile(t, `
name: PR Base Checkout
on: pull_request_target

jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout base
        uses: actions/checkout@v4
      - name: Run tests
        run: make test
`)

	findings := prtFindingsForRule(wf)

	if len(findings) == 0 {
		t.Fatal("expected at least one INSECURE_PULL_REQUEST_TARGET finding, got none")
	}
	for _, f := range findings {
		if f.Severity == rules.Critical {
			t.Errorf("expected non-CRITICAL severity for base checkout, got CRITICAL (evidence: %s)", f.Evidence)
		}
		if f.Severity != rules.Medium {
			t.Errorf("expected MEDIUM severity for base checkout, got %s", f.Severity)
		}
	}
}

// TestPRT_InfoForNoCheckout verifies that pull_request_target without any checkout step
// yields an INFO finding (labeling/commenting workflows).
func TestPRT_InfoForNoCheckout(t *testing.T) {
	wf := buildPRTWorkflowFile(t, `
name: PR Labeler
on: pull_request_target

jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - name: Apply label
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.addLabels({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              labels: ['needs-review']
            })
`)

	findings := prtFindingsForRule(wf)

	if len(findings) == 0 {
		t.Fatal("expected at least one INSECURE_PULL_REQUEST_TARGET finding (INFO level), got none")
	}
	for _, f := range findings {
		if f.Severity == rules.Critical {
			t.Errorf("expected non-CRITICAL severity for no-checkout workflow, got CRITICAL")
		}
		if f.Severity != rules.Info {
			t.Errorf("expected INFO severity for no-checkout workflow, got %s", f.Severity)
		}
	}
}

// TestPRT_NotTriggeredForPR verifies that a regular pull_request event (not pull_request_target)
// with a head checkout does NOT generate an INSECURE_PULL_REQUEST_TARGET finding.
func TestPRT_NotTriggeredForPR(t *testing.T) {
	wf := buildPRTWorkflowFile(t, `
name: Regular PR
on: pull_request

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Build
        run: make build
`)

	findings := prtFindingsForRule(wf)

	if len(findings) != 0 {
		t.Errorf("expected zero INSECURE_PULL_REQUEST_TARGET findings for pull_request trigger, got: %v", findingIDs(findings))
	}
}

// TestPRT_MapEventTrigger verifies the rule fires when pull_request_target is specified
// as a map (with branches filter).
func TestPRT_MapEventTrigger(t *testing.T) {
	wf := buildPRTWorkflowFile(t, `
name: PR Map Trigger
on:
  pull_request_target:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`)

	findings := prtFindingsForRule(wf)

	if len(findings) == 0 {
		t.Fatal("expected INSECURE_PULL_REQUEST_TARGET finding for map-style trigger, got none")
	}
	for _, f := range findings {
		if f.Severity != rules.Critical {
			t.Errorf("expected CRITICAL for map-style pull_request_target + head.sha checkout, got %s", f.Severity)
		}
	}
}

// TestPRT_ArrayEventTrigger verifies the rule fires when pull_request_target is one item
// in a list of triggers.
func TestPRT_ArrayEventTrigger(t *testing.T) {
	wf := buildPRTWorkflowFile(t, `
name: PR Array Trigger
on: [push, pull_request_target]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`)

	findings := prtFindingsForRule(wf)

	if len(findings) == 0 {
		t.Fatal("expected INSECURE_PULL_REQUEST_TARGET finding for array-style trigger, got none")
	}
	for _, f := range findings {
		if f.Severity != rules.Medium {
			t.Errorf("expected MEDIUM for array-style pull_request_target + base checkout, got %s", f.Severity)
		}
	}
}
