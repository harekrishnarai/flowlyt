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

// buildWRTWorkflowFile parses a YAML string into a parser.WorkflowFile for WRT rule tests.
func buildWRTWorkflowFile(t *testing.T, content string) parser.WorkflowFile {
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

// hasRuleID returns true if any finding in the slice has the given rule ID.
func hasRuleID(findings []rules.Finding, id string) bool {
	for _, f := range findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

// TestWRT001_Vulnerable checks that a workflow_run workflow using dawidd6/action-download-artifact
// without a run_id generates a WORKFLOW_RUN_ARTIFACT_UNTRUSTED finding.
func TestWRT001_Vulnerable(t *testing.T) {
	workflow := buildWRTWorkflowFile(t, `
name: Download Artifacts
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]

jobs:
  download:
    runs-on: ubuntu-latest
    steps:
      - name: Download artifact
        uses: dawidd6/action-download-artifact@v3
        with:
          workflow: ci.yml
          name: my-artifact
`)

	findings := rules.CheckWorkflowRunTrust(workflow)

	if !hasRuleID(findings, "WORKFLOW_RUN_ARTIFACT_UNTRUSTED") {
		t.Errorf("expected WORKFLOW_RUN_ARTIFACT_UNTRUSTED finding, got: %v", findingIDs(findings))
	}
}

// TestWRT001_SafeWithRunID checks that providing a run_id in the with: block suppresses WRT-001.
func TestWRT001_SafeWithRunID(t *testing.T) {
	workflow := buildWRTWorkflowFile(t, `
name: Download Artifacts Safe
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]

jobs:
  download:
    runs-on: ubuntu-latest
    steps:
      - name: Download artifact
        uses: dawidd6/action-download-artifact@v3
        with:
          workflow: ci.yml
          name: my-artifact
          run_id: ${{ github.event.workflow_run.id }}
`)

	findings := rules.CheckWorkflowRunTrust(workflow)

	for _, f := range findings {
		if f.RuleID == "WORKFLOW_RUN_ARTIFACT_UNTRUSTED" {
			t.Errorf("unexpected WORKFLOW_RUN_ARTIFACT_UNTRUSTED finding when run_id is set")
		}
	}
}

// TestWRT002_EnvInjection checks that a workflow_run job with an artifact download step
// followed by a step writing to $GITHUB_ENV generates a WORKFLOW_RUN_ENV_INJECTION finding.
func TestWRT002_EnvInjection(t *testing.T) {
	workflow := buildWRTWorkflowFile(t, `
name: Env Injection via Artifact
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]

jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - name: Download artifact
        uses: actions/download-artifact@v4
        with:
          name: build-output
      - name: Process artifact
        run: |
          cat artifact-env.txt >> $GITHUB_ENV
`)

	findings := rules.CheckWorkflowRunTrust(workflow)

	if !hasRuleID(findings, "WORKFLOW_RUN_ENV_INJECTION") {
		t.Errorf("expected WORKFLOW_RUN_ENV_INJECTION finding, got: %v", findingIDs(findings))
	}
}

// TestWRT003_ElevatedContext checks that a workflow_run job combining an artifact download
// with write permissions generates a WORKFLOW_RUN_ELEVATED_CONTEXT finding.
func TestWRT003_ElevatedContext(t *testing.T) {
	workflow := buildWRTWorkflowFile(t, `
name: Elevated Permissions with Artifact
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - name: Download artifact
        uses: dawidd6/action-download-artifact@v3
        with:
          workflow: ci.yml
          name: release-asset
      - name: Deploy
        run: echo "deploying"
`)

	findings := rules.CheckWorkflowRunTrust(workflow)

	if !hasRuleID(findings, "WORKFLOW_RUN_ELEVATED_CONTEXT") {
		t.Errorf("expected WORKFLOW_RUN_ELEVATED_CONTEXT finding, got: %v", findingIDs(findings))
	}
}

// TestWRT_NotTriggeredForPushWorkflow checks that none of the WRT rules fire for
// a push-triggered workflow, even if it contains artifact download and env-writing steps.
func TestWRT_NotTriggeredForPushWorkflow(t *testing.T) {
	workflow := buildWRTWorkflowFile(t, `
name: Push Workflow
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - name: Download artifact
        uses: dawidd6/action-download-artifact@v3
        with:
          workflow: ci.yml
          name: build-artifact
      - name: Set env
        run: cat artifact-env.txt >> $GITHUB_ENV
`)

	findings := rules.CheckWorkflowRunTrust(workflow)

	if len(findings) != 0 {
		t.Errorf("expected zero WRT findings for push workflow, got: %v", findingIDs(findings))
	}
}

// TestWRT001_ActionsDownloadArtifact checks that actions/download-artifact (without run_id)
// also triggers WRT-001, not just the dawidd6 variant.
func TestWRT001_ActionsDownloadArtifact(t *testing.T) {
	workflow := buildWRTWorkflowFile(t, `
name: Actions Download Artifact
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]

jobs:
  fetch:
    runs-on: ubuntu-latest
    steps:
      - name: Download
        uses: actions/download-artifact@v4
        with:
          name: dist
`)

	findings := rules.CheckWorkflowRunTrust(workflow)

	if !hasRuleID(findings, "WORKFLOW_RUN_ARTIFACT_UNTRUSTED") {
		t.Errorf("expected WORKFLOW_RUN_ARTIFACT_UNTRUSTED for actions/download-artifact, got: %v", findingIDs(findings))
	}
}

// TestWRT003_WriteAllPermissions checks that "write-all" at the workflow level triggers WRT-003.
func TestWRT003_WriteAllPermissions(t *testing.T) {
	workflow := buildWRTWorkflowFile(t, `
name: Write-All Permissions
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]

permissions: write-all

jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - name: Download artifact
        uses: actions/download-artifact@v4
        with:
          name: dist
`)

	findings := rules.CheckWorkflowRunTrust(workflow)

	if !hasRuleID(findings, "WORKFLOW_RUN_ELEVATED_CONTEXT") {
		t.Errorf("expected WORKFLOW_RUN_ELEVATED_CONTEXT for write-all workflow permissions, got: %v", findingIDs(findings))
	}
}

// findingIDs is a test helper that returns a slice of rule IDs from a findings list.
func findingIDs(findings []rules.Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.RuleID)
	}
	return ids
}
