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
)

func TestCheckDockerExecWithSecrets_DirectDockerRun(t *testing.T) {
	workflow := parser.WorkflowFile{
		Path: ".github/workflows/review.yml",
		Content: []byte(`name: Review PR
on:
  pull_request_target:
    types: [opened]
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Run review agent
        run: |
          docker run --rm -e VENDOR_API_KEY -e VENDOR_API_BASE_URL -v $PWD:/mnt/repo:ro my-agent:latest agent run --skill review-pr --cwd /mnt/repo
`),
		Workflow: parser.Workflow{
			On: map[string]interface{}{
				"pull_request_target": map[string]interface{}{
					"types": []interface{}{"opened"},
				},
			},
			Jobs: map[string]parser.Job{
				"review": {
					Steps: []parser.Step{
						{
							Uses: "actions/checkout@v4",
							With: map[string]interface{}{
								"ref": "${{ github.event.pull_request.head.sha }}",
							},
						},
						{
							Name: "Run review agent",
							Run:  "docker run --rm -e VENDOR_API_KEY -e VENDOR_API_BASE_URL -v $PWD:/mnt/repo:ro my-agent:latest agent run --skill review-pr --cwd /mnt/repo",
						},
					},
				},
			},
		},
	}

	findings := CheckDockerAgentExposure(workflow)
	// Also run the AI agent check independently (as it would be from StandardRules)
	findings = append(findings, checkAIAgentOnUntrustedCode(workflow)...)

	if len(findings) == 0 {
		t.Fatal("Expected findings for docker run with secrets on fork code, got none")
	}

	foundDocker := false
	foundAI := false
	for _, f := range findings {
		if f.RuleID == "DOCKER_EXEC_WITH_SECRETS_ON_FORK_CODE" {
			foundDocker = true
			if f.Severity != Critical {
				t.Errorf("Expected Critical severity, got %s", f.Severity)
			}
		}
		if f.RuleID == "AI_AGENT_ON_UNTRUSTED_CODE" {
			foundAI = true
		}
	}

	if !foundDocker {
		t.Error("Expected DOCKER_EXEC_WITH_SECRETS_ON_FORK_CODE finding")
	}
	if !foundAI {
		t.Error("Expected AI_AGENT_ON_UNTRUSTED_CODE finding (docker run with agent keyword)")
	}
}

func TestCheckDockerExecWithSecrets_NetworkNoneMitigates(t *testing.T) {
	workflow := parser.WorkflowFile{
		Path: ".github/workflows/review.yml",
		Content: []byte(`name: Review PR
on:
  pull_request_target:
    types: [opened]
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - name: Run review agent
        run: |
          docker run --rm --network=none -e VENDOR_API_KEY -v $PWD:/mnt/repo:ro my-agent:latest
`),
		Workflow: parser.Workflow{
			On: map[string]interface{}{
				"pull_request_target": map[string]interface{}{
					"types": []interface{}{"opened"},
				},
			},
			Jobs: map[string]parser.Job{
				"review": {
					Steps: []parser.Step{
						{
							Name: "Run review agent",
							Run:  "docker run --rm --network=none -e VENDOR_API_KEY -v $PWD:/mnt/repo:ro my-agent:latest",
						},
					},
				},
			},
		},
	}

	findings := CheckDockerAgentExposure(workflow)

	for _, f := range findings {
		if f.RuleID == "DOCKER_EXEC_WITH_SECRETS_ON_FORK_CODE" {
			t.Error("Should NOT flag docker run with --network=none (exfiltration mitigated)")
		}
	}
}

func TestCheckDockerExecWithSecrets_NoPRTargetNoFinding(t *testing.T) {
	workflow := parser.WorkflowFile{
		Path: ".github/workflows/ci.yml",
		Content: []byte(`name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Run agent
        run: docker run --rm -e SECRET_KEY my-agent:latest
`),
		Workflow: parser.Workflow{
			On: "push",
			Jobs: map[string]parser.Job{
				"build": {
					Steps: []parser.Step{
						{
							Name: "Run agent",
							Run:  "docker run --rm -e SECRET_KEY my-agent:latest",
						},
					},
				},
			},
		},
	}

	findings := CheckDockerAgentExposure(workflow)
	if len(findings) != 0 {
		t.Errorf("Expected no findings for non-pull_request_target workflow, got %d", len(findings))
	}
}

func TestCheckAIAgentOnUntrustedCode_ReusableWorkflow(t *testing.T) {
	workflow := parser.WorkflowFile{
		Path: ".github/workflows/review-pull-request.yml",
		Content: []byte(`name: Review
on:
  pull_request_target:
    types: [opened]
jobs:
  review:
    uses: org/reusable-workflows/.github/workflows/review-pull-request.yml@main
    secrets: inherit
`),
		Workflow: parser.Workflow{
			On: map[string]interface{}{
				"pull_request_target": map[string]interface{}{
					"types": []interface{}{"opened"},
				},
			},
			Jobs: map[string]parser.Job{
				"review": {
					Steps: []parser.Step{
						{
							Uses: "org/reusable-workflows/.github/workflows/review-pull-request.yml@main",
						},
					},
				},
			},
		},
	}

	findings := CheckDockerAgentExposure(workflow)

	found := false
	for _, f := range findings {
		if f.RuleID == "DOCKER_EXEC_WITH_SECRETS_ON_FORK_CODE" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected finding for reusable review workflow with secrets:inherit")
	}
}

func TestCheckAIAgentOnUntrustedCode_OzAgentAction(t *testing.T) {
	workflow := parser.WorkflowFile{
		Path: ".github/workflows/review.yml",
		Content: []byte(`name: Review
on:
  pull_request_target:
    types: [opened]
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - name: AI Code Review
        uses: org/oz-agent-action@main
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
`),
		Workflow: parser.Workflow{
			On: map[string]interface{}{
				"pull_request_target": map[string]interface{}{
					"types": []interface{}{"opened"},
				},
			},
			Jobs: map[string]parser.Job{
				"review": {
					Steps: []parser.Step{
						{
							Name: "AI Code Review",
							Uses: "org/oz-agent-action@main",
							With: map[string]interface{}{
								"token": "${{ secrets.GITHUB_TOKEN }}",
							},
						},
					},
				},
			},
		},
	}

	findings := checkAIAgentOnUntrustedCode(workflow)

	found := false
	for _, f := range findings {
		if f.RuleID == "AI_AGENT_ON_UNTRUSTED_CODE" {
			found = true
			if f.Severity != High {
				t.Errorf("Expected High severity, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("Expected AI_AGENT_ON_UNTRUSTED_CODE finding for oz-agent-action with secrets")
	}
}
