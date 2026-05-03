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
	"strings"
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
					Uses:    "org/reusable-workflows/.github/workflows/review-pull-request.yml@main",
					Secrets: "inherit",
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
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
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
							Uses: "actions/checkout@v4",
							With: map[string]interface{}{
								"ref": "${{ github.event.pull_request.head.sha }}",
							},
						},
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

func TestCheckAIAgentCommentTriggered_ClaudeCodeAction(t *testing.T) {
	workflow := parser.WorkflowFile{
		Path: ".github/workflows/claude-mention.yml",
		Content: []byte(`name: Claude Code Mention
on:
  issue_comment:
    types: [created]
  pull_request_review_comment:
    types: [created]
jobs:
  claude:
    runs-on: ubuntu-latest
    if: contains(github.event.comment.body, '@claude')
    permissions:
      contents: read
      pull-requests: write
      issues: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 1
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          github_token: ${{ secrets.GITHUB_TOKEN }}
`),
		Workflow: parser.Workflow{
			On: map[string]interface{}{
				"issue_comment": map[string]interface{}{
					"types": []interface{}{"created"},
				},
				"pull_request_review_comment": map[string]interface{}{
					"types": []interface{}{"created"},
				},
			},
			Jobs: map[string]parser.Job{
				"claude": {
					Permissions: map[string]interface{}{
						"contents":      "read",
						"pull-requests": "write",
						"issues":        "write",
						"id-token":      "write",
					},
					Steps: []parser.Step{
						{
							Uses: "actions/checkout@v4",
							With: map[string]interface{}{
								"fetch-depth": "1",
							},
						},
						{
							Uses: "anthropics/claude-code-action@v1",
							With: map[string]interface{}{
								"anthropic_api_key": "${{ secrets.ANTHROPIC_API_KEY }}",
								"github_token":      "${{ secrets.GITHUB_TOKEN }}",
							},
						},
					},
				},
			},
		},
	}

	findings := CheckAIAgentCommentTriggered(workflow)

	if len(findings) == 0 {
		t.Fatal("Expected finding for comment-triggered AI agent with secrets")
	}

	f := findings[0]
	if f.RuleID != "AI_AGENT_COMMENT_TRIGGERED" {
		t.Errorf("Expected AI_AGENT_COMMENT_TRIGGERED, got %s", f.RuleID)
	}
	if f.Severity != Critical {
		t.Errorf("Expected Critical severity (has write permissions), got %v", f.Severity)
	}
	if !strings.Contains(f.Description, "secrets") {
		t.Error("Description should mention secrets")
	}
}

func TestCheckAIAgentCommentTriggered_NoSecrets(t *testing.T) {
	workflow := parser.WorkflowFile{
		Path: ".github/workflows/claude-mention.yml",
		Content: []byte(`name: Claude Code Mention
on:
  issue_comment:
    types: [created]
jobs:
  claude:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          model: claude-sonnet
`),
		Workflow: parser.Workflow{
			On: map[string]interface{}{
				"issue_comment": map[string]interface{}{
					"types": []interface{}{"created"},
				},
			},
			Jobs: map[string]parser.Job{
				"claude": {
					Steps: []parser.Step{
						{
							Uses: "anthropics/claude-code-action@v1",
							With: map[string]interface{}{
								"model": "claude-sonnet",
							},
						},
					},
				},
			},
		},
	}

	findings := CheckAIAgentCommentTriggered(workflow)

	if len(findings) == 0 {
		t.Fatal("Expected denial-of-wallet finding even without secrets")
	}
	if findings[0].Severity != Medium {
		t.Errorf("Expected Medium severity for denial-of-wallet, got %v", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Description, "denial-of-wallet") {
		t.Error("Description should mention denial-of-wallet")
	}
}

func TestCheckAIAgentCommentTriggered_NotCommentTrigger(t *testing.T) {
	workflow := parser.WorkflowFile{
		Path: ".github/workflows/claude-pr.yml",
		Content: []byte(`name: Claude on PR
on:
  pull_request:
    types: [opened]
jobs:
  claude:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
`),
		Workflow: parser.Workflow{
			On: map[string]interface{}{
				"pull_request": map[string]interface{}{
					"types": []interface{}{"opened"},
				},
			},
			Jobs: map[string]parser.Job{
				"claude": {
					Steps: []parser.Step{
						{
							Uses: "anthropics/claude-code-action@v1",
							With: map[string]interface{}{
								"anthropic_api_key": "${{ secrets.ANTHROPIC_API_KEY }}",
							},
						},
					},
				},
			},
		},
	}

	findings := CheckAIAgentCommentTriggered(workflow)

	if len(findings) != 0 {
		t.Errorf("Expected no findings for non-comment trigger, got %d", len(findings))
	}
}

func TestCheckAIAgentCommentTriggered_AuthorAssociationGate(t *testing.T) {
	workflow := parser.WorkflowFile{
		Path: ".github/workflows/claude-mention.yml",
		Content: []byte(`name: Claude Code Mention
on:
  issue_comment:
    types: [created]
jobs:
  claude:
    runs-on: ubuntu-latest
    if: github.event.comment.author_association == 'MEMBER'
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
`),
		Workflow: parser.Workflow{
			On: map[string]interface{}{
				"issue_comment": map[string]interface{}{
					"types": []interface{}{"created"},
				},
			},
			Jobs: map[string]parser.Job{
				"claude": {
					If: "github.event.comment.author_association == 'MEMBER'",
					Steps: []parser.Step{
						{
							Uses: "anthropics/claude-code-action@v1",
							With: map[string]interface{}{
								"anthropic_api_key": "${{ secrets.ANTHROPIC_API_KEY }}",
							},
						},
					},
				},
			},
		},
	}

	findings := CheckAIAgentCommentTriggered(workflow)

	if len(findings) != 0 {
		t.Errorf("Expected no findings when author_association gate is present, got %d", len(findings))
	}
}
