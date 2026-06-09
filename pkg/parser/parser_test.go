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

package parser_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
)

func TestFindWorkflows(t *testing.T) {
	// Use the test repo path
	repoPath := "../../test/sample-repo"

	workflows, err := parser.FindWorkflows(repoPath)
	if err != nil {
		t.Fatalf("Failed to find workflows: %v", err)
	}

	// We should have found 3 workflow files
	if len(workflows) != 3 {
		t.Errorf("Expected to find 3 workflow files, got %d", len(workflows))
	}

	// Check if the workflows were parsed correctly
	for _, workflow := range workflows {
		if workflow.Name == "" {
			t.Errorf("Workflow name should not be empty")
		}

		// Test workflow structure
		if len(workflow.Workflow.Jobs) == 0 {
			t.Errorf("Workflow %s should have at least one job", workflow.Name)
		}

		// Check if we can access job details
		for jobName, job := range workflow.Workflow.Jobs {
			if len(job.Steps) == 0 {
				t.Errorf("Job %s in workflow %s should have at least one step", jobName, workflow.Name)
			}
		}
	}
}

func TestParseInvalidWorkflow(t *testing.T) {
	// Create a temporary invalid YAML file
	tmpFile, err := os.CreateTemp("", "invalid-workflow-*.yml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write invalid YAML content
	invalidYAML := `
name: Invalid Workflow
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
  - name: Missing indentation
      run: echo "This YAML is invalid"
`
	if err := os.WriteFile(tmpFile.Name(), []byte(invalidYAML), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	// Create a temporary directory structure with workflows
	tmpDir, err := os.MkdirTemp("", "workflow-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	workflowsDir := tmpDir + "/.github/workflows"
	err = os.MkdirAll(workflowsDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create workflows dir: %v", err)
	}

	// Copy the invalid file to the workflows directory
	invalidWorkflowPath := workflowsDir + "/invalid.yml"
	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read temp file: %v", err)
	}

	err = os.WriteFile(invalidWorkflowPath, content, 0644)
	if err != nil {
		t.Fatalf("Failed to write invalid workflow file: %v", err)
	}

	// This should return an error when parsing the invalid YAML
	_, err = parser.FindWorkflows(tmpDir)
	if err == nil {
		t.Errorf("Expected error parsing invalid workflow, got nil")
	}
}

// TestTemplatedContinueOnError guards against a regression where a templated
// `continue-on-error: ${{ ... }}` (or fail-fast/strategy expressions) caused
// the YAML unmarshal to fail and abort the entire scan. These expressions are
// extremely common in real-world workflows.
func TestTemplatedContinueOnError(t *testing.T) {
	dir := t.TempDir()
	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    continue-on-error: ${{ github.event_name == 'push' }}
    steps:
      - uses: actions/checkout@v4
      - name: test
        continue-on-error: ${{ github.ref == 'refs/heads/main' }}
        run: go test ./...
`
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	workflows, err := parser.FindWorkflows(dir)
	if err != nil {
		t.Fatalf("templated continue-on-error must parse, got error: %v", err)
	}
	if len(workflows) != 1 {
		t.Fatalf("expected 1 workflow, got %d", len(workflows))
	}
	job, ok := workflows[0].Workflow.Jobs["build"]
	if !ok {
		t.Fatal("missing job 'build'")
	}
	// The expression is preserved as a string, not coerced to a bool.
	if _, isStr := job.ContinueOnError.(string); !isStr {
		t.Errorf("expected continue-on-error preserved as string, got %T", job.ContinueOnError)
	}
}

// TestFindWorkflowsSkipsUnparseable verifies that one malformed workflow does
// not abort the whole scan — valid sibling workflows are still returned.
func TestFindWorkflowsSkipsUnparseable(t *testing.T) {
	dir := t.TempDir()
	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	valid := `name: Good
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
`
	broken := "name: Bad\n\tthis: is: not: valid: yaml\n  - broken"
	if err := os.WriteFile(filepath.Join(wfDir, "good.yml"), []byte(valid), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "bad.yml"), []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}

	workflows, err := parser.FindWorkflows(dir)
	if err != nil {
		t.Fatalf("scan must succeed despite one bad file, got: %v", err)
	}
	if len(workflows) != 1 || workflows[0].Name != "good.yml" {
		t.Fatalf("expected only the valid workflow, got %+v", workflows)
	}
}

func TestContinueOnErrorEnabled(t *testing.T) {
	tests := []struct {
		val  interface{}
		want bool
	}{
		{true, true},
		{false, false},
		{"true", true},
		{"TRUE", true},
		{"${{ github.event_name == 'push' }}", false}, // expression: not statically true
		{nil, false},
	}
	for _, tt := range tests {
		if got := parser.ContinueOnErrorEnabled(tt.val); got != tt.want {
			t.Errorf("ContinueOnErrorEnabled(%v) = %v, want %v", tt.val, got, tt.want)
		}
	}
}
