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
	"testing"

	"github.com/harekrishnarai/flowlyt/pkg/parser"
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
