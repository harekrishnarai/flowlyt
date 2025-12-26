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

package shell_test

import (
	"testing"

	"github.com/harekrishnarai/flowlyt/pkg/parser"
	"github.com/harekrishnarai/flowlyt/pkg/shell"
)

func TestShellAnalyzer(t *testing.T) {
	// Initialize shell analyzer
	analyzer := shell.NewAnalyzer()

	// Load the test insecure workflow
	repoPath := "../../test/sample-repo"
	workflows, err := parser.FindWorkflows(repoPath)
	if err != nil {
		t.Fatalf("Failed to find workflows: %v", err)
	}

	// Find the insecure workflow
	var insecureWorkflow parser.WorkflowFile
	for _, workflow := range workflows {
		if workflow.Name == "insecure_workflow.yml" {
			insecureWorkflow = workflow
			break
		}
	}

	if insecureWorkflow.Path == "" {
		t.Fatal("Failed to find insecure_workflow.yml in test files")
	}

	// Analyze the workflow
	findings := analyzer.Analyze(insecureWorkflow)

	// We should have found shell issues
	if len(findings) == 0 {
		t.Error("No shell issues detected in insecure workflow")
	}

	// Check for expected findings
	foundEvalUsage := false
	foundShellObfuscation := false

	for _, finding := range findings {
		switch finding.RuleID {
		case "SHELL_EVAL_USAGE":
			foundEvalUsage = true
		case "SHELL_OBFUSCATION":
			foundShellObfuscation = true
		}
	}

	if !foundEvalUsage {
		t.Error("Failed to detect eval usage")
	}

	if !foundShellObfuscation {
		t.Error("Failed to detect shell obfuscation with base64")
	}
}

func TestShellParser(t *testing.T) {
	// Test valid shell script parsing
	validScript := `
	#!/bin/bash
	echo "Hello, world!"
	for i in {1..5}; do
		echo $i
	done
	`

	syntaxTree, err := shell.Parse(validScript)
	if err != nil {
		t.Errorf("Failed to parse valid shell script: %v", err)
	}

	if syntaxTree == nil {
		t.Error("Syntax tree is nil for valid script")
	}

	// Test invalid shell script parsing
	invalidScript := `
	#!/bin/bash
	echo "Unbalanced quotes
	for i in {1..5}; do
		echo $i
	done
	`

	_, err = shell.Parse(invalidScript)
	if err == nil {
		t.Error("Expected error parsing invalid shell script, got nil")
	}
}
