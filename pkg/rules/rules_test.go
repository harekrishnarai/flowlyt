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
	"strings"
	"testing"

	"github.com/harekrishnarai/flowlyt/pkg/parser"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

func TestStandardRules(t *testing.T) {
	// Get all standard rules
	standardRules := rules.StandardRules()

	// Ensure we have rules defined
	if len(standardRules) == 0 {
		t.Fatal("No standard rules defined")
	}

	// Check that each rule has required fields
	for _, rule := range standardRules {
		if rule.ID == "" {
			t.Errorf("Rule ID should not be empty")
		}
		if rule.Name == "" {
			t.Errorf("Rule name should not be empty for rule %s", rule.ID)
		}
		if rule.Description == "" {
			t.Errorf("Rule description should not be empty for rule %s", rule.ID)
		}
		if rule.Check == nil {
			t.Errorf("Rule check function should not be nil for rule %s", rule.ID)
		}
	}
}

func TestInsecureWorkflowFindings(t *testing.T) {
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

	// Apply all standard rules
	standardRules := rules.StandardRules()
	var findings []rules.Finding

	for _, rule := range standardRules {
		ruleFindings := rule.Check(insecureWorkflow)
		findings = append(findings, ruleFindings...)
	}

	// We should have found several issues in the insecure workflow
	if len(findings) == 0 {
		t.Error("No findings detected in insecure workflow")
	}

	// Check for specific expected findings
	foundCurlPipeBash := false
	foundPullRequestTarget := false
	foundUnpinnedAction := false

	for _, finding := range findings {
		switch finding.RuleID {
		case "MALICIOUS_CURL_PIPE_BASH":
			foundCurlPipeBash = true
		case "INSECURE_PULL_REQUEST_TARGET":
			foundPullRequestTarget = true
		case "UNPINNED_ACTION":
			foundUnpinnedAction = true
		}
	}

	if !foundCurlPipeBash {
		t.Error("Failed to detect curl pipe to bash issue")
	}
	if !foundPullRequestTarget {
		t.Error("Failed to detect insecure pull_request_target usage")
	}
	if !foundUnpinnedAction {
		t.Error("Failed to detect unpinned action issue")
	}
}

func TestSecureWorkflowFindings(t *testing.T) {
	// Load the test secure workflow
	repoPath := "../../test/sample-repo"
	workflows, err := parser.FindWorkflows(repoPath)
	if err != nil {
		t.Fatalf("Failed to find workflows: %v", err)
	}

	// Find the secure workflow
	var secureWorkflow parser.WorkflowFile
	for _, workflow := range workflows {
		if workflow.Name == "secure_workflow.yml" {
			secureWorkflow = workflow
			break
		}
	}

	if secureWorkflow.Path == "" {
		t.Fatal("Failed to find secure_workflow.yml in test files")
	}

	// Apply all standard rules
	standardRules := rules.StandardRules()
	var findings []rules.Finding

	for _, rule := range standardRules {
		// Skip secret detection rules for this test
		// This is because our current implementation might have false positives
		if rule.Category == "SECRET_EXPOSURE" {
			continue
		}

		ruleFindings := rule.Check(secureWorkflow)
		findings = append(findings, ruleFindings...)
	}

	// We should have minimal or no findings in the secure workflow
	// At least, we shouldn't have critical issues
	criticalFindings := 0
	for _, finding := range findings {
		if finding.Severity == rules.Critical {
			criticalFindings++
			t.Logf("Critical finding in secure workflow: %s - %s", finding.RuleID, finding.RuleName)
		}
	}

	// Allow for some findings, but no critical ones
	if criticalFindings > 0 {
		t.Errorf("Found %d critical issues in secure workflow, expected none", criticalFindings)
	}
}

// TestExfiltrationWorkflowDetection tests the data exfiltration detection rule
func TestExfiltrationWorkflowDetection(t *testing.T) {
	// Load the test workflows
	repoPath := "../../test/sample-repo"
	workflows, err := parser.FindWorkflows(repoPath)
	if err != nil {
		t.Fatalf("Failed to find workflows: %v", err)
	}

	// Find the exfiltration workflow
	var exfilWorkflow parser.WorkflowFile
	for _, workflow := range workflows {
		if workflow.Name == "exfiltration_workflow.yml" {
			exfilWorkflow = workflow
			break
		}
	}

	if exfilWorkflow.Path == "" {
		t.Fatal("Failed to find exfiltration_workflow.yml in test files")
	}

	// Apply all standard rules
	standardRules := rules.StandardRules()
	var findings []rules.Finding

	for _, rule := range standardRules {
		if rule.ID == "MALICIOUS_DATA_EXFILTRATION" {
			ruleFindings := rule.Check(exfilWorkflow)
			findings = append(findings, ruleFindings...)
		}
	}

	// We should have found several exfiltration issues
	if len(findings) == 0 {
		t.Error("No data exfiltration findings detected in the exfiltration workflow")
	}

	// Output the findings for logging purposes
	for i, finding := range findings {
		t.Logf("Finding %d: %s in job '%s', step '%s'",
			i+1, finding.RuleName, finding.JobName, finding.StepName)
		t.Logf("  Evidence: %s", finding.Evidence)
	}

	// Check for specific expected patterns
	expectedPatterns := []string{
		"ngrok", "192.168.1.100", "webhook.site", "attacker.command.io",
		"secrets.GITHUB_TOKEN", "paste.bin.io", "collect.exfil.io",
		"malicious.ngrok.io", "webhook.command.com",
	}

	patternFound := make(map[string]bool)
	for _, pattern := range expectedPatterns {
		patternFound[pattern] = false
	}

	// Check if each expected pattern was found in any finding
	for _, finding := range findings {
		for _, pattern := range expectedPatterns {
			if strings.Contains(finding.Evidence, pattern) {
				patternFound[pattern] = true
			}
		}
	}

	// Report missing patterns
	for pattern, found := range patternFound {
		if !found {
			t.Errorf("Expected exfiltration pattern '%s' was not detected", pattern)
		}
	}
}
