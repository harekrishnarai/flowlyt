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

package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/harekrishnarai/flowlyt/pkg/rules"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

func TestSARIFGeneration(t *testing.T) {
	// Create a test result with findings
	result := ScanResult{
		Repository:     "test-repo",
		WorkflowsCount: 2,
		RulesCount:     10,
		ScanTime:       time.Now(),
		Duration:       5 * time.Second,
		Summary: ResultSummary{
			Critical: 1,
			High:     2,
			Medium:   3,
			Low:      4,
			Info:     5,
		},
		Findings: []rules.Finding{
			{
				RuleID:      "FLOW-001",
				RuleName:    "Test Rule",
				Description: "Test description",
				Severity:    rules.High,
				Category:    rules.SecretExposure,
				FilePath:    ".github/workflows/test.yml",
				LineNumber:  10,
				JobName:     "test-job",
				StepName:    "test-step",
				Evidence:    "test evidence",
				Remediation: "Fix the issue",
			},
			{
				RuleID:      "FLOW-002",
				RuleName:    "Another Test Rule",
				Description: "Another test description",
				Severity:    rules.Medium,
				Category:    rules.InjectionAttack,
				FilePath:    ".github/workflows/deploy.yml",
				LineNumber:  25,
				Evidence:    "another evidence",
				Remediation: "Fix this too",
			},
		},
	}

	// Create generator
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "test-output.sarif")
	
	generator := NewGenerator(result, "sarif", false, outputFile)

	// Generate SARIF report
	err := generator.Generate()
	if err != nil {
		t.Fatalf("Failed to generate SARIF report: %v", err)
	}

	// Verify the file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Fatalf("SARIF file was not created: %s", outputFile)
	}

	// Read and validate the SARIF file
	report, err := sarif.Open(outputFile)
	if err != nil {
		t.Fatalf("Failed to open SARIF file: %v", err)
	}

	// Validate SARIF version
	if report.Version != "2.1.0" {
		t.Errorf("Expected SARIF version 2.1.0, got %s", report.Version)
	}

	// Validate runs
	if len(report.Runs) != 1 {
		t.Fatalf("Expected 1 run, got %d", len(report.Runs))
	}

	run := report.Runs[0]

	// Validate tool information
	if run.Tool.Driver.Name != "Flowlyt" {
		t.Errorf("Expected tool name 'Flowlyt', got '%s'", run.Tool.Driver.Name)
	}

	// Validate results count
	if len(run.Results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(run.Results))
	}

	// Validate first result
	if len(run.Results) > 0 {
		result0 := run.Results[0]
		if *result0.RuleID != "FLOW-001" {
			t.Errorf("Expected rule ID 'FLOW-001', got '%s'", *result0.RuleID)
		}
		if *result0.Level != "error" {
			t.Errorf("Expected level 'error' for high severity, got '%s'", *result0.Level)
		}
		if len(result0.Locations) == 0 {
			t.Error("Expected at least one location")
		} else {
			location := result0.Locations[0]
			if location.PhysicalLocation == nil {
				t.Error("Expected physical location")
			} else {
				if *location.PhysicalLocation.ArtifactLocation.URI != ".github/workflows/test.yml" {
					t.Errorf("Expected URI '.github/workflows/test.yml', got '%s'", 
						*location.PhysicalLocation.ArtifactLocation.URI)
				}
				if location.PhysicalLocation.Region != nil {
					if *location.PhysicalLocation.Region.StartLine != 10 {
						t.Errorf("Expected start line 10, got %d", 
							*location.PhysicalLocation.Region.StartLine)
					}
				}
			}
		}
	}

	// Validate rules are defined
	if run.Tool.Driver.Rules == nil || len(run.Tool.Driver.Rules) == 0 {
		t.Error("Expected rules to be defined in tool driver")
	} else {
		// Validate that rules have security-severity property
		for _, rule := range run.Tool.Driver.Rules {
			if rule.Properties == nil {
				t.Errorf("Expected rule %s to have properties", rule.ID)
				continue
			}
			if _, ok := rule.Properties["security-severity"]; !ok {
				t.Errorf("Expected rule %s to have security-severity property", rule.ID)
			}
		}
	}

	// Validate the JSON structure is valid
	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("Failed to read SARIF file: %v", err)
	}

	var jsonObj map[string]interface{}
	if err := json.Unmarshal(data, &jsonObj); err != nil {
		t.Fatalf("Invalid JSON in SARIF file: %v", err)
	}

	// Validate required fields
	if _, ok := jsonObj["version"]; !ok {
		t.Error("Missing 'version' field in SARIF")
	}
	if _, ok := jsonObj["$schema"]; !ok {
		t.Error("Missing '$schema' field in SARIF")
	}
	if _, ok := jsonObj["runs"]; !ok {
		t.Error("Missing 'runs' field in SARIF")
	}
}

func TestSeverityToSARIFLevel(t *testing.T) {
	tests := []struct {
		severity rules.Severity
		expected string
	}{
		{rules.Critical, "error"},
		{rules.High, "error"},
		{rules.Medium, "warning"},
		{rules.Low, "warning"},
		{rules.Info, "note"},
	}

	result := ScanResult{}
	generator := NewGenerator(result, "sarif", false, "")

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			level := generator.severityToSARIFLevel(tt.severity)
			if level != tt.expected {
				t.Errorf("Expected level '%s' for severity '%s', got '%s'", 
					tt.expected, tt.severity, level)
			}
		})
	}
}

func TestGetSecuritySeverityScore(t *testing.T) {
	tests := []struct {
		severity     rules.Severity
		expected     string
		description  string
	}{
		{rules.Critical, "9.0", "Critical should map to 9.0 (9.0-10.0 range)"},
		{rules.High, "8.0", "High should map to 8.0 (7.0-8.9 range)"},
		{rules.Medium, "5.0", "Medium should map to 5.0 (4.0-6.9 range)"},
		{rules.Low, "3.0", "Low should map to 3.0 (0.1-3.9 range)"},
		{rules.Info, "0.0", "Info should map to 0.0"},
	}

	result := ScanResult{}
	generator := NewGenerator(result, "sarif", false, "")

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			score := generator.getSecuritySeverityScore(tt.severity)
			if score != tt.expected {
				t.Errorf("Expected security-severity '%s' for severity '%s', got '%s'. %s", 
					tt.expected, tt.severity, score, tt.description)
			}
		})
	}
}

func TestNormalizeFilePath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "GitHub workflow path",
			input:    "/tmp/repo/.github/workflows/ci.yml",
			expected: ".github/workflows/ci.yml",
		},
		{
			name:     "GitLab CI file",
			input:    "/tmp/repo/.gitlab-ci.yml",
			expected: ".gitlab-ci.yml",
		},
		{
			name:     "Already relative GitHub path",
			input:    ".github/workflows/test.yml",
			expected: ".github/workflows/test.yml",
		},
	}

	result := ScanResult{}
	generator := NewGenerator(result, "sarif", false, "")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized := generator.normalizeFilePath(tt.input)
			if normalized != tt.expected {
				t.Errorf("Expected normalized path '%s', got '%s'", tt.expected, normalized)
			}
		})
	}
}
