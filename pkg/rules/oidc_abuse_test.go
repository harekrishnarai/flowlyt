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

// TestOA001_WorkflowLevelPermission verifies that a multi-job workflow with
// id-token: write at the workflow level triggers OA-001.
func TestOA001_WorkflowLevelPermission(t *testing.T) {
	workflow := parser.WorkflowFile{
		Path: "test.yml",
		Workflow: parser.Workflow{
			Name: "Deploy",
			Permissions: map[string]interface{}{
				"id-token": "write",
				"contents": "read",
			},
			Jobs: map[string]parser.Job{
				"build": {
					Name:  "Build",
					Steps: []parser.Step{{Name: "Build step", Run: "go build ./..."}},
				},
				"deploy": {
					Name:  "Deploy",
					Steps: []parser.Step{{Name: "Deploy step", Run: "echo deploy"}},
				},
			},
		},
	}

	findings := CheckOIDCAbuse(workflow)

	var oa001Findings []Finding
	for _, f := range findings {
		if f.RuleID == "OIDC_WORKFLOW_LEVEL_PERMISSION" {
			oa001Findings = append(oa001Findings, f)
		}
	}

	if len(oa001Findings) == 0 {
		t.Error("expected OA-001 finding for workflow-level id-token:write in multi-job workflow, got none")
	}
	if len(oa001Findings) > 1 {
		t.Errorf("expected exactly 1 OA-001 finding, got %d", len(oa001Findings))
	}
	if len(oa001Findings) == 1 {
		f := oa001Findings[0]
		if f.Severity != High {
			t.Errorf("expected severity HIGH, got %s", f.Severity)
		}
		if f.Category != PrivilegeEscalation {
			t.Errorf("expected category PRIVILEGE_ESCALATION, got %s", f.Category)
		}
	}
}

// TestOA001_SafeJobLevel verifies that id-token: write at job level (not workflow level)
// does NOT trigger OA-001.
func TestOA001_SafeJobLevel(t *testing.T) {
	workflow := parser.WorkflowFile{
		Path: "test.yml",
		Workflow: parser.Workflow{
			Name: "Deploy",
			// No workflow-level id-token permission
			Permissions: map[string]interface{}{
				"contents": "read",
			},
			Jobs: map[string]parser.Job{
				"build": {
					Name:  "Build",
					Steps: []parser.Step{{Name: "Build step", Run: "go build ./..."}},
				},
				"deploy": {
					Name: "Deploy",
					Permissions: map[string]interface{}{
						"id-token": "write",
					},
					Environment: "production",
					Steps:       []parser.Step{{Name: "Deploy step", Run: "echo deploy"}},
				},
			},
		},
	}

	findings := CheckOIDCAbuse(workflow)

	for _, f := range findings {
		if f.RuleID == "OIDC_WORKFLOW_LEVEL_PERMISSION" {
			t.Errorf("unexpected OA-001 finding when id-token:write is only at job level: %+v", f)
		}
	}
}

// TestOA001_SafeSingleJob verifies that a single-job workflow with workflow-level
// id-token: write does NOT trigger OA-001 (no cross-job exposure).
func TestOA001_SafeSingleJob(t *testing.T) {
	workflow := parser.WorkflowFile{
		Path: "test.yml",
		Workflow: parser.Workflow{
			Name: "Single Job Deploy",
			Permissions: map[string]interface{}{
				"id-token": "write",
			},
			Jobs: map[string]parser.Job{
				"deploy": {
					Name:        "Deploy",
					Environment: "production",
					Steps:       []parser.Step{{Name: "Deploy step", Run: "echo deploy"}},
				},
			},
		},
	}

	findings := CheckOIDCAbuse(workflow)

	for _, f := range findings {
		if f.RuleID == "OIDC_WORKFLOW_LEVEL_PERMISSION" {
			t.Errorf("unexpected OA-001 finding for single-job workflow (no cross-job exposure): %+v", f)
		}
	}
}

// TestOA002_WithoutEnvironment verifies that a job with id-token: write but
// no environment: triggers OA-002.
func TestOA002_WithoutEnvironment(t *testing.T) {
	workflow := parser.WorkflowFile{
		Path: "test.yml",
		Workflow: parser.Workflow{
			Name: "Deploy",
			Jobs: map[string]parser.Job{
				"deploy": {
					Name: "Deploy",
					Permissions: map[string]interface{}{
						"id-token": "write",
					},
					// No Environment set
					Steps: []parser.Step{{Name: "Deploy step", Run: "echo deploy"}},
				},
			},
		},
	}

	findings := CheckOIDCAbuse(workflow)

	var oa002Findings []Finding
	for _, f := range findings {
		if f.RuleID == "OIDC_WITHOUT_ENVIRONMENT_SCOPE" {
			oa002Findings = append(oa002Findings, f)
		}
	}

	if len(oa002Findings) == 0 {
		t.Error("expected OA-002 finding for id-token:write without environment scope, got none")
	}
	if len(oa002Findings) == 1 {
		f := oa002Findings[0]
		if f.Severity != Medium {
			t.Errorf("expected severity MEDIUM, got %s", f.Severity)
		}
		if f.Category != PrivilegeEscalation {
			t.Errorf("expected category PRIVILEGE_ESCALATION, got %s", f.Category)
		}
	}
}

// TestOA002_SafeWithEnvironment verifies that a job with id-token: write AND
// environment: production does NOT trigger OA-002.
func TestOA002_SafeWithEnvironment(t *testing.T) {
	workflow := parser.WorkflowFile{
		Path: "test.yml",
		Workflow: parser.Workflow{
			Name: "Deploy",
			Jobs: map[string]parser.Job{
				"deploy": {
					Name: "Deploy",
					Permissions: map[string]interface{}{
						"id-token": "write",
					},
					Environment: "production",
					Steps:       []parser.Step{{Name: "Deploy step", Run: "echo deploy"}},
				},
			},
		},
	}

	findings := CheckOIDCAbuse(workflow)

	for _, f := range findings {
		if f.RuleID == "OIDC_WITHOUT_ENVIRONMENT_SCOPE" {
			t.Errorf("unexpected OA-002 finding when environment is set to 'production': %+v", f)
		}
	}
}

// TestOA001_WriteAll verifies that "write-all" shorthand at workflow level is also detected.
func TestOA001_WriteAll(t *testing.T) {
	workflow := parser.WorkflowFile{
		Path: "test.yml",
		Workflow: parser.Workflow{
			Name:        "Deploy",
			Permissions: "write-all",
			Jobs: map[string]parser.Job{
				"build":  {Steps: []parser.Step{{Run: "go build ./..."}}},
				"deploy": {Steps: []parser.Step{{Run: "echo deploy"}}},
			},
		},
	}

	findings := CheckOIDCAbuse(workflow)

	var oa001Findings []Finding
	for _, f := range findings {
		if f.RuleID == "OIDC_WORKFLOW_LEVEL_PERMISSION" {
			oa001Findings = append(oa001Findings, f)
		}
	}

	if len(oa001Findings) == 0 {
		t.Error("expected OA-001 finding for write-all permissions in multi-job workflow, got none")
	}
}
