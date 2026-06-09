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

package opa

import (
	"testing"

	"github.com/harekrishnarai/flowlyt/pkg/platform"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

func newLoadedEngine(t *testing.T) *Engine {
	t.Helper()
	e := NewEngine()
	if err := e.LoadPolicyFromFile(""); err != nil {
		t.Fatalf("LoadPolicyFromFile: %v", err)
	}
	return e
}

func TestNewEngine(t *testing.T) {
	e := NewEngine()
	if e == nil {
		t.Fatal("NewEngine returned nil")
	}
	if len(e.GetPolicies()) != 0 {
		t.Errorf("expected no policies on a fresh engine, got %d", len(e.GetPolicies()))
	}
}

func TestLoadBuiltinPolicies(t *testing.T) {
	e := newLoadedEngine(t)

	if got := len(e.GetPolicies()); got != 3 {
		t.Fatalf("expected 3 builtin policies, got %d", got)
	}
	for _, id := range []string{"HARDCODED_SECRETS_OPA", "DANGEROUS_COMMANDS_OPA", "UNPINNED_ACTIONS_OPA"} {
		if _, ok := e.GetPolicy(id); !ok {
			t.Errorf("expected builtin policy %q to be loaded", id)
		}
	}
}

func TestRemovePolicy(t *testing.T) {
	e := newLoadedEngine(t)
	e.RemovePolicy("HARDCODED_SECRETS_OPA")

	if _, ok := e.GetPolicy("HARDCODED_SECRETS_OPA"); ok {
		t.Error("policy should have been removed")
	}
	if got := len(e.GetPolicies()); got != 2 {
		t.Errorf("expected 2 policies after removal, got %d", got)
	}
}

func TestEvaluateWorkflow_Benign(t *testing.T) {
	e := newLoadedEngine(t)
	wf := &platform.Workflow{
		Platform: "github-actions",
		Name:     "CI",
		Jobs: []platform.Job{
			{
				ID:   "build",
				Name: "build",
				Steps: []platform.Step{
					{Name: "checkout", Type: "action", Action: "actions/checkout@v4"},
					{Name: "run", Type: "script", Script: []string{"echo hello"}},
				},
			},
		},
	}

	// A benign workflow should evaluate without error against all loaded policies.
	findings, err := e.EvaluateWorkflow(wf)
	if err != nil {
		t.Fatalf("EvaluateWorkflow: %v", err)
	}
	_ = findings // count is policy-dependent; we assert only that evaluation succeeds.
}

func TestGetPlatformFromInput(t *testing.T) {
	e := NewEngine()

	wf := &platform.Workflow{Platform: "gitlab-ci"}
	in := map[string]interface{}{"workflow": wf}
	if got := e.getPlatformFromInput(in); got != "gitlab-ci" {
		t.Errorf("getPlatformFromInput = %q, want gitlab-ci", got)
	}

	if got := e.getPlatformFromInput(map[string]interface{}{}); got != "unknown" {
		t.Errorf("getPlatformFromInput(empty) = %q, want unknown", got)
	}
}

func TestExtractSecurityContext(t *testing.T) {
	e := NewEngine()
	wf := &platform.Workflow{
		Platform: "github-actions",
		Jobs: []platform.Job{
			{ID: "a", Steps: []platform.Step{{Name: "s1"}}},
			{ID: "b", Steps: []platform.Step{{Name: "s2"}, {Name: "s3"}}},
		},
	}

	ctx := e.extractSecurityContext(wf)
	if ctx["platform"] != "github-actions" {
		t.Errorf("platform = %v, want github-actions", ctx["platform"])
	}
	jobs, ok := ctx["jobs"].([]map[string]interface{})
	if !ok {
		t.Fatalf("jobs has unexpected type %T", ctx["jobs"])
	}
	if len(jobs) != 2 {
		t.Errorf("jobs len = %d, want 2", len(jobs))
	}
}

func TestToRulesFinding(t *testing.T) {
	f := Finding{
		RuleID:      "TEST_RULE",
		RuleName:    "Test Rule",
		Description: "desc",
		Severity:    rules.High,
		Category:    rules.SecretExposure,
		FilePath:    "ci.yml",
		LineNumber:  42,
		Evidence:    "evidence",
		JobID:       "build",
		StepID:      "checkout",
	}

	rf := f.ToRulesFinding()
	if rf.RuleID != "TEST_RULE" || rf.Severity != rules.High || rf.Category != rules.SecretExposure {
		t.Errorf("core fields not mapped: %+v", rf)
	}
	if rf.JobName != "build" {
		t.Errorf("JobName = %q, want build (mapped from JobID)", rf.JobName)
	}
	if rf.StepName != "checkout" {
		t.Errorf("StepName = %q, want checkout (mapped from StepID)", rf.StepName)
	}
	if rf.Remediation == "" {
		t.Error("expected a non-empty default remediation")
	}
}
