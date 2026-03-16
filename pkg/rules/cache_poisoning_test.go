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

// helper: build a minimal WorkflowFile from a Workflow struct
func makeWorkflow(w parser.Workflow) parser.WorkflowFile {
	return parser.WorkflowFile{
		Path:     "test.yml",
		Name:     "test.yml",
		Content:  []byte{},
		Workflow: w,
	}
}

// ---- CP-001 tests ----

// TestCP001_BroadRestoreKeys: restore-keys contains a line without hashFiles → CP-001 finding
func TestCP001_BroadRestoreKeys(t *testing.T) {
	wf := makeWorkflow(parser.Workflow{
		Jobs: map[string]parser.Job{
			"build": {
				Steps: []parser.Step{
					{
						Name: "Cache npm",
						Uses: "actions/cache@v3",
						With: map[string]interface{}{
							"path":         "~/.npm",
							"key":          "${{ runner.os }}-npm-${{ hashFiles('**/package-lock.json') }}",
							"restore-keys": "${{ runner.os }}-npm-",
						},
					},
				},
			},
		},
	})

	findings := CheckCachePoisoning(wf)

	var cp001 []Finding
	for _, f := range findings {
		if f.RuleID == "CACHE_RESTORE_KEYS_TOO_BROAD" {
			cp001 = append(cp001, f)
		}
	}

	if len(cp001) == 0 {
		t.Fatal("expected CP-001 finding for broad restore-key without hashFiles, got none")
	}
}

// TestCP001_SafeWithHash: restore-keys contains hashFiles on every line → no CP-001 finding
func TestCP001_SafeWithHash(t *testing.T) {
	wf := makeWorkflow(parser.Workflow{
		Jobs: map[string]parser.Job{
			"build": {
				Steps: []parser.Step{
					{
						Name: "Cache npm",
						Uses: "actions/cache@v3",
						With: map[string]interface{}{
							"path":         "~/.npm",
							"key":          "${{ runner.os }}-npm-${{ hashFiles('**/package-lock.json') }}",
							"restore-keys": "${{ runner.os }}-npm-${{ hashFiles('**/package-lock.json') }}",
						},
					},
				},
			},
		},
	})

	findings := CheckCachePoisoning(wf)

	for _, f := range findings {
		if f.RuleID == "CACHE_RESTORE_KEYS_TOO_BROAD" {
			t.Fatalf("unexpected CP-001 finding when hashFiles is present: %s", f.Evidence)
		}
	}
}

// TestCP001_NoRestoreKeys: actions/cache with no restore-keys field at all → no CP-001 finding
func TestCP001_NoRestoreKeys(t *testing.T) {
	wf := makeWorkflow(parser.Workflow{
		Jobs: map[string]parser.Job{
			"build": {
				Steps: []parser.Step{
					{
						Name: "Cache npm",
						Uses: "actions/cache@v4",
						With: map[string]interface{}{
							"path": "~/.npm",
							"key":  "${{ runner.os }}-npm-${{ hashFiles('**/package-lock.json') }}",
						},
					},
				},
			},
		},
	})

	findings := CheckCachePoisoning(wf)

	for _, f := range findings {
		if f.RuleID == "CACHE_RESTORE_KEYS_TOO_BROAD" {
			t.Fatalf("unexpected CP-001 finding when no restore-keys field: %s", f.Evidence)
		}
	}
}

// ---- CP-002 tests ----

// TestCP002_CacheWriteInPR: pull_request workflow with actions/cache@v3 (not restore-only) → CP-002 finding
func TestCP002_CacheWriteInPR(t *testing.T) {
	wf := makeWorkflow(parser.Workflow{
		On: map[string]interface{}{
			"pull_request": nil,
		},
		Jobs: map[string]parser.Job{
			"build": {
				Steps: []parser.Step{
					{
						Name: "Cache deps",
						Uses: "actions/cache@v3",
						With: map[string]interface{}{
							"path": "~/.npm",
							"key":  "${{ runner.os }}-npm-${{ hashFiles('**/package-lock.json') }}",
						},
					},
				},
			},
		},
	})

	findings := CheckCachePoisoning(wf)

	var cp002 []Finding
	for _, f := range findings {
		if f.RuleID == "CACHE_WRITE_IN_PR_WORKFLOW" {
			cp002 = append(cp002, f)
		}
	}

	if len(cp002) == 0 {
		t.Fatal("expected CP-002 finding for cache write in PR workflow, got none")
	}
}

// TestCP002_SafeRestoreOnly: pull_request workflow with actions/cache/restore@v3 → no CP-002 finding
func TestCP002_SafeRestoreOnly(t *testing.T) {
	wf := makeWorkflow(parser.Workflow{
		On: map[string]interface{}{
			"pull_request": nil,
		},
		Jobs: map[string]parser.Job{
			"build": {
				Steps: []parser.Step{
					{
						Name: "Restore cache",
						Uses: "actions/cache/restore@v3",
						With: map[string]interface{}{
							"path": "~/.npm",
							"key":  "${{ runner.os }}-npm-${{ hashFiles('**/package-lock.json') }}",
						},
					},
				},
			},
		},
	})

	findings := CheckCachePoisoning(wf)

	for _, f := range findings {
		if f.RuleID == "CACHE_WRITE_IN_PR_WORKFLOW" {
			t.Fatalf("unexpected CP-002 finding for restore-only action: %s", f.Evidence)
		}
	}
}

// TestCP002_SafePushWorkflow: push workflow (not PR) with cache write → no CP-002 finding
func TestCP002_SafePushWorkflow(t *testing.T) {
	wf := makeWorkflow(parser.Workflow{
		On: map[string]interface{}{
			"push": nil,
		},
		Jobs: map[string]parser.Job{
			"build": {
				Steps: []parser.Step{
					{
						Name: "Cache deps",
						Uses: "actions/cache@v3",
						With: map[string]interface{}{
							"path": "~/.npm",
							"key":  "${{ runner.os }}-npm-${{ hashFiles('**/package-lock.json') }}",
						},
					},
				},
			},
		},
	})

	findings := CheckCachePoisoning(wf)

	for _, f := range findings {
		if f.RuleID == "CACHE_WRITE_IN_PR_WORKFLOW" {
			t.Fatalf("unexpected CP-002 finding for non-PR workflow: %s", f.Evidence)
		}
	}
}
