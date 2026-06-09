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

package github

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/harekrishnarai/flowlyt/pkg/platform"
)

const sampleWorkflow = `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "hello"
`

func TestGitHubPlatformName(t *testing.T) {
	if got := NewGitHubPlatform().Name(); got != "github-actions" {
		t.Errorf("Name = %q, want github-actions", got)
	}
}

func TestGitHubDetectWorkflows(t *testing.T) {
	dir := t.TempDir()
	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte(sampleWorkflow), 0o644); err != nil {
		t.Fatal(err)
	}
	// A non-YAML file should be ignored.
	if err := os.WriteFile(filepath.Join(wfDir, "README.md"), []byte("ignore me"), 0o644); err != nil {
		t.Fatal(err)
	}

	gp := NewGitHubPlatform()
	found, err := gp.DetectWorkflows(dir)
	if err != nil {
		t.Fatalf("DetectWorkflows: %v", err)
	}
	if len(found) != 1 {
		t.Errorf("found %d workflows, want 1: %v", len(found), found)
	}

	// No workflows directory -> error.
	if _, err := gp.DetectWorkflows(t.TempDir()); err == nil {
		t.Error("expected error when no .github/workflows directory exists")
	}
}

func TestGitHubParseWorkflow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ci.yml")
	if err := os.WriteFile(path, []byte(sampleWorkflow), 0o644); err != nil {
		t.Fatal(err)
	}

	gp := NewGitHubPlatform()
	wf, err := gp.ParseWorkflow(path)
	if err != nil {
		t.Fatalf("ParseWorkflow: %v", err)
	}
	if wf.Platform != "github-actions" {
		t.Errorf("Platform = %q, want github-actions", wf.Platform)
	}
	if wf.Name != "CI" {
		t.Errorf("Name = %q, want CI", wf.Name)
	}
	if len(wf.Jobs) == 0 {
		t.Error("expected at least one job")
	}
	if len(wf.Content) == 0 {
		t.Error("expected raw content to be preserved")
	}

	if _, err := gp.ParseWorkflow(filepath.Join(dir, "missing.yml")); err == nil {
		t.Error("expected error parsing nonexistent file")
	}
}

func TestGitHubValidateWorkflow(t *testing.T) {
	gp := NewGitHubPlatform()

	valid := &platform.Workflow{Platform: "github-actions", Jobs: []platform.Job{{ID: "build"}}}
	if err := gp.ValidateWorkflow(valid); err != nil {
		t.Errorf("expected valid workflow, got error: %v", err)
	}

	wrongPlatform := &platform.Workflow{Platform: "gitlab-ci", Jobs: []platform.Job{{ID: "build"}}}
	if err := gp.ValidateWorkflow(wrongPlatform); err == nil {
		t.Error("expected error for wrong platform")
	}

	noJobs := &platform.Workflow{Platform: "github-actions"}
	if err := gp.ValidateWorkflow(noJobs); err == nil {
		t.Error("expected error for workflow with no jobs")
	}
}
