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

package gitlab

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/harekrishnarai/flowlyt/v2/pkg/platform"
)

const sampleGitLabCI = `stages:
  - build
  - test

build-job:
  stage: build
  script:
    - echo "building"

test-job:
  stage: test
  script:
    - echo "testing"
`

func TestGitLabPlatformName(t *testing.T) {
	if got := NewGitLabPlatform().Name(); got != "gitlab-ci" {
		t.Errorf("Name = %q, want gitlab-ci", got)
	}
}

func TestGitLabDetectWorkflows(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".gitlab-ci.yml"), []byte(sampleGitLabCI), 0o644); err != nil {
		t.Fatal(err)
	}

	glp := NewGitLabPlatform()
	found, err := glp.DetectWorkflows(dir)
	if err != nil {
		t.Fatalf("DetectWorkflows: %v", err)
	}
	if len(found) != 1 {
		t.Errorf("found %d files, want 1: %v", len(found), found)
	}

	// No GitLab CI files -> error.
	if _, err := glp.DetectWorkflows(t.TempDir()); err == nil {
		t.Error("expected error when no GitLab CI files exist")
	}
}

func TestGitLabParseWorkflow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitlab-ci.yml")
	if err := os.WriteFile(path, []byte(sampleGitLabCI), 0o644); err != nil {
		t.Fatal(err)
	}

	glp := NewGitLabPlatform()
	wf, err := glp.ParseWorkflow(path)
	if err != nil {
		t.Fatalf("ParseWorkflow: %v", err)
	}
	if wf.Platform != "gitlab-ci" {
		t.Errorf("Platform = %q, want gitlab-ci", wf.Platform)
	}
	if len(wf.Jobs) == 0 {
		t.Error("expected at least one job")
	}
	// No workflow.name specified -> falls back to file name.
	if wf.Name == "" {
		t.Error("expected non-empty name (filename fallback)")
	}
}

func TestGitLabValidateWorkflow(t *testing.T) {
	glp := NewGitLabPlatform()

	valid := &platform.Workflow{Platform: "gitlab-ci", Jobs: []platform.Job{{ID: "build"}}}
	if err := glp.ValidateWorkflow(valid); err != nil {
		t.Errorf("expected valid workflow, got error: %v", err)
	}

	wrongPlatform := &platform.Workflow{Platform: "github-actions", Jobs: []platform.Job{{ID: "build"}}}
	if err := glp.ValidateWorkflow(wrongPlatform); err == nil {
		t.Error("expected error for wrong platform")
	}

	noJobs := &platform.Workflow{Platform: "gitlab-ci"}
	if err := glp.ValidateWorkflow(noJobs); err == nil {
		t.Error("expected error for workflow with no jobs")
	}
}

func TestGitLabIsKnownCIVariable(t *testing.T) {
	glp := NewGitLabPlatform()
	known := []string{"CI", "CI_PROJECT_ID", "GITLAB_CI", "HOME", "PATH"}
	for _, v := range known {
		if !glp.isKnownCIVariable(v) {
			t.Errorf("isKnownCIVariable(%q) = false, want true", v)
		}
	}
	unknown := []string{"MY_SECRET", "DB_PASSWORD", "RANDOM_VAR"}
	for _, v := range unknown {
		if glp.isKnownCIVariable(v) {
			t.Errorf("isKnownCIVariable(%q) = true, want false", v)
		}
	}
}
