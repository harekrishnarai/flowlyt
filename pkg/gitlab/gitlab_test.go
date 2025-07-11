package gitlab

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/harekrishnarai/flowlyt/pkg/parser"
)

func TestFindGitLabWorkflows(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Create a test .gitlab-ci.yml file
	gitlabCIContent := `image: ubuntu:latest

stages:
  - build
  - test

variables:
  SECRET_KEY: "hardcoded_secret_123"

build-job:
  stage: build
  script:
    - echo "Building..."
    - echo $SECRET_KEY

test-job:
  stage: test
  script:
    - echo "Testing..."
`

	gitlabCIPath := filepath.Join(tempDir, ".gitlab-ci.yml")
	err := os.WriteFile(gitlabCIPath, []byte(gitlabCIContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Test FindGitLabWorkflows
	workflows, err := FindGitLabWorkflows(tempDir)
	if err != nil {
		t.Fatalf("FindGitLabWorkflows failed: %v", err)
	}

	if len(workflows) != 1 {
		t.Fatalf("Expected 1 workflow, got %d", len(workflows))
	}

	workflow := workflows[0]
	if workflow.Name != ".gitlab-ci.yml" {
		t.Errorf("Expected workflow name '.gitlab-ci.yml', got '%s'", workflow.Name)
	}

	if workflow.Path != gitlabCIPath {
		t.Errorf("Expected workflow path '%s', got '%s'", gitlabCIPath, workflow.Path)
	}

	// Test that the workflow has the expected structure
	if len(workflow.Workflow.Jobs) == 0 {
		t.Error("Expected workflow to have jobs, but got none")
	}
}

func TestGitLabRules(t *testing.T) {
	rules := GitLabRules()

	if len(rules) == 0 {
		t.Error("Expected GitLab rules to return some rules, but got none")
	}

	// Check that we have the expected rule IDs
	expectedRuleIDs := []string{
		"GITLAB_INSECURE_IMAGE",
		"GITLAB_SCRIPT_INJECTION",
		"GITLAB_EXPOSED_VARIABLES",
		"GITLAB_UNRESTRICTED_RULES",
		"GITLAB_PRIVILEGED_SERVICES",
		"GITLAB_INSECURE_ARTIFACTS",
	}

	ruleIDs := make(map[string]bool)
	for _, rule := range rules {
		ruleIDs[rule.ID] = true
	}

	for _, expectedID := range expectedRuleIDs {
		if !ruleIDs[expectedID] {
			t.Errorf("Expected rule ID '%s' not found in GitLab rules", expectedID)
		}
	}
}

func TestGitLabRuleChecks(t *testing.T) {
	// Create a test workflow with known vulnerabilities
	content := []byte(`image: ubuntu:latest

variables:
  SECRET_KEY: "hardcoded_secret_123"
  API_TOKEN: $CI_SECRET_TOKEN

build-job:
  stage: build
  script:
    - echo "Building..."
    - echo $SECRET_KEY
    - eval "$(echo $USER_INPUT)"
    - docker run --privileged alpine:latest
  artifacts:
    paths:
      - build/
`)

	workflow := parser.WorkflowFile{
		Name:    ".gitlab-ci.yml",
		Path:    "/test/.gitlab-ci.yml",
		Content: content,
	}

	rules := GitLabRules()

	// Test each rule
	totalFindings := 0
	for _, rule := range rules {
		findings := rule.Check(workflow)
		totalFindings += len(findings)

		// Verify findings have required fields
		for _, finding := range findings {
			if finding.RuleID == "" {
				t.Error("Finding missing RuleID")
			}
			if finding.Description == "" {
				t.Error("Finding missing Description")
			}
			if finding.Severity == "" {
				t.Error("Finding missing Severity")
			}
		}
	}

	if totalFindings == 0 {
		t.Error("Expected GitLab rules to find some issues in the test workflow, but found none")
	}
}

func TestParseRepositoryURL(t *testing.T) {
	tests := []struct {
		name             string
		repoURL          string
		expectedInstance string
		expectedOwner    string
		expectedRepo     string
		shouldError      bool
	}{
		{
			name:             "GitLab SaaS HTTPS",
			repoURL:          "https://gitlab.com/owner/repo",
			expectedInstance: "https://gitlab.com",
			expectedOwner:    "owner",
			expectedRepo:     "repo",
			shouldError:      false,
		},
		{
			name:             "GitLab SaaS with .git suffix",
			repoURL:          "https://gitlab.com/owner/repo.git",
			expectedInstance: "https://gitlab.com",
			expectedOwner:    "owner",
			expectedRepo:     "repo",
			shouldError:      false,
		},
		{
			name:             "On-premise GitLab",
			repoURL:          "https://gitlab.company.com/team/project",
			expectedInstance: "https://gitlab.company.com",
			expectedOwner:    "team",
			expectedRepo:     "project",
			shouldError:      false,
		},
		{
			name:        "Invalid URL format",
			repoURL:     "invalid-url",
			shouldError: true,
		},
		{
			name:        "Incomplete path",
			repoURL:     "https://gitlab.com/owner",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instanceURL, owner, repo, err := ParseRepositoryURL(tt.repoURL)

			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error for URL %s, but got none", tt.repoURL)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error for URL %s: %v", tt.repoURL, err)
				return
			}

			if instanceURL != tt.expectedInstance {
				t.Errorf("Expected instance URL %s, got %s", tt.expectedInstance, instanceURL)
			}

			if owner != tt.expectedOwner {
				t.Errorf("Expected owner %s, got %s", tt.expectedOwner, owner)
			}

			if repo != tt.expectedRepo {
				t.Errorf("Expected repo %s, got %s", tt.expectedRepo, repo)
			}
		})
	}
}

func TestIsGitLabURL(t *testing.T) {
	tests := []struct {
		name     string
		repoURL  string
		expected bool
	}{
		{
			name:     "GitLab SaaS",
			repoURL:  "https://gitlab.com/owner/repo",
			expected: true,
		},
		{
			name:     "On-premise GitLab",
			repoURL:  "https://gitlab.company.com/team/project",
			expected: true,
		},
		{
			name:     "GitHub URL",
			repoURL:  "https://github.com/owner/repo",
			expected: false,
		},
		{
			name:     "Non-Git URL",
			repoURL:  "https://example.com/some/path",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsGitLabURL(tt.repoURL)
			if result != tt.expected {
				t.Errorf("Expected %v for URL %s, got %v", tt.expected, tt.repoURL, result)
			}
		})
	}
}

func TestNewClient(t *testing.T) {
	tests := []struct {
		name        string
		instanceURL string
		expected    string
	}{
		{
			name:        "Default GitLab SaaS",
			instanceURL: "",
			expected:    "https://gitlab.com",
		},
		{
			name:        "Explicit GitLab SaaS",
			instanceURL: "https://gitlab.com",
			expected:    "https://gitlab.com",
		},
		{
			name:        "On-premise with HTTPS",
			instanceURL: "https://gitlab.company.com",
			expected:    "https://gitlab.company.com",
		},
		{
			name:        "On-premise without protocol",
			instanceURL: "gitlab.company.com",
			expected:    "https://gitlab.company.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.instanceURL)
			if err != nil {
				t.Errorf("Unexpected error creating client: %v", err)
				return
			}

			if client.instanceURL != tt.expected {
				t.Errorf("Expected instance URL %s, got %s", tt.expected, client.instanceURL)
			}
		})
	}
}
