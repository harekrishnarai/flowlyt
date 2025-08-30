package github

import (
	"strings"
	"testing"
)

func TestEnvironmentDetectionIntegration(t *testing.T) {
	client := NewClient()
	if client == nil {
		t.Fatal("Expected client to be created")
	}
}

func TestParseRepositoryURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		owner    string
		repo     string
		hasError bool
	}{
		{
			name:  "HTTPS URL",
			url:   "https://github.com/owner/repo",
			owner: "owner",
			repo:  "repo",
		},
		{
			name:  "HTTPS URL with .git",
			url:   "https://github.com/owner/repo.git",
			owner: "owner",
			repo:  "repo",
		},
		{
			name:     "Invalid URL",
			url:      "invalid-url",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, err := ParseRepositoryURL(tt.url)

			if tt.hasError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if owner != tt.owner {
				t.Errorf("Expected owner %s, got %s", tt.owner, owner)
			}

			if repo != tt.repo {
				t.Errorf("Expected repo %s, got %s", tt.repo, repo)
			}
		})
	}
}

func TestCloneRepositoryWithProgress(t *testing.T) {
	client := NewClient()

	// Test that the function exists and can be called
	// We don't actually clone to avoid network dependencies in tests
	_, err := client.CloneRepositoryWithProgress("", "", false, nil)
	if err == nil {
		t.Error("Expected error for empty URL")
	}

	// Verify error contains expected message
	if !strings.Contains(err.Error(), "invalid GitHub repository URL") {
		t.Errorf("Expected URL validation error, got: %v", err)
	}
}
