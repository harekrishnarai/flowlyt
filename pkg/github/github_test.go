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
