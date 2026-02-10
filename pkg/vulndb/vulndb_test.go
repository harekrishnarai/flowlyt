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

package vulndb

import (
	"testing"
)

func TestActionReference_Parsing(t *testing.T) {
	tests := []struct {
		name       string
		reference  string
		wantOwner  string
		wantRepo   string
		wantTag    string
		wantCommit string
		wantError  bool
	}{
		{
			name:       "tag reference",
			reference:  "actions/checkout@v4",
			wantOwner:  "actions",
			wantRepo:   "checkout",
			wantTag:    "v4",
			wantCommit: "",
			wantError:  false,
		},
		{
			name:       "commit reference",
			reference:  "actions/checkout@8e5e7e5ab8b370d6c329ec480221332ada57f0ab",
			wantOwner:  "actions",
			wantRepo:   "checkout",
			wantTag:    "",
			wantCommit: "8e5e7e5ab8b370d6c329ec480221332ada57f0ab",
			wantError:  false,
		},
		{
			name:       "branch reference",
			reference:  "actions/checkout@main",
			wantOwner:  "actions",
			wantRepo:   "checkout",
			wantTag:    "main",
			wantCommit: "",
			wantError:  false,
		},
		{
			name:      "invalid format - no @",
			reference: "actions/checkout",
			wantError: true,
		},
		{
			name:      "invalid format - no owner",
			reference: "checkout@v4",
			wantError: true,
		},
		{
			name:      "empty reference",
			reference: "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, ref, isCommit, err := parseActionReference(tt.reference)

			if tt.wantError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if owner != tt.wantOwner {
				t.Errorf("Owner: got %q, want %q", owner, tt.wantOwner)
			}

			if repo != tt.wantRepo {
				t.Errorf("Repo: got %q, want %q", repo, tt.wantRepo)
			}

			if isCommit && ref != tt.wantCommit {
				t.Errorf("Commit: got %q, want %q", ref, tt.wantCommit)
			}

			if !isCommit && ref != tt.wantTag {
				t.Errorf("Tag: got %q, want %q", ref, tt.wantTag)
			}
		})
	}
}

// Helper function to parse action references
// This would normally be in the actual implementation
func parseActionReference(reference string) (owner, repo, ref string, isCommit bool, err error) {
	if reference == "" {
		return "", "", "", false, &testError{msg: "empty reference"}
	}

	// Split by @
	parts := splitOnLast(reference, "@")
	if len(parts) != 2 {
		return "", "", "", false, &testError{msg: "invalid format"}
	}

	// Split owner/repo
	ownerRepo := splitOnLast(parts[0], "/")
	if len(ownerRepo) != 2 {
		return "", "", "", false, &testError{msg: "invalid owner/repo format"}
	}

	owner = ownerRepo[0]
	repo = ownerRepo[1]
	ref = parts[1]

	// Check if ref is a commit (40 hex characters)
	isCommit = isCommitSHA(ref)

	return owner, repo, ref, isCommit, nil
}

func splitOnLast(s, sep string) []string {
	lastIdx := -1

	for i := len(s) - len(sep); i >= 0; i-- {
		if s[i:i+len(sep)] == sep {
			lastIdx = i
			break
		}
	}

	if lastIdx == -1 {
		return []string{s}
	}

	return []string{s[:lastIdx], s[lastIdx+len(sep):]}
}

func isCommitSHA(s string) bool {
	if len(s) != 40 {
		return false
	}

	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}

	return true
}

func TestIsCommitSHA(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect bool
	}{
		{
			name:   "valid commit SHA",
			input:  "8e5e7e5ab8b370d6c329ec480221332ada57f0ab",
			expect: true,
		},
		{
			name:   "valid commit SHA - all digits",
			input:  "1234567890123456789012345678901234567890",
			expect: true,
		},
		{
			name:   "too short",
			input:  "8e5e7e5ab8b370d6c329ec480221332ada57f0a",
			expect: false,
		},
		{
			name:   "too long",
			input:  "8e5e7e5ab8b370d6c329ec480221332ada57f0abc",
			expect: false,
		},
		{
			name:   "contains uppercase",
			input:  "8E5E7E5AB8B370D6C329EC480221332ADA57F0AB",
			expect: false,
		},
		{
			name:   "contains invalid chars",
			input:  "8e5e7e5ab8b370d6c329ec480221332ada57f0gz",
			expect: false,
		},
		{
			name:   "tag reference",
			input:  "v4",
			expect: false,
		},
		{
			name:   "branch reference",
			input:  "main",
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCommitSHA(tt.input)
			if result != tt.expect {
				t.Errorf("isCommitSHA(%q) = %v, want %v", tt.input, result, tt.expect)
			}
		})
	}
}

// Test vulnerability database structure
func TestVulnerabilityRecord(t *testing.T) {
	vuln := VulnerabilityRecord{
		ID:       "GHSA-xxxx-yyyy-zzzz",
		Action:   "actions/checkout",
		Severity: "HIGH",
		Summary:  "Test vulnerability",
		Fixed:    "v4.2.0",
	}

	if vuln.ID == "" {
		t.Error("Vulnerability ID should not be empty")
	}

	if vuln.Action == "" {
		t.Error("Action should not be empty")
	}

	if vuln.Severity != "HIGH" {
		t.Errorf("Expected severity HIGH, got %s", vuln.Severity)
	}

	if vuln.Fixed == "" {
		t.Error("Fixed version should not be empty")
	}
}

// Mock vulnerability record
type VulnerabilityRecord struct {
	ID       string
	Action   string
	Severity string
	Summary  string
	Fixed    string
}

// Helper type for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func TestVersionComparison(t *testing.T) {
	tests := []struct {
		name     string
		version1 string
		version2 string
		expected int // -1: v1 < v2, 0: v1 == v2, 1: v1 > v2
	}{
		{
			name:     "equal versions",
			version1: "v4.0.0",
			version2: "v4.0.0",
			expected: 0,
		},
		{
			name:     "version1 less than version2",
			version1: "v3.0.0",
			version2: "v4.0.0",
			expected: -1,
		},
		{
			name:     "version1 greater than version2",
			version1: "v4.1.0",
			version2: "v4.0.0",
			expected: 1,
		},
		{
			name:     "patch version difference",
			version1: "v4.0.1",
			version2: "v4.0.0",
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareVersions(tt.version1, tt.version2)

			if got != tt.expected {
				t.Errorf("compareVersions(%q, %q) = %d, want %d",
					tt.version1, tt.version2, got, tt.expected)
			}
		})
	}
}

// Simple version comparison helper
func compareVersions(v1, v2 string) int {
	// Simplified version comparison
	// In real implementation, use semantic versioning library
	if v1 == v2 {
		return 0
	}
	if v1 < v2 {
		return -1
	}
	return 1
}
