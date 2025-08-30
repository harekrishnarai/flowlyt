package validation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/harekrishnarai/flowlyt/pkg/errors"
)

func TestValidator_ValidateConfig(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name       string
		configPath string
		wantError  bool
		errorType  errors.ErrorType
	}{
		{
			name:       "empty config path should be valid",
			configPath: "",
			wantError:  false,
		},
		{
			name:       "path traversal should be invalid",
			configPath: "../../../etc/passwd",
			wantError:  true,
			errorType:  errors.ErrorTypeConfig,
		},
		{
			name:       "non-existent file should be invalid",
			configPath: "non-existent-config.yml",
			wantError:  true,
			errorType:  errors.ErrorTypeConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateConfig(tt.configPath)
			if tt.wantError {
				if err == nil {
					t.Errorf("ValidateConfig() expected error but got none")
					return
				}
				if flowlytErr, ok := err.(*errors.FlowlytError); ok {
					if flowlytErr.Type != tt.errorType {
						t.Errorf("ValidateConfig() error type = %v, want %v", flowlytErr.Type, tt.errorType)
					}
				}
			} else if err != nil {
				t.Errorf("ValidateConfig() unexpected error = %v", err)
			}
		})
	}
}

func TestValidator_ValidateRepository(t *testing.T) {
	validator := NewValidator()

	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "flowlyt-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a temporary file for testing
	tempFile := filepath.Join(tempDir, "test-file.txt")
	if err := os.WriteFile(tempFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	tests := []struct {
		name      string
		repoPath  string
		wantError bool
		errorType errors.ErrorType
	}{
		{
			name:      "empty repo path should be valid",
			repoPath:  "",
			wantError: false,
		},
		{
			name:      "valid directory should be valid",
			repoPath:  tempDir,
			wantError: false,
		},
		{
			name:      "path traversal should be invalid",
			repoPath:  "../../etc",
			wantError: true,
			errorType: errors.ErrorTypeRepository,
		},
		{
			name:      "non-existent directory should be invalid",
			repoPath:  "/non/existent/directory",
			wantError: true,
			errorType: errors.ErrorTypeRepository,
		},
		{
			name:      "file instead of directory should be invalid",
			repoPath:  tempFile,
			wantError: true,
			errorType: errors.ErrorTypeRepository,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateRepository(tt.repoPath)
			if tt.wantError {
				if err == nil {
					t.Errorf("ValidateRepository() expected error but got none")
					return
				}
				if flowlytErr, ok := err.(*errors.FlowlytError); ok {
					if flowlytErr.Type != tt.errorType {
						t.Errorf("ValidateRepository() error type = %v, want %v", flowlytErr.Type, tt.errorType)
					}
				}
			} else if err != nil {
				t.Errorf("ValidateRepository() unexpected error = %v", err)
			}
		})
	}
}

func TestValidator_ValidateURL(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name      string
		repoURL   string
		wantError bool
		errorType errors.ErrorType
	}{
		{
			name:      "empty URL should be valid",
			repoURL:   "",
			wantError: false,
		},
		{
			name:      "valid GitHub URL should be valid",
			repoURL:   "https://github.com/owner/repo",
			wantError: false,
		},
		{
			name:      "valid GitLab URL should be valid",
			repoURL:   "https://gitlab.com/owner/repo",
			wantError: false,
		},
		{
			name:      "invalid URL format should be invalid",
			repoURL:   "not-a-url",
			wantError: true,
			errorType: errors.ErrorTypeRepository,
		},
		{
			name:      "localhost URL should be invalid",
			repoURL:   "https://localhost/repo",
			wantError: true,
			errorType: errors.ErrorTypeRepository,
		},
		{
			name:      "private IP URL should be invalid",
			repoURL:   "https://192.168.1.100/repo",
			wantError: true,
			errorType: errors.ErrorTypeRepository,
		},
		{
			name:      "unknown host should be invalid",
			repoURL:   "https://unknown-git-host.com/repo",
			wantError: true,
			errorType: errors.ErrorTypeRepository,
		},
		{
			name:      "SSH URL should be invalid",
			repoURL:   "git@github.com:owner/repo.git",
			wantError: true,
			errorType: errors.ErrorTypeRepository,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateURL(tt.repoURL)
			if tt.wantError {
				if err == nil {
					t.Errorf("ValidateURL() expected error but got none")
					return
				}
				if flowlytErr, ok := err.(*errors.FlowlytError); ok {
					if flowlytErr.Type != tt.errorType {
						t.Errorf("ValidateURL() error type = %v, want %v", flowlytErr.Type, tt.errorType)
					}
				}
			} else if err != nil {
				t.Errorf("ValidateURL() unexpected error = %v", err)
			}
		})
	}
}

func TestValidator_ValidateWorkflowFile(t *testing.T) {
	validator := NewValidator()

	// Create a temporary workflow file for testing
	tempDir, err := os.MkdirTemp("", "flowlyt-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	tempWorkflow := filepath.Join(tempDir, "workflow.yml")
	if err := os.WriteFile(tempWorkflow, []byte("name: test"), 0644); err != nil {
		t.Fatalf("Failed to create temp workflow: %v", err)
	}

	tests := []struct {
		name         string
		workflowPath string
		wantError    bool
		errorType    errors.ErrorType
	}{
		{
			name:         "empty workflow path should be valid",
			workflowPath: "",
			wantError:    false,
		},
		{
			name:         "valid workflow file should be valid",
			workflowPath: tempWorkflow,
			wantError:    false,
		},
		{
			name:         "path traversal should be invalid",
			workflowPath: "../../../etc/passwd",
			wantError:    true,
			errorType:    errors.ErrorTypeWorkflow,
		},
		{
			name:         "non-existent file should be invalid",
			workflowPath: "/non/existent/workflow.yml",
			wantError:    true,
			errorType:    errors.ErrorTypeWorkflow,
		},
		{
			name:         "directory instead of file should be invalid",
			workflowPath: tempDir,
			wantError:    true,
			errorType:    errors.ErrorTypeWorkflow,
		},
		{
			name:         "invalid file extension should be invalid",
			workflowPath: "/tmp/workflow.txt",
			wantError:    true,
			errorType:    errors.ErrorTypeWorkflow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateWorkflowFile(tt.workflowPath)
			if tt.wantError {
				if err == nil {
					t.Errorf("ValidateWorkflowFile() expected error but got none")
					return
				}
				if flowlytErr, ok := err.(*errors.FlowlytError); ok {
					if flowlytErr.Type != tt.errorType {
						t.Errorf("ValidateWorkflowFile() error type = %v, want %v", flowlytErr.Type, tt.errorType)
					}
				}
			} else if err != nil {
				t.Errorf("ValidateWorkflowFile() unexpected error = %v", err)
			}
		})
	}
}

func TestValidator_ValidatePlatform(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name      string
		platform  string
		wantError bool
		errorType errors.ErrorType
	}{
		{
			name:      "empty platform should be invalid",
			platform:  "",
			wantError: true,
			errorType: errors.ErrorTypeValidation,
		},
		{
			name:      "github platform should be valid",
			platform:  "github",
			wantError: false,
		},
		{
			name:      "gitlab platform should be valid",
			platform:  "gitlab",
			wantError: false,
		},
		{
			name:      "invalid platform should be invalid",
			platform:  "invalid-platform",
			wantError: true,
			errorType: errors.ErrorTypePlatform,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidatePlatform(tt.platform)
			if tt.wantError {
				if err == nil {
					t.Errorf("ValidatePlatform() expected error but got none")
					return
				}
				if flowlytErr, ok := err.(*errors.FlowlytError); ok {
					if flowlytErr.Type != tt.errorType {
						t.Errorf("ValidatePlatform() error type = %v, want %v", flowlytErr.Type, tt.errorType)
					}
				}
			} else if err != nil {
				t.Errorf("ValidatePlatform() unexpected error = %v", err)
			}
		})
	}
}

func TestValidator_ValidateEntropyThreshold(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name      string
		threshold float64
		wantError bool
	}{
		{
			name:      "valid threshold 4.5 should be valid",
			threshold: 4.5,
			wantError: false,
		},
		{
			name:      "minimum threshold 0.0 should be valid",
			threshold: 0.0,
			wantError: false,
		},
		{
			name:      "maximum threshold 8.0 should be valid",
			threshold: 8.0,
			wantError: false,
		},
		{
			name:      "negative threshold should be invalid",
			threshold: -1.0,
			wantError: true,
		},
		{
			name:      "too high threshold should be invalid",
			threshold: 10.0,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateEntropyThreshold(tt.threshold)
			if tt.wantError && err == nil {
				t.Errorf("ValidateEntropyThreshold() expected error but got none")
			} else if !tt.wantError && err != nil {
				t.Errorf("ValidateEntropyThreshold() unexpected error = %v", err)
			}
		})
	}
}

func TestValidator_validatePathSafety(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name      string
		path      string
		wantError bool
	}{
		{
			name:      "safe relative path should be valid",
			path:      "config/test.yml",
			wantError: false,
		},
		{
			name:      "path traversal should be invalid",
			path:      "../../../etc/passwd",
			wantError: true,
		},
		{
			name:      "null byte should be invalid",
			path:      "config\x00.yml",
			wantError: true,
		},
		{
			name:      "system directory access should be invalid",
			path:      "/etc/passwd",
			wantError: true,
		},
		{
			name:      "safe absolute path should be valid",
			path:      "/home/user/project/config.yml",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validatePathSafety(tt.path)
			if tt.wantError && err == nil {
				t.Errorf("validatePathSafety() expected error but got none")
			} else if !tt.wantError && err != nil {
				t.Errorf("validatePathSafety() unexpected error = %v", err)
			}
		})
	}
}

func TestValidator_isPrivateOrLocalhost(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		{
			name:     "localhost should be private",
			host:     "localhost",
			expected: true,
		},
		{
			name:     "127.0.0.1 should be private",
			host:     "127.0.0.1",
			expected: true,
		},
		{
			name:     "192.168.1.1 should be private",
			host:     "192.168.1.1",
			expected: true,
		},
		{
			name:     "10.0.0.1 should be private",
			host:     "10.0.0.1",
			expected: true,
		},
		{
			name:     "github.com should not be private",
			host:     "github.com",
			expected: false,
		},
		{
			name:     "8.8.8.8 should not be private",
			host:     "8.8.8.8",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.isPrivateOrLocalhost(tt.host)
			if result != tt.expected {
				t.Errorf("isPrivateOrLocalhost() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestValidator_isKnownGitHost(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		{
			name:     "github.com should be known",
			host:     "github.com",
			expected: true,
		},
		{
			name:     "gitlab.com should be known",
			host:     "gitlab.com",
			expected: true,
		},
		{
			name:     "gitlab.company.com should be known",
			host:     "gitlab.company.com",
			expected: true,
		},
		{
			name:     "unknown-host.com should not be known",
			host:     "unknown-host.com",
			expected: false,
		},
		{
			name:     "malicious-site.com should not be known",
			host:     "malicious-site.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.isKnownGitHost(tt.host)
			if result != tt.expected {
				t.Errorf("isKnownGitHost() = %v, want %v", result, tt.expected)
			}
		})
	}
}
