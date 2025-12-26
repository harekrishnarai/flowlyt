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

package constants

import (
	"os"
	"testing"
)

func TestIsRunningInCI(t *testing.T) {
	// Save original environment
	originalCI := os.Getenv(EnvCI)
	originalGitHubActions := os.Getenv(EnvGitHubActions)

	// Clean up after test
	defer func() {
		os.Setenv(EnvCI, originalCI)
		os.Setenv(EnvGitHubActions, originalGitHubActions)
	}()

	tests := []struct {
		name       string
		envVars    map[string]string
		expectedCI bool
	}{
		{
			name:       "No CI environment",
			envVars:    map[string]string{},
			expectedCI: false,
		},
		{
			name: "GitHub Actions environment",
			envVars: map[string]string{
				EnvGitHubActions: "true",
			},
			expectedCI: true,
		},
		{
			name: "Generic CI environment",
			envVars: map[string]string{
				EnvCI: "true",
			},
			expectedCI: true,
		},
		{
			name: "Travis CI environment",
			envVars: map[string]string{
				"TRAVIS": "true",
			},
			expectedCI: true,
		},
		{
			name: "GitLab CI environment",
			envVars: map[string]string{
				"GITLAB_CI": "true",
			},
			expectedCI: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all CI-related environment variables
			ciEnvs := []string{
				EnvCI, EnvGitHubActions, "TRAVIS", "CIRCLECI", "JENKINS_URL",
				"GITLAB_CI", "BUILDKITE", "TF_BUILD", "GITHUB_WORKFLOW",
			}
			for _, env := range ciEnvs {
				os.Unsetenv(env)
			}

			// Set test environment variables
			for key, value := range tt.envVars {
				os.Setenv(key, value)
			}

			result := IsRunningInCI()
			if result != tt.expectedCI {
				t.Errorf("Expected IsRunningInCI() = %v, got %v", tt.expectedCI, result)
			}
		})
	}
}

func TestIsRunningInGitHubActions(t *testing.T) {
	// Save original environment
	originalGitHubActions := os.Getenv(EnvGitHubActions)

	// Clean up after test
	defer func() {
		os.Setenv(EnvGitHubActions, originalGitHubActions)
	}()

	tests := []struct {
		name             string
		gitHubActionsEnv string
		expectedGitHub   bool
	}{
		{
			name:             "Not in GitHub Actions",
			gitHubActionsEnv: "",
			expectedGitHub:   false,
		},
		{
			name:             "In GitHub Actions",
			gitHubActionsEnv: "true",
			expectedGitHub:   true,
		},
		{
			name:             "GitHub Actions false",
			gitHubActionsEnv: "false",
			expectedGitHub:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv(EnvGitHubActions, tt.gitHubActionsEnv)

			result := IsRunningInGitHubActions()
			if result != tt.expectedGitHub {
				t.Errorf("Expected IsRunningInGitHubActions() = %v, got %v", tt.expectedGitHub, result)
			}
		})
	}
}

func TestConstants(t *testing.T) {
	// Test that constants are properly defined
	if AppName != "flowlyt" {
		t.Errorf("Expected AppName to be 'flowlyt', got %s", AppName)
	}

	if DefaultPlatform != "github" {
		t.Errorf("Expected DefaultPlatform to be 'github', got %s", DefaultPlatform)
	}

	if len(SupportedPlatforms) == 0 {
		t.Error("Expected SupportedPlatforms to have values")
	}

	if len(SupportedOutputFormats) == 0 {
		t.Error("Expected SupportedOutputFormats to have values")
	}
}
