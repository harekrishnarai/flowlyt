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

package platform

import (
	"errors"
	"fmt"
)

// Platform represents a CI/CD platform (GitHub Actions, GitLab CI, etc.)
type Platform interface {
	Name() string
	DetectWorkflows(rootPath string) ([]string, error)
	ParseWorkflow(path string) (*Workflow, error)
	GetSecurityContext(workflow *Workflow) *SecurityContext
	ValidateWorkflow(workflow *Workflow) error
}

// Workflow represents a generic CI/CD workflow structure
type Workflow struct {
	Platform    string                 `json:"platform"`
	Name        string                 `json:"name"`
	FilePath    string                 `json:"file_path"`
	Content     []byte                 `json:"content,omitempty"`
	Triggers    []Trigger              `json:"triggers"`
	Jobs        []Job                  `json:"jobs"`
	Environment map[string]string      `json:"environment,omitempty"`
	Permissions interface{}            `json:"permissions,omitempty"`
	Variables   map[string]interface{} `json:"variables,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Job represents a job in a CI/CD workflow
type Job struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Platform        string                 `json:"platform"`
	RunsOn          interface{}            `json:"runs_on"`
	Image           string                 `json:"image,omitempty"`
	Dependencies    []string               `json:"dependencies,omitempty"`
	Conditions      []string               `json:"conditions,omitempty"`
	Steps           []Step                 `json:"steps"`
	Environment     map[string]string      `json:"environment,omitempty"`
	Permissions     interface{}            `json:"permissions,omitempty"`
	Timeout         string                 `json:"timeout,omitempty"`
	ContinueOnError bool                   `json:"continue_on_error,omitempty"`
	AllowFailure    bool                   `json:"allow_failure,omitempty"`
	Variables       map[string]interface{} `json:"variables,omitempty"`
	Services        map[string]interface{} `json:"services,omitempty"`
	Artifacts       interface{}            `json:"artifacts,omitempty"`
	Cache           interface{}            `json:"cache,omitempty"`
}

// Step represents a step in a CI/CD job
type Step struct {
	ID               string                 `json:"id,omitempty"`
	Name             string                 `json:"name,omitempty"`
	Platform         string                 `json:"platform"`
	Type             string                 `json:"type"`             // "action", "script", "service", etc.
	Action           string                 `json:"action,omitempty"` // GitHub: uses, GitLab: extends
	Script           []string               `json:"script,omitempty"` // Commands to run
	Image            string                 `json:"image,omitempty"`  // Container image
	Shell            string                 `json:"shell,omitempty"`  // Shell to use
	WorkingDirectory string                 `json:"working_directory,omitempty"`
	Environment      map[string]string      `json:"environment,omitempty"`
	Inputs           map[string]interface{} `json:"inputs,omitempty"`  // GitHub: with, GitLab: variables
	Outputs          map[string]interface{} `json:"outputs,omitempty"` // Step outputs
	Conditions       []string               `json:"conditions,omitempty"`
	ContinueOnError  bool                   `json:"continue_on_error,omitempty"`
	AllowFailure     bool                   `json:"allow_failure,omitempty"`
	Timeout          string                 `json:"timeout,omitempty"`
	Retry            interface{}            `json:"retry,omitempty"`
	When             string                 `json:"when,omitempty"` // GitLab: when condition
}

// Trigger represents workflow triggers
type Trigger struct {
	Type       string                 `json:"type"`       // "push", "pull_request", "schedule", etc.
	Events     []string               `json:"events"`     // Specific events
	Branches   []string               `json:"branches"`   // Branch filters
	Tags       []string               `json:"tags"`       // Tag filters
	Paths      []string               `json:"paths"`      // Path filters
	Schedule   string                 `json:"schedule"`   // Cron schedule
	Conditions map[string]interface{} `json:"conditions"` // Platform-specific conditions
}

// SecurityContext contains security-relevant information extracted from a workflow
type SecurityContext struct {
	Workflow           *Workflow           `json:"workflow"`
	UserControlledVars []UserControlledVar `json:"user_controlled_vars"`
	ExternalActions    []ExternalAction    `json:"external_actions"`
	Permissions        []Permission        `json:"permissions"`
	Secrets            []SecretUsage       `json:"secrets"`
	NetworkAccess      []NetworkAccess     `json:"network_access"`
	FileOperations     []FileOperation     `json:"file_operations"`
	PrivilegeChanges   []PrivilegeChange   `json:"privilege_changes"`
	SupplyChainRisks   []SupplyChainRisk   `json:"supply_chain_risks"`
}

// UserControlledVar represents variables that can be controlled by users
type UserControlledVar struct {
	Name     string `json:"name"`
	Source   string `json:"source"`  // "github.event", "inputs", etc.
	Context  string `json:"context"` // Where it's used
	JobID    string `json:"job_id"`
	StepID   string `json:"step_id"`
	Platform string `json:"platform"`
}

// ExternalAction represents external actions/includes used
type ExternalAction struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Source   string `json:"source"` // Repository or registry
	JobID    string `json:"job_id"`
	StepID   string `json:"step_id"`
	Platform string `json:"platform"`
}

// Permission represents permissions granted to jobs/workflows
type Permission struct {
	Scope       string `json:"scope"`   // "contents", "issues", etc.
	Level       string `json:"level"`   // "read", "write", "admin"
	Context     string `json:"context"` // Where it's defined
	JobID       string `json:"job_id"`
	Platform    string `json:"platform"`
	Inheritance string `json:"inheritance"` // "inherited", "explicit", "default"
}

// SecretUsage represents usage of secrets
type SecretUsage struct {
	Name     string `json:"name"`
	Context  string `json:"context"` // Where it's used
	JobID    string `json:"job_id"`
	StepID   string `json:"step_id"`
	Platform string `json:"platform"`
	Type     string `json:"type"` // "env", "input", "file"
}

// NetworkAccess represents network access patterns
type NetworkAccess struct {
	Type        string   `json:"type"`        // "http", "https", "tcp", "udp"
	Destination string   `json:"destination"` // URL or IP
	Purpose     string   `json:"purpose"`     // What it's used for
	JobID       string   `json:"job_id"`
	StepID      string   `json:"step_id"`
	Platform    string   `json:"platform"`
	Protocols   []string `json:"protocols"`
}

// FileOperation represents file system operations
type FileOperation struct {
	Type     string `json:"type"`    // "read", "write", "execute", "delete"
	Path     string `json:"path"`    // File or directory path
	Purpose  string `json:"purpose"` // What it's used for
	JobID    string `json:"job_id"`
	StepID   string `json:"step_id"`
	Platform string `json:"platform"`
}

// PrivilegeChange represents privilege escalation attempts
type PrivilegeChange struct {
	Type     string `json:"type"`    // "sudo", "setuid", "docker", etc.
	Command  string `json:"command"` // Command that changes privileges
	Target   string `json:"target"`  // What privileges are changed
	JobID    string `json:"job_id"`
	StepID   string `json:"step_id"`
	Platform string `json:"platform"`
	Severity string `json:"severity"` // "low", "medium", "high", "critical"
}

// SupplyChainRisk represents supply chain security risks
type SupplyChainRisk struct {
	Type       string                 `json:"type"`      // "action", "package", "image", "script"
	Component  string                 `json:"component"` // Name of the component
	Version    string                 `json:"version"`   // Version if available
	Source     string                 `json:"source"`    // Where it comes from
	Risks      []string               `json:"risks"`     // Identified risks
	Metadata   map[string]interface{} `json:"metadata"`  // Additional metadata
	JobID      string                 `json:"job_id"`
	StepID     string                 `json:"step_id"`
	Platform   string                 `json:"platform"`
	Confidence float64                `json:"confidence"` // Risk confidence score
}

// PlatformRegistry manages platform implementations
type PlatformRegistry struct {
	platforms map[string]Platform
}

// NewPlatformRegistry creates a new platform registry
func NewPlatformRegistry() *PlatformRegistry {
	return &PlatformRegistry{
		platforms: make(map[string]Platform),
	}
}

// Register registers a platform implementation
func (pr *PlatformRegistry) Register(platform Platform) {
	pr.platforms[platform.Name()] = platform
}

// Get returns a platform implementation by name
func (pr *PlatformRegistry) Get(name string) (Platform, error) {
	platform, exists := pr.platforms[name]
	if !exists {
		return nil, fmt.Errorf("platform %s not found", name)
	}
	return platform, nil
}

// List returns all registered platform names
func (pr *PlatformRegistry) List() []string {
	var names []string
	for name := range pr.platforms {
		names = append(names, name)
	}
	return names
}

// DetectPlatform attempts to detect the platform type from a directory
func (pr *PlatformRegistry) DetectPlatform(rootPath string) (Platform, error) {
	for _, platform := range pr.platforms {
		workflows, err := platform.DetectWorkflows(rootPath)
		if err == nil && len(workflows) > 0 {
			return platform, nil
		}
	}
	return nil, errors.New("no supported CI/CD platform detected")
}

// Global platform registry instance
var DefaultRegistry = NewPlatformRegistry()
