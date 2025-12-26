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
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/platform"
	"gopkg.in/yaml.v3"
)

// GitLabPlatform implements the Platform interface for GitLab CI
type GitLabPlatform struct{}

// NewGitLabPlatform creates a new GitLab CI platform implementation
func NewGitLabPlatform() *GitLabPlatform {
	return &GitLabPlatform{}
}

// Name returns the platform name
func (glp *GitLabPlatform) Name() string {
	return "gitlab-ci"
}

// DetectWorkflows finds GitLab CI workflow files
func (glp *GitLabPlatform) DetectWorkflows(rootPath string) ([]string, error) {
	var workflows []string

	// Check for .gitlab-ci.yml in root
	gitlabCIPath := filepath.Join(rootPath, ".gitlab-ci.yml")
	if _, err := os.Stat(gitlabCIPath); err == nil {
		workflows = append(workflows, gitlabCIPath)
	}

	// Check for .gitlab-ci.yaml
	gitlabCIPathYaml := filepath.Join(rootPath, ".gitlab-ci.yaml")
	if _, err := os.Stat(gitlabCIPathYaml); err == nil {
		workflows = append(workflows, gitlabCIPathYaml)
	}

	// Check for .gitlab/ directory with CI files
	gitlabDir := filepath.Join(rootPath, ".gitlab")
	if _, err := os.Stat(gitlabDir); err == nil {
		err := filepath.Walk(gitlabDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if !info.IsDir() && (strings.HasSuffix(info.Name(), ".yml") || strings.HasSuffix(info.Name(), ".yaml")) {
				workflows = append(workflows, path)
			}

			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	if len(workflows) == 0 {
		return nil, fmt.Errorf("no GitLab CI files found")
	}

	return workflows, nil
}

// ParseWorkflow parses a GitLab CI workflow file
func (glp *GitLabPlatform) ParseWorkflow(path string) (*platform.Workflow, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read GitLab CI file %s: %w", path, err)
	}

	var glWorkflow GitLabWorkflow
	if err := yaml.Unmarshal(content, &glWorkflow); err != nil {
		return nil, fmt.Errorf("failed to parse GitLab CI workflow: %w", err)
	}

	// Convert to generic workflow structure
	workflow := &platform.Workflow{
		Platform:    "gitlab-ci",
		Name:        glWorkflow.Workflow.Name,
		FilePath:    path,
		Content:     content,
		Triggers:    glp.convertTriggers(glWorkflow),
		Jobs:        glp.convertJobs(glWorkflow),
		Environment: glWorkflow.Variables,
		Variables: map[string]interface{}{
			"stages":        glWorkflow.Stages,
			"image":         glWorkflow.Image,
			"services":      glWorkflow.Services,
			"before_script": glWorkflow.BeforeScript,
			"after_script":  glWorkflow.AfterScript,
			"cache":         glWorkflow.Cache,
			"artifacts":     glWorkflow.Artifacts,
			"include":       glWorkflow.Include,
		},
	}

	// If no name specified, use filename
	if workflow.Name == "" {
		workflow.Name = filepath.Base(path)
	}

	return workflow, nil
}

// GetSecurityContext extracts security-relevant information from a GitLab CI workflow
func (glp *GitLabPlatform) GetSecurityContext(workflow *platform.Workflow) *platform.SecurityContext {
	ctx := &platform.SecurityContext{
		Workflow:           workflow,
		UserControlledVars: glp.extractUserControlledVars(workflow),
		ExternalActions:    glp.extractExternalActions(workflow),
		Permissions:        glp.extractPermissions(workflow),
		Secrets:            glp.extractSecrets(workflow),
		NetworkAccess:      glp.extractNetworkAccess(workflow),
		FileOperations:     glp.extractFileOperations(workflow),
		PrivilegeChanges:   glp.extractPrivilegeChanges(workflow),
		SupplyChainRisks:   glp.extractSupplyChainRisks(workflow),
	}

	return ctx
}

// ValidateWorkflow validates a GitLab CI workflow
func (glp *GitLabPlatform) ValidateWorkflow(workflow *platform.Workflow) error {
	if workflow.Platform != "gitlab-ci" {
		return fmt.Errorf("workflow is not a GitLab CI workflow")
	}

	if len(workflow.Jobs) == 0 {
		return fmt.Errorf("workflow must have at least one job")
	}

	return nil
}

// GitLab CI specific structures
type GitLabWorkflow struct {
	Workflow     GitLabWorkflowConfig `yaml:"workflow,omitempty"`
	Image        interface{}          `yaml:"image,omitempty"`
	Services     []interface{}        `yaml:"services,omitempty"`
	Stages       []string             `yaml:"stages,omitempty"`
	Variables    map[string]string    `yaml:"variables,omitempty"`
	BeforeScript []string             `yaml:"before_script,omitempty"`
	AfterScript  []string             `yaml:"after_script,omitempty"`
	Cache        interface{}          `yaml:"cache,omitempty"`
	Artifacts    interface{}          `yaml:"artifacts,omitempty"`
	Include      []interface{}        `yaml:"include,omitempty"`
	Jobs         map[string]GitLabJob `yaml:",inline"`
}

type GitLabWorkflowConfig struct {
	Name  string                   `yaml:"name,omitempty"`
	Rules []map[string]interface{} `yaml:"rules,omitempty"`
}

type GitLabJob struct {
	Image         interface{}              `yaml:"image,omitempty"`
	Stage         string                   `yaml:"stage,omitempty"`
	Script        []string                 `yaml:"script,omitempty"`
	BeforeScript  []string                 `yaml:"before_script,omitempty"`
	AfterScript   []string                 `yaml:"after_script,omitempty"`
	Variables     map[string]string        `yaml:"variables,omitempty"`
	Cache         interface{}              `yaml:"cache,omitempty"`
	Artifacts     interface{}              `yaml:"artifacts,omitempty"`
	Dependencies  []string                 `yaml:"dependencies,omitempty"`
	Needs         []interface{}            `yaml:"needs,omitempty"`
	Rules         []map[string]interface{} `yaml:"rules,omitempty"`
	Only          interface{}              `yaml:"only,omitempty"`
	Except        interface{}              `yaml:"except,omitempty"`
	When          string                   `yaml:"when,omitempty"`
	AllowFailure  bool                     `yaml:"allow_failure,omitempty"`
	Timeout       string                   `yaml:"timeout,omitempty"`
	Retry         interface{}              `yaml:"retry,omitempty"`
	Parallel      interface{}              `yaml:"parallel,omitempty"`
	Tags          []string                 `yaml:"tags,omitempty"`
	Services      []interface{}            `yaml:"services,omitempty"`
	Environment   interface{}              `yaml:"environment,omitempty"`
	Coverage      string                   `yaml:"coverage,omitempty"`
	Release       interface{}              `yaml:"release,omitempty"`
	Trigger       interface{}              `yaml:"trigger,omitempty"`
	Inherit       interface{}              `yaml:"inherit,omitempty"`
	Extends       interface{}              `yaml:"extends,omitempty"`
	ResourceGroup string                   `yaml:"resource_group,omitempty"`
}

// Helper methods for conversion

func (glp *GitLabPlatform) convertTriggers(glWorkflow GitLabWorkflow) []platform.Trigger {
	var triggers []platform.Trigger

	// GitLab CI uses rules, only/except for triggering
	// Extract from workflow-level rules
	if len(glWorkflow.Workflow.Rules) > 0 {
		for _, rule := range glWorkflow.Workflow.Rules {
			trigger := platform.Trigger{
				Type:       "rule",
				Events:     []string{"pipeline"},
				Conditions: rule,
			}
			triggers = append(triggers, trigger)
		}
	}

	// Extract from job-level rules
	for _, job := range glWorkflow.Jobs {
		if len(job.Rules) > 0 {
			for _, rule := range job.Rules {
				trigger := platform.Trigger{
					Type:       "job_rule",
					Events:     []string{"job"},
					Conditions: rule,
				}
				triggers = append(triggers, trigger)
			}
		}

		// Handle only/except
		if job.Only != nil {
			trigger := platform.Trigger{
				Type:   "only",
				Events: []string{"push"},
			}
			triggers = append(triggers, trigger)
		}

		if job.Except != nil {
			trigger := platform.Trigger{
				Type:   "except",
				Events: []string{"push"},
			}
			triggers = append(triggers, trigger)
		}
	}

	// Default trigger if none specified
	if len(triggers) == 0 {
		triggers = append(triggers, platform.Trigger{
			Type:   "push",
			Events: []string{"push"},
		})
	}

	return triggers
}

func (glp *GitLabPlatform) convertJobs(glWorkflow GitLabWorkflow) []platform.Job {
	var jobs []platform.Job

	// Filter out non-job keys
	reservedKeys := map[string]bool{
		"workflow":      true,
		"image":         true,
		"services":      true,
		"stages":        true,
		"variables":     true,
		"before_script": true,
		"after_script":  true,
		"cache":         true,
		"artifacts":     true,
		"include":       true,
		"default":       true,
	}

	for jobID, glJob := range glWorkflow.Jobs {
		// Skip reserved keys
		if reservedKeys[jobID] {
			continue
		}

		job := platform.Job{
			ID:           jobID,
			Name:         jobID, // GitLab CI doesn't have separate name field
			Platform:     "gitlab-ci",
			Image:        glp.convertImage(glJob.Image),
			Environment:  glJob.Variables,
			Dependencies: glJob.Dependencies,
			AllowFailure: glJob.AllowFailure,
			Timeout:      glJob.Timeout,
			Variables: map[string]interface{}{
				"stage":          glJob.Stage,
				"cache":          glJob.Cache,
				"artifacts":      glJob.Artifacts,
				"rules":          glJob.Rules,
				"only":           glJob.Only,
				"except":         glJob.Except,
				"when":           glJob.When,
				"retry":          glJob.Retry,
				"parallel":       glJob.Parallel,
				"tags":           glJob.Tags,
				"services":       glJob.Services,
				"environment":    glJob.Environment,
				"coverage":       glJob.Coverage,
				"release":        glJob.Release,
				"trigger":        glJob.Trigger,
				"inherit":        glJob.Inherit,
				"extends":        glJob.Extends,
				"resource_group": glJob.ResourceGroup,
			},
		}

		// Convert needs to dependencies
		for _, need := range glJob.Needs {
			if needStr, ok := need.(string); ok {
				job.Dependencies = append(job.Dependencies, needStr)
			} else if needMap, ok := need.(map[string]interface{}); ok {
				if jobName, ok := needMap["job"].(string); ok {
					job.Dependencies = append(job.Dependencies, jobName)
				}
			}
		}

		// Convert conditions
		if glJob.When != "" {
			job.Conditions = append(job.Conditions, glJob.When)
		}

		// Convert steps
		job.Steps = glp.convertSteps(glJob)

		jobs = append(jobs, job)
	}

	return jobs
}

func (glp *GitLabPlatform) convertImage(image interface{}) string {
	switch v := image.(type) {
	case string:
		return v
	case map[string]interface{}:
		if name, ok := v["name"].(string); ok {
			return name
		}
	}
	return ""
}

func (glp *GitLabPlatform) convertSteps(glJob GitLabJob) []platform.Step {
	var steps []platform.Step

	stepID := 1

	// Before script as steps
	for _, script := range glJob.BeforeScript {
		steps = append(steps, platform.Step{
			ID:       fmt.Sprintf("before_script_%d", stepID),
			Name:     fmt.Sprintf("Before Script %d", stepID),
			Platform: "gitlab-ci",
			Type:     "script",
			Script:   []string{script},
		})
		stepID++
	}

	// Main script as steps
	for _, script := range glJob.Script {
		steps = append(steps, platform.Step{
			ID:       fmt.Sprintf("script_%d", stepID),
			Name:     fmt.Sprintf("Script %d", stepID),
			Platform: "gitlab-ci",
			Type:     "script",
			Script:   []string{script},
		})
		stepID++
	}

	// After script as steps
	for _, script := range glJob.AfterScript {
		steps = append(steps, platform.Step{
			ID:       fmt.Sprintf("after_script_%d", stepID),
			Name:     fmt.Sprintf("After Script %d", stepID),
			Platform: "gitlab-ci",
			Type:     "script",
			Script:   []string{script},
		})
		stepID++
	}

	return steps
}

// Security context extraction methods

func (glp *GitLabPlatform) extractUserControlledVars(workflow *platform.Workflow) []platform.UserControlledVar {
	var vars []platform.UserControlledVar

	// GitLab-specific user-controlled variables
	userControlledPatterns := []*regexp.Regexp{
		regexp.MustCompile(`\$\{?CI_MERGE_REQUEST_(SOURCE_BRANCH_NAME|SOURCE_PROJECT_PATH|TITLE|DESCRIPTION|ASSIGNEES|LABELS)\}?`),
		regexp.MustCompile(`\$\{?CI_COMMIT_(MESSAGE|AUTHOR_NAME|AUTHOR_EMAIL|REF_NAME|BRANCH)\}?`),
		regexp.MustCompile(`\$\{?CI_EXTERNAL_PULL_REQUEST_(SOURCE_BRANCH_NAME|TARGET_BRANCH_NAME|IID)\}?`),
	}

	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			// Check in script content
			for _, script := range step.Script {
				for _, pattern := range userControlledPatterns {
					matches := pattern.FindAllString(script, -1)
					for _, match := range matches {
						vars = append(vars, platform.UserControlledVar{
							Name:     match,
							Source:   "ci_variables",
							Context:  script,
							JobID:    job.ID,
							StepID:   step.ID,
							Platform: "gitlab-ci",
						})
					}
				}
			}

			// Check in environment variables
			for key, value := range step.Environment {
				for _, pattern := range userControlledPatterns {
					if pattern.MatchString(value) {
						vars = append(vars, platform.UserControlledVar{
							Name:     key,
							Source:   "environment",
							Context:  value,
							JobID:    job.ID,
							StepID:   step.ID,
							Platform: "gitlab-ci",
						})
					}
				}
			}
		}
	}

	return vars
}

func (glp *GitLabPlatform) extractExternalActions(workflow *platform.Workflow) []platform.ExternalAction {
	var actions []platform.ExternalAction

	// GitLab CI uses "include" for external templates
	if includes, ok := workflow.Variables["include"].([]interface{}); ok {
		for _, include := range includes {
			if includeMap, ok := include.(map[string]interface{}); ok {
				if project, ok := includeMap["project"].(string); ok {
					actions = append(actions, platform.ExternalAction{
						Name:     project,
						Version:  "", // GitLab includes often don't specify versions
						Source:   "gitlab",
						JobID:    "",
						StepID:   "",
						Platform: "gitlab-ci",
					})
				}
				if remote, ok := includeMap["remote"].(string); ok {
					actions = append(actions, platform.ExternalAction{
						Name:     remote,
						Version:  "",
						Source:   "remote",
						JobID:    "",
						StepID:   "",
						Platform: "gitlab-ci",
					})
				}
			}
		}
	}

	// Check for container images
	for _, job := range workflow.Jobs {
		if job.Image != "" {
			actions = append(actions, platform.ExternalAction{
				Name:     job.Image,
				Version:  "",
				Source:   "container_registry",
				JobID:    job.ID,
				StepID:   "",
				Platform: "gitlab-ci",
			})
		}
	}

	return actions
}

func (glp *GitLabPlatform) extractPermissions(workflow *platform.Workflow) []platform.Permission {
	var permissions []platform.Permission

	// GitLab CI doesn't have explicit permissions like GitHub Actions
	// We can infer some from job context and variables
	for _, job := range workflow.Jobs {
		// Check for deployment environments
		if env, ok := job.Variables["environment"]; ok {
			permissions = append(permissions, platform.Permission{
				Scope:    "environment",
				Level:    "deploy",
				Context:  fmt.Sprintf("environment: %v", env),
				JobID:    job.ID,
				Platform: "gitlab-ci",
			})
		}

		// Check for release creation
		if release, ok := job.Variables["release"]; ok && release != nil {
			permissions = append(permissions, platform.Permission{
				Scope:    "releases",
				Level:    "write",
				Context:  "release creation",
				JobID:    job.ID,
				Platform: "gitlab-ci",
			})
		}
	}

	return permissions
}

func (glp *GitLabPlatform) extractSecrets(workflow *platform.Workflow) []platform.SecretUsage {
	var secrets []platform.SecretUsage

	// GitLab CI variables can be secrets
	secretPattern := regexp.MustCompile(`\$\{?([A-Z_][A-Z0-9_]*)\}?`)

	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			// Check in script content
			for _, script := range step.Script {
				matches := secretPattern.FindAllStringSubmatch(script, -1)
				for _, match := range matches {
					if len(match) > 1 {
						// Skip known CI variables
						if !glp.isKnownCIVariable(match[1]) {
							secrets = append(secrets, platform.SecretUsage{
								Name:     match[1],
								Context:  script,
								JobID:    job.ID,
								StepID:   step.ID,
								Platform: "gitlab-ci",
								Type:     "env",
							})
						}
					}
				}
			}

			// Check in environment variables
			for key, value := range step.Environment {
				if secretPattern.MatchString(value) {
					matches := secretPattern.FindAllStringSubmatch(value, -1)
					for _, match := range matches {
						if len(match) > 1 && !glp.isKnownCIVariable(match[1]) {
							secrets = append(secrets, platform.SecretUsage{
								Name:     match[1],
								Context:  key + "=" + value,
								JobID:    job.ID,
								StepID:   step.ID,
								Platform: "gitlab-ci",
								Type:     "env",
							})
						}
					}
				}
			}
		}
	}

	return secrets
}

func (glp *GitLabPlatform) isKnownCIVariable(varName string) bool {
	knownVars := map[string]bool{
		"CI":                 true,
		"CI_PROJECT_ID":      true,
		"CI_PROJECT_NAME":    true,
		"CI_PROJECT_PATH":    true,
		"CI_COMMIT_SHA":      true,
		"CI_COMMIT_REF_NAME": true,
		"CI_JOB_NAME":        true,
		"CI_JOB_STAGE":       true,
		"CI_PIPELINE_ID":     true,
		"CI_RUNNER_TAGS":     true,
		"GITLAB_CI":          true,
		"HOME":               true,
		"USER":               true,
		"PATH":               true,
	}
	return knownVars[varName]
}

func (glp *GitLabPlatform) extractNetworkAccess(workflow *platform.Workflow) []platform.NetworkAccess {
	var access []platform.NetworkAccess

	// Patterns for detecting network access
	urlPattern := regexp.MustCompile(`https?://[^\s\'"]+`)
	curlPattern := regexp.MustCompile(`curl\s+.*?https?://[^\s\'"]+`)

	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			for _, script := range step.Script {
				// Find URL patterns
				urls := urlPattern.FindAllString(script, -1)
				for _, url := range urls {
					access = append(access, platform.NetworkAccess{
						Type:        "https",
						Destination: url,
						Purpose:     "script",
						JobID:       job.ID,
						StepID:      step.ID,
						Platform:    "gitlab-ci",
						Protocols:   []string{"https"},
					})
				}

				// Find curl commands
				if curlPattern.MatchString(script) {
					access = append(access, platform.NetworkAccess{
						Type:        "http",
						Destination: "external",
						Purpose:     "curl",
						JobID:       job.ID,
						StepID:      step.ID,
						Platform:    "gitlab-ci",
						Protocols:   []string{"http", "https"},
					})
				}
			}
		}
	}

	return access
}

func (glp *GitLabPlatform) extractFileOperations(workflow *platform.Workflow) []platform.FileOperation {
	var operations []platform.FileOperation

	// Patterns for detecting file operations
	patterns := map[string]*regexp.Regexp{
		"read":    regexp.MustCompile(`(cat|less|more|head|tail|grep)\s+[^\s]+`),
		"write":   regexp.MustCompile(`(echo|printf|tee|>\s*[^\s]+|>>\s*[^\s]+)`),
		"execute": regexp.MustCompile(`(\./[^\s]+|bash\s+[^\s]+|sh\s+[^\s]+)`),
		"delete":  regexp.MustCompile(`(rm|rmdir)\s+[^\s]+`),
	}

	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			for _, script := range step.Script {
				for opType, pattern := range patterns {
					if pattern.MatchString(script) {
						operations = append(operations, platform.FileOperation{
							Type:     opType,
							Path:     "detected",
							Purpose:  "script",
							JobID:    job.ID,
							StepID:   step.ID,
							Platform: "gitlab-ci",
						})
					}
				}
			}
		}
	}

	return operations
}

func (glp *GitLabPlatform) extractPrivilegeChanges(workflow *platform.Workflow) []platform.PrivilegeChange {
	var changes []platform.PrivilegeChange

	// Patterns for detecting privilege escalation
	patterns := map[string]*regexp.Regexp{
		"sudo":   regexp.MustCompile(`sudo\s+[^\s]+`),
		"setuid": regexp.MustCompile(`(chmod\s+[+]s|setuid)`),
		"docker": regexp.MustCompile(`docker\s+(run|exec).*--privileged`),
	}

	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			for _, script := range step.Script {
				for privType, pattern := range patterns {
					if pattern.MatchString(script) {
						severity := "medium"
						if privType == "sudo" || privType == "docker" {
							severity = "high"
						}

						changes = append(changes, platform.PrivilegeChange{
							Type:     privType,
							Command:  script,
							Target:   "system",
							JobID:    job.ID,
							StepID:   step.ID,
							Platform: "gitlab-ci",
							Severity: severity,
						})
					}
				}
			}
		}
	}

	return changes
}

func (glp *GitLabPlatform) extractSupplyChainRisks(workflow *platform.Workflow) []platform.SupplyChainRisk {
	var risks []platform.SupplyChainRisk

	// Check includes for supply chain risks
	if includes, ok := workflow.Variables["include"].([]interface{}); ok {
		for _, include := range includes {
			if includeMap, ok := include.(map[string]interface{}); ok {
				// Remote includes are risky
				if remote, ok := includeMap["remote"].(string); ok {
					risks = append(risks, platform.SupplyChainRisk{
						Type:       "include",
						Component:  remote,
						Source:     "remote",
						Risks:      []string{"remote_include", "untrusted_source"},
						Platform:   "gitlab-ci",
						Confidence: 0.7,
						Metadata: map[string]interface{}{
							"include_type": "remote",
						},
					})
				}

				// Project includes from external projects
				if project, ok := includeMap["project"].(string); ok {
					risks = append(risks, platform.SupplyChainRisk{
						Type:       "include",
						Component:  project,
						Source:     "gitlab_project",
						Risks:      []string{"external_project", "dependency_risk"},
						Platform:   "gitlab-ci",
						Confidence: 0.5,
						Metadata: map[string]interface{}{
							"include_type": "project",
						},
					})
				}
			}
		}
	}

	// Check container images
	for _, job := range workflow.Jobs {
		if job.Image != "" && !strings.HasPrefix(job.Image, "registry.gitlab.com") {
			var riskList []string
			confidence := 0.3

			// Check for latest tag
			if strings.Contains(job.Image, ":latest") || !strings.Contains(job.Image, ":") {
				riskList = append(riskList, "unpinned_version")
				confidence += 0.3
			}

			// Check for non-official registries
			if !strings.Contains(job.Image, "docker.io") && !strings.Contains(job.Image, "registry.gitlab.com") {
				riskList = append(riskList, "third_party_registry")
				confidence += 0.2
			}

			if len(riskList) > 0 {
				risks = append(risks, platform.SupplyChainRisk{
					Type:       "image",
					Component:  job.Image,
					Source:     "container_registry",
					Risks:      riskList,
					JobID:      job.ID,
					Platform:   "gitlab-ci",
					Confidence: confidence,
					Metadata: map[string]interface{}{
						"image_ref": job.Image,
					},
				})
			}
		}
	}

	return risks
}
