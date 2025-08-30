package github

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/platform"
	"gopkg.in/yaml.v3"
)

// GitHubPlatform implements the Platform interface for GitHub Actions
type GitHubPlatform struct{}

// NewGitHubPlatform creates a new GitHub Actions platform implementation
func NewGitHubPlatform() *GitHubPlatform {
	return &GitHubPlatform{}
}

// Name returns the platform name
func (gp *GitHubPlatform) Name() string {
	return "github-actions"
}

// DetectWorkflows finds GitHub Actions workflow files
func (gp *GitHubPlatform) DetectWorkflows(rootPath string) ([]string, error) {
	workflowsDir := filepath.Join(rootPath, ".github", "workflows")

	// Check if workflows directory exists
	if _, err := os.Stat(workflowsDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("no .github/workflows directory found")
	}

	var workflows []string
	err := filepath.Walk(workflowsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Only process YAML files
		if strings.HasSuffix(info.Name(), ".yml") || strings.HasSuffix(info.Name(), ".yaml") {
			workflows = append(workflows, path)
		}

		return nil
	})

	return workflows, err
}

// ParseWorkflow parses a GitHub Actions workflow file
func (gp *GitHubPlatform) ParseWorkflow(path string) (*platform.Workflow, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read workflow file %s: %w", path, err)
	}

	var ghWorkflow GitHubWorkflow
	if err := yaml.Unmarshal(content, &ghWorkflow); err != nil {
		return nil, fmt.Errorf("failed to parse GitHub Actions workflow: %w", err)
	}

	// Convert to generic workflow structure
	workflow := &platform.Workflow{
		Platform:    "github-actions",
		Name:        ghWorkflow.Name,
		FilePath:    path,
		Content:     content,
		Triggers:    gp.convertTriggers(ghWorkflow.On),
		Jobs:        gp.convertJobs(ghWorkflow.Jobs),
		Environment: ghWorkflow.Env,
		Permissions: ghWorkflow.Permissions,
		Variables: map[string]interface{}{
			"defaults": ghWorkflow.Defaults,
		},
	}

	return workflow, nil
}

// GetSecurityContext extracts security-relevant information from a workflow
func (gp *GitHubPlatform) GetSecurityContext(workflow *platform.Workflow) *platform.SecurityContext {
	ctx := &platform.SecurityContext{
		Workflow:           workflow,
		UserControlledVars: gp.extractUserControlledVars(workflow),
		ExternalActions:    gp.extractExternalActions(workflow),
		Permissions:        gp.extractPermissions(workflow),
		Secrets:            gp.extractSecrets(workflow),
		NetworkAccess:      gp.extractNetworkAccess(workflow),
		FileOperations:     gp.extractFileOperations(workflow),
		PrivilegeChanges:   gp.extractPrivilegeChanges(workflow),
		SupplyChainRisks:   gp.extractSupplyChainRisks(workflow),
	}

	return ctx
}

// ValidateWorkflow validates a GitHub Actions workflow
func (gp *GitHubPlatform) ValidateWorkflow(workflow *platform.Workflow) error {
	if workflow.Platform != "github-actions" {
		return fmt.Errorf("workflow is not a GitHub Actions workflow")
	}

	if len(workflow.Jobs) == 0 {
		return fmt.Errorf("workflow must have at least one job")
	}

	return nil
}

// GitHub Actions specific structures
type GitHubWorkflow struct {
	Name        string                 `yaml:"name"`
	On          interface{}            `yaml:"on"`
	Env         map[string]string      `yaml:"env,omitempty"`
	Jobs        map[string]GitHubJob   `yaml:"jobs"`
	Permissions interface{}            `yaml:"permissions,omitempty"`
	Defaults    map[string]interface{} `yaml:"defaults,omitempty"`
}

type GitHubJob struct {
	Name            string                 `yaml:"name,omitempty"`
	RunsOn          interface{}            `yaml:"runs-on"`
	Permissions     interface{}            `yaml:"permissions,omitempty"`
	Needs           interface{}            `yaml:"needs,omitempty"`
	If              string                 `yaml:"if,omitempty"`
	Steps           []GitHubStep           `yaml:"steps"`
	Env             map[string]string      `yaml:"env,omitempty"`
	Defaults        map[string]interface{} `yaml:"defaults,omitempty"`
	ContinueOnError bool                   `yaml:"continue-on-error,omitempty"`
	Container       interface{}            `yaml:"container,omitempty"`
	Services        map[string]interface{} `yaml:"services,omitempty"`
	Strategy        map[string]interface{} `yaml:"strategy,omitempty"`
	Outputs         map[string]string      `yaml:"outputs,omitempty"`
}

type GitHubStep struct {
	Name             string                 `yaml:"name,omitempty"`
	ID               string                 `yaml:"id,omitempty"`
	If               string                 `yaml:"if,omitempty"`
	Uses             string                 `yaml:"uses,omitempty"`
	Run              string                 `yaml:"run,omitempty"`
	Shell            string                 `yaml:"shell,omitempty"`
	With             map[string]interface{} `yaml:"with,omitempty"`
	Env              map[string]string      `yaml:"env,omitempty"`
	ContinueOnError  bool                   `yaml:"continue-on-error,omitempty"`
	WorkingDirectory string                 `yaml:"working-directory,omitempty"`
}

// Helper methods for conversion

func (gp *GitHubPlatform) convertTriggers(on interface{}) []platform.Trigger {
	var triggers []platform.Trigger

	switch v := on.(type) {
	case string:
		triggers = append(triggers, platform.Trigger{
			Type:   v,
			Events: []string{v},
		})
	case []interface{}:
		for _, event := range v {
			if eventStr, ok := event.(string); ok {
				triggers = append(triggers, platform.Trigger{
					Type:   eventStr,
					Events: []string{eventStr},
				})
			}
		}
	case map[string]interface{}:
		for event, config := range v {
			trigger := platform.Trigger{
				Type:   event,
				Events: []string{event},
			}

			// Extract branches, tags, paths from config
			if configMap, ok := config.(map[string]interface{}); ok {
				if branches, ok := configMap["branches"].([]interface{}); ok {
					for _, branch := range branches {
						if branchStr, ok := branch.(string); ok {
							trigger.Branches = append(trigger.Branches, branchStr)
						}
					}
				}
				if tags, ok := configMap["tags"].([]interface{}); ok {
					for _, tag := range tags {
						if tagStr, ok := tag.(string); ok {
							trigger.Tags = append(trigger.Tags, tagStr)
						}
					}
				}
				if paths, ok := configMap["paths"].([]interface{}); ok {
					for _, path := range paths {
						if pathStr, ok := path.(string); ok {
							trigger.Paths = append(trigger.Paths, pathStr)
						}
					}
				}
			}

			triggers = append(triggers, trigger)
		}
	}

	return triggers
}

func (gp *GitHubPlatform) convertJobs(ghJobs map[string]GitHubJob) []platform.Job {
	var jobs []platform.Job

	for jobID, ghJob := range ghJobs {
		job := platform.Job{
			ID:              jobID,
			Name:            ghJob.Name,
			Platform:        "github-actions",
			RunsOn:          ghJob.RunsOn,
			Environment:     ghJob.Env,
			Permissions:     ghJob.Permissions,
			ContinueOnError: ghJob.ContinueOnError,
			Services:        ghJob.Services,
			Variables: map[string]interface{}{
				"needs":     ghJob.Needs,
				"if":        ghJob.If,
				"defaults":  ghJob.Defaults,
				"container": ghJob.Container,
				"strategy":  ghJob.Strategy,
				"outputs":   ghJob.Outputs,
			},
		}

		// Convert dependencies
		if needs, ok := ghJob.Needs.([]interface{}); ok {
			for _, need := range needs {
				if needStr, ok := need.(string); ok {
					job.Dependencies = append(job.Dependencies, needStr)
				}
			}
		} else if needStr, ok := ghJob.Needs.(string); ok {
			job.Dependencies = append(job.Dependencies, needStr)
		}

		// Convert conditions
		if ghJob.If != "" {
			job.Conditions = append(job.Conditions, ghJob.If)
		}

		// Convert steps
		job.Steps = gp.convertSteps(ghJob.Steps)

		jobs = append(jobs, job)
	}

	return jobs
}

func (gp *GitHubPlatform) convertSteps(ghSteps []GitHubStep) []platform.Step {
	var steps []platform.Step

	for i, ghStep := range ghSteps {
		step := platform.Step{
			ID:               ghStep.ID,
			Name:             ghStep.Name,
			Platform:         "github-actions",
			Shell:            ghStep.Shell,
			WorkingDirectory: ghStep.WorkingDirectory,
			Environment:      ghStep.Env,
			Inputs:           ghStep.With,
			ContinueOnError:  ghStep.ContinueOnError,
		}

		// Set step ID if not provided
		if step.ID == "" {
			step.ID = fmt.Sprintf("step-%d", i+1)
		}

		// Determine step type and set appropriate fields
		if ghStep.Uses != "" {
			step.Type = "action"
			step.Action = ghStep.Uses
		} else if ghStep.Run != "" {
			step.Type = "script"
			step.Script = strings.Split(ghStep.Run, "\n")
		}

		// Convert conditions
		if ghStep.If != "" {
			step.Conditions = append(step.Conditions, ghStep.If)
		}

		steps = append(steps, step)
	}

	return steps
}

// Security context extraction methods

func (gp *GitHubPlatform) extractUserControlledVars(workflow *platform.Workflow) []platform.UserControlledVar {
	var vars []platform.UserControlledVar

	// GitHub-specific user-controlled variables
	userControlledPatterns := []*regexp.Regexp{
		regexp.MustCompile(`\$\{\{\s*(github\.head_ref|github\.event\.workflow_run\.(head_branch|head_repository\.description|head_repository\.owner\.email|pull_requests[^}]+?(head\.ref|head\.repo\.name)))\s*\}\}`),
		regexp.MustCompile(`\$\{\{\s*github\.event\.(issue\.(title|body)|pull_request\.(title|body)|comment\.body|review\.body|review_comment\.body|pages\.[^}]+?\.page_name|head_commit\.message|head_commit\.author\.(email|name)|commits[^}]+?\.author\.(email|name)|pull_request\.head\.(ref|label)|pull_request\.head\.repo\.default_branch|(inputs|client_payload)[^}]+?)\s*\}\}`),
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
							Source:   "github.event",
							Context:  script,
							JobID:    job.ID,
							StepID:   step.ID,
							Platform: "github-actions",
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
							Platform: "github-actions",
						})
					}
				}
			}
		}
	}

	return vars
}

func (gp *GitHubPlatform) extractExternalActions(workflow *platform.Workflow) []platform.ExternalAction {
	var actions []platform.ExternalAction

	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if step.Type == "action" && step.Action != "" {
				// Parse action reference (e.g., "actions/checkout@v3")
				parts := strings.Split(step.Action, "@")
				name := parts[0]
				version := ""
				if len(parts) > 1 {
					version = parts[1]
				}

				actions = append(actions, platform.ExternalAction{
					Name:     name,
					Version:  version,
					Source:   "github",
					JobID:    job.ID,
					StepID:   step.ID,
					Platform: "github-actions",
				})
			}
		}
	}

	return actions
}

func (gp *GitHubPlatform) extractPermissions(workflow *platform.Workflow) []platform.Permission {
	var permissions []platform.Permission

	// Extract workflow-level permissions
	if perms := gp.parsePermissions(workflow.Permissions, "", ""); len(perms) > 0 {
		permissions = append(permissions, perms...)
	}

	// Extract job-level permissions
	for _, job := range workflow.Jobs {
		if perms := gp.parsePermissions(job.Permissions, job.ID, ""); len(perms) > 0 {
			permissions = append(permissions, perms...)
		}
	}

	return permissions
}

func (gp *GitHubPlatform) parsePermissions(perms interface{}, jobID, context string) []platform.Permission {
	var permissions []platform.Permission

	switch v := perms.(type) {
	case string:
		// Handle "read-all", "write-all", etc.
		permissions = append(permissions, platform.Permission{
			Scope:    "all",
			Level:    v,
			Context:  context,
			JobID:    jobID,
			Platform: "github-actions",
		})
	case map[string]interface{}:
		for scope, level := range v {
			if levelStr, ok := level.(string); ok {
				permissions = append(permissions, platform.Permission{
					Scope:    scope,
					Level:    levelStr,
					Context:  context,
					JobID:    jobID,
					Platform: "github-actions",
				})
			}
		}
	}

	return permissions
}

func (gp *GitHubPlatform) extractSecrets(workflow *platform.Workflow) []platform.SecretUsage {
	var secrets []platform.SecretUsage

	secretPattern := regexp.MustCompile(`\$\{\{\s*secrets\.([A-Z_][A-Z0-9_]*)\s*\}\}`)

	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			// Check in script content
			for _, script := range step.Script {
				matches := secretPattern.FindAllStringSubmatch(script, -1)
				for _, match := range matches {
					if len(match) > 1 {
						secrets = append(secrets, platform.SecretUsage{
							Name:     match[1],
							Context:  script,
							JobID:    job.ID,
							StepID:   step.ID,
							Platform: "github-actions",
							Type:     "env",
						})
					}
				}
			}

			// Check in environment variables
			for key, value := range step.Environment {
				if secretPattern.MatchString(value) {
					matches := secretPattern.FindAllStringSubmatch(value, -1)
					for _, match := range matches {
						if len(match) > 1 {
							secrets = append(secrets, platform.SecretUsage{
								Name:     match[1],
								Context:  key + "=" + value,
								JobID:    job.ID,
								StepID:   step.ID,
								Platform: "github-actions",
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

func (gp *GitHubPlatform) extractNetworkAccess(workflow *platform.Workflow) []platform.NetworkAccess {
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
						Platform:    "github-actions",
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
						Platform:    "github-actions",
						Protocols:   []string{"http", "https"},
					})
				}
			}
		}
	}

	return access
}

func (gp *GitHubPlatform) extractFileOperations(workflow *platform.Workflow) []platform.FileOperation {
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
							Platform: "github-actions",
						})
					}
				}
			}
		}
	}

	return operations
}

func (gp *GitHubPlatform) extractPrivilegeChanges(workflow *platform.Workflow) []platform.PrivilegeChange {
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
							Platform: "github-actions",
							Severity: severity,
						})
					}
				}
			}
		}
	}

	return changes
}

func (gp *GitHubPlatform) extractSupplyChainRisks(workflow *platform.Workflow) []platform.SupplyChainRisk {
	var risks []platform.SupplyChainRisk

	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if step.Type == "action" && step.Action != "" {
				// Analyze external actions
				parts := strings.Split(step.Action, "@")
				name := parts[0]
				version := ""
				if len(parts) > 1 {
					version = parts[1]
				}

				// Assess risks
				var riskList []string
				confidence := 0.5

				// Check for version pinning
				if version == "" || strings.Contains(version, "main") || strings.Contains(version, "master") {
					riskList = append(riskList, "unpinned_version")
					confidence += 0.3
				}

				// Check for third-party actions
				if !strings.HasPrefix(name, "actions/") && !strings.HasPrefix(name, "github/") {
					riskList = append(riskList, "third_party_action")
					confidence += 0.2
				}

				if len(riskList) > 0 {
					risks = append(risks, platform.SupplyChainRisk{
						Type:       "action",
						Component:  name,
						Version:    version,
						Source:     "github",
						Risks:      riskList,
						JobID:      job.ID,
						StepID:     step.ID,
						Platform:   "github-actions",
						Confidence: confidence,
						Metadata: map[string]interface{}{
							"action_ref": step.Action,
						},
					})
				}
			}
		}
	}

	return risks
}
