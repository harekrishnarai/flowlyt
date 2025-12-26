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
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/parser"
	"gopkg.in/yaml.v3"
)

// GitLabWorkflow represents a GitLab CI/CD pipeline
type GitLabWorkflow struct {
	Stages    []string                 `yaml:"stages"`
	Image     interface{}              `yaml:"image"`
	Variables map[string]interface{}   `yaml:"variables"`
	Before    []string                 `yaml:"before_script"`
	After     []string                 `yaml:"after_script"`
	Jobs      map[string]GitLabJob     `yaml:",inline"`
	Include   []map[string]interface{} `yaml:"include"`
	Workflow  map[string]interface{}   `yaml:"workflow"`
}

// GitLabJob represents a job in GitLab CI/CD
type GitLabJob struct {
	Stage        string                   `yaml:"stage"`
	Image        interface{}              `yaml:"image"`
	Script       []string                 `yaml:"script"`
	BeforeScript []string                 `yaml:"before_script"`
	AfterScript  []string                 `yaml:"after_script"`
	Variables    map[string]interface{}   `yaml:"variables"`
	Rules        []map[string]interface{} `yaml:"rules"`
	Only         interface{}              `yaml:"only"`
	Except       interface{}              `yaml:"except"`
	When         string                   `yaml:"when"`
	Allow        map[string]interface{}   `yaml:"allow_failure"`
	Artifacts    map[string]interface{}   `yaml:"artifacts"`
	Cache        map[string]interface{}   `yaml:"cache"`
	Services     []interface{}            `yaml:"services"`
	Needs        []interface{}            `yaml:"needs"`
	Tags         []string                 `yaml:"tags"`
	Environment  map[string]interface{}   `yaml:"environment"`
}

// FindGitLabWorkflows searches for GitLab CI/CD files in a repository
func FindGitLabWorkflows(repoPath string) ([]parser.WorkflowFile, error) {
	var workflows []parser.WorkflowFile

	// GitLab CI file locations
	possibleFiles := []string{
		".gitlab-ci.yml",
		".gitlab-ci.yaml",
	}

	for _, filename := range possibleFiles {
		filePath := filepath.Join(repoPath, filename)

		if _, err := os.Stat(filePath); err == nil {
			content, err := os.ReadFile(filePath)
			if err != nil {
				return nil, fmt.Errorf("failed to read GitLab CI file %s: %w", filePath, err)
			}

			// Parse GitLab CI YAML
			gitlabWorkflow := GitLabWorkflow{}
			if err := yaml.Unmarshal(content, &gitlabWorkflow); err != nil {
				return nil, fmt.Errorf("failed to parse GitLab CI file %s: %w", filePath, err)
			}

			// Convert to common WorkflowFile format
			workflow := convertGitLabToWorkflow(gitlabWorkflow)

			workflows = append(workflows, parser.WorkflowFile{
				Path:     filePath,
				Name:     filename,
				Content:  content,
				Workflow: workflow,
			})
		}
	}

	if len(workflows) == 0 {
		return nil, fmt.Errorf("no GitLab CI files found in %s", repoPath)
	}

	return workflows, nil
}

// convertGitLabToWorkflow converts GitLab CI structure to common workflow format
func convertGitLabToWorkflow(gitlab GitLabWorkflow) parser.Workflow {
	jobs := make(map[string]parser.Job)

	// Convert GitLab jobs to common format
	for jobName, gitlabJob := range gitlab.Jobs {
		// Skip if it's not a job (e.g., global keys)
		if isGlobalKey(jobName) {
			continue
		}

		// Convert script to steps
		var steps []parser.Step

		// Add before_script as steps
		for i, script := range gitlabJob.BeforeScript {
			steps = append(steps, parser.Step{
				Name: fmt.Sprintf("Before Script %d", i+1),
				Run:  script,
			})
		}

		// Add main script as steps
		for i, script := range gitlabJob.Script {
			steps = append(steps, parser.Step{
				Name: fmt.Sprintf("Script %d", i+1),
				Run:  script,
			})
		}

		// Add after_script as steps
		for i, script := range gitlabJob.AfterScript {
			steps = append(steps, parser.Step{
				Name: fmt.Sprintf("After Script %d", i+1),
				Run:  script,
			})
		}

		// Convert environment variables
		env := make(map[string]string)
		for key, value := range gitlabJob.Variables {
			if strValue, ok := value.(string); ok {
				env[key] = strValue
			}
		}

		// Determine runner (GitLab uses tags or image)
		var runsOn interface{} = "gitlab-runner"
		if len(gitlabJob.Tags) > 0 {
			runsOn = gitlabJob.Tags[0] // Use first tag as runner
		}

		jobs[jobName] = parser.Job{
			Name:   jobName,
			RunsOn: runsOn,
			Steps:  steps,
			Env:    env,
		}
	}

	return parser.Workflow{
		Name: "GitLab CI Pipeline",
		Jobs: jobs,
	}
}

// isGlobalKey checks if a key is a global GitLab CI key, not a job
func isGlobalKey(key string) bool {
	globalKeys := []string{
		"stages", "image", "variables", "before_script", "after_script",
		"include", "workflow", "cache", "services", "default",
	}

	for _, globalKey := range globalKeys {
		if key == globalKey {
			return true
		}
	}

	// Keys starting with . are also global (e.g., .hidden-job)
	return strings.HasPrefix(key, ".")
}

// LoadSingleGitLabWorkflow loads and parses a single GitLab CI file
func LoadSingleGitLabWorkflow(filePath string) ([]parser.WorkflowFile, error) {
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("GitLab CI file not found: %s", filePath)
	}

	// Read the file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read GitLab CI file %s: %w", filePath, err)
	}

	// Make sure it's a YAML file
	if !strings.HasSuffix(filePath, ".yml") && !strings.HasSuffix(filePath, ".yaml") {
		return nil, fmt.Errorf("file %s does not have a YAML extension (.yml or .yaml)", filePath)
	}

	// Parse GitLab CI YAML
	gitlabWorkflow := GitLabWorkflow{}
	if err := yaml.Unmarshal(content, &gitlabWorkflow); err != nil {
		return nil, fmt.Errorf("failed to parse GitLab CI file %s: %w", filePath, err)
	}

	// Convert to common format
	workflow := convertGitLabToWorkflow(gitlabWorkflow)

	// Create a workflow file object
	workflowFile := parser.WorkflowFile{
		Path:     filePath,
		Name:     filepath.Base(filePath),
		Content:  content,
		Workflow: workflow,
	}

	return []parser.WorkflowFile{workflowFile}, nil
}
