package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// WorkflowFile represents a GitHub Actions workflow file
type WorkflowFile struct {
	Path     string
	Name     string
	Content  []byte
	Workflow Workflow
}

// Workflow represents the parsed structure of a GitHub Actions workflow file
type Workflow struct {
	Name        string                 `yaml:"name"`
	On          interface{}            `yaml:"on"`
	Env         map[string]string      `yaml:"env,omitempty"`
	Jobs        map[string]Job         `yaml:"jobs"`
	Permissions interface{}            `yaml:"permissions,omitempty"`
	Defaults    map[string]interface{} `yaml:"defaults,omitempty"`
}

// Job represents a job in a GitHub Actions workflow
type Job struct {
	Name            string                 `yaml:"name,omitempty"`
	RunsOn          interface{}            `yaml:"runs-on"`
	Permissions     interface{}            `yaml:"permissions,omitempty"`
	Needs           interface{}            `yaml:"needs,omitempty"`
	If              string                 `yaml:"if,omitempty"`
	Steps           []Step                 `yaml:"steps"`
	Env             map[string]string      `yaml:"env,omitempty"`
	Defaults        map[string]interface{} `yaml:"defaults,omitempty"`
	ContinueOnError bool                   `yaml:"continue-on-error,omitempty"`
	Container       interface{}            `yaml:"container,omitempty"`
	Services        map[string]interface{} `yaml:"services,omitempty"`
	Strategy        map[string]interface{} `yaml:"strategy,omitempty"`
	Outputs         map[string]string      `yaml:"outputs,omitempty"`
}

// Step represents a step in a GitHub Actions job
type Step struct {
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

// FindWorkflows searches for GitHub Actions workflow files in a repository
func FindWorkflows(repoPath string) ([]WorkflowFile, error) {
	workflowsDir := filepath.Join(repoPath, ".github", "workflows")

	// Check if workflows directory exists
	if _, err := os.Stat(workflowsDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("no .github/workflows directory found in %s", repoPath)
	}

	// Find all YAML files in the workflows directory
	var workflows []WorkflowFile
	err := filepath.Walk(workflowsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Only process YAML files
		if !strings.HasSuffix(info.Name(), ".yml") && !strings.HasSuffix(info.Name(), ".yaml") {
			return nil
		}

		// Read the file
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read workflow file %s: %w", path, err)
		}

		// Parse the workflow
		workflow := Workflow{}
		if err := yaml.Unmarshal(content, &workflow); err != nil {
			return fmt.Errorf("failed to parse workflow file %s: %w", path, err)
		}

		// Add to the list of workflows
		workflows = append(workflows, WorkflowFile{
			Path:     path,
			Name:     info.Name(),
			Content:  content,
			Workflow: workflow,
		})

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error searching for workflow files: %w", err)
	}

	if len(workflows) == 0 {
		return nil, fmt.Errorf("no workflow files found in %s", workflowsDir)
	}

	return workflows, nil
}

// ParseWorkflowYAML parses a workflow file's YAML content
func ParseWorkflowYAML(workflow *WorkflowFile) error {
	var parsedWorkflow Workflow

	if err := yaml.Unmarshal(workflow.Content, &parsedWorkflow); err != nil {
		return fmt.Errorf("failed to parse YAML: %w", err)
	}

	workflow.Workflow = parsedWorkflow
	return nil
}

// LoadSingleWorkflow loads and parses a single workflow file
func LoadSingleWorkflow(filePath string) ([]WorkflowFile, error) {
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("workflow file not found: %s", filePath)
	}

	// Read the file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read workflow file %s: %w", filePath, err)
	}

	// Make sure it's a YAML file
	if !strings.HasSuffix(filePath, ".yml") && !strings.HasSuffix(filePath, ".yaml") {
		return nil, fmt.Errorf("file %s does not have a YAML extension (.yml or .yaml)", filePath)
	}

	// Parse the workflow
	workflow := Workflow{}
	if err := yaml.Unmarshal(content, &workflow); err != nil {
		return nil, fmt.Errorf("failed to parse workflow file %s: %w", filePath, err)
	}

	// Create a workflow file object
	workflowFile := WorkflowFile{
		Path:     filePath,
		Name:     filepath.Base(filePath),
		Content:  content,
		Workflow: workflow,
	}

	return []WorkflowFile{workflowFile}, nil
}
