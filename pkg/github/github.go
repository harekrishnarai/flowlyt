package github

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/go-github/v53/github"
	"golang.org/x/oauth2"
)

// Client represents a GitHub API client
type Client struct {
	client *github.Client
	ctx    context.Context
}

// NewClient creates a new GitHub API client
func NewClient() *Client {
	ctx := context.Background()
	var client *github.Client

	// Check if GitHub token is available
	token := os.Getenv("GITHUB_TOKEN")
	if token != "" {
		// Create authenticated client
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		)
		tc := oauth2.NewClient(ctx, ts)
		client = github.NewClient(tc)
	} else {
		// Create unauthenticated client (rate limited)
		client = github.NewClient(nil)
	}

	return &Client{
		client: client,
		ctx:    ctx,
	}
}

// ParseRepositoryURL parses a GitHub repository URL
func ParseRepositoryURL(repoURL string) (owner, repo string, err error) {
	// Handle URLs like https://github.com/owner/repo
	if strings.HasPrefix(repoURL, "https://github.com/") {
		parts := strings.Split(strings.TrimPrefix(repoURL, "https://github.com/"), "/")
		if len(parts) >= 2 {
			owner = parts[0]
			repo = parts[1]
			// Strip .git suffix if present
			repo = strings.TrimSuffix(repo, ".git")
			return owner, repo, nil
		}
	}

	// Handle git URLs like git@github.com:owner/repo.git
	if strings.HasPrefix(repoURL, "git@github.com:") {
		parts := strings.Split(strings.TrimPrefix(repoURL, "git@github.com:"), "/")
		if len(parts) >= 2 {
			owner = parts[0]
			repo = parts[1]
			// Strip .git suffix if present
			repo = strings.TrimSuffix(repo, ".git")
			return owner, repo, nil
		}
	}

	return "", "", fmt.Errorf("invalid GitHub repository URL: %s", repoURL)
}

// CloneRepository clones a GitHub repository to a local directory
func (c *Client) CloneRepository(repoURL, destDir string) (string, error) {
	owner, repo, err := ParseRepositoryURL(repoURL)
	if err != nil {
		return "", err
	}

	// Create destination directory
	if destDir == "" {
		// Create a temporary directory
		tempDir, err := os.MkdirTemp("", fmt.Sprintf("flowlyt-%s-%s", owner, repo))
		if err != nil {
			return "", fmt.Errorf("failed to create temporary directory: %w", err)
		}
		destDir = tempDir
	} else if _, err := os.Stat(destDir); os.IsNotExist(err) {
		// Create the specified directory if it doesn't exist
		if err := os.MkdirAll(destDir, 0755); err != nil {
			return "", fmt.Errorf("failed to create directory: %w", err)
		}
	}

	// Determine if we should use authenticated URL
	cloneURL := fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		cloneURL = fmt.Sprintf("https://x-access-token:%s@github.com/%s/%s.git", url.QueryEscape(token), owner, repo)
	}

	// Use the git command to clone the repository
	cmd := exec.Command("git", "clone", cloneURL, destDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git clone failed: %w, output: %s", err, string(output))
	}

	return destDir, nil
}

// GetWorkflowFiles gets the GitHub Actions workflow files from a repository
func (c *Client) GetWorkflowFiles(owner, repo string) ([]*github.RepositoryContent, error) {
	// Path to workflows directory
	workflowsPath := ".github/workflows"

	// List files in the workflows directory
	_, directoryContent, _, err := c.client.Repositories.GetContents(
		c.ctx,
		owner,
		repo,
		workflowsPath,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list workflow files: %w", err)
	}

	// Filter YAML files
	var workflowFiles []*github.RepositoryContent
	for _, content := range directoryContent {
		if content.GetType() == "file" && (strings.HasSuffix(content.GetName(), ".yml") || strings.HasSuffix(content.GetName(), ".yaml")) {
			workflowFiles = append(workflowFiles, content)
		}
	}

	return workflowFiles, nil
}

// DownloadWorkflowFiles downloads workflow files to a local directory
func (c *Client) DownloadWorkflowFiles(owner, repo, destDir string) ([]string, error) {
	// Get workflow files
	workflowFiles, err := c.GetWorkflowFiles(owner, repo)
	if err != nil {
		return nil, err
	}

	// Create workflows directory
	workflowsDir := filepath.Join(destDir, ".github", "workflows")
	if err := os.MkdirAll(workflowsDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create workflows directory: %w", err)
	}

	// Download each workflow file
	var downloadedFiles []string
	for _, file := range workflowFiles {
		// Get the file content
		fileContent, _, _, err := c.client.Repositories.GetContents(
			c.ctx,
			owner,
			repo,
			file.GetPath(),
			nil,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to get file %s: %w", file.GetPath(), err)
		}

		// Decode content
		content, err := fileContent.GetContent()
		if err != nil {
			return nil, fmt.Errorf("failed to decode content of %s: %w", file.GetPath(), err)
		}

		// Write to file
		filePath := filepath.Join(workflowsDir, file.GetName())
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			return nil, fmt.Errorf("failed to write file %s: %w", filePath, err)
		}

		downloadedFiles = append(downloadedFiles, filePath)
	}

	return downloadedFiles, nil
}

// CreateIssueComment creates a comment on a GitHub issue or pull request
func (c *Client) CreateIssueComment(owner, repo string, number int, body string) error {
	comment := &github.IssueComment{
		Body: github.String(body),
	}

	_, _, err := c.client.Issues.CreateComment(c.ctx, owner, repo, number, comment)
	if err != nil {
		return fmt.Errorf("failed to create issue comment: %w", err)
	}

	return nil
}

// CreateCheckRun creates a GitHub check run for a commit
func (c *Client) CreateCheckRun(owner, repo, sha string, findings []string) error {
	// Create conclusion based on findings
	conclusion := "success"
	if len(findings) > 0 {
		conclusion = "neutral"
	}

	// Build summary text
	summary := "## Flowlyt Security Analysis\n\n"
	if len(findings) == 0 {
		summary += "✅ No security issues found in GitHub Actions workflows.\n"
	} else {
		summary += fmt.Sprintf("⚠️ Found %d potential security issues in GitHub Actions workflows.\n\n", len(findings))
		for i, finding := range findings {
			summary += fmt.Sprintf("%d. %s\n", i+1, finding)
		}
	}

	// Create check run options
	opts := github.CreateCheckRunOptions{
		Name:       "Flowlyt Security Analysis",
		HeadSHA:    sha,
		Status:     github.String("completed"),
		Conclusion: github.String(conclusion),
		Output: &github.CheckRunOutput{
			Title:   github.String("Flowlyt GitHub Actions Security Analysis"),
			Summary: github.String(summary),
		},
	}

	_, _, err := c.client.Checks.CreateCheckRun(c.ctx, owner, repo, opts)
	if err != nil {
		return fmt.Errorf("failed to create check run: %w", err)
	}

	return nil
}