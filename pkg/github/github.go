package github

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

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
	return c.CloneRepositoryWithProgress(repoURL, destDir, false, nil)
}

// CloneRepositoryWithProgress clones a GitHub repository with optional progress reporting
func (c *Client) CloneRepositoryWithProgress(repoURL, destDir string, showProgress bool, progressCallback func(progress int, stage string)) (string, error) {
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

	if showProgress && progressCallback != nil {
		progressCallback(0, "Initializing clone")
		return c.cloneWithProgress(cloneURL, destDir, progressCallback)
	}

	// Use the git command to clone the repository (original behavior)
	cmd := exec.Command("git", "clone", cloneURL, destDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git clone failed: %w, output: %s", err, string(output))
	}

	return destDir, nil
}

// cloneWithProgress performs git clone with progress reporting
func (c *Client) cloneWithProgress(cloneURL, destDir string, progressCallback func(progress int, stage string)) (string, error) {
	// Use git clone with progress reporting
	cmd := exec.Command("git", "clone", "--progress", cloneURL, destDir)

	// Create pipes to capture stderr (where git outputs progress)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start git clone: %w", err)
	}

	// Parse progress output
	scanner := bufio.NewScanner(stderr)
	progressRegex := regexp.MustCompile(`(\d+)%.*?\((\d+)/(\d+)\)`)

	go func() {
		lastProgress := 0
		lastStage := "Cloning"

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())

			// Skip empty lines
			if line == "" {
				continue
			}

			// Determine stage based on git output
			stage := lastStage
			if strings.Contains(line, "Counting objects") {
				stage = "Counting objects"
			} else if strings.Contains(line, "Compressing objects") {
				stage = "Compressing objects"
			} else if strings.Contains(line, "Receiving objects") {
				stage = "Receiving objects"
			} else if strings.Contains(line, "Resolving deltas") {
				stage = "Resolving deltas"
			} else if strings.Contains(line, "Checking out files") {
				stage = "Checking out files"
			}

			// Extract percentage if available
			matches := progressRegex.FindStringSubmatch(line)
			if len(matches) >= 2 {
				if progress, err := strconv.Atoi(matches[1]); err == nil {
					// Only update if progress has changed significantly (avoid spam)
					if progress != lastProgress && (progress-lastProgress >= 5 || progress >= 100) {
						progressCallback(progress, stage)
						lastProgress = progress
					}
				}
			} else if stage != lastStage {
				// Stage changed, report progress
				progressCallback(lastProgress, stage)
			}

			lastStage = stage
		}

		// Ensure we report 100% completion
		if lastProgress < 100 {
			progressCallback(100, "Completed")
		}
	}()

	// Wait for the command to complete
	err = cmd.Wait()
	if err != nil {
		return "", fmt.Errorf("git clone failed: %w", err)
	}

	// Give the progress goroutine a moment to finish
	time.Sleep(100 * time.Millisecond)

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

// GenerateFileURL creates a GitHub URL pointing to a specific line in a file
func GenerateFileURL(repoURL, filePath string, lineNumber int) string {
	// Parse repository URL to get owner and repo
	owner, repo, err := ParseRepositoryURL(repoURL)
	if err != nil {
		return ""
	}

	// Remove leading slash and any temporary directory prefixes from file path
	cleanPath := strings.TrimPrefix(filePath, "/")

	// Remove common temporary directory patterns
	// Example: /var/folders/.../flowlyt-owner-repo12345/.github/workflows/file.yml -> .github/workflows/file.yml
	if idx := strings.Index(cleanPath, ".github/workflows/"); idx != -1 {
		cleanPath = cleanPath[idx:]
	} else if idx := strings.Index(cleanPath, ".gitlab-ci.yml"); idx != -1 {
		cleanPath = ".gitlab-ci.yml"
	}

	if lineNumber > 0 {
		return fmt.Sprintf("https://github.com/%s/%s/blob/main/%s#L%d", owner, repo, cleanPath, lineNumber)
	}

	return fmt.Sprintf("https://github.com/%s/%s/blob/main/%s", owner, repo, cleanPath)
}

// IsGitHubRepository checks if a repository URL is a GitHub repository
func IsGitHubRepository(repoURL string) bool {
	return strings.Contains(repoURL, "github.com")
}
