package gitlab

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Client represents a GitLab repository client
type Client struct {
	ctx         context.Context
	instanceURL string
	token       string
}

// NewClient creates a new GitLab client
// instanceURL can be:
// - "" or "https://gitlab.com" for GitLab SaaS
// - "https://gitlab.company.com" for on-premise instances
func NewClient(instanceURL string) (*Client, error) {
	ctx := context.Background()

	// Default to GitLab SaaS if no instance URL provided
	if instanceURL == "" {
		instanceURL = "https://gitlab.com"
	}

	// Ensure the URL has proper format
	if !strings.HasPrefix(instanceURL, "http://") && !strings.HasPrefix(instanceURL, "https://") {
		instanceURL = "https://" + instanceURL
	}

	// Get GitLab token from environment
	token := os.Getenv("GITLAB_TOKEN")

	return &Client{
		ctx:         ctx,
		instanceURL: instanceURL,
		token:       token,
	}, nil
}

// ParseRepositoryURL parses a GitLab repository URL and detects the instance
func ParseRepositoryURL(repoURL string) (instanceURL, owner, repo string, err error) {
	// Remove .git suffix if present
	repoURL = strings.TrimSuffix(repoURL, ".git")

	// Parse the URL
	u, err := url.Parse(repoURL)
	if err != nil {
		return "", "", "", fmt.Errorf("invalid repository URL: %w", err)
	}

	// Extract instance URL (scheme + host)
	instanceURL = fmt.Sprintf("%s://%s", u.Scheme, u.Host)

	// Parse path to get owner/repo
	pathParts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(pathParts) < 2 {
		return "", "", "", fmt.Errorf("invalid GitLab repository URL format. Expected: https://gitlab.com/owner/repo")
	}

	owner = pathParts[0]
	repo = pathParts[1]

	return instanceURL, owner, repo, nil
}

// IsGitLabURL checks if a URL is a GitLab repository URL
func IsGitLabURL(repoURL string) bool {
	// Check for common GitLab patterns
	if strings.Contains(repoURL, "gitlab.com") {
		return true
	}

	// Check for common on-premise GitLab patterns
	if strings.Contains(repoURL, "gitlab") && (strings.Contains(repoURL, "http://") || strings.Contains(repoURL, "https://")) {
		return true
	}

	return false
}

// CloneRepository clones a GitLab repository to a temporary directory
func (c *Client) CloneRepository(repoURL, tempDir string) (string, error) {
	_, _, repo, err := ParseRepositoryURL(repoURL)
	if err != nil {
		return "", err
	}

	// Create temporary directory if not provided
	if tempDir == "" {
		tempDir, err = os.MkdirTemp("", "flowlyt-gitlab-*")
		if err != nil {
			return "", fmt.Errorf("failed to create temp directory: %w", err)
		}
	}

	repoPath := filepath.Join(tempDir, repo)

	// Clone the repository using git
	fmt.Printf("Cloning GitLab repository from %s...\n", repoURL)

	// Check if git is available
	if _, err := exec.LookPath("git"); err != nil {
		return "", fmt.Errorf("git command not found. Please install git to clone repositories")
	}

	// Create clone command
	cmd := exec.Command("git", "clone", "--depth", "1", repoURL, repoPath)

	// Set environment variables for authentication if token is available
	if c.token != "" {
		// For HTTPS cloning with token, we can use git credential helper
		// or modify the URL to include the token

		// Parse the URL to inject token for authentication
		u, parseErr := url.Parse(repoURL)
		if parseErr == nil {
			// Create authenticated URL: https://oauth2:token@gitlab.com/owner/repo.git
			u.User = url.UserPassword("oauth2", c.token)
			authenticatedURL := u.String()
			cmd = exec.Command("git", "clone", "--depth", "1", authenticatedURL, repoPath)
		}
	}

	// Execute the clone command
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to clone repository: %w\nOutput: %s", err, string(output))
	}

	return repoPath, nil
}

// ValidateConnection tests basic connectivity to the GitLab instance
func (c *Client) ValidateConnection() error {
	if c.instanceURL == "" {
		return fmt.Errorf("no GitLab instance URL configured")
	}

	// For now, we just verify the URL format
	// In the future, we could add a simple HTTP check or API ping
	if _, err := url.Parse(c.instanceURL); err != nil {
		return fmt.Errorf("invalid GitLab instance URL: %w", err)
	}

	return nil
}
