package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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

// GenerateFileURL generates a GitLab URL pointing to a specific file and line number
func GenerateFileURL(repoURL, filePath string, lineNumber int) string {
	// Parse repository URL to get instance, owner/namespace and repo
	instanceURL, owner, repo, err := ParseRepositoryURL(repoURL)
	if err != nil {
		return ""
	}

	// Remove leading slash and any temporary directory prefixes from file path
	cleanPath := strings.TrimPrefix(filePath, "/")

	// Remove common temporary directory patterns
	// Example: /var/folders/.../flowlyt-gitlab-owner-repo12345/.gitlab-ci.yml -> .gitlab-ci.yml
	if idx := strings.Index(cleanPath, ".gitlab-ci.yml"); idx != -1 {
		cleanPath = ".gitlab-ci.yml"
	} else if idx := strings.Index(cleanPath, ".gitlab-ci.yaml"); idx != -1 {
		cleanPath = ".gitlab-ci.yaml"
	}

	// Determine best ref (SHA > branch > default)
	ref := detectGitLabRef(instanceURL, owner, repo)
	if ref == "" {
		ref = "master"
	}
	if lineNumber > 0 {
		return fmt.Sprintf("%s/%s/%s/-/blob/%s/%s#L%d", instanceURL, owner, repo, ref, cleanPath, lineNumber)
	}
	return fmt.Sprintf("%s/%s/%s/-/blob/%s/%s", instanceURL, owner, repo, ref, cleanPath)
}

func detectGitLabRef(instanceURL, owner, repo string) string {
	// Prefer CI SHA if available
	if sha := strings.TrimSpace(os.Getenv("CI_COMMIT_SHA")); sha != "" {
		return sha
	}
	// Branch name in CI
	if br := strings.TrimSpace(os.Getenv("CI_COMMIT_REF_NAME")); br != "" {
		return br
	}
	// Try local git HEAD
	if head := localGitHeadSHA(); head != "" {
		return head
	}
	// Fallback to default_branch via API
	if def := fetchGitLabDefaultBranch(instanceURL, owner, repo); def != "" {
		return def
	}
	return ""
}

func fetchGitLabDefaultBranch(instanceURL, owner, repo string) string {
	// GET /api/v4/projects/:id  where :id is URL-encoded "namespace/project"
	project := url.QueryEscape(fmt.Sprintf("%s/%s", owner, repo))
	reqURL := fmt.Sprintf("%s/api/v4/projects/%s", strings.TrimRight(instanceURL, "/"), project)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return ""
	}
	if tok := strings.TrimSpace(getenvCompat("GITLAB_TOKEN")); tok != "" {
		req.Header.Set("PRIVATE-TOKEN", tok)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ""
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	var obj struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		return ""
	}
	return strings.TrimSpace(obj.DefaultBranch)
}

var netHttpClient http.Client

func localGitHeadSHA() string {
	if _, err := exec.LookPath("git"); err != nil {
		return ""
	}
	cmd := exec.Command("git", "rev-parse", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func getenvCompat(k string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	if v := os.Getenv(strings.ToLower(k)); v != "" {
		return v
	}
	if v := os.Getenv(strings.ToUpper(k)); v != "" {
		return v
	}
	return ""
}
