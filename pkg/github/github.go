package github

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

// getGitHubToken attempts to get a GitHub token from multiple sources
func getGitHubToken(providedToken string) (string, string) {
	// 1. Use provided token (highest priority)
	if providedToken != "" {
		return providedToken, "provided token"
	}

	// 2. Check GITHUB_TOKEN environment variable
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		return token, "GITHUB_TOKEN environment variable"
	}

	// 3. Try to get token from GitHub CLI
	if token := getGHCLIToken(); token != "" {
		return token, "GitHub CLI (gh auth)"
	}

	return "", "no authentication found"
}

// getGHCLIToken attempts to get the GitHub CLI token
func getGHCLIToken() string {
	// Check if gh CLI is available and authenticated
	cmd := exec.Command("gh", "auth", "token")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	token := strings.TrimSpace(string(output))
	if token != "" && token != "no authentication found" {
		return token
	}

	return ""
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

// NewClientWithSmartAuth creates a GitHub client with intelligent authentication
func NewClientWithSmartAuth(providedToken string) (*Client, string) {
	ctx := context.Background()
	var client *github.Client

	token, source := getGitHubToken(providedToken)

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
	}, source
}

// NewClientWithToken creates a new GitHub API client with the provided token
func NewClientWithToken(token string) *Client {
	ctx := context.Background()
	var client *github.Client

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

// GetWorkflowFilesContents fetches all workflow files from a repository using the GitHub API.
func (c *Client) GetWorkflowFilesContents(owner, repo string) (map[string][]byte, error) {
	workflowFiles, err := c.GetWorkflowFiles(owner, repo)
	if err != nil {
		return nil, fmt.Errorf("failed to list workflow files: %w", err)
	}

	contents := make(map[string][]byte)
	for _, file := range workflowFiles {
		fileContent, _, _, err := c.client.Repositories.GetContents(
			c.ctx,
			owner,
			repo,
			file.GetPath(),
			nil,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to get content for file %s: %w", file.GetPath(), err)
		}

		decodedContent, err := fileContent.GetContent()
		if err != nil {
			return nil, fmt.Errorf("failed to decode content of %s: %w", file.GetPath(), err)
		}
		contents[file.GetPath()] = []byte(decodedContent)
	}

	return contents, nil
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

	// Normalize path separators and strip any temp prefixes so URLs never include local paths
	cleanPath := strings.ReplaceAll(filePath, "\\", "/")
	cleanPath = strings.TrimPrefix(cleanPath, "/")
	// If the path contains a workflow root, slice from there
	if idx := strings.Index(cleanPath, ".github/workflows/"); idx != -1 {
		cleanPath = cleanPath[idx:]
	} else if idx := strings.Index(cleanPath, "/.github/workflows/"); idx != -1 {
		cleanPath = cleanPath[idx+1:]
	} else if strings.HasSuffix(cleanPath, ".gitlab-ci.yml") {
		cleanPath = ".gitlab-ci.yml"
	} else if strings.HasSuffix(cleanPath, ".gitlab-ci.yaml") {
		cleanPath = ".gitlab-ci.yaml"
	}

	// Detect best ref: prefer SHA, then explicit ref, then default branch
	ref := detectGitHubRef(owner, repo)
	if ref == "" {
		ref = "main"
	}
	if lineNumber > 0 {
		return fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s#L%d", owner, repo, ref, cleanPath, lineNumber)
	}
	return fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s", owner, repo, ref, cleanPath)
}

// IsGitHubRepository checks if a repository URL is a GitHub repository
func IsGitHubRepository(repoURL string) bool {
	return strings.Contains(repoURL, "github.com")
}

// GenerateFileURLWithBranch creates a GitHub URL using an explicit branch name (no SHA).
func GenerateFileURLWithBranch(repoURL, filePath string, lineNumber int, branch string) string {
	owner, repo, err := ParseRepositoryURL(repoURL)
	if err != nil {
		return ""
	}
	cleanPath := strings.ReplaceAll(filePath, "\\", "/")
	cleanPath = strings.TrimPrefix(cleanPath, "/")
	if idx := strings.Index(cleanPath, ".github/workflows/"); idx != -1 {
		cleanPath = cleanPath[idx:]
	} else if idx := strings.Index(cleanPath, "/.github/workflows/"); idx != -1 {
		cleanPath = cleanPath[idx+1:]
	} else if strings.HasSuffix(cleanPath, ".gitlab-ci.yml") {
		cleanPath = ".gitlab-ci.yml"
	} else if strings.HasSuffix(cleanPath, ".gitlab-ci.yaml") {
		cleanPath = ".gitlab-ci.yaml"
	}
	if strings.TrimSpace(branch) == "" {
		branch = "main"
	}
	if lineNumber > 0 {
		return fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s#L%d", owner, repo, branch, cleanPath, lineNumber)
	}
	return fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s", owner, repo, branch, cleanPath)
}

// detectGitHubRef determines the best ref (prefer immutable SHA, else default branch)
func detectGitHubRef(owner, repo string) string {
	// Prefer explicit CI env
	if sha := strings.TrimSpace(os.Getenv("GITHUB_SHA")); sha != "" {
		return sha
	}
	// GitHub Actions: branch or tag name
	if rn := strings.TrimSpace(os.Getenv("GITHUB_REF_NAME")); rn != "" {
		return rn
	}
	// Try local git HEAD
	if head := localGitHeadSHA(); head != "" {
		return head
	}
	// Fallback: repository default branch via API
	if def := fetchGitHubDefaultBranch(owner, repo); def != "" {
		return def
	}
	return ""
}

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

func fetchGitHubDefaultBranch(owner, repo string) string {
	reqURL := fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return ""
	}
	// Add token if available to increase rate limits
	if tok := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
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

// RepositoryFilter defines criteria for filtering repositories during organization analysis
type RepositoryFilter struct {
	IncludeForks    bool   // Include forked repositories
	IncludeArchived bool   // Include archived repositories
	IncludePrivate  bool   // Include private repositories
	IncludePublic   bool   // Include public repositories
	MaxRepos        int    // Maximum number of repositories to analyze (0 = no limit)
	NameFilter      string // Regular expression to filter repository names
}

// DiscoverOrganizationRepositories discovers all repositories in a GitHub organization
func (c *Client) DiscoverOrganizationRepositories(orgName string, filter interface{}) ([]RepositoryInfo, error) {
	// Convert interface{} to RepositoryFilter
	var repoFilter RepositoryFilter
	if f, ok := filter.(RepositoryFilter); ok {
		repoFilter = f
	} else {
		// Default filter if conversion fails
		repoFilter = RepositoryFilter{
			IncludeForks:    true,
			IncludeArchived: true,
			IncludePrivate:  true,
			IncludePublic:   true,
			MaxRepos:        0,
			NameFilter:      "",
		}
	}

	// Get repositories for the organization
	opt := &github.RepositoryListByOrgOptions{
		Type: "all", // public, private, forks, sources, member, all
		ListOptions: github.ListOptions{
			PerPage: 100, // Maximum per page
		},
	}

	var allRepos []RepositoryInfo

	// Compile name filter regex if provided
	var nameRegex *regexp.Regexp
	if repoFilter.NameFilter != "" {
		var err error
		nameRegex, err = regexp.Compile(repoFilter.NameFilter)
		if err != nil {
			return nil, fmt.Errorf("invalid name filter regex: %w", err)
		}
	}

	for {
		repos, resp, err := c.client.Repositories.ListByOrg(c.ctx, orgName, opt)
		if err != nil {
			return nil, fmt.Errorf("failed to list organization repositories: %w", err)
		}

		// Convert GitHub repositories to our format and apply filters
		for _, repo := range repos {
			// Apply visibility filters
			if repo.GetPrivate() && !repoFilter.IncludePrivate {
				continue
			}
			if !repo.GetPrivate() && !repoFilter.IncludePublic {
				continue
			}

			// Apply fork filter
			if repo.GetFork() && !repoFilter.IncludeForks {
				continue
			}

			// Apply archived filter
			if repo.GetArchived() && !repoFilter.IncludeArchived {
				continue
			}

			// Apply name filter
			if nameRegex != nil && !nameRegex.MatchString(repo.GetName()) {
				continue
			}

			repoInfo := RepositoryInfo{
				Name:        repo.GetName(),
				FullName:    repo.GetFullName(),
				URL:         repo.GetHTMLURL(),
				CloneURL:    repo.GetCloneURL(),
				IsPrivate:   repo.GetPrivate(),
				IsFork:      repo.GetFork(),
				IsArchived:  repo.GetArchived(),
				Language:    repo.GetLanguage(),
				Description: repo.GetDescription(),
				UpdatedAt:   repo.GetUpdatedAt().Format(time.RFC3339),
			}

			allRepos = append(allRepos, repoInfo)

			// Apply max repos limit
			if repoFilter.MaxRepos > 0 && len(allRepos) >= repoFilter.MaxRepos {
				return allRepos, nil
			}
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return allRepos, nil
}

// RepositoryInfo represents basic information about a repository
type RepositoryInfo struct {
	Name        string `json:"name"`
	FullName    string `json:"full_name"`
	URL         string `json:"url"`
	CloneURL    string `json:"clone_url"`
	IsPrivate   bool   `json:"is_private"`
	IsFork      bool   `json:"is_fork"`
	IsArchived  bool   `json:"is_archived"`
	Language    string `json:"language,omitempty"`
	Description string `json:"description,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}
