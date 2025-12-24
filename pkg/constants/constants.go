package constants

import "os"

// Application constants
const (
	// Version information
	AppName    = "flowlyt"
	AppVersion = "0.0.9"
	AppUsage   = "Multi-Platform CI/CD Security Analyzer"

	// Default configuration values
	DefaultMinSeverity      = "LOW"
	DefaultOutputFormat     = "cli"
	DefaultPlatform         = "github"
	DefaultEntropyThreshold = 4.5
	DefaultConfigFile       = ".flowlyt.yml"
	DefaultMaxWorkers       = 0   // 0 means use CPU count
	DefaultWorkflowTimeout  = 30  // seconds
	DefaultTotalTimeout     = 300 // seconds (5 minutes)

	// Supported platforms
	PlatformGitHub = "github"
	PlatformGitLab = "gitlab"

	// Supported output formats
	OutputFormatCLI      = "cli"
	OutputFormatJSON     = "json"
	OutputFormatMarkdown = "markdown"
	OutputFormatSARIF    = "sarif"

	// Configuration file names
	ConfigFileFlowlytYML  = ".flowlyt.yml"
	ConfigFileFlowlytYAML = ".flowlyt.yaml"
	ConfigFileBaseYML     = "flowlyt.yml"
	ConfigFileBaseYAML    = "flowlyt.yaml"

	// Severity levels
	SeverityInfo     = "INFO"
	SeverityLow      = "LOW"
	SeverityMedium   = "MEDIUM"
	SeverityHigh     = "HIGH"
	SeverityCritical = "CRITICAL"

	// Rule categories
	CategoryMaliciousPattern = "MaliciousPattern"
	CategoryShellObfuscation = "ShellObfuscation"
	CategoryMisconfiguration = "Misconfiguration"
	CategorySecretExposure   = "SecretExposure"
	CategorySupplyChain      = "SupplyChain"
	CategoryDataExfiltration = "DataExfiltration"
	CategoryReachability     = "Reachability"
	CategoryDataFlow         = "DataFlow"
	CategoryCallGraph        = "CallGraph"

	// Common paths and patterns
	GitHubWorkflowsPath = ".github/workflows"
	GitLabCIFileName    = ".gitlab-ci.yml"

	// GitHub Actions environment variables
	EnvGitHubActions = "GITHUB_ACTIONS"
	EnvCI            = "CI"
	EnvGitHubActor   = "GITHUB_ACTOR"
	EnvGitHubRunID   = "GITHUB_RUN_ID"

	// Error messages
	ErrInvalidPlatform       = "unsupported platform"
	ErrNoInputSpecified      = "either --repo, --url, or --workflow must be specified"
	ErrConfigLoadFailed      = "failed to load configuration"
	ErrWorkflowLoadFailed    = "failed to load workflow file"
	ErrRepositoryCloneFailed = "failed to clone repository"
)

// Common false positive patterns that should be ignored
var DefaultIgnorePatterns = []string{
	"example",
	"placeholder",
	"test",
	"dummy",
	"sample",
	"YOUR_SECRET_HERE",
	"your-secret-here",
	"changeme",
	"change-me",
	"XXXXXX",
	"xxxxxx",
	"000000",
	"111111",
	"password",
	"secret",
	"token",
	"key",
	"admin",
	"user",
	"default",
	"localhost",
	"127.0.0.1",
	"0.0.0.0",
	"::1",
}

// Severity level mapping for filtering
var SeverityLevels = map[string]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// Supported platforms list
var SupportedPlatforms = []string{
	PlatformGitHub,
	PlatformGitLab,
}

// Supported output formats list
var SupportedOutputFormats = []string{
	OutputFormatCLI,
	OutputFormatJSON,
	OutputFormatMarkdown,
	OutputFormatSARIF,
}

// IsRunningInCI detects if the application is running in a CI environment
func IsRunningInCI() bool {
	// Check for GitHub Actions
	if os.Getenv(EnvGitHubActions) == "true" {
		return true
	}

	// Check for generic CI environment
	if os.Getenv(EnvCI) == "true" {
		return true
	}

	// Check for other common CI environment variables
	ciEnvs := []string{
		"TRAVIS",          // Travis CI
		"CIRCLECI",        // Circle CI
		"JENKINS_URL",     // Jenkins
		"GITLAB_CI",       // GitLab CI
		"BUILDKITE",       // Buildkite
		"TF_BUILD",        // Azure DevOps
		"GITHUB_WORKFLOW", // GitHub Actions (alternative check)
	}

	for _, env := range ciEnvs {
		if os.Getenv(env) != "" {
			return true
		}
	}

	return false
}

// IsRunningInGitHubActions specifically detects GitHub Actions environment
func IsRunningInGitHubActions() bool {
	return os.Getenv(EnvGitHubActions) == "true"
}
