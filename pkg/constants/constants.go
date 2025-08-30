package constants

// Application constants
const (
	// Version information
	AppName    = "flowlyt"
	AppVersion = "0.0.3"
	AppUsage   = "Multi-Platform CI/CD Security Analyzer"

	// Default configuration values
	DefaultMinSeverity      = "LOW"
	DefaultOutputFormat     = "cli"
	DefaultPlatform         = "github"
	DefaultEntropyThreshold = 4.5
	DefaultConfigFile       = ".flowlyt.yml"
	DefaultMaxWorkers       = 0 // 0 means use CPU count
	DefaultWorkflowTimeout  = 30 // seconds
	DefaultTotalTimeout     = 300 // seconds (5 minutes)

	// Supported platforms
	PlatformGitHub = "github"
	PlatformGitLab = "gitlab"

	// Supported output formats
	OutputFormatCLI      = "cli"
	OutputFormatJSON     = "json"
	OutputFormatMarkdown = "markdown"

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

	// Common paths and patterns
	GitHubWorkflowsPath = ".github/workflows"
	GitLabCIFileName    = ".gitlab-ci.yml"

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
}
