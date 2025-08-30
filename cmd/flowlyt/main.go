package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/harekrishnarai/flowlyt/pkg/concurrent"
	"github.com/harekrishnarai/flowlyt/pkg/config"
	"github.com/harekrishnarai/flowlyt/pkg/constants"
	"github.com/harekrishnarai/flowlyt/pkg/errors"
	"github.com/harekrishnarai/flowlyt/pkg/github"
	"github.com/harekrishnarai/flowlyt/pkg/gitlab"
	"github.com/harekrishnarai/flowlyt/pkg/organization"
	"github.com/harekrishnarai/flowlyt/pkg/parser"
	"github.com/harekrishnarai/flowlyt/pkg/policies"
	"github.com/harekrishnarai/flowlyt/pkg/report"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
	"github.com/harekrishnarai/flowlyt/pkg/validation"
	"github.com/urfave/cli/v2"
)

var version = constants.AppVersion

func main() {
	app := &cli.App{
		Name:    constants.AppName,
		Version: version,
		Usage:   constants.AppUsage,
		Authors: []*cli.Author{
			{
				Name: "Flowlyt Team",
			},
		},
		Commands: []*cli.Command{
			{
				Name:    "scan",
				Aliases: []string{"s"},
				Usage:   "Scan repository or workflow files for security issues",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "platform",
						Aliases: []string{"pl"},
						Usage:   "CI/CD platform (github, gitlab, jenkins, azure)",
						Value:   constants.DefaultPlatform,
					},
					&cli.StringFlag{
						Name:    "repo",
						Aliases: []string{"r"},
						Usage:   "Local repository path to scan",
					},
					&cli.StringFlag{
						Name:    "url",
						Aliases: []string{"u"},
						Usage:   "Repository URL to scan (GitHub or GitLab)",
					},
					&cli.StringFlag{
						Name:    "workflow",
						Aliases: []string{"w"},
						Usage:   "Specific workflow file to scan",
					},
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Usage:   "Configuration file path",
						Value:   constants.DefaultConfigFile,
					},
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "Output format (json, yaml, table, sarif)",
						Value:   constants.DefaultOutputFormat,
					},
					&cli.StringFlag{
						Name:  "output-file",
						Usage: "Output file path (default: stdout)",
					},
					&cli.StringFlag{
						Name:    "min-severity",
						Aliases: []string{"severity"},
						Usage:   "Minimum severity level (info, low, medium, high, critical)",
						Value:   constants.DefaultMinSeverity,
					},
					&cli.Float64Flag{
						Name:    "entropy-threshold",
						Aliases: []string{"entropy"},
						Usage:   "Entropy threshold for secret detection",
						Value:   constants.DefaultEntropyThreshold,
					},
					&cli.BoolFlag{
						Name:    "ignore-errors",
						Aliases: []string{"ie"},
						Usage:   "Continue scanning even if errors occur",
					},
					&cli.BoolFlag{
						Name:    "verbose",
						Aliases: []string{"v"},
						Usage:   "Enable verbose output",
					},
					&cli.BoolFlag{
						Name:  "no-banner",
						Usage: "Disable banner output",
					},
					&cli.IntFlag{
						Name:    "max-workers",
						Aliases: []string{"j"},
						Usage:   "Maximum number of concurrent workers (0 = CPU count)",
						Value:   constants.DefaultMaxWorkers,
					},
					&cli.IntFlag{
						Name:  "workflow-timeout",
						Usage: "Timeout for processing single workflow (seconds)",
						Value: constants.DefaultWorkflowTimeout,
					},
					&cli.IntFlag{
						Name:  "total-timeout",
						Usage: "Total timeout for analysis (seconds)",
						Value: constants.DefaultTotalTimeout,
					},
					&cli.BoolFlag{
						Name:  "no-progress",
						Usage: "Disable progress reporting",
					},
					&cli.BoolFlag{
						Name:  "no-default-rules",
						Usage: "Disable default security rules",
					},
				},
				Action: scanAction,
			},
			{
				Name:    "analyze-org",
				Aliases: []string{"org"},
				Usage:   "Analyze all repositories in a GitHub organization",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "organization",
						Aliases:  []string{"org", "o"},
						Usage:    "GitHub organization name to analyze",
						Required: true,
					},
					&cli.StringFlag{
						Name:    "output-format",
						Aliases: []string{"f"},
						Value:   constants.DefaultOutputFormat,
						Usage:   "Output format: cli, json, markdown",
					},
					&cli.StringFlag{
						Name:    "output-file",
						Aliases: []string{"o"},
						Usage:   "Output file path (default: stdout)",
					},
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Usage:   "Configuration file path",
					},
					&cli.StringFlag{
						Name:  "min-severity",
						Value: constants.DefaultMinSeverity,
						Usage: "Minimum severity level to report: INFO, LOW, MEDIUM, HIGH, CRITICAL",
					},
					&cli.IntFlag{
						Name:  "max-repos",
						Value: 100,
						Usage: "Maximum number of repositories to analyze (0 = no limit)",
					},
					&cli.StringFlag{
						Name:  "repo-filter",
						Usage: "Regular expression to filter repository names",
					},
					&cli.BoolFlag{
						Name:  "include-forks",
						Usage: "Include forked repositories in the analysis",
					},
					&cli.BoolFlag{
						Name:  "include-archived",
						Usage: "Include archived repositories in the analysis",
					},
					&cli.BoolFlag{
						Name:  "include-private",
						Value: true,
						Usage: "Include private repositories in the analysis",
					},
					&cli.BoolFlag{
						Name:  "include-public",
						Value: true,
						Usage: "Include public repositories in the analysis",
					},
					&cli.IntFlag{
						Name:  "max-workers",
						Value: constants.DefaultMaxWorkers,
						Usage: "Maximum number of concurrent workers (0 = CPU count)",
					},
					&cli.BoolFlag{
						Name:  "no-progress",
						Usage: "Disable progress reporting",
					},
					&cli.BoolFlag{
						Name:  "summary-only",
						Usage: "Show only organization-level summary, skip individual repository details",
					},
				},
				Action: analyzeOrgAction,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		if flowlytErr, ok := err.(*errors.FlowlytError); ok {
			fmt.Fprintf(os.Stderr, "%s\n", flowlytErr.UserFriendlyMessage())
		} else {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}
}

// scanAction handles the scan command
func scanAction(c *cli.Context) error {
	return scan(c, c.String("output"), c.String("output-file"))
}

// analyzeOrgAction handles the analyze-org command
func analyzeOrgAction(c *cli.Context) error {
	return analyzeOrganization(c, c.String("output-format"), c.String("output-file"))
}

// loadAndOverrideConfig loads configuration and applies CLI flag overrides
func loadAndOverrideConfig(c *cli.Context, outputFormat, outputFile string) (*config.Config, error) {
	// Load configuration
	configPath := c.String("config")
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, errors.NewConfigError("Failed to load configuration", err,
			"Check the configuration file path and syntax",
			"Use 'flowlyt --help' to see configuration options",
		)
	}

	// Override config with CLI flags
	if c.String("min-severity") != constants.DefaultMinSeverity {
		cfg.Output.MinSeverity = c.String("min-severity")
	}
	if c.String("output") != constants.DefaultOutputFormat {
		cfg.Output.Format = c.String("output")
	}
	if c.String("output-file") != "" {
		cfg.Output.File = c.String("output-file")
	}

	// Handle rule enable/disable flags
	if enabledRules := c.StringSlice("enable-rules"); len(enabledRules) > 0 {
		cfg.Rules.Enabled = append(cfg.Rules.Enabled, enabledRules...)
	}
	if disabledRules := c.StringSlice("disable-rules"); len(disabledRules) > 0 {
		cfg.Rules.Disabled = append(cfg.Rules.Disabled, disabledRules...)
	}

	return cfg, nil
}

// acquireRepository handles repository acquisition (clone or local path)
func acquireRepository(c *cli.Context, repoURL, repoPath, platform string) (string, func(), error) {
	var repoLocalPath string
	var cleanup func()

	if repoURL != "" {
		fmt.Printf("Cloning repository from %s...\n", repoURL)

		// Auto-detect platform from URL if not explicitly specified
		if platform == constants.PlatformGitHub && c.String("platform") == constants.PlatformGitHub {
			// Check if URL is actually GitLab
			if gitlab.IsGitLabURL(repoURL) {
				platform = constants.PlatformGitLab
				fmt.Printf("Auto-detected GitLab repository, switching to GitLab platform\n")
			}
		}

		var err error
		switch platform {
		case constants.PlatformGitHub:
			client := github.NewClient()
			tempDir := c.String("temp-dir")

			// Determine if we should show progress
			showProgress := !constants.IsRunningInCI() && !c.Bool("no-progress")

			if showProgress {
				fmt.Printf("🔄 Cloning GitHub repository: %s\n", repoURL)

				// Create progress callback
				progressCallback := func(progress int, stage string) {
					// Create a simple progress bar
					barWidth := 40
					filled := int((float64(progress) / 100) * float64(barWidth))
					bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

					// Print progress with carriage return to overwrite previous line
					fmt.Printf("\r[%s] %d%% - %s", bar, progress, stage)
					if progress >= 100 {
						fmt.Println() // New line when complete
					}
				}

				repoLocalPath, err = client.CloneRepositoryWithProgress(repoURL, tempDir, true, progressCallback)
			} else {
				// In CI environment or progress disabled, use quiet cloning
				if constants.IsRunningInCI() {
					fmt.Printf("Cloning repository: %s\n", repoURL)
				}
				repoLocalPath, err = client.CloneRepository(repoURL, tempDir)
			}

			if err != nil {
				return "", nil, fmt.Errorf("failed to clone GitHub repository: %w", err)
			}

		case constants.PlatformGitLab:
			gitlabInstance := c.String("gitlab-instance")
			client, err := gitlab.NewClient(gitlabInstance)
			if err != nil {
				return "", nil, fmt.Errorf("failed to create GitLab client: %w", err)
			}

			tempDir := c.String("temp-dir")
			repoLocalPath, err = client.CloneRepository(repoURL, tempDir)
			if err != nil {
				return "", nil, fmt.Errorf("failed to clone GitLab repository: %w", err)
			}

		default:
			return "", nil, fmt.Errorf("repository cloning from URL is not supported for platform: %s", platform)
		}

		// Set up cleanup function if we created a temporary directory
		tempDirFlag := c.String("temp-dir")
		if tempDirFlag == "" {
			cleanup = func() {
				fmt.Printf("Cleaning up temporary directory %s...\n", repoLocalPath)
				os.RemoveAll(repoLocalPath)
			}
		}
	} else if repoPath != "" {
		repoLocalPath = repoPath
	}

	return repoLocalPath, cleanup, nil
}

// findWorkflowFiles finds workflow files based on platform and input
func findWorkflowFiles(workflowFile, repoLocalPath, platform string) ([]parser.WorkflowFile, error) {
	var workflowFiles []parser.WorkflowFile
	var err error

	if workflowFile != "" {
		fmt.Printf("Scanning single workflow file %s...\n", workflowFile)
		workflowFiles, err = parser.LoadSingleWorkflow(workflowFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load workflow file: %w", err)
		}
	} else {
		switch platform {
		case constants.PlatformGitHub:
			fmt.Printf("Scanning GitHub Actions workflows in %s...\n", repoLocalPath)
			workflowFiles, err = parser.FindWorkflows(repoLocalPath)
		case constants.PlatformGitLab:
			fmt.Printf("Scanning GitLab CI/CD pipelines in %s...\n", repoLocalPath)
			workflowFiles, err = gitlab.FindGitLabWorkflows(repoLocalPath)
		default:
			return nil, errors.ErrUnsupportedPlatform(platform, constants.SupportedPlatforms)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to find workflow files: %w", err)
		}
	}

	return workflowFiles, nil
}

// prepareSecurityRules prepares and filters security rules based on configuration
func prepareSecurityRules(c *cli.Context, cfg *config.Config, platform string) ([]rules.Rule, error) {
	var standardRules []rules.Rule

	if c.Bool("no-default-rules") {
		standardRules = []rules.Rule{}
	} else {
		switch platform {
		case constants.PlatformGitHub:
			standardRules = rules.StandardRules()
		case constants.PlatformGitLab:
			// Combine standard rules with GitLab-specific rules
			standardRules = append(rules.StandardRules(), gitlab.GitLabRules()...)
		default:
			standardRules = rules.StandardRules()
		}
	}

	// Filter rules based on configuration
	filteredRules := []rules.Rule{}
	for _, rule := range standardRules {
		if cfg.IsRuleEnabled(rule.ID) {
			filteredRules = append(filteredRules, rule)
		}
	}

	return filteredRules, nil
}

// runAnalysis executes all analysis steps on the workflow files using concurrent processing
func runAnalysis(c *cli.Context, workflowFiles []parser.WorkflowFile, standardRules []rules.Rule, policyEngine *policies.PolicyEngine, cfg *config.Config, repoURL string) ([]rules.Finding, error) {
	// Create concurrent processor configuration
	processorConfig := &concurrent.ProcessorConfig{
		MaxWorkers:      c.Int("max-workers"),
		WorkflowTimeout: time.Duration(c.Int("workflow-timeout")) * time.Second,
		TotalTimeout:    time.Duration(c.Int("total-timeout")) * time.Second,
		ShowProgress:    !c.Bool("no-progress"),
		BufferSize:      100,
	}

	// Create processor
	processor := concurrent.NewConcurrentProcessor(processorConfig)

	// Create context for cancellation
	ctx := context.Background()

	// Process workflows concurrently
	findings, err := processor.ProcessWorkflows(ctx, workflowFiles, standardRules, policyEngine, cfg)
	if err != nil {
		return nil, err
	}

	// Enhance findings with GitHub URLs if scanning a remote repository
	if repoURL != "" && github.IsGitHubRepository(repoURL) {
		for i := range findings {
			findings[i].GitHubURL = github.GenerateFileURL(repoURL, findings[i].FilePath, findings[i].LineNumber)
		}
	}

	return findings, nil
}

// processAndGenerateReport filters findings, generates reports, and prints summary
func processAndGenerateReport(allFindings []rules.Finding, cfg *config.Config, outputFormat, outputFile string, startTime time.Time, workflowsCount, rulesCount int, repoLocalPath string) error {
	// Filter findings based on configuration
	filteredFindings := []rules.Finding{}
	for _, finding := range allFindings {
		// Check if finding should be ignored based on configuration
		if cfg.ShouldIgnoreForRule(finding.RuleID, finding.Evidence, finding.FilePath) {
			continue
		}

		// Check minimum severity
		if !shouldIncludeSeverity(string(finding.Severity), cfg.Output.MinSeverity) {
			continue
		}

		filteredFindings = append(filteredFindings, finding)
	}

	// Sort findings by severity
	sortedFindings := report.SortFindingsBySeverity(filteredFindings)

	// Calculate summary
	summary := report.CalculateSummary(sortedFindings)

	// Create scan result
	result := report.ScanResult{
		Repository:     repoLocalPath,
		ScanTime:       startTime,
		Duration:       time.Since(startTime),
		WorkflowsCount: workflowsCount,
		RulesCount:     rulesCount,
		Findings:       sortedFindings,
		Summary:        summary,
	}

	// Use configuration for output format and file
	actualOutputFormat := cfg.Output.Format
	actualOutputFile := cfg.Output.File

	// CLI overrides config
	if outputFormat != constants.DefaultOutputFormat {
		actualOutputFormat = outputFormat
	}
	if outputFile != "" {
		actualOutputFile = outputFile
	}

	// Generate report
	timestamp := time.Now().Format("20060102-150405")

	if actualOutputFormat == constants.OutputFormatJSON || actualOutputFormat == constants.OutputFormatMarkdown {
		fileExt := "." + actualOutputFormat
		if actualOutputFile == "" {
			actualOutputFile = "flowlyt-report-" + timestamp + fileExt
		}
	}

	reportGenerator := report.NewGenerator(result, actualOutputFormat, false, actualOutputFile)
	if err := reportGenerator.Generate(); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	// Print scan completion message
	fmt.Printf("\n✅ Scan completed in %s\n", time.Since(startTime).Round(time.Millisecond))
	fmt.Printf("Found %d issues (%d Critical, %d High, %d Medium, %d Low, %d Info)\n",
		summary.Total, summary.Critical, summary.High, summary.Medium, summary.Low, summary.Info)

	return nil
}

// validateInputs validates all user inputs before processing
func validateInputs(c *cli.Context, validator *validation.Validator, outputFormat, outputFile string) error {
	// Validate configuration path
	if err := validator.ValidateConfig(c.String("config")); err != nil {
		return err
	}

	// Validate platform
	if err := validator.ValidatePlatform(c.String("platform")); err != nil {
		return err
	}

	// Validate repository path
	if err := validator.ValidateRepository(c.String("repo")); err != nil {
		return err
	}

	// Validate repository URL
	if err := validator.ValidateURL(c.String("url")); err != nil {
		return err
	}

	// Validate workflow file
	if err := validator.ValidateWorkflowFile(c.String("workflow")); err != nil {
		return err
	}

	// Validate output format
	if err := validator.ValidateOutputFormat(outputFormat); err != nil {
		return err
	}

	// Validate output file
	if err := validator.ValidateOutputFile(outputFile); err != nil {
		return err
	}

	// Validate severity level
	if err := validator.ValidateSeverity(c.String("min-severity")); err != nil {
		return err
	}

	// Validate entropy threshold
	if err := validator.ValidateEntropyThreshold(c.Float64("entropy-threshold")); err != nil {
		return err
	}

	// Validate that at least one input source is specified
	repoPath := c.String("repo")
	repoURL := c.String("url")
	workflowFile := c.String("workflow")

	if repoPath == "" && repoURL == "" && workflowFile == "" {
		return errors.ErrNoInputSpecified()
	}

	// Validate that only one input source is specified
	inputCount := 0
	if repoPath != "" {
		inputCount++
	}
	if repoURL != "" {
		inputCount++
	}
	if workflowFile != "" {
		inputCount++
	}

	if inputCount > 1 {
		return errors.NewValidationError("Multiple input sources specified", "input", nil,
			"Specify only one of --repo, --url, or --workflow",
			"Use --repo for local repositories, --url for remote repositories, or --workflow for single files",
		)
	}

	return nil
}

func scan(c *cli.Context, outputFormat, outputFile string) error {
	startTime := time.Now()

	// Initialize validator and validate all inputs
	validator := validation.NewValidator()
	if err := validateInputs(c, validator, outputFormat, outputFile); err != nil {
		return err
	}

	// Load and override configuration
	cfg, err := loadAndOverrideConfig(c, outputFormat, outputFile)
	if err != nil {
		return err
	}

	// Get the repository path, URL, or workflow file
	repoPath := c.String("repo")
	repoURL := c.String("url")
	workflowFile := c.String("workflow")

	if repoPath == "" && repoURL == "" && workflowFile == "" {
		return errors.ErrNoInputSpecified()
	}

	// Get platform from CLI
	platform := c.String("platform")

	fmt.Printf("🔍 Flowlyt - Multi-Platform CI/CD Security Analyzer\n")
	fmt.Printf("Platform: %s\n", strings.ToUpper(platform))
	fmt.Println("=======================================")

	// Handle repository acquisition
	repoLocalPath, cleanup, err := acquireRepository(c, repoURL, repoPath, platform)
	if err != nil {
		return err
	}
	if cleanup != nil {
		defer cleanup()
	}

	// Find workflow files based on platform
	workflowFiles, err := findWorkflowFiles(workflowFile, repoLocalPath, platform)
	if err != nil {
		return err
	}

	fmt.Printf("Found %d workflow files.\n", len(workflowFiles))

	// Analyze workflows
	var allFindings []rules.Finding

	// Get standard security rules based on platform
	standardRules, err := prepareSecurityRules(c, cfg, platform)
	if err != nil {
		return err
	}

	// Load custom policies if specified
	var policyEngine *policies.PolicyEngine
	if policyPath := c.String("policy"); policyPath != "" {
		policyFiles, err := policies.LoadPolicyFiles(policyPath)
		if err != nil {
			return fmt.Errorf("failed to load policy files: %w", err)
		}

		fmt.Printf("Loaded %d policy files.\n", len(policyFiles))
		policyEngine = policies.NewPolicyEngine(policyFiles)
	}

	// Run analysis on all workflows
	allFindings, err = runAnalysis(c, workflowFiles, standardRules, policyEngine, cfg, repoURL)
	if err != nil {
		return err
	}

	// Process results and generate report
	return processAndGenerateReport(allFindings, cfg, outputFormat, outputFile, startTime, len(workflowFiles), len(standardRules), repoLocalPath)
}

// shouldIncludeSeverity checks if a finding should be included based on minimum severity
func shouldIncludeSeverity(findingSeverity, minSeverity string) bool {
	findingLevel, ok := constants.SeverityLevels[findingSeverity]
	if !ok {
		return true // Include if severity is unknown
	}

	minLevel, ok := constants.SeverityLevels[minSeverity]
	if !ok {
		return true // Include if min severity is unknown
	}

	return findingLevel >= minLevel
}

// analyzeOrganization analyzes all repositories in a GitHub organization
func analyzeOrganization(c *cli.Context, outputFormat, outputFile string) error {
	// Initialize validator and validate inputs
	validator := validation.NewValidator()

	// Validate organization name
	orgName := c.String("organization")
	if orgName == "" {
		return fmt.Errorf("organization name is required")
	}

	// Validate other inputs
	if err := validator.ValidateOutputFormat(outputFormat); err != nil {
		return err
	}

	if err := validator.ValidateOutputFile(outputFile); err != nil {
		return err
	}

	// Load configuration
	cfg, err := loadAndOverrideConfig(c, outputFormat, outputFile)
	if err != nil {
		return err
	}

	// Initialize GitHub client
	client := github.NewClient()

	// Create organization analyzer
	analyzer := organization.NewAnalyzer(
		client,
		cfg,
		c.Int("max-workers"),
		!c.Bool("no-progress"),
	)

	// Create repository filter
	repoFilter := organization.RepositoryFilter{
		IncludeForks:    c.Bool("include-forks"),
		IncludeArchived: c.Bool("include-archived"),
		IncludePrivate:  c.Bool("include-private"),
		IncludePublic:   c.Bool("include-public"),
		MaxRepos:        c.Int("max-repos"),
		NameFilter:      c.String("repo-filter"),
	}

	// Analyze the organization
	ctx := context.Background()
	orgResult, err := analyzer.AnalyzeOrganization(ctx, orgName, repoFilter)
	if err != nil {
		return fmt.Errorf("failed to analyze organization: %w", err)
	}

	// Generate report
	return generateOrganizationReport(orgResult, outputFormat, outputFile, c.Bool("summary-only"))
}

// generateOrganizationReport creates and outputs the organization analysis report
func generateOrganizationReport(result *organization.OrganizationResult, outputFormat, outputFile string, summaryOnly bool) error {
	// TODO: Implement proper organization reporting
	// For now, just print basic information

	fmt.Printf("\n🏢 Organization Analysis Report: %s\n", result.Organization)
	fmt.Printf("📊 Scan completed in: %v\n", result.Duration)
	fmt.Printf("📦 Repositories analyzed: %d/%d\n", result.AnalyzedRepositories, result.TotalRepositories)

	if result.SkippedRepositories > 0 {
		fmt.Printf("⚠️  Repositories skipped: %d\n", result.SkippedRepositories)
	}

	// Print summary statistics
	fmt.Printf("\n📈 Summary:\n")
	fmt.Printf("  Total findings: %d\n", result.Summary.TotalFindings)

	if len(result.Summary.FindingsBySeverity) > 0 {
		fmt.Printf("  Findings by severity:\n")
		for severity, count := range result.Summary.FindingsBySeverity {
			fmt.Printf("    %s: %d\n", severity, count)
		}
	}

	if len(result.Summary.RepositoriesByRisk) > 0 {
		fmt.Printf("  Repositories by risk:\n")
		for risk, count := range result.Summary.RepositoriesByRisk {
			fmt.Printf("    %s: %d\n", risk, count)
		}
	}

	// Show individual repository results if not summary-only
	if !summaryOnly && len(result.RepositoryResults) > 0 {
		fmt.Printf("\n📋 Repository Details:\n")
		for _, repoResult := range result.RepositoryResults {
			if repoResult.Error != nil {
				fmt.Printf("  ❌ %s: %v\n", repoResult.Repository.FullName, repoResult.Error)
			} else {
				fmt.Printf("  ✅ %s: %d findings (%v)\n",
					repoResult.Repository.FullName,
					len(repoResult.Findings),
					repoResult.Duration)
			}
		}
	}

	fmt.Printf("\n✨ Organization analysis complete!\n")
	return nil
}
