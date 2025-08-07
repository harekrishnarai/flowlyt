package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/harekrishnarai/flowlyt/pkg/config"
	"github.com/harekrishnarai/flowlyt/pkg/github"
	"github.com/harekrishnarai/flowlyt/pkg/gitlab"
	"github.com/harekrishnarai/flowlyt/pkg/parser"
	"github.com/harekrishnarai/flowlyt/pkg/policies"
	"github.com/harekrishnarai/flowlyt/pkg/report"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
	"github.com/harekrishnarai/flowlyt/pkg/shell"
	"github.com/urfave/cli/v2"
)

var version = "0.0.2"

func main() {
	outputFormat := "cli"
	outputFile := ""
	// Parse -o flag
	for i, arg := range os.Args {
		if arg == "-o" && i+1 < len(os.Args) {
			outputFormat = strings.ToLower(os.Args[i+1])
		}
	}

	app := &cli.App{
		Name:    "flowlyt",
		Version: version,
		Usage:   "Multi-Platform CI/CD Security Analyzer",
		Authors: []*cli.Author{
			{
				Name: "Flowlyt Team",
			},
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "platform",
				Aliases: []string{"pl"},
				Usage:   "CI/CD platform (github, gitlab, jenkins, azure)",
				Value:   "github",
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
				Name:  "gitlab-instance",
				Usage: "GitLab instance URL for on-premise GitLab (e.g., https://gitlab.company.com)",
			},
			&cli.StringFlag{
				Name:    "workflow",
				Aliases: []string{"w"},
				Usage:   "Path to a single workflow file to scan",
			},
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "Output format (cli, json, markdown)",
				Value:   "cli",
			},
			&cli.StringFlag{
				Name:    "output-file",
				Aliases: []string{"f"},
				Usage:   "Output file path (if not specified, prints to stdout)",
			},
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "Configuration file path (.flowlyt.yml)",
			},
			&cli.StringFlag{
				Name:    "policy",
				Aliases: []string{"p"},
				Usage:   "Custom policy file or directory",
			},
			&cli.BoolFlag{
				Name:  "no-default-rules",
				Usage: "Disable default security rules",
				Value: false,
			},
			&cli.StringSliceFlag{
				Name:    "enable-rules",
				Aliases: []string{"enable"},
				Usage:   "Enable specific rules (comma-separated)",
			},
			&cli.StringSliceFlag{
				Name:    "disable-rules",
				Aliases: []string{"disable"},
				Usage:   "Disable specific rules (comma-separated)",
			},
			&cli.StringFlag{
				Name:  "min-severity",
				Usage: "Minimum severity level to report (CRITICAL, HIGH, MEDIUM, LOW, INFO)",
				Value: "LOW",
			},
			&cli.Float64Flag{
				Name:  "entropy-threshold",
				Usage: "Entropy threshold for secret detection",
				Value: 4.5,
			},
			&cli.StringFlag{
				Name:  "temp-dir",
				Usage: "Temporary directory for repository clone",
			},
		},
		Action: func(c *cli.Context) error {
			return scan(c, outputFormat, outputFile)
		},
		Commands: []*cli.Command{
			{
				Name:  "init-policy",
				Usage: "Create an example policy file",
				Action: func(c *cli.Context) error {
					outputPath := c.Args().First()
					if outputPath == "" {
						outputPath = "policies/example.rego"
					}

					fmt.Printf("Creating example policy file at %s...\n", outputPath)
					if err := policies.CreateExamplePolicy(outputPath); err != nil {
						return fmt.Errorf("failed to create example policy: %w", err)
					}

					fmt.Println("Example policy file created successfully!")
					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func scan(c *cli.Context, outputFormat, outputFile string) error {
	startTime := time.Now()

	// Load configuration
	configPath := c.String("config")
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Override config with CLI flags
	if c.String("min-severity") != "LOW" {
		cfg.Output.MinSeverity = c.String("min-severity")
	}
	if c.String("output") != "cli" {
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

	// Get the repository path, URL, or workflow file
	repoPath := c.String("repo")
	repoURL := c.String("url")
	workflowFile := c.String("workflow")

	if repoPath == "" && repoURL == "" && workflowFile == "" {
		return fmt.Errorf("either --repo, --url, or --workflow must be specified")
	}

	// Get platform from CLI
	platform := c.String("platform")

	fmt.Printf("🔍 Flowlyt - Multi-Platform CI/CD Security Analyzer\n")
	fmt.Printf("Platform: %s\n", strings.ToUpper(platform))
	fmt.Println("=======================================")
	// Handle repository acquisition if URL is provided
	var repoLocalPath string

	if repoURL != "" {
		fmt.Printf("Cloning repository from %s...\n", repoURL)

		// Auto-detect platform from URL if not explicitly specified
		if platform == "github" && c.String("platform") == "github" {
			// Check if URL is actually GitLab
			if gitlab.IsGitLabURL(repoURL) {
				platform = "gitlab"
				fmt.Printf("Auto-detected GitLab repository, switching to GitLab platform\n")
			}
		}

		switch platform {
		case "github":
			client := github.NewClient()
			tempDir := c.String("temp-dir")
			var err error
			repoLocalPath, err = client.CloneRepository(repoURL, tempDir)
			if err != nil {
				return fmt.Errorf("failed to clone GitHub repository: %w", err)
			}

		case "gitlab":
			gitlabInstance := c.String("gitlab-instance")
			client, err := gitlab.NewClient(gitlabInstance)
			if err != nil {
				return fmt.Errorf("failed to create GitLab client: %w", err)
			}

			tempDir := c.String("temp-dir")
			repoLocalPath, err = client.CloneRepository(repoURL, tempDir)
			if err != nil {
				return fmt.Errorf("failed to clone GitLab repository: %w", err)
			}

		default:
			return fmt.Errorf("repository cloning from URL is not supported for platform: %s", platform)
		}

		// Clean up temporary directory if we created one (when no temp-dir was specified)
		tempDirFlag := c.String("temp-dir")
		if tempDirFlag == "" {
			defer func() {
				fmt.Printf("Cleaning up temporary directory %s...\n", repoLocalPath)
				os.RemoveAll(repoLocalPath)
			}()
		}
	} else if repoPath != "" {
		repoLocalPath = repoPath
	}

	// Find workflow files based on platform
	var workflowFiles []parser.WorkflowFile

	if workflowFile != "" {
		fmt.Printf("Scanning single workflow file %s...\n", workflowFile)
		workflowFiles, err = parser.LoadSingleWorkflow(workflowFile)
		if err != nil {
			return fmt.Errorf("failed to load workflow file: %w", err)
		}
	} else {
		switch platform {
		case "github":
			fmt.Printf("Scanning GitHub Actions workflows in %s...\n", repoLocalPath)
			workflowFiles, err = parser.FindWorkflows(repoLocalPath)
		case "gitlab":
			fmt.Printf("Scanning GitLab CI/CD pipelines in %s...\n", repoLocalPath)
			workflowFiles, err = gitlab.FindGitLabWorkflows(repoLocalPath)
		default:
			return fmt.Errorf("unsupported platform: %s. Supported platforms: github, gitlab", platform)
		}

		if err != nil {
			return fmt.Errorf("failed to find workflow files: %w", err)
		}
	}

	fmt.Printf("Found %d workflow files.\n", len(workflowFiles))

	// Analyze workflows
	var allFindings []rules.Finding

	// Get standard security rules based on platform
	var standardRules []rules.Rule
	if c.Bool("no-default-rules") {
		standardRules = []rules.Rule{}
	} else {
		switch platform {
		case "github":
			standardRules = rules.StandardRules()
		case "gitlab":
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
	standardRules = filteredRules

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

	// Initialize shell analyzer
	shellAnalyzer := shell.NewAnalyzer()

	// Analyze each workflow
	for _, workflow := range workflowFiles {
		fmt.Printf("Analyzing %s...\n", workflow.Name)

		// Apply standard rules
		for _, rule := range standardRules {
			findings := rule.Check(workflow)
			allFindings = append(allFindings, findings...)
		}

		// Apply shell analysis (only if rules are enabled)
		shellFindings := shellAnalyzer.Analyze(workflow)
		for _, finding := range shellFindings {
			if cfg.IsRuleEnabled(finding.RuleID) {
				allFindings = append(allFindings, finding)
			}
		}

		// Apply policy engine if configured
		if policyEngine != nil {
			policyFindings, err := policyEngine.EvaluateWorkflow(workflow)
			if err != nil {
				fmt.Printf("Warning: policy evaluation error for %s: %v\n", workflow.Name, err)
			} else {
				// Filter policy findings by enabled rules
				for _, finding := range policyFindings {
					if cfg.IsRuleEnabled(finding.RuleID) {
						allFindings = append(allFindings, finding)
					}
				}
			}
		}
	}

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
		WorkflowsCount: len(workflowFiles),
		RulesCount:     len(standardRules),
		Findings:       sortedFindings,
		Summary:        summary,
	}

	// Use configuration for output format and file
	actualOutputFormat := cfg.Output.Format
	actualOutputFile := cfg.Output.File

	// CLI overrides config
	if outputFormat != "cli" {
		actualOutputFormat = outputFormat
	}
	if outputFile != "" {
		actualOutputFile = outputFile
	}

	// Generate report
	timestamp := time.Now().Format("20060102-150405")

	if actualOutputFormat == "json" || actualOutputFormat == "markdown" {
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

// shouldIncludeSeverity checks if a finding should be included based on minimum severity
func shouldIncludeSeverity(findingSeverity, minSeverity string) bool {
	severityLevels := map[string]int{
		"INFO":     0,
		"LOW":      1,
		"MEDIUM":   2,
		"HIGH":     3,
		"CRITICAL": 4,
	}

	findingLevel, ok := severityLevels[findingSeverity]
	if !ok {
		return true // Include if severity is unknown
	}

	minLevel, ok := severityLevels[minSeverity]
	if !ok {
		return true // Include if min severity is unknown
	}

	return findingLevel >= minLevel
}
