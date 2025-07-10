package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/harekrishnarai/flowlyt/pkg/github"
	"github.com/harekrishnarai/flowlyt/pkg/parser"
	"github.com/harekrishnarai/flowlyt/pkg/policies"
	"github.com/harekrishnarai/flowlyt/pkg/report"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
	"github.com/harekrishnarai/flowlyt/pkg/secrets"
	"github.com/harekrishnarai/flowlyt/pkg/shell"
	"github.com/urfave/cli/v2"
)

var version = "2.1.0"

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
		Usage:   "GitHub Actions Workflow Security Analyzer",
		Authors: []*cli.Author{
			{
				Name: "Flowlyt Team",
			},
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "repo",
				Aliases: []string{"r"},
				Usage:   "Local repository path to scan",
			},
			&cli.StringFlag{
				Name:    "url",
				Aliases: []string{"u"},
				Usage:   "GitHub repository URL to scan",
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
				Name:    "policy",
				Aliases: []string{"p"},
				Usage:   "Custom policy file or directory",
			},
			&cli.BoolFlag{
				Name:  "no-default-rules",
				Usage: "Disable default security rules",
				Value: false,
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

	// Get the repository path, URL, or workflow file
	repoPath := c.String("repo")
	repoURL := c.String("url")
	workflowFile := c.String("workflow")

	if repoPath == "" && repoURL == "" && workflowFile == "" {
		return fmt.Errorf("either --repo, --url, or --workflow must be specified")
	}

	fmt.Println("🔍 Flowlyt - GitHub Actions Security Analyzer")
	fmt.Println("=======================================")

	// Handle repository acquisition if URL is provided
	var repoLocalPath string

	if repoURL != "" {
		fmt.Printf("Cloning repository from %s...\n", repoURL)
		client := github.NewClient()
		tempDir := c.String("temp-dir")

		var err error
		repoLocalPath, err = client.CloneRepository(repoURL, tempDir)
		if err != nil {
			return fmt.Errorf("failed to clone repository: %w", err)
		}

		// Clean up temporary directory if we created one
		if tempDir == "" {
			defer func() {
				fmt.Printf("Cleaning up temporary directory %s...\n", repoLocalPath)
				os.RemoveAll(repoLocalPath)
			}()
		}
	} else if repoPath != "" {
		repoLocalPath = repoPath
	}

	// Find workflow files
	var workflowFiles []parser.WorkflowFile
	var err error

	if workflowFile != "" {
		fmt.Printf("Scanning single workflow file %s...\n", workflowFile)
		workflowFiles, err = parser.LoadSingleWorkflow(workflowFile)
		if err != nil {
			return fmt.Errorf("failed to load workflow file: %w", err)
		}
	} else {
		fmt.Printf("Scanning GitHub Actions workflows in %s...\n", repoLocalPath)
		workflowFiles, err = parser.FindWorkflows(repoLocalPath)
		if err != nil {
			return fmt.Errorf("failed to find workflow files: %w", err)
		}
	}

	fmt.Printf("Found %d workflow files.\n", len(workflowFiles))

	// Analyze workflows
	var allFindings []rules.Finding

	// Get standard security rules
	standardRules := rules.StandardRules()
	if c.Bool("no-default-rules") {
		standardRules = []rules.Rule{}
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

	// Initialize shell analyzer
	shellAnalyzer := shell.NewAnalyzer()

	// Initialize secrets detector
	secretsDetector := secrets.NewDetector()
	if threshold := c.Float64("entropy-threshold"); threshold > 0 {
		secretsDetector.SetEntropyThreshold(threshold)
	}

	// Analyze each workflow
	for _, workflow := range workflowFiles {
		fmt.Printf("Analyzing %s...\n", workflow.Name)

		// Apply standard rules
		for _, rule := range standardRules {
			findings := rule.Check(workflow)
			allFindings = append(allFindings, findings...)
		}

		// Apply shell analysis
		shellFindings := shellAnalyzer.Analyze(workflow)
		allFindings = append(allFindings, shellFindings...)

		// Apply secrets detection
		secretFindings := secretsDetector.Detect(workflow)
		allFindings = append(allFindings, secretFindings...)

		// Apply policy engine if configured
		if policyEngine != nil {
			policyFindings, err := policyEngine.EvaluateWorkflow(workflow)
			if err != nil {
				fmt.Printf("Warning: policy evaluation error for %s: %v\n", workflow.Name, err)
			} else {
				allFindings = append(allFindings, policyFindings...)
			}
		}
	}

	// Sort findings by severity
	sortedFindings := report.SortFindingsBySeverity(allFindings)

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

	// Generate report
	timestamp := time.Now().Format("20060102-150405")

	if outputFormat == "json" || outputFormat == "markdown" {
		fileExt := "." + outputFormat
		if outputFile == "" {
			outputFile = "flowlyt-report-" + timestamp + fileExt
		}
	}

	reportGenerator := report.NewGenerator(result, outputFormat, false, outputFile)
	if err := reportGenerator.Generate(); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	// Print scan completion message
	fmt.Printf("\n✅ Scan completed in %s\n", time.Since(startTime).Round(time.Millisecond))
	fmt.Printf("Found %d issues (%d Critical, %d High, %d Medium, %d Low, %d Info)\n",
		summary.Total, summary.Critical, summary.High, summary.Medium, summary.Low, summary.Info)

	return nil
}
