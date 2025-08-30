package engine

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/opa"
	"github.com/harekrishnarai/flowlyt/pkg/parser"
	"github.com/harekrishnarai/flowlyt/pkg/platform"
	"github.com/harekrishnarai/flowlyt/pkg/platform/github"
	"github.com/harekrishnarai/flowlyt/pkg/platform/gitlab"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

// HybridEngine combines Go-native rules with OPA policies
type HybridEngine struct {
	platformRegistry *platform.PlatformRegistry
	goRuleEngine     *rules.RuleEngine
	opaEngine        *opa.Engine
	config           Config
}

// Config defines configuration for the hybrid engine
type Config struct {
	EnableGoRules   bool            `json:"enable_go_rules"`
	EnableOPARules  bool            `json:"enable_opa_rules"`
	GoRulesConfig   GoRulesConfig   `json:"go_rules_config"`
	OPARulesConfig  OPARulesConfig  `json:"opa_rules_config"`
	PlatformConfig  PlatformConfig  `json:"platform_config"`
	ReportingConfig ReportingConfig `json:"reporting_config"`
}

// GoRulesConfig configures Go-based rule execution
type GoRulesConfig struct {
	EnabledCategories []rules.Category `json:"enabled_categories"`
	DisabledRules     []string         `json:"disabled_rules"`
	CustomRules       []string         `json:"custom_rules"`
	PerformanceMode   bool             `json:"performance_mode"`
}

// OPARulesConfig configures OPA policy execution
type OPARulesConfig struct {
	PolicyPaths    []string `json:"policy_paths"`
	CustomPolicies []string `json:"custom_policies"`
	StrictMode     bool     `json:"strict_mode"`
}

// PlatformConfig configures platform support
type PlatformConfig struct {
	AutoDetect         bool     `json:"auto_detect"`
	SupportedPlatforms []string `json:"supported_platforms"`
	PreferredPlatform  string   `json:"preferred_platform"`
}

// ReportingConfig configures output and reporting
type ReportingConfig struct {
	Format          string `json:"format"`
	IncludeMetadata bool   `json:"include_metadata"`
	Verbose         bool   `json:"verbose"`
}

// AnalysisResult represents the combined analysis results
type AnalysisResult struct {
	Workflows        []*platform.Workflow `json:"workflows"`
	GoFindings       []rules.Finding      `json:"go_findings"`
	OPAFindings      []opa.Finding        `json:"opa_findings"`
	CombinedFindings []rules.Finding      `json:"combined_findings"`
	Statistics       Statistics           `json:"statistics"`
	Performance      PerformanceMetrics   `json:"performance"`
}

// Statistics provides analysis statistics
type Statistics struct {
	TotalWorkflows      int                    `json:"total_workflows"`
	PlatformBreakdown   map[string]int         `json:"platform_breakdown"`
	FindingsByCategory  map[rules.Category]int `json:"findings_by_category"`
	FindingsBySeverity  map[rules.Severity]int `json:"findings_by_severity"`
	GoRulesExecuted     int                    `json:"go_rules_executed"`
	OPAPoliciesExecuted int                    `json:"opa_policies_executed"`
}

// PerformanceMetrics tracks execution performance
type PerformanceMetrics struct {
	TotalExecutionTimeMs int64 `json:"total_execution_time_ms"`
	GoRulesTimeMs        int64 `json:"go_rules_time_ms"`
	OPATimeMs            int64 `json:"opa_time_ms"`
	PlatformDetectionMs  int64 `json:"platform_detection_ms"`
	WorkflowParsingMs    int64 `json:"workflow_parsing_ms"`
}

// NewHybridEngine creates a new hybrid engine
func NewHybridEngine(config Config) (*HybridEngine, error) {
	// Initialize platform registry
	registry := platform.NewPlatformRegistry()

	// Register supported platforms
	registry.Register(github.NewGitHubPlatform())
	registry.Register(gitlab.NewGitLabPlatform())

	// Initialize Go rule engine
	var goEngine *rules.RuleEngine
	if config.EnableGoRules {
		// This would normally use a config interface
		goEngine = rules.NewRuleEngine(nil) // For now, nil config
	}

	// Initialize OPA engine
	var opaEngine *opa.Engine
	if config.EnableOPARules {
		opaEngine = opa.NewEngine()

		// Load built-in policies
		if err := opaEngine.LoadPolicyFromFile(""); err != nil {
			return nil, fmt.Errorf("failed to load OPA policies: %w", err)
		}
	}

	return &HybridEngine{
		platformRegistry: registry,
		goRuleEngine:     goEngine,
		opaEngine:        opaEngine,
		config:           config,
	}, nil
}

// AnalyzeRepository analyzes a repository with both Go rules and OPA policies
func (he *HybridEngine) AnalyzeRepository(repoPath string) (*AnalysisResult, error) {
	result := &AnalysisResult{
		Statistics:  Statistics{PlatformBreakdown: make(map[string]int), FindingsByCategory: make(map[rules.Category]int), FindingsBySeverity: make(map[rules.Severity]int)},
		Performance: PerformanceMetrics{},
	}

	// Try each platform to find workflows
	var allWorkflows []*platform.Workflow

	for _, platformName := range he.platformRegistry.List() {
		platform, err := he.platformRegistry.Get(platformName)
		if err != nil {
			continue
		}

		workflowPaths, err := platform.DetectWorkflows(repoPath)
		if err != nil {
			continue // No workflows for this platform
		}

		// Parse workflows for this platform
		for _, workflowPath := range workflowPaths {
			workflow, err := platform.ParseWorkflow(workflowPath)
			if err != nil {
				continue // Skip invalid workflows
			}
			allWorkflows = append(allWorkflows, workflow)
			result.Statistics.PlatformBreakdown[workflow.Platform]++
		}
	}

	result.Workflows = allWorkflows
	result.Statistics.TotalWorkflows = len(result.Workflows)

	// Analyze with Go rules
	if he.config.EnableGoRules && he.goRuleEngine != nil {
		for _, workflow := range result.Workflows {
			goFindings := he.analyzeWithGoRules(workflow)
			result.GoFindings = append(result.GoFindings, goFindings...)
		}
	}

	// Analyze with OPA policies
	if he.config.EnableOPARules && he.opaEngine != nil {
		for _, workflow := range result.Workflows {
			opaFindings, err := he.opaEngine.EvaluateWorkflow(workflow)
			if err != nil {
				continue // Skip failed evaluations
			}
			result.OPAFindings = append(result.OPAFindings, opaFindings...)
		}
	}

	// Combine findings
	result.CombinedFindings = append(result.CombinedFindings, result.GoFindings...)
	for _, opaFinding := range result.OPAFindings {
		result.CombinedFindings = append(result.CombinedFindings, opaFinding.ToRulesFinding())
	}

	// Update statistics
	he.updateStatistics(&result.Statistics, result.CombinedFindings)

	return result, nil
}

// AnalyzeWorkflow analyzes a single workflow file
func (he *HybridEngine) AnalyzeWorkflow(workflowPath string) (*AnalysisResult, error) {
	result := &AnalysisResult{
		Statistics:  Statistics{PlatformBreakdown: make(map[string]int), FindingsByCategory: make(map[rules.Category]int), FindingsBySeverity: make(map[rules.Severity]int)},
		Performance: PerformanceMetrics{},
	}

	// Detect platform based on file path/name
	platformName := he.detectPlatformFromPath(workflowPath)
	detectedPlatform, err := he.platformRegistry.Get(platformName)
	if err != nil {
		return nil, fmt.Errorf("unsupported platform for workflow %s: %w", workflowPath, err)
	}

	// Parse workflow
	workflow, err := detectedPlatform.ParseWorkflow(workflowPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse workflow: %w", err)
	}

	result.Workflows = []*platform.Workflow{workflow}
	result.Statistics.TotalWorkflows = 1
	result.Statistics.PlatformBreakdown[workflow.Platform] = 1

	// Analyze with Go rules
	if he.config.EnableGoRules && he.goRuleEngine != nil {
		goFindings := he.analyzeWithGoRules(workflow)
		result.GoFindings = goFindings
	}

	// Analyze with OPA policies
	if he.config.EnableOPARules && he.opaEngine != nil {
		opaFindings, err := he.opaEngine.EvaluateWorkflow(workflow)
		if err == nil {
			result.OPAFindings = opaFindings
		}
	}

	// Combine findings
	result.CombinedFindings = append(result.CombinedFindings, result.GoFindings...)
	for _, opaFinding := range result.OPAFindings {
		result.CombinedFindings = append(result.CombinedFindings, opaFinding.ToRulesFinding())
	}

	// Update statistics
	he.updateStatistics(&result.Statistics, result.CombinedFindings)

	return result, nil
}

// analyzeWithGoRules analyzes a workflow using Go-based rules
func (he *HybridEngine) analyzeWithGoRules(workflow *platform.Workflow) []rules.Finding {
	// Convert platform.Workflow to parser.WorkflowFile for compatibility
	// This is a bridge until we fully migrate to the new architecture
	workflowFile := he.convertToLegacyWorkflow(workflow)

	// Get standard rules
	standardRules := rules.StandardRules()

	// Execute rules
	if he.goRuleEngine != nil {
		return he.goRuleEngine.ExecuteRules(workflowFile, standardRules)
	}

	// Fallback: direct execution without config
	var allFindings []rules.Finding
	for _, rule := range standardRules {
		findings := rule.Check(workflowFile)
		allFindings = append(allFindings, findings...)
	}

	return allFindings
}

// convertToLegacyWorkflow converts new platform.Workflow to legacy parser.WorkflowFile
func (he *HybridEngine) convertToLegacyWorkflow(workflow *platform.Workflow) parser.WorkflowFile {
	// This is a temporary bridge - we'll eventually migrate all rules to use platform.Workflow
	return parser.WorkflowFile{
		Path:    workflow.FilePath,
		Name:    workflow.Name,
		Content: workflow.Content,
		// For now, we'll need to implement conversion logic based on platform
	}
}

// detectPlatformFromPath detects platform based on workflow file path
func (he *HybridEngine) detectPlatformFromPath(workflowPath string) string {
	path := strings.ToLower(workflowPath)

	if strings.Contains(path, ".github/workflows") {
		return "github-actions"
	}

	if strings.Contains(path, ".gitlab-ci.yml") || strings.Contains(path, ".gitlab-ci.yaml") {
		return "gitlab-ci"
	}

	// Check file extension and name patterns
	fileName := filepath.Base(path)
	if strings.HasPrefix(fileName, ".gitlab-ci") {
		return "gitlab-ci"
	}

	// Default to GitHub Actions for YAML files in workflows directory
	if strings.HasSuffix(fileName, ".yml") || strings.HasSuffix(fileName, ".yaml") {
		return "github-actions"
	}

	return "github-actions" // Default fallback
}

// updateStatistics updates analysis statistics
func (he *HybridEngine) updateStatistics(stats *Statistics, findings []rules.Finding) {
	for _, finding := range findings {
		stats.FindingsByCategory[finding.Category]++
		stats.FindingsBySeverity[finding.Severity]++
	}
}

// GetSupportedPlatforms returns list of supported platforms
func (he *HybridEngine) GetSupportedPlatforms() []string {
	return he.platformRegistry.List()
}

// GetGoRules returns available Go rules
func (he *HybridEngine) GetGoRules() []rules.Rule {
	return rules.StandardRules()
}

// GetOPAPolicies returns loaded OPA policies
func (he *HybridEngine) GetOPAPolicies() map[string]*opa.Policy {
	if he.opaEngine != nil {
		return he.opaEngine.GetPolicies()
	}
	return make(map[string]*opa.Policy)
}

// DefaultConfig returns a default configuration
func DefaultConfig() Config {
	return Config{
		EnableGoRules:  true,
		EnableOPARules: true,
		GoRulesConfig: GoRulesConfig{
			EnabledCategories: []rules.Category{
				rules.MaliciousPattern,
				rules.SecretExposure,
				rules.SupplyChain,
				rules.InjectionAttack,
				rules.PrivilegeEscalation,
			},
			PerformanceMode: false,
		},
		OPARulesConfig: OPARulesConfig{
			StrictMode: false,
		},
		PlatformConfig: PlatformConfig{
			AutoDetect:         true,
			SupportedPlatforms: []string{"github-actions", "gitlab-ci"},
		},
		ReportingConfig: ReportingConfig{
			Format:          "json",
			IncludeMetadata: true,
			Verbose:         false,
		},
	}
}
