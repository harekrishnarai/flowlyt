package organization

import (
	"context"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/harekrishnarai/flowlyt/pkg/config"
	"github.com/harekrishnarai/flowlyt/pkg/github"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

// RepositoryFilter defines criteria for filtering repositories during organization analysis
type RepositoryFilter struct {
	IncludeForks    bool   // Include forked repositories
	IncludeArchived bool   // Include archived repositories
	IncludePrivate  bool   // Include private repositories
	IncludePublic   bool   // Include public repositories
	MaxRepos        int    // Maximum number of repositories to analyze (0 = no limit)
	NameFilter      string // Regular expression to filter repository names
}

// RepositoryResult represents the analysis result for a single repository
type RepositoryResult struct {
	Repository   github.RepositoryInfo `json:"repository"`
	Findings     []rules.Finding       `json:"findings"`
	WorkflowsCount int                 `json:"workflows_count"`
	RulesCount   int                   `json:"rules_count"`
	Duration     time.Duration         `json:"duration"`
	Error        error                 `json:"error,omitempty"`
}

// OrganizationResult represents the analysis result for an entire organization
type OrganizationResult struct {
	Organization     string             `json:"organization"`
	ScanTime         time.Time          `json:"scan_time"`
	Duration         time.Duration      `json:"duration"`
	TotalRepositories int               `json:"total_repositories"`
	AnalyzedRepositories int           `json:"analyzed_repositories"`
	SkippedRepositories  int           `json:"skipped_repositories"`
	RepositoryResults []RepositoryResult `json:"repository_results"`
	Summary          OrganizationSummary `json:"summary"`
}

// OrganizationSummary provides aggregated statistics for an organization
type OrganizationSummary struct {
	TotalFindings     int                    `json:"total_findings"`
	FindingsBySeverity map[string]int        `json:"findings_by_severity"`
	FindingsByCategory map[string]int        `json:"findings_by_category"`
	RepositoriesByRisk map[string]int        `json:"repositories_by_risk"`
	TopFindings       []TopFinding          `json:"top_findings"`
	RiskDistribution  []RepositoryRiskInfo  `json:"risk_distribution"`
}

// TopFinding represents frequently occurring security issues
type TopFinding struct {
	RuleID       string `json:"rule_id"`
	RuleName     string `json:"rule_name"`
	Severity     string `json:"severity"`
	Count        int    `json:"count"`
	Repositories []string `json:"repositories"`
}

// RepositoryRiskInfo provides risk assessment for individual repositories
type RepositoryRiskInfo struct {
	Repository   github.RepositoryInfo `json:"repository"`
	RiskLevel    string                `json:"risk_level"`    // LOW, MEDIUM, HIGH, CRITICAL
	FindingsCount int                  `json:"findings_count"`
	CriticalCount int                  `json:"critical_count"`
	HighCount    int                   `json:"high_count"`
	Score        float64               `json:"score"`         // Risk score 0-100
}

// Analyzer handles organization-wide analysis
type Analyzer struct {
	client     *github.Client
	config     *config.Config
	maxWorkers int
	progress   bool
}

// NewAnalyzer creates a new organization analyzer
func NewAnalyzer(client *github.Client, cfg *config.Config, maxWorkers int, showProgress bool) *Analyzer {
	return &Analyzer{
		client:     client,
		config:     cfg,
		maxWorkers: maxWorkers,
		progress:   showProgress,
	}
}

// AnalyzeOrganization performs security analysis on all repositories in an organization
func (a *Analyzer) AnalyzeOrganization(ctx context.Context, orgName string, filter RepositoryFilter) (*OrganizationResult, error) {
	startTime := time.Now()
	
	// Discover repositories
	repositories, err := a.client.DiscoverOrganizationRepositories(orgName, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to discover repositories: %w", err)
	}
	
	if a.progress {
		fmt.Printf("📦 Discovered %d repositories in organization '%s'\n", len(repositories), orgName)
	}
	
	// Analyze repositories concurrently
	results := a.analyzeRepositoriesConcurrently(ctx, repositories)
	
	// Calculate summary statistics
	summary := a.calculateSummary(results)
	
	return &OrganizationResult{
		Organization:         orgName,
		ScanTime:            startTime,
		Duration:            time.Since(startTime),
		TotalRepositories:   len(repositories),
		AnalyzedRepositories: a.countAnalyzedRepositories(results),
		SkippedRepositories:  a.countSkippedRepositories(results),
		RepositoryResults:   results,
		Summary:             summary,
	}, nil
}

// analyzeRepositoriesConcurrently processes multiple repositories in parallel
func (a *Analyzer) analyzeRepositoriesConcurrently(ctx context.Context, repositories []github.RepositoryInfo) []RepositoryResult {
	// Create channels for job distribution
	jobs := make(chan github.RepositoryInfo, len(repositories))
	results := make(chan RepositoryResult, len(repositories))
	
	// Determine number of workers
	numWorkers := a.maxWorkers
	if numWorkers <= 0 {
		numWorkers = 4 // Default for organization analysis
	}
	if numWorkers > len(repositories) {
		numWorkers = len(repositories)
	}
	
	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go a.repositoryWorker(ctx, &wg, jobs, results)
	}
	
	// Send jobs
	go func() {
		defer close(jobs)
		for _, repo := range repositories {
			select {
			case jobs <- repo:
			case <-ctx.Done():
				return
			}
		}
	}()
	
	// Collect results
	var repoResults []RepositoryResult
	completed := 0
	
	for completed < len(repositories) {
		select {
		case result := <-results:
			repoResults = append(repoResults, result)
			completed++
			
			if a.progress {
				fmt.Printf("\r🔍 Analyzed repositories: %d/%d", completed, len(repositories))
				if completed == len(repositories) {
					fmt.Println() // New line when complete
				}
			}
			
		case <-ctx.Done():
			// Context cancelled, stop waiting
			return repoResults
		}
	}
	
	// Wait for all workers to finish
	wg.Wait()
	close(results)
	
	return repoResults
}

// repositoryWorker processes individual repository analysis jobs
func (a *Analyzer) repositoryWorker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan github.RepositoryInfo, results chan<- RepositoryResult) {
	defer wg.Done()
	
	for repo := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
		}
		
		result := a.analyzeRepository(ctx, repo)
		
		select {
		case results <- result:
		case <-ctx.Done():
			return
		}
	}
}

// analyzeRepository performs security analysis on a single repository
func (a *Analyzer) analyzeRepository(ctx context.Context, repo github.RepositoryInfo) RepositoryResult {
	startTime := time.Now()
	
	result := RepositoryResult{
		Repository: repo,
		Findings:   []rules.Finding{},
		Duration:   0,
	}
	
	// Clone repository temporarily (placeholder for now)
	_, err := a.client.CloneRepository(repo.CloneURL, "")
	if err != nil {
		result.Error = fmt.Errorf("failed to clone repository: %w", err)
		result.Duration = time.Since(startTime)
		return result
	}
	
	// TODO: Implement the actual workflow analysis
	// This would involve:
	// 1. Finding workflow files in the repository
	// 2. Parsing and analyzing them
	// 3. Running security rules
	// 4. Collecting findings
	
	// For now, return empty result to avoid compilation errors
	result.Duration = time.Since(startTime)
	return result
}

// calculateSummary computes organization-level statistics
func (a *Analyzer) calculateSummary(results []RepositoryResult) OrganizationSummary {
	summary := OrganizationSummary{
		FindingsBySeverity: make(map[string]int),
		FindingsByCategory: make(map[string]int),
		RepositoriesByRisk: make(map[string]int),
		TopFindings:       []TopFinding{},
		RiskDistribution:  []RepositoryRiskInfo{},
	}
	
	findingCounts := make(map[string]map[string]int) // ruleID -> repository -> count
	
	// Process each repository result
	for _, result := range results {
		if result.Error != nil {
			continue // Skip repositories with errors
		}
		
		// Count findings by severity
		repoFindings := len(result.Findings)
		summary.TotalFindings += repoFindings
		
		criticalCount := 0
		highCount := 0
		
		for _, finding := range result.Findings {
			severity := string(finding.Severity)
			category := string(finding.Category)
			
			summary.FindingsBySeverity[severity]++
			summary.FindingsByCategory[category]++
			
			// Track finding frequencies
			if findingCounts[finding.RuleID] == nil {
				findingCounts[finding.RuleID] = make(map[string]int)
			}
			findingCounts[finding.RuleID][result.Repository.FullName]++
			
			// Count high-risk findings
			if severity == "CRITICAL" {
				criticalCount++
			} else if severity == "HIGH" {
				highCount++
			}
		}
		
		// Calculate repository risk level
		riskLevel := a.calculateRepositoryRiskLevel(repoFindings, criticalCount, highCount)
		summary.RepositoriesByRisk[riskLevel]++
		
		// Add to risk distribution
		summary.RiskDistribution = append(summary.RiskDistribution, RepositoryRiskInfo{
			Repository:    result.Repository,
			RiskLevel:     riskLevel,
			FindingsCount: repoFindings,
			CriticalCount: criticalCount,
			HighCount:     highCount,
			Score:         a.calculateRiskScore(repoFindings, criticalCount, highCount),
		})
	}
	
	// Generate top findings
	summary.TopFindings = a.generateTopFindings(findingCounts, results)
	
	return summary
}

// calculateRepositoryRiskLevel determines the risk level for a repository
func (a *Analyzer) calculateRepositoryRiskLevel(totalFindings, criticalCount, highCount int) string {
	if criticalCount > 0 {
		return "CRITICAL"
	}
	if highCount > 2 {
		return "HIGH"
	}
	if totalFindings > 5 {
		return "MEDIUM"
	}
	if totalFindings > 0 {
		return "LOW"
	}
	return "CLEAN"
}

// calculateRiskScore computes a numerical risk score (0-100)
func (a *Analyzer) calculateRiskScore(totalFindings, criticalCount, highCount int) float64 {
	score := float64(totalFindings)
	score += float64(criticalCount * 10) // Critical findings are worth 10 points each
	score += float64(highCount * 5)      // High findings are worth 5 points each
	
	// Cap at 100
	if score > 100 {
		score = 100
	}
	
	return score
}

// generateTopFindings identifies the most common security issues
func (a *Analyzer) generateTopFindings(findingCounts map[string]map[string]int, results []RepositoryResult) []TopFinding {
	// TODO: Implement top findings generation
	// This would aggregate findings by rule ID and return the most frequent ones
	return []TopFinding{}
}

// Helper methods

func (a *Analyzer) countAnalyzedRepositories(results []RepositoryResult) int {
	count := 0
	for _, result := range results {
		if result.Error == nil {
			count++
		}
	}
	return count
}

func (a *Analyzer) countSkippedRepositories(results []RepositoryResult) int {
	count := 0
	for _, result := range results {
		if result.Error != nil {
			count++
		}
	}
	return count
}

// ApplyRepositoryFilter checks if a repository matches the filter criteria
func ApplyRepositoryFilter(repo github.RepositoryInfo, filter RepositoryFilter) bool {
	// Check visibility filters
	if repo.IsPrivate && !filter.IncludePrivate {
		return false
	}
	if !repo.IsPrivate && !filter.IncludePublic {
		return false
	}
	
	// Check special repository types
	if repo.IsFork && !filter.IncludeForks {
		return false
	}
	if repo.IsArchived && !filter.IncludeArchived {
		return false
	}
	
	// Apply name filter if specified
	if filter.NameFilter != "" {
		matched, err := regexp.MatchString(filter.NameFilter, repo.Name)
		if err != nil || !matched {
			return false
		}
	}
	
	return true
}
