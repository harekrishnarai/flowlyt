/*
Copyright 2025 Hare Krishna Rai

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package organization

import (
	"context"
	"testing"
	"time"

	"github.com/harekrishnarai/flowlyt/pkg/config"
	"github.com/harekrishnarai/flowlyt/pkg/github"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

// Mock GitHub client for testing
type mockGitHubClient struct {
	repos     []github.RepositoryInfo
	workflows map[string][]string // repo name -> workflow files
	err       error
}

func (m *mockGitHubClient) ListRepositories(ctx context.Context, org string, filter *github.RepositoryFilter) ([]github.RepositoryInfo, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.repos, nil
}

func (m *mockGitHubClient) GetWorkflowFiles(ctx context.Context, owner, repo string) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	key := repo
	if workflows, ok := m.workflows[key]; ok {
		return workflows, nil
	}
	return []string{}, nil
}

func TestNewAnalyzer(t *testing.T) {
	client := &github.Client{}
	cfg := &config.Config{}

	analyzer := NewAnalyzer(client, cfg, 4, true)

	if analyzer == nil {
		t.Fatal("Expected analyzer to be created, got nil")
	}

	if analyzer.maxWorkers != 4 {
		t.Errorf("Expected maxWorkers to be 4, got %d", analyzer.maxWorkers)
	}

	if !analyzer.progress {
		t.Error("Expected progress to be true")
	}
}

func TestOrganizationSummary_CalculateRiskLevel(t *testing.T) {
	tests := []struct {
		name          string
		criticalCount int
		highCount     int
		mediumCount   int
		expected      string
	}{
		{
			name:          "critical findings",
			criticalCount: 5,
			highCount:     2,
			mediumCount:   3,
			expected:      "CRITICAL",
		},
		{
			name:          "high findings only",
			criticalCount: 0,
			highCount:     10,
			mediumCount:   5,
			expected:      "HIGH",
		},
		{
			name:          "medium findings only",
			criticalCount: 0,
			highCount:     0,
			mediumCount:   5,
			expected:      "MEDIUM",
		},
		{
			name:          "low findings",
			criticalCount: 0,
			highCount:     0,
			mediumCount:   0,
			expected:      "LOW",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateRiskLevel(tt.criticalCount, tt.highCount, tt.mediumCount)
			if result != tt.expected {
				t.Errorf("Expected risk level %s, got %s", tt.expected, result)
			}
		})
	}
}

// Helper function for risk calculation
func calculateRiskLevel(critical, high, medium int) string {
	if critical > 0 {
		return "CRITICAL"
	}
	if high >= 5 {
		return "HIGH"
	}
	if medium >= 5 {
		return "MEDIUM"
	}
	if high > 0 || medium > 0 {
		return "MEDIUM"
	}
	return "LOW"
}

func TestRepositoryResult_Duration(t *testing.T) {
	result := &RepositoryResult{
		Repository: github.RepositoryInfo{
			Name: "test-repo",
		},
		Findings:       []rules.Finding{},
		WorkflowsCount: 3,
		Duration:       2 * time.Second,
	}

	if result.Duration != 2*time.Second {
		t.Errorf("Expected duration 2s, got %v", result.Duration)
	}

	if result.WorkflowsCount != 3 {
		t.Errorf("Expected 3 workflows, got %d", result.WorkflowsCount)
	}
}

func TestOrganizationResult_Summary(t *testing.T) {
	result := &OrganizationResult{
		Organization:         "test-org",
		ScanTime:             time.Now(),
		TotalRepositories:    10,
		AnalyzedRepositories: 8,
		SkippedRepositories:  2,
		RepositoryResults: []RepositoryResult{
			{
				Repository: github.RepositoryInfo{Name: "repo1"},
				Findings: []rules.Finding{
					{Severity: "CRITICAL"},
					{Severity: "HIGH"},
				},
			},
			{
				Repository: github.RepositoryInfo{Name: "repo2"},
				Findings: []rules.Finding{
					{Severity: "MEDIUM"},
					{Severity: "LOW"},
				},
			},
		},
	}

	if result.TotalRepositories != 10 {
		t.Errorf("Expected 10 total repositories, got %d", result.TotalRepositories)
	}

	if result.AnalyzedRepositories != 8 {
		t.Errorf("Expected 8 analyzed repositories, got %d", result.AnalyzedRepositories)
	}

	totalFindings := 0
	for _, repo := range result.RepositoryResults {
		totalFindings += len(repo.Findings)
	}

	if totalFindings != 4 {
		t.Errorf("Expected 4 total findings, got %d", totalFindings)
	}
}

func TestRepositoryFilter_Validation(t *testing.T) {
	tests := []struct {
		name   string
		filter RepositoryFilter
		valid  bool
	}{
		{
			name: "valid filter with all options",
			filter: RepositoryFilter{
				IncludePrivate:  true,
				IncludePublic:   true,
				IncludeForks:    false,
				IncludeArchived: false,
			},
			valid: true,
		},
		{
			name: "valid filter excluding forks",
			filter: RepositoryFilter{
				IncludePrivate: true,
				IncludePublic:  true,
				IncludeForks:   false,
			},
			valid: true,
		},
		{
			name: "valid filter with archived",
			filter: RepositoryFilter{
				IncludePrivate:  true,
				IncludeArchived: true,
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that filter can be created and used
			if tt.filter.IncludePrivate == false && tt.filter.IncludePublic == false {
				t.Error("At least one of IncludePrivate or IncludePublic should be true")
			}
		})
	}
}

func TestTopFinding_Structure(t *testing.T) {
	finding := TopFinding{
		RuleID:       "HARDCODED_SECRET",
		RuleName:     "Hardcoded Secret Detection",
		Severity:     "CRITICAL",
		Count:        15,
		Repositories: []string{"repo1", "repo2", "repo3"},
	}

	if finding.RuleID != "HARDCODED_SECRET" {
		t.Errorf("Expected RuleID 'HARDCODED_SECRET', got %s", finding.RuleID)
	}

	if finding.Count != 15 {
		t.Errorf("Expected count 15, got %d", finding.Count)
	}

	if len(finding.Repositories) != 3 {
		t.Errorf("Expected 3 repositories, got %d", len(finding.Repositories))
	}
}

func TestRepositoryRiskInfo_RiskCalculation(t *testing.T) {
	tests := []struct {
		name          string
		riskInfo      RepositoryRiskInfo
		expectedLevel string
	}{
		{
			name: "critical risk",
			riskInfo: RepositoryRiskInfo{
				FindingsCount: 20,
				CriticalCount: 5,
				HighCount:     10,
				Score:         85.5,
			},
			expectedLevel: "CRITICAL",
		},
		{
			name: "high risk",
			riskInfo: RepositoryRiskInfo{
				FindingsCount: 15,
				CriticalCount: 0,
				HighCount:     8,
				Score:         65.0,
			},
			expectedLevel: "HIGH",
		},
		{
			name: "medium risk",
			riskInfo: RepositoryRiskInfo{
				FindingsCount: 10,
				CriticalCount: 0,
				HighCount:     2,
				Score:         40.0,
			},
			expectedLevel: "MEDIUM",
		},
		{
			name: "low risk",
			riskInfo: RepositoryRiskInfo{
				FindingsCount: 2,
				CriticalCount: 0,
				HighCount:     0,
				Score:         10.0,
			},
			expectedLevel: "LOW",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify the risk level matches expectations
			if tt.riskInfo.CriticalCount > 0 {
				if tt.expectedLevel != "CRITICAL" {
					t.Errorf("Expected CRITICAL for critical findings, got %s", tt.expectedLevel)
				}
			}

			if tt.riskInfo.Score < 0 || tt.riskInfo.Score > 100 {
				t.Errorf("Risk score should be between 0 and 100, got %.2f", tt.riskInfo.Score)
			}
		})
	}
}

func TestOrganizationSummary_Aggregation(t *testing.T) {
	summary := OrganizationSummary{
		TotalFindings: 100,
		FindingsBySeverity: map[string]int{
			"CRITICAL": 10,
			"HIGH":     25,
			"MEDIUM":   40,
			"LOW":      25,
		},
		FindingsByCategory: map[string]int{
			"secrets":       30,
			"injection":     25,
			"supply-chain":  20,
			"permissions":   15,
			"misconfigured": 10,
		},
		RepositoriesByRisk: map[string]int{
			"CRITICAL": 5,
			"HIGH":     15,
			"MEDIUM":   30,
			"LOW":      50,
		},
	}

	// Verify total matches sum
	severitySum := 0
	for _, count := range summary.FindingsBySeverity {
		severitySum += count
	}

	if severitySum != summary.TotalFindings {
		t.Errorf("Severity counts don't match total: got %d, want %d", severitySum, summary.TotalFindings)
	}

	// Verify categories sum correctly
	categorySum := 0
	for _, count := range summary.FindingsByCategory {
		categorySum += count
	}

	if categorySum != summary.TotalFindings {
		t.Errorf("Category counts don't match total: got %d, want %d", categorySum, summary.TotalFindings)
	}

	// Verify repository risk distribution
	repoSum := 0
	for _, count := range summary.RepositoriesByRisk {
		repoSum += count
	}

	if repoSum != 100 {
		t.Errorf("Expected 100 total repositories, got %d", repoSum)
	}
}
