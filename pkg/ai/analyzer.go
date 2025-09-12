package ai

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

// EnhancedFinding represents a finding enhanced with AI verification
type EnhancedFinding struct {
	rules.Finding
	AIVerification *VerificationResult `json:"ai_verification,omitempty"`
	AIError        string              `json:"ai_error,omitempty"`
}

// Analyzer handles AI-powered analysis of findings
type Analyzer struct {
	client     Client
	maxWorkers int
	timeout    time.Duration
}

// NewAnalyzer creates a new AI analyzer
func NewAnalyzer(client Client, maxWorkers int, timeout time.Duration) *Analyzer {
	if maxWorkers <= 0 {
		maxWorkers = 5 // Default to 5 concurrent workers
	}
	if timeout == 0 {
		timeout = 30 * time.Second // Default timeout
	}
	
	return &Analyzer{
		client:     client,
		maxWorkers: maxWorkers,
		timeout:    timeout,
	}
}

// AnalyzeFindings analyzes multiple findings using AI
func (a *Analyzer) AnalyzeFindings(ctx context.Context, findings []rules.Finding) ([]EnhancedFinding, error) {
	if len(findings) == 0 {
		return []EnhancedFinding{}, nil
	}

	// Create context with timeout
	analyzeCtx, cancel := context.WithTimeout(ctx, a.timeout*time.Duration(len(findings)))
	defer cancel()

	// Create channels for work distribution
	findingsChan := make(chan rules.Finding, len(findings))
	resultsChan := make(chan EnhancedFinding, len(findings))
	
	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < a.maxWorkers; i++ {
		wg.Add(1)
		go a.worker(analyzeCtx, &wg, findingsChan, resultsChan)
	}

	// Send findings to workers
	go func() {
		for _, finding := range findings {
			select {
			case findingsChan <- finding:
			case <-analyzeCtx.Done():
				break
			}
		}
		close(findingsChan)
	}()

	// Wait for workers to complete and close results channel
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	enhancedFindings := make([]EnhancedFinding, 0, len(findings))
	for result := range resultsChan {
		enhancedFindings = append(enhancedFindings, result)
	}

	// Check if context was cancelled
	if analyzeCtx.Err() != nil {
		return enhancedFindings, fmt.Errorf("AI analysis timed out or was cancelled: %w", analyzeCtx.Err())
	}

	return enhancedFindings, nil
}

// worker processes findings from the channel
func (a *Analyzer) worker(ctx context.Context, wg *sync.WaitGroup, findingsChan <-chan rules.Finding, resultsChan chan<- EnhancedFinding) {
	defer wg.Done()

	for {
		select {
		case finding, ok := <-findingsChan:
			if !ok {
				return // Channel closed, worker done
			}

			enhanced := EnhancedFinding{Finding: finding}

			// Create a timeout for this individual analysis
			analyzeCtx, cancel := context.WithTimeout(ctx, a.timeout)
			verification, err := a.client.VerifyFinding(analyzeCtx, finding)
			cancel()

			if err != nil {
				enhanced.AIError = err.Error()
			} else {
				enhanced.AIVerification = verification
			}

			select {
			case resultsChan <- enhanced:
			case <-ctx.Done():
				return // Context cancelled
			}

		case <-ctx.Done():
			return // Context cancelled
		}
	}
}

// AnalyzeSingleFinding analyzes a single finding using AI
func (a *Analyzer) AnalyzeSingleFinding(ctx context.Context, finding rules.Finding) (*EnhancedFinding, error) {
	analyzeCtx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	enhanced := &EnhancedFinding{Finding: finding}

	verification, err := a.client.VerifyFinding(analyzeCtx, finding)
	if err != nil {
		enhanced.AIError = err.Error()
		return enhanced, nil // Return the enhanced finding with error, don't fail completely
	}

	enhanced.AIVerification = verification
	return enhanced, nil
}

// GetSummary returns a summary of AI analysis results
func GetSummary(enhancedFindings []EnhancedFinding) AISummary {
	summary := AISummary{}

	for _, enhanced := range enhancedFindings {
		summary.TotalAnalyzed++

		if enhanced.AIError != "" {
			summary.AnalysisErrors++
			continue
		}

		if enhanced.AIVerification == nil {
			continue
		}

		summary.SuccessfullyAnalyzed++

		if enhanced.AIVerification.IsLikelyFalsePositive {
			summary.LikelyFalsePositives++
		} else {
			summary.LikelyTruePositives++
		}

		// Track confidence levels
		confidence := enhanced.AIVerification.Confidence
		switch {
		case confidence >= 0.8:
			summary.HighConfidence++
		case confidence >= 0.6:
			summary.MediumConfidence++
		default:
			summary.LowConfidence++
		}
	}

	return summary
}

// AISummary provides statistics about AI analysis results
type AISummary struct {
	TotalAnalyzed         int `json:"total_analyzed"`
	SuccessfullyAnalyzed  int `json:"successfully_analyzed"`
	AnalysisErrors        int `json:"analysis_errors"`
	LikelyFalsePositives  int `json:"likely_false_positives"`
	LikelyTruePositives   int `json:"likely_true_positives"`
	HighConfidence        int `json:"high_confidence"`   // >= 0.8
	MediumConfidence      int `json:"medium_confidence"` // >= 0.6 && < 0.8
	LowConfidence         int `json:"low_confidence"`    // < 0.6
}

// Close cleans up the analyzer
func (a *Analyzer) Close() error {
	if a.client != nil {
		return a.client.Close()
	}
	return nil
}