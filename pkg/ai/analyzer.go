package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
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
	// inRunCache avoids duplicate AI calls for equivalent findings during a single run
	// key: fingerprint string, value: *VerificationResult or error string
	cache sync.Map

	// filtering controls (config-driven via env for now)
	minSeverity  string
	includeRules map[string]struct{}
	excludeRules map[string]struct{}

	// optional persistent cache across runs
	cacheFilePath string
	persistCache  map[string]*VerificationResult // fp -> result
}

// NewAnalyzer creates a new AI analyzer
func NewAnalyzer(client Client, maxWorkers int, timeout time.Duration) *Analyzer {
	if maxWorkers <= 0 {
		maxWorkers = 5 // Default to 5 concurrent workers
	}
	if timeout == 0 {
		timeout = 30 * time.Second // Default timeout
	}

	// Load filtering config (env-based for now)
	minSev := strings.TrimSpace(os.Getenv("AI_MIN_SEVERITY"))
	include := parseCSVSet(os.Getenv("AI_INCLUDE_RULES"))
	exclude := parseCSVSet(os.Getenv("AI_EXCLUDE_RULES"))
	cachePath := strings.TrimSpace(os.Getenv("AI_CACHE_FILE"))

	return &Analyzer{
		client:        client,
		maxWorkers:    maxWorkers,
		timeout:       timeout,
		minSeverity:   strings.ToUpper(minSev),
		includeRules:  include,
		excludeRules:  exclude,
		cacheFilePath: cachePath,
		persistCache:  make(map[string]*VerificationResult, 256),
	}
}

// AnalyzeFindings analyzes multiple findings using AI
func (a *Analyzer) AnalyzeFindings(ctx context.Context, findings []rules.Finding) ([]EnhancedFinding, error) {
	if len(findings) == 0 {
		return []EnhancedFinding{}, nil
	}

	// Optionally load persistent cache
	a.loadPersistentCache()

	// Filter findings based on configured scope
	filtered := make([]rules.Finding, 0, len(findings))
	for _, f := range findings {
		if !a.shouldSendToAI(f) {
			continue
		}
		filtered = append(filtered, f)
	}
	if len(filtered) == 0 {
		return []EnhancedFinding{}, nil
	}

	// Create context with timeout
	analyzeCtx, cancel := context.WithTimeout(ctx, a.timeout*time.Duration(len(filtered)))
	defer cancel()

	// Create channels for work distribution
	findingsChan := make(chan rules.Finding, len(filtered))
	resultsChan := make(chan EnhancedFinding, len(filtered))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < a.maxWorkers; i++ {
		wg.Add(1)
		go a.worker(analyzeCtx, &wg, findingsChan, resultsChan)
	}

	// Send findings to workers
	go func() {
		for _, finding := range filtered {
			select {
			case findingsChan <- finding:
			case <-analyzeCtx.Done():
				return
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

	// Persist any new cache entries (successful ones only)
	a.flushPersistentCache()

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

			// Fingerprint to coalesce duplicate analyses within this run
			fp := fingerprintFinding(finding)

			var verification *VerificationResult
			var err error

			if cached, ok := a.cache.Load(fp); ok {
				switch v := cached.(type) {
				case *VerificationResult:
					verification = v
				case error:
					err = v
				case string:
					err = fmt.Errorf("%s", v)
				}
			} else {
				// Create a timeout for this individual analysis
				analyzeCtx, cancel := context.WithTimeout(ctx, a.timeout)
				verification, err = a.client.VerifyFinding(analyzeCtx, finding)
				cancel()

				if err != nil {
					a.cache.Store(fp, err.Error())
				} else {
					a.cache.Store(fp, verification)
					// Also stage for persistence
					a.stagePersist(fp, verification)
				}
			}

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

// fingerprintFinding creates a stable identity for a finding, minimizing token waste by caching equal work.
func fingerprintFinding(f rules.Finding) string {
	// Concise composite key; if needed, add more fields later
	return strings.Join([]string{
		f.RuleID,
		f.FilePath,
		f.JobName,
		f.StepName,
		strings.TrimSpace(f.Trigger),
		strings.TrimSpace(f.RunnerType),
		strings.TrimSpace(f.FileContext),
		// Evidence can be long; keep a stable slice
		hashEvidence(f.Evidence),
	}, "|")
}

func hashEvidence(s string) string {
	const n = 256
	// Simple, fast hash to avoid pulling crypto into hot path
	h := uint64(1469598103934665603) // FNV-1a offset
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	// Return fixed-size text
	return fmt.Sprintf("%x", h)[:n/4]
}

// shouldSendToAI decides if a finding should be sent to AI based on configured severity/rule filters.
func (a *Analyzer) shouldSendToAI(f rules.Finding) bool {
	// Exclude-list takes precedence
	if _, denied := a.excludeRules[strings.ToUpper(f.RuleID)]; denied {
		return false
	}
	// Include-list overrides severity
	if len(a.includeRules) > 0 {
		if _, ok := a.includeRules[strings.ToUpper(f.RuleID)]; ok {
			return true
		}
		// Not included explicitly
		return false
	}
	// Min severity gate
	if a.minSeverity == "" {
		return true
	}
	levels := map[string]int{
		"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5,
	}
	fs := strings.ToUpper(string(f.Severity))
	return levels[fs] >= levels[a.minSeverity]
}

// parseCSVSet builds a case-insensitive set from comma-separated env var.
func parseCSVSet(s string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, part := range strings.Split(s, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		m[strings.ToUpper(p)] = struct{}{}
	}
	return m
}

// persistent cache handling (simple JSONL: {"fp":"...", "result":{...}})
type cacheLine struct {
	FP     string              `json:"fp"`
	Result *VerificationResult `json:"result,omitempty"`
}

func (a *Analyzer) loadPersistentCache() {
	if a.cacheFilePath == "" {
		return
	}
	data, err := os.ReadFile(a.cacheFilePath)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var cl cacheLine
		if err := json.Unmarshal([]byte(line), &cl); err != nil || cl.FP == "" || cl.Result == nil {
			continue
		}
		a.persistCache[cl.FP] = cl.Result
		// Seed in-run cache too
		a.cache.Store(cl.FP, cl.Result)
	}
}

func (a *Analyzer) stagePersist(fp string, vr *VerificationResult) {
	if a.cacheFilePath == "" || vr == nil {
		return
	}
	// Keep in memory so we can flush at the end
	if _, ok := a.persistCache[fp]; !ok {
		a.persistCache[fp] = vr
	}
}

func (a *Analyzer) flushPersistentCache() {
	if a.cacheFilePath == "" || len(a.persistCache) == 0 {
		return
	}
	// Append new lines; read existing to avoid duplicates in file
	existing := map[string]struct{}{}
	if data, err := os.ReadFile(a.cacheFilePath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			var cl cacheLine
			if json.Unmarshal([]byte(line), &cl) == nil && cl.FP != "" {
				existing[cl.FP] = struct{}{}
			}
		}
	}

	var b strings.Builder
	for fp, vr := range a.persistCache {
		if _, seen := existing[fp]; seen {
			continue
		}
		cl := cacheLine{FP: fp, Result: vr}
		raw, err := json.Marshal(cl)
		if err != nil {
			continue
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	if b.Len() == 0 {
		return
	}
	_ = os.MkdirAll(strings.TrimSuffix(a.cacheFilePath, "/"+filepathBase(a.cacheFilePath)), 0o755)
	f, err := os.OpenFile(a.cacheFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(b.String())
}

func filepathBase(p string) string {
	i := strings.LastIndexAny(p, "/\\")
	if i == -1 {
		return p
	}
	return p[i+1:]
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
	TotalAnalyzed        int `json:"total_analyzed"`
	SuccessfullyAnalyzed int `json:"successfully_analyzed"`
	AnalysisErrors       int `json:"analysis_errors"`
	LikelyFalsePositives int `json:"likely_false_positives"`
	LikelyTruePositives  int `json:"likely_true_positives"`
	HighConfidence       int `json:"high_confidence"`   // >= 0.8
	MediumConfidence     int `json:"medium_confidence"` // >= 0.6 && < 0.8
	LowConfidence        int `json:"low_confidence"`    // < 0.6
}

// Close cleans up the analyzer
func (a *Analyzer) Close() error {
	if a.client != nil {
		return a.client.Close()
	}
	return nil
}
