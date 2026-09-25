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

package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/harekrishnarai/flowlyt/v2/pkg/rules"
	"github.com/harekrishnarai/flowlyt/v2/pkg/terminal"
)

// EnhancedFinding represents a finding enhanced with AI verification
type EnhancedFinding struct {
	rules.Finding
	AIVerification *VerificationResult `json:"ai_verification,omitempty"`
	AIError        string              `json:"ai_error,omitempty"`
	AISkipped      bool                `json:"ai_skipped,omitempty"`
	AISkipReason   string              `json:"ai_skip_reason,omitempty"`
}

// Analyzer handles AI-powered analysis of findings
type Analyzer struct {
	client Client
	// timeout bounds a single provider request (one batch, or one finding on
	// the fallback path).
	timeout time.Duration
	// totalTimeout optionally bounds the whole analysis. Zero means unbounded,
	// leaving cancellation to the caller's context.
	totalTimeout time.Duration
	// workers is the number of batches dispatched concurrently.
	workers int
	// contexts supplies the workflow evidence attached to each finding.
	contexts *ContextProvider
	// inRunCache avoids duplicate AI calls for equivalent findings during a single run
	// key: fingerprint string, value: *VerificationResult or error string
	cache sync.Map

	// optional persistent cache across runs
	cacheFilePath string
	persistCache  map[string]*VerificationResult // fp -> result

	// for progress / logging
	provider Provider
}

// Options configures an Analyzer.
type Options struct {
	// RequestTimeout bounds a single provider request. Defaults to 30s.
	RequestTimeout time.Duration
	// TotalTimeout optionally bounds the whole analysis. Zero means unbounded.
	TotalTimeout time.Duration
	// Workers is the number of batches dispatched concurrently. Defaults to 4,
	// which keeps throughput high without tripping provider rate limits.
	Workers int
	// Contexts supplies workflow evidence for each finding. May be nil, in
	// which case findings are sent without surrounding context.
	Contexts *ContextProvider
}

// DefaultWorkers is the batch concurrency used when none is configured.
const DefaultWorkers = 4

// NewAnalyzer creates a new AI analyzer with default options.
func NewAnalyzer(client Client, timeout time.Duration) *Analyzer {
	return NewAnalyzerWithOptions(client, Options{RequestTimeout: timeout})
}

// NewAnalyzerWithOptions creates a new AI analyzer.
func NewAnalyzerWithOptions(client Client, opts Options) *Analyzer {
	if opts.RequestTimeout == 0 {
		opts.RequestTimeout = 30 * time.Second
	}
	if opts.Workers <= 0 {
		opts.Workers = DefaultWorkers
	}

	cachePath := strings.TrimSpace(os.Getenv("AI_CACHE_FILE"))

	return &Analyzer{
		client:        client,
		timeout:       opts.RequestTimeout,
		totalTimeout:  opts.TotalTimeout,
		workers:       opts.Workers,
		contexts:      opts.Contexts,
		cacheFilePath: cachePath,
		persistCache:  make(map[string]*VerificationResult, 256),
		provider:      client.GetProvider(),
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
	var skippedFindings []EnhancedFinding
	for _, f := range findings {
		if skip, reason := ShouldSkipAI(f); skip {
			skippedFindings = append(skippedFindings, EnhancedFinding{
				Finding:      f,
				AISkipped:    true,
				AISkipReason: reason,
			})
			continue
		}
		filtered = append(filtered, f)
	}

	if len(filtered) == 0 {
		return skippedFindings, nil
	}

	enhancedFindings := make([]EnhancedFinding, 0, len(findings))

	const batchSize = 5

	// Cache pre-check: split into cached and uncached
	var toDispatch []rules.Finding
	for _, f := range filtered {
		fp := fingerprintFinding(f)
		if cached, ok := a.cache.Load(fp); ok {
			if vr, ok2 := cached.(*VerificationResult); ok2 {
				enhancedFindings = append(enhancedFindings, EnhancedFinding{Finding: f, AIVerification: vr})
				continue
			}
		}
		if a.persistCache != nil {
			if vr, ok := a.persistCache[fp]; ok {
				enhancedFindings = append(enhancedFindings, EnhancedFinding{Finding: f, AIVerification: vr})
				continue
			}
		}
		toDispatch = append(toDispatch, f)
	}

	dispatchCount := len(toDispatch)
	if dispatchCount == 0 {
		enhancedFindings = append(enhancedFindings, skippedFindings...)
		return enhancedFindings, nil
	}

	// A whole-run deadline, if configured. Each batch additionally gets its own
	// deadline inside runBatch: scaling one global deadline by the number of
	// findings meant a slow early batch consumed the budget for every later
	// one, so a single stalled request could fail an entire run.
	overall := ctx
	if a.totalTimeout > 0 {
		var cancelOverall context.CancelFunc
		overall, cancelOverall = context.WithTimeout(ctx, a.totalTimeout)
		defer cancelOverall()
	}

	// Group uncached findings by class, preserving first-seen order.
	toDispatchByClass := make(map[string][]rules.Finding)
	var classOrder []string
	for _, f := range toDispatch {
		class := categoryToClass(f.Category)
		if _, exists := toDispatchByClass[class]; !exists {
			classOrder = append(classOrder, class)
		}
		toDispatchByClass[class] = append(toDispatchByClass[class], f)
	}

	// Build the batch work list up front so results can be reassembled in a
	// deterministic order regardless of completion order.
	type batchJob struct {
		class    string
		findings []rules.Finding
	}
	var jobs []batchJob
	for _, class := range classOrder {
		classFindings := toDispatchByClass[class]
		for start := 0; start < len(classFindings); start += batchSize {
			end := start + batchSize
			if end > len(classFindings) {
				end = len(classFindings)
			}
			jobs = append(jobs, batchJob{class: class, findings: classFindings[start:end]})
		}
	}

	results := make([][]EnhancedFinding, len(jobs))

	workers := a.workers
	if workers < 1 {
		workers = 1
	}
	if workers > len(jobs) {
		workers = len(jobs)
	}

	// Progress is a single in-place line on an interactive terminal and nothing
	// when output is piped. Findings themselves appear in the final report.
	showProgress := terminal.Default().IsTTY()

	// Provider APIs are network-bound, so batches are dispatched concurrently.
	// They previously ran one after another, which meant a hundred findings
	// cost twenty sequential round-trips.
	var (
		nextJob  atomic.Int64
		progress atomic.Int64
		wg       sync.WaitGroup
	)
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for {
				i := int(nextJob.Add(1)) - 1
				if i >= len(jobs) {
					return
				}
				if overall.Err() != nil {
					return
				}

				results[i] = a.runBatch(overall, jobs[i].class, jobs[i].findings)

				completed := int(progress.Add(int64(len(jobs[i].findings))))
				if showProgress {
					fmt.Fprintf(os.Stderr, "\rAI analysis: %d/%d findings", completed, dispatchCount)
				}
			}
		}()
	}
	wg.Wait()

	for _, r := range results {
		enhancedFindings = append(enhancedFindings, r...)
	}

	done := int(progress.Load())
	if showProgress {
		fmt.Fprintf(os.Stderr, "\rAI analysis: %d/%d findings — done\n", done, dispatchCount)
	}

	enhancedFindings = append(enhancedFindings, skippedFindings...)

	// Persist any new cache entries (including those from partial runs)
	a.flushPersistentCache()

	if overall.Err() != nil {
		return enhancedFindings, fmt.Errorf("AI analysis timed out or was canceled: %w", overall.Err())
	}

	return enhancedFindings, nil
}

// runBatch verifies one batch of findings, falling back to individual requests
// if the batch call fails.
//
// The batch gets its own deadline so that one slow provider response cannot
// consume the budget belonging to other batches.
func (a *Analyzer) runBatch(ctx context.Context, class string, batch []rules.Finding) []EnhancedFinding {
	batchCtx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	contextual := make([]ContextualFinding, len(batch))
	for i, f := range batch {
		contextual[i] = ContextualFinding{Finding: f, Context: a.contexts.For(f)}
	}

	batchResults, err := a.client.VerifyBatch(batchCtx, class, contextual)
	if err != nil {
		return a.verifyIndividually(ctx, batch)
	}

	out := make([]EnhancedFinding, 0, len(batch))
	for _, br := range batchResults {
		if br.Index < 0 || br.Index >= len(batch) {
			continue
		}
		f := batch[br.Index]
		ef := EnhancedFinding{Finding: f}
		if br.Error != "" {
			ef.AIError = br.Error
		} else if br.Result != nil {
			ef.AIVerification = br.Result
			fp := fingerprintFinding(f)
			a.cache.Store(fp, br.Result)
			a.stagePersist(fp, br.Result)
		}
		out = append(out, ef)
	}
	return out
}

// verifyIndividually is the fallback when a batch request fails. Each finding
// gets its own deadline so the fallback cannot inherit an already-exhausted one.
func (a *Analyzer) verifyIndividually(ctx context.Context, batch []rules.Finding) []EnhancedFinding {
	out := make([]EnhancedFinding, 0, len(batch))
	for _, f := range batch {
		singleCtx, cancel := context.WithTimeout(ctx, a.timeout)
		vr, err := a.client.VerifyFinding(singleCtx, f)
		cancel()

		ef := EnhancedFinding{Finding: f}
		if err != nil {
			ef.AIError = err.Error()
		} else {
			ef.AIVerification = vr
			fp := fingerprintFinding(f)
			a.cache.Store(fp, vr)
			a.stagePersist(fp, vr)
		}
		out = append(out, ef)
	}
	return out
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
	if len(s) == 0 {
		return "evidence:none"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:]) // 64 hex chars
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
	if err := os.MkdirAll(strings.TrimSuffix(a.cacheFilePath, "/"+filepathBase(a.cacheFilePath)), 0o750); err != nil {
		return
	}
	f, err := os.OpenFile(a.cacheFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	if _, err := f.WriteString(b.String()); err != nil {
		return
	}
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

	fp := fingerprintFinding(finding)
	if cached, ok := a.cache.Load(fp); ok {
		switch v := cached.(type) {
		case *VerificationResult:
			enhanced.AIVerification = v
			return enhanced, nil
		case error:
			enhanced.AIError = v.Error()
			return enhanced, nil
		case string:
			enhanced.AIError = v
			return enhanced, nil
		}
	}

	verification, err := a.client.VerifyFinding(analyzeCtx, finding)
	if err != nil {
		enhanced.AIError = err.Error()
		a.cache.Store(fp, err.Error())
		return enhanced, nil // Return the enhanced finding with error, don't fail completely
	}

	enhanced.AIVerification = verification
	a.cache.Store(fp, verification)
	a.stagePersist(fp, verification)
	return enhanced, nil
}

// GetSummary returns a summary of AI analysis results
func GetSummary(enhancedFindings []EnhancedFinding) AISummary {
	summary := AISummary{}

	for _, enhanced := range enhancedFindings {
		summary.TotalAnalyzed++

		if enhanced.AISkipped {
			summary.SkippedByFilter++
			continue
		}

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
	SkippedByFilter      int `json:"skipped_by_filter"`
}

// Close cleans up the analyzer
func (a *Analyzer) Close() error {
	if a.client != nil {
		return a.client.Close()
	}
	return nil
}

// PrintAISummary prints a summary box of AI analysis results to the terminal.
func PrintAISummary(term *terminal.Terminal, summary AISummary, provider Provider, model string) {
	if !term.IsTTY() {
		return
	}
	const w = 54
	title := " AI Analysis Summary "
	top := "┌─ " + title + strings.Repeat("─", w-4-len(title)) + "┐"
	mid := func(content string) string {
		inner := w - 2
		if len(content) > inner {
			content = content[:inner]
		}
		return "│" + content + strings.Repeat(" ", inner-len(content)) + "│"
	}
	bot := "└" + strings.Repeat("─", w-2) + "┘"

	term.Printf("%s\n", top)
	term.Printf("%s\n", mid(fmt.Sprintf("  %-20s %-6d  Skipped by filter  %-4d",
		"Analyzed", summary.TotalAnalyzed, summary.SkippedByFilter)))
	term.Printf("%s\n", mid(fmt.Sprintf("  %-20s %-6d  False pos          %-4d",
		"True pos", summary.LikelyTruePositives, summary.LikelyFalsePositives)))
	term.Printf("%s\n", mid(fmt.Sprintf("  %-20s %-6d  Low conf           %-4d",
		"High conf", summary.HighConfidence, summary.LowConfidence)))
	term.Printf("%s\n", mid(fmt.Sprintf("  Provider  %s · %s", provider, model)))
	term.Printf("%s\n", bot)
}
