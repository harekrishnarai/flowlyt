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
	"time"

	"github.com/harekrishnarai/flowlyt/pkg/rules"
	"github.com/harekrishnarai/flowlyt/pkg/terminal"
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
	client  Client
	timeout time.Duration
	// inRunCache avoids duplicate AI calls for equivalent findings during a single run
	// key: fingerprint string, value: *VerificationResult or error string
	cache sync.Map

	// optional persistent cache across runs
	cacheFilePath string
	persistCache  map[string]*VerificationResult // fp -> result

	// for progress / logging
	provider Provider
}

// NewAnalyzer creates a new AI analyzer
func NewAnalyzer(client Client, maxWorkers int, timeout time.Duration) *Analyzer {
	if maxWorkers <= 0 {
		maxWorkers = 5 // Default to 5 concurrent workers
	}
	if timeout == 0 {
		timeout = 30 * time.Second // Default timeout
	}

	cachePath := strings.TrimSpace(os.Getenv("AI_CACHE_FILE"))

	return &Analyzer{
		client:        client,
		timeout:       timeout,
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

	// Create context with timeout
	analyzeCtx, cancel := context.WithTimeout(ctx, a.timeout*time.Duration(dispatchCount))
	defer cancel()

	// Group uncached findings by class (stable order)
	toDispatchByClass := make(map[string][]rules.Finding)
	classOrder := []string{}
	for _, f := range toDispatch {
		class := categoryToClass(f.Category)
		if _, exists := toDispatchByClass[class]; !exists {
			classOrder = append(classOrder, class)
		}
		toDispatchByClass[class] = append(toDispatchByClass[class], f)
	}

	// Set up streaming progress bar
	term := terminal.Default()
	var bar *terminal.ProgressBar
	if term.IsTTY() {
		bar = term.NewProgressBar(dispatchCount)
		bar.SetPrefix("🤖 AI analysis")
		bar.SetStyle(terminal.DefaultProgressStyle)
	}

	// Dispatch batches per class (synchronously)
	for _, class := range classOrder {
		classFindings, ok := toDispatchByClass[class]
		if !ok {
			continue
		}
		totalBatches := (len(classFindings) + batchSize - 1) / batchSize
		for batchNum := 1; batchNum <= totalBatches; batchNum++ {
			start := (batchNum - 1) * batchSize
			end := start + batchSize
			if end > len(classFindings) {
				end = len(classFindings)
			}
			batch := classFindings[start:end]

			batchResults, err := a.client.VerifyBatch(analyzeCtx, class, batch)
			if err != nil {
				// Fall back to individual calls on batch failure
				for _, f := range batch {
					vr, singleErr := a.client.VerifyFinding(analyzeCtx, f)
					ef := EnhancedFinding{Finding: f}
					if singleErr != nil {
						ef.AIError = singleErr.Error()
					} else {
						ef.AIVerification = vr
						fp := fingerprintFinding(f)
						a.cache.Store(fp, vr)
						a.stagePersist(fp, vr)
					}
					enhancedFindings = append(enhancedFindings, ef)
				}
				continue
			}

			// Attribute by index, collect into batchEnhanced for streaming
			batchEnhanced := make([]EnhancedFinding, 0, len(batch))
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
				batchEnhanced = append(batchEnhanced, ef)
			}
			enhancedFindings = append(enhancedFindings, batchEnhanced...)

			if bar != nil {
				bar.SetSuffix(fmt.Sprintf("(%s batch %d/%d)", class, batchNum, totalBatches))
				bar.Add(len(batch))
				term.Println("") // advance past the bar line before printing findings
				for _, ef := range batchEnhanced {
					printFindingResult(term, ef)
				}
			}
		}
	}

	if bar != nil {
		bar.Finish()
	}

	enhancedFindings = append(enhancedFindings, skippedFindings...)

	// Persist any new cache entries (including those from partial runs)
	a.flushPersistentCache()

	// Check if context was cancelled
	if analyzeCtx.Err() != nil {
		return enhancedFindings, fmt.Errorf("AI analysis timed out or was cancelled: %w", analyzeCtx.Err())
	}

	return enhancedFindings, nil
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

// printFindingResult prints a per-finding result to the terminal during streaming.
func printFindingResult(term *terminal.Terminal, ef EnhancedFinding) {
	if !term.IsTTY() {
		return
	}
	if ef.AISkipped || ef.AIVerification == nil {
		return
	}
	v := ef.AIVerification
	if v.IsLikelyFalsePositive {
		dim := terminal.NewStyle().WithDim()
		term.PrintStyled(fmt.Sprintf("  ~  %-42s %s  FALSE POSITIVE  %.0f%%\n",
			ef.RuleID, v.Severity, v.Confidence*100), dim)
	} else {
		red := terminal.NewStyle().WithForeground(terminal.ColorCritical).WithBold()
		term.PrintStyled(fmt.Sprintf("  ✗  %-42s %s  TRUE POSITIVE   %.0f%%\n",
			ef.RuleID, v.Severity, v.Confidence*100), red)
		if v.Reasoning != "" {
			term.Printf("     %s\n", v.Reasoning)
		}
		if v.Remediation != "" {
			term.Printf("     Fix: %s\n", v.Remediation)
		}
	}
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
