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

package ast

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestMetricsCollector(t *testing.T) {
	collector := NewMetricsCollector()

	// Test recording analysis
	collector.RecordAnalysis(5*time.Millisecond, 10*time.Millisecond, "small", nil)
	collector.RecordAnalysis(10*time.Millisecond, 20*time.Millisecond, "medium", nil)

	metrics := collector.GetMetrics()

	if metrics.totalAnalyses != 2 {
		t.Errorf("Expected 2 analyses, got %d", metrics.totalAnalyses)
	}

	if metrics.averageParseTime != 7500*time.Microsecond {
		t.Errorf("Expected average parse time 7.5ms, got %v", metrics.averageParseTime)
	}

	if metrics.averageAnalysisTime != 15*time.Millisecond {
		t.Errorf("Expected average analysis time 15ms, got %v", metrics.averageAnalysisTime)
	}
}

func TestMetricsCollectorComponentTracking(t *testing.T) {
	collector := NewMetricsCollector()

	// Record component executions
	collector.RecordComponentExecution("parser", 5*time.Millisecond, nil)
	collector.RecordComponentExecution("parser", 10*time.Millisecond, nil)
	collector.RecordComponentExecution("dataflow", 15*time.Millisecond, nil)

	metrics := collector.GetMetrics()

	parserMetrics := metrics.componentMetrics["parser"]
	if parserMetrics == nil {
		t.Fatal("Parser metrics not found")
	}

	if parserMetrics.TotalExecutions != 2 {
		t.Errorf("Expected 2 parser executions, got %d", parserMetrics.TotalExecutions)
	}

	if parserMetrics.AverageTime != 7500*time.Microsecond {
		t.Errorf("Expected average parser time 7.5ms, got %v", parserMetrics.AverageTime)
	}

	if parserMetrics.MinTime != 5*time.Millisecond {
		t.Errorf("Expected min parser time 5ms, got %v", parserMetrics.MinTime)
	}

	if parserMetrics.MaxTime != 10*time.Millisecond {
		t.Errorf("Expected max parser time 10ms, got %v", parserMetrics.MaxTime)
	}

	dataflowMetrics := metrics.componentMetrics["dataflow"]
	if dataflowMetrics == nil {
		t.Fatal("Dataflow metrics not found")
	}

	if dataflowMetrics.TotalExecutions != 1 {
		t.Errorf("Expected 1 dataflow execution, got %d", dataflowMetrics.TotalExecutions)
	}
}

func TestMetricsCollectorCacheTracking(t *testing.T) {
	collector := NewMetricsCollector()

	// Record cache operations
	collector.RecordCacheHit()
	collector.RecordCacheHit()
	collector.RecordCacheMiss()

	metrics := collector.GetMetrics()

	if metrics.cacheHits != 2 {
		t.Errorf("Expected 2 cache hits, got %d", metrics.cacheHits)
	}

	if metrics.cacheMisses != 1 {
		t.Errorf("Expected 1 cache miss, got %d", metrics.cacheMisses)
	}

	hitRate := metrics.GetCacheHitRate()
	expectedHitRate := 66.66666666666666 // 2/3 * 100
	if hitRate != expectedHitRate {
		t.Errorf("Expected hit rate %.2f%%, got %.2f%%", expectedHitRate, hitRate)
	}
}

func TestMetricsCollectorComplexityTracking(t *testing.T) {
	collector := NewMetricsCollector()

	// Need to record analyses first to establish a baseline count
	collector.RecordAnalysis(5*time.Millisecond, 10*time.Millisecond, "small", nil)
	collector.UpdateComplexityMetrics(5, 10, 2.5, 3, 8)

	collector.RecordAnalysis(10*time.Millisecond, 20*time.Millisecond, "medium", nil)
	collector.UpdateComplexityMetrics(3, 8, 1.5, 2, 6)

	metrics := collector.GetMetrics()
	profile := metrics.performanceProfile

	// After 2 analyses: (5+3)/2 = 4.0 average job count
	if profile.ComplexityMetrics.AverageJobCount != 4.0 {
		t.Errorf("Expected average job count 4.0, got %f", profile.ComplexityMetrics.AverageJobCount)
	}

	// After 2 analyses: (10+8)/2 = 9.0 average step count
	if profile.ComplexityMetrics.AverageStepCount != 9.0 {
		t.Errorf("Expected average step count 9.0, got %f", profile.ComplexityMetrics.AverageStepCount)
	}

	if profile.ComplexityMetrics.MaxCallGraphDepth != 3 {
		t.Errorf("Expected max call graph depth 3, got %d", profile.ComplexityMetrics.MaxCallGraphDepth)
	}
}

func TestMetricsReportGeneration(t *testing.T) {
	collector := NewMetricsCollector()

	// Generate some activity
	collector.RecordAnalysis(5*time.Millisecond, 10*time.Millisecond, "small", nil)
	collector.RecordAnalysis(100*time.Millisecond, 200*time.Millisecond, "large", nil) // Slow analysis
	collector.RecordComponentExecution("slow_component", 60*time.Millisecond, nil)

	report := collector.GenerateReport()

	if report.TotalAnalyses != 2 {
		t.Errorf("Expected 2 analyses in report, got %d", report.TotalAnalyses)
	}

	// Should recommend optimization for slow analysis
	found := false
	for _, rec := range report.Recommendations {
		if strings.Contains(rec, "slow") || strings.Contains(rec, "100ms") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected recommendation about slow analysis time")
	}
}

func TestMetricsCollectorDisable(t *testing.T) {
	collector := NewMetricsCollector()

	// Disable metrics
	collector.Disable()

	// These should not be recorded
	collector.RecordAnalysis(5*time.Millisecond, 10*time.Millisecond, "small", nil)
	collector.RecordCacheHit()

	metrics := collector.GetMetrics()

	if metrics.totalAnalyses != 0 {
		t.Errorf("Expected 0 analyses when disabled, got %d", metrics.totalAnalyses)
	}

	if metrics.cacheHits != 0 {
		t.Errorf("Expected 0 cache hits when disabled, got %d", metrics.cacheHits)
	}

	// Re-enable and test
	collector.Enable()
	collector.RecordAnalysis(5*time.Millisecond, 10*time.Millisecond, "small", nil)

	metrics = collector.GetMetrics()
	if metrics.totalAnalyses != 1 {
		t.Errorf("Expected 1 analysis after re-enabling, got %d", metrics.totalAnalyses)
	}
}

func TestCache(t *testing.T) {
	config := &CacheConfig{
		MaxSizeMB:   1,  // 1MB
		MaxEntries:  10, // 10 entries
		TTL:         time.Hour,
		CleanupFreq: time.Minute,
	}
	cache := NewCache(config)

	// Test basic put/get
	key := CacheKey{
		WorkflowHash: "hash1",
		ConfigHash:   "config1",
		AnalysisType: "workflow",
		Version:      "1.0",
	}

	result := &ComprehensiveAnalysisResult{
		SecurityRisks: []string{"risk1", "risk2"},
	}

	cache.Put(key, result)

	retrieved, found := cache.Get(key)
	if !found {
		t.Error("Expected to find cached result")
	}

	if retrievedResult, ok := retrieved.(*ComprehensiveAnalysisResult); ok {
		if len(retrievedResult.SecurityRisks) != 2 {
			t.Errorf("Expected 2 security risks, got %d", len(retrievedResult.SecurityRisks))
		}
	} else {
		t.Error("Retrieved result is not of expected type")
	}
}

func TestCacheEviction(t *testing.T) {
	config := &CacheConfig{
		MaxSizeMB:   1, // Very small cache
		MaxEntries:  2, // Only 2 entries
		TTL:         time.Hour,
		CleanupFreq: 0, // No automatic cleanup
	}
	cache := NewCache(config)

	// Add entries beyond capacity
	for i := 0; i < 5; i++ {
		key := CacheKey{
			WorkflowHash: fmt.Sprintf("hash%d", i),
			ConfigHash:   "config1",
			AnalysisType: "workflow",
			Version:      "1.0",
		}

		result := &ComprehensiveAnalysisResult{
			SecurityRisks: []string{fmt.Sprintf("risk%d", i)},
		}

		cache.Put(key, result)
		time.Sleep(time.Millisecond) // Ensure different access times
	}

	stats := cache.Stats()
	if stats.Entries > 2 {
		t.Errorf("Expected at most 2 entries due to eviction, got %d", stats.Entries)
	}
}

func TestCacheExpiration(t *testing.T) {
	config := &CacheConfig{
		MaxSizeMB:   10,
		MaxEntries:  10,
		TTL:         10 * time.Millisecond, // Very short TTL
		CleanupFreq: 0,                     // No automatic cleanup
	}
	cache := NewCache(config)

	key := CacheKey{
		WorkflowHash: "hash1",
		ConfigHash:   "config1",
		AnalysisType: "workflow",
		Version:      "1.0",
	}

	result := &ComprehensiveAnalysisResult{
		SecurityRisks: []string{"risk1"},
	}

	cache.Put(key, result)

	// Should be found immediately
	_, found := cache.Get(key)
	if !found {
		t.Error("Expected to find cached result immediately")
	}

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	// Should not be found after expiration
	_, found = cache.Get(key)
	if found {
		t.Error("Expected cached result to be expired")
	}
}

func TestCacheStats(t *testing.T) {
	cache := NewCache(DefaultCacheConfig())

	key := CacheKey{
		WorkflowHash: "hash1",
		ConfigHash:   "config1",
		AnalysisType: "workflow",
		Version:      "1.0",
	}

	result := &ComprehensiveAnalysisResult{
		SecurityRisks: []string{"risk1"},
	}

	// Test cache miss
	_, found := cache.Get(key)
	if found {
		t.Error("Expected cache miss for non-existent key")
	}

	// Test cache hit
	cache.Put(key, result)
	_, found = cache.Get(key)
	if !found {
		t.Error("Expected cache hit for existing key")
	}

	stats := cache.Stats()
	if stats.HitCount != 1 {
		t.Errorf("Expected 1 hit, got %d", stats.HitCount)
	}
	if stats.MissCount != 1 {
		t.Errorf("Expected 1 miss, got %d", stats.MissCount)
	}
	if stats.HitRate != 50.0 {
		t.Errorf("Expected 50%% hit rate, got %.2f%%", stats.HitRate)
	}
}

func TestCachedAnalyzer(t *testing.T) {
	analyzer := NewASTAnalyzer()
	cachedAnalyzer := NewCachedAnalyzer(analyzer, DefaultCacheConfig())

	workflowContent := `
name: Test Workflow
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: echo "Hello World"
`

	config := DefaultASTConfig()

	// First analysis should be a cache miss
	result1, err := cachedAnalyzer.AnalyzeWorkflow(workflowContent, config)
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	// Second analysis should be a cache hit
	result2, err := cachedAnalyzer.AnalyzeWorkflow(workflowContent, config)
	if err != nil {
		t.Fatalf("Second analysis failed: %v", err)
	}

	// Results should be identical
	if len(result1.SecurityRisks) != len(result2.SecurityRisks) {
		t.Error("Cached result differs from original")
	}

	// Check cache stats
	stats := cachedAnalyzer.GetCacheStats()
	if stats.HitCount != 1 {
		t.Errorf("Expected 1 cache hit, got %d", stats.HitCount)
	}
	if stats.MissCount != 1 {
		t.Errorf("Expected 1 cache miss, got %d", stats.MissCount)
	}
}

func TestGenerateWorkflowKey(t *testing.T) {
	content1 := "workflow content 1"
	content2 := "workflow content 2"
	config1 := &ASTConfig{EnableActionAnalysis: true}
	config2 := &ASTConfig{EnableActionAnalysis: false}

	// Same content and config should produce same key
	key1 := GenerateWorkflowKey(content1, config1, "workflow")
	key2 := GenerateWorkflowKey(content1, config1, "workflow")
	if key1.String() != key2.String() {
		t.Error("Same inputs should produce same cache key")
	}

	// Different content should produce different keys
	key3 := GenerateWorkflowKey(content2, config1, "workflow")
	if key1.String() == key3.String() {
		t.Error("Different content should produce different cache keys")
	}

	// Different config should produce different keys
	key4 := GenerateWorkflowKey(content1, config2, "workflow")
	if key1.String() == key4.String() {
		t.Error("Different config should produce different cache keys")
	}
}

func BenchmarkCacheOperations(b *testing.B) {
	cache := NewCache(DefaultCacheConfig())

	key := CacheKey{
		WorkflowHash: "benchhash",
		ConfigHash:   "benchconfig",
		AnalysisType: "workflow",
		Version:      "1.0",
	}

	result := &ComprehensiveAnalysisResult{
		SecurityRisks: []string{"risk1", "risk2", "risk3"},
	}

	b.ResetTimer()

	b.Run("Put", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			testKey := key
			testKey.WorkflowHash = fmt.Sprintf("hash%d", i)
			cache.Put(testKey, result)
		}
	})

	// Pre-populate cache for get benchmark
	cache.Put(key, result)

	b.Run("Get", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			cache.Get(key)
		}
	})
}

func BenchmarkMetricsCollection(b *testing.B) {
	collector := NewMetricsCollector()

	b.ResetTimer()

	b.Run("RecordAnalysis", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			collector.RecordAnalysis(
				time.Duration(i%10)*time.Millisecond,
				time.Duration(i%20)*time.Millisecond,
				"medium",
				nil,
			)
		}
	})

	b.Run("RecordComponentExecution", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			collector.RecordComponentExecution(
				fmt.Sprintf("component%d", i%5),
				time.Duration(i%10)*time.Millisecond,
				nil,
			)
		}
	})
}
