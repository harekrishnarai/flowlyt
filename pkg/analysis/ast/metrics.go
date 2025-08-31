package ast

import (
	"fmt"
	"runtime"
	"sync"
	"time"
)

// Metrics provides observability into AST analysis performance
type Metrics struct {
	mu                  sync.RWMutex
	totalAnalyses       int64
	totalParseTime      time.Duration
	totalAnalysisTime   time.Duration
	averageParseTime    time.Duration
	averageAnalysisTime time.Duration
	peakMemoryUsage     uint64
	cacheHits           int64
	cacheMisses         int64
	errorCount          int64
	componentMetrics    map[string]*ComponentMetrics
	performanceProfile  *PerformanceProfile
	startTime           time.Time
}

// ComponentMetrics tracks performance of individual analysis components
type ComponentMetrics struct {
	Name              string
	TotalExecutions   int64
	TotalTime         time.Duration
	AverageTime       time.Duration
	MinTime           time.Duration
	MaxTime           time.Duration
	ErrorCount        int64
	LastExecutionTime time.Time
}

// PerformanceProfile tracks detailed performance characteristics
type PerformanceProfile struct {
	WorkflowSizeDistribution map[string]int64 // small, medium, large
	ComplexityMetrics        ComplexityMetrics
	ResourceUsage            ResourceUsage
	BottleneckAnalysis       BottleneckAnalysis
}

// ComplexityMetrics tracks analysis complexity patterns
type ComplexityMetrics struct {
	AverageJobCount            float64
	AverageStepCount           float64
	AverageConditionComplexity float64
	MaxCallGraphDepth          int
	AverageDataFlowCount       float64
}

// ResourceUsage tracks resource consumption
type ResourceUsage struct {
	AverageMemoryMB   float64
	PeakMemoryMB      uint64
	AverageCPUPercent float64
	GCPauseTimeMS     float64
	AllocationsPerSec float64
}

// BottleneckAnalysis identifies performance bottlenecks
type BottleneckAnalysis struct {
	SlowestComponent        string
	SlowestComponentTime    time.Duration
	MemoryIntensiveStage    string
	MostFrequentError       string
	OptimizationSuggestions []string
}

// MetricsCollector provides centralized metrics collection
type MetricsCollector struct {
	metrics *Metrics
	enabled bool
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		metrics: &Metrics{
			componentMetrics: make(map[string]*ComponentMetrics),
			performanceProfile: &PerformanceProfile{
				WorkflowSizeDistribution: make(map[string]int64),
				ComplexityMetrics:        ComplexityMetrics{},
				ResourceUsage:            ResourceUsage{},
				BottleneckAnalysis: BottleneckAnalysis{
					OptimizationSuggestions: []string{},
				},
			},
			startTime: time.Now(),
		},
		enabled: true,
	}
}

// Enable turns on metrics collection
func (mc *MetricsCollector) Enable() {
	mc.enabled = true
}

// Disable turns off metrics collection
func (mc *MetricsCollector) Disable() {
	mc.enabled = false
}

// RecordAnalysis records a complete analysis execution
func (mc *MetricsCollector) RecordAnalysis(parseTime, analysisTime time.Duration, workflowSize string, err error) {
	if !mc.enabled {
		return
	}

	mc.metrics.mu.Lock()
	defer mc.metrics.mu.Unlock()

	mc.metrics.totalAnalyses++
	mc.metrics.totalParseTime += parseTime
	mc.metrics.totalAnalysisTime += analysisTime

	// Update averages
	mc.metrics.averageParseTime = mc.metrics.totalParseTime / time.Duration(mc.metrics.totalAnalyses)
	mc.metrics.averageAnalysisTime = mc.metrics.totalAnalysisTime / time.Duration(mc.metrics.totalAnalyses)

	// Track workflow size distribution
	mc.metrics.performanceProfile.WorkflowSizeDistribution[workflowSize]++

	// Record errors
	if err != nil {
		mc.metrics.errorCount++
	}

	// Update memory usage
	mc.updateMemoryUsage()
}

// RecordComponentExecution records execution of individual components
func (mc *MetricsCollector) RecordComponentExecution(componentName string, duration time.Duration, err error) {
	if !mc.enabled {
		return
	}

	mc.metrics.mu.Lock()
	defer mc.metrics.mu.Unlock()

	component, exists := mc.metrics.componentMetrics[componentName]
	if !exists {
		component = &ComponentMetrics{
			Name:    componentName,
			MinTime: duration,
			MaxTime: duration,
		}
		mc.metrics.componentMetrics[componentName] = component
	}

	component.TotalExecutions++
	component.TotalTime += duration
	component.AverageTime = component.TotalTime / time.Duration(component.TotalExecutions)
	component.LastExecutionTime = time.Now()

	// Update min/max
	if duration < component.MinTime {
		component.MinTime = duration
	}
	if duration > component.MaxTime {
		component.MaxTime = duration
	}

	// Record errors
	if err != nil {
		component.ErrorCount++
	}
}

// RecordCacheHit records a cache hit
func (mc *MetricsCollector) RecordCacheHit() {
	if !mc.enabled {
		return
	}

	mc.metrics.mu.Lock()
	defer mc.metrics.mu.Unlock()
	mc.metrics.cacheHits++
}

// RecordCacheMiss records a cache miss
func (mc *MetricsCollector) RecordCacheMiss() {
	if !mc.enabled {
		return
	}

	mc.metrics.mu.Lock()
	defer mc.metrics.mu.Unlock()
	mc.metrics.cacheMisses++
}

// UpdateComplexityMetrics updates complexity-related metrics
func (mc *MetricsCollector) UpdateComplexityMetrics(jobCount, stepCount int, conditionComplexity float64, callGraphDepth int, dataFlowCount int) {
	if !mc.enabled {
		return
	}

	mc.metrics.mu.Lock()
	defer mc.metrics.mu.Unlock()

	profile := mc.metrics.performanceProfile
	total := float64(mc.metrics.totalAnalyses)

	// Update running averages
	profile.ComplexityMetrics.AverageJobCount = updateAverage(profile.ComplexityMetrics.AverageJobCount, float64(jobCount), total)
	profile.ComplexityMetrics.AverageStepCount = updateAverage(profile.ComplexityMetrics.AverageStepCount, float64(stepCount), total)
	profile.ComplexityMetrics.AverageConditionComplexity = updateAverage(profile.ComplexityMetrics.AverageConditionComplexity, conditionComplexity, total)
	profile.ComplexityMetrics.AverageDataFlowCount = updateAverage(profile.ComplexityMetrics.AverageDataFlowCount, float64(dataFlowCount), total)

	// Update max call graph depth
	if callGraphDepth > profile.ComplexityMetrics.MaxCallGraphDepth {
		profile.ComplexityMetrics.MaxCallGraphDepth = callGraphDepth
	}
}

// GetMetrics returns a copy of current metrics
func (mc *MetricsCollector) GetMetrics() *Metrics {
	mc.metrics.mu.RLock()
	defer mc.metrics.mu.RUnlock()

	// Create a deep copy
	metricsCopy := &Metrics{
		totalAnalyses:       mc.metrics.totalAnalyses,
		totalParseTime:      mc.metrics.totalParseTime,
		totalAnalysisTime:   mc.metrics.totalAnalysisTime,
		averageParseTime:    mc.metrics.averageParseTime,
		averageAnalysisTime: mc.metrics.averageAnalysisTime,
		peakMemoryUsage:     mc.metrics.peakMemoryUsage,
		cacheHits:           mc.metrics.cacheHits,
		cacheMisses:         mc.metrics.cacheMisses,
		errorCount:          mc.metrics.errorCount,
		componentMetrics:    make(map[string]*ComponentMetrics),
		startTime:           mc.metrics.startTime,
		performanceProfile:  &PerformanceProfile{},
	}

	// Copy component metrics
	for name, component := range mc.metrics.componentMetrics {
		metricsCopy.componentMetrics[name] = &ComponentMetrics{
			Name:              component.Name,
			TotalExecutions:   component.TotalExecutions,
			TotalTime:         component.TotalTime,
			AverageTime:       component.AverageTime,
			MinTime:           component.MinTime,
			MaxTime:           component.MaxTime,
			ErrorCount:        component.ErrorCount,
			LastExecutionTime: component.LastExecutionTime,
		}
	}

	// Copy performance profile
	if mc.metrics.performanceProfile != nil {
		metricsCopy.performanceProfile = &PerformanceProfile{
			WorkflowSizeDistribution: make(map[string]int64),
			ComplexityMetrics:        mc.metrics.performanceProfile.ComplexityMetrics,
			ResourceUsage:            mc.metrics.performanceProfile.ResourceUsage,
			BottleneckAnalysis:       mc.metrics.performanceProfile.BottleneckAnalysis,
		}

		// Copy workflow size distribution
		for size, count := range mc.metrics.performanceProfile.WorkflowSizeDistribution {
			metricsCopy.performanceProfile.WorkflowSizeDistribution[size] = count
		}
	}

	return metricsCopy
}

// GenerateReport creates a comprehensive performance report
func (mc *MetricsCollector) GenerateReport() *PerformanceReport {
	metrics := mc.GetMetrics()

	report := &PerformanceReport{
		GeneratedAt:     time.Now(),
		UpTime:          time.Since(metrics.startTime),
		TotalAnalyses:   metrics.totalAnalyses,
		Metrics:         metrics,
		Recommendations: mc.generateRecommendations(metrics),
	}

	return report
}

// PerformanceReport provides a comprehensive analysis performance overview
type PerformanceReport struct {
	GeneratedAt     time.Time     `json:"generated_at"`
	UpTime          time.Duration `json:"uptime"`
	TotalAnalyses   int64         `json:"total_analyses"`
	Metrics         *Metrics      `json:"metrics"`
	Recommendations []string      `json:"recommendations"`
}

// updateMemoryUsage updates current memory usage statistics
func (mc *MetricsCollector) updateMemoryUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	currentMB := m.Alloc / 1024 / 1024
	if currentMB > mc.metrics.peakMemoryUsage {
		mc.metrics.peakMemoryUsage = currentMB
	}

	// Update resource usage metrics
	profile := mc.metrics.performanceProfile
	profile.ResourceUsage.AverageMemoryMB = updateAverage(
		profile.ResourceUsage.AverageMemoryMB,
		float64(currentMB),
		float64(mc.metrics.totalAnalyses),
	)
	profile.ResourceUsage.PeakMemoryMB = mc.metrics.peakMemoryUsage
}

// generateRecommendations creates performance optimization recommendations
func (mc *MetricsCollector) generateRecommendations(metrics *Metrics) []string {
	recommendations := []string{}

	// High error rate
	if metrics.totalAnalyses > 10 && float64(metrics.errorCount)/float64(metrics.totalAnalyses) > 0.1 {
		recommendations = append(recommendations, "High error rate detected (>10%). Consider improving input validation.")
	}

	// Slow average analysis time
	if metrics.averageAnalysisTime > 100*time.Millisecond {
		recommendations = append(recommendations, "Average analysis time is slow (>100ms). Consider enabling caching or reducing analysis depth.")
	}

	// High memory usage
	if metrics.peakMemoryUsage > 500 {
		recommendations = append(recommendations, "High peak memory usage (>500MB). Consider processing workflows in smaller batches.")
	}

	// Low cache hit rate
	cacheTotal := metrics.cacheHits + metrics.cacheMisses
	if cacheTotal > 10 && float64(metrics.cacheHits)/float64(cacheTotal) < 0.5 {
		recommendations = append(recommendations, "Low cache hit rate (<50%). Consider increasing cache size or reviewing cache key strategy.")
	}

	// Identify slowest component
	var slowestComponent string
	var slowestTime time.Duration
	for name, component := range metrics.componentMetrics {
		if component.AverageTime > slowestTime {
			slowestTime = component.AverageTime
			slowestComponent = name
		}
	}

	if slowestComponent != "" && slowestTime > 50*time.Millisecond {
		recommendations = append(recommendations, fmt.Sprintf("Component '%s' is slow (avg: %v). Consider optimizing this component.", slowestComponent, slowestTime))
	}

	return recommendations
}

// updateAverage calculates a running average
func updateAverage(currentAvg, newValue, totalCount float64) float64 {
	if totalCount == 0 {
		return newValue
	}
	return ((currentAvg * (totalCount - 1)) + newValue) / totalCount
}

// GetCacheHitRate returns the cache hit rate as a percentage
func (m *Metrics) GetCacheHitRate() float64 {
	total := m.cacheHits + m.cacheMisses
	if total == 0 {
		return 0
	}
	return float64(m.cacheHits) / float64(total) * 100
}

// GetErrorRate returns the error rate as a percentage
func (m *Metrics) GetErrorRate() float64 {
	if m.totalAnalyses == 0 {
		return 0
	}
	return float64(m.errorCount) / float64(m.totalAnalyses) * 100
}

// GetThroughput returns analyses per second
func (m *Metrics) GetThroughput() float64 {
	uptime := time.Since(m.startTime)
	if uptime == 0 {
		return 0
	}
	return float64(m.totalAnalyses) / uptime.Seconds()
}
