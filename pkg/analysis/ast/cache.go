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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// CacheKey represents a unique identifier for cached analysis results
type CacheKey struct {
	WorkflowHash string
	ConfigHash   string
	AnalysisType string
	Version      string
}

// String returns a string representation of the cache key
func (ck CacheKey) String() string {
	return fmt.Sprintf("%s:%s:%s:%s", ck.WorkflowHash, ck.ConfigHash, ck.AnalysisType, ck.Version)
}

// CachedResult represents a cached analysis result with metadata
type CachedResult struct {
	Key         CacheKey
	Result      interface{}
	CreatedAt   time.Time
	AccessedAt  time.Time
	AccessCount int64
	Size        int64 // Estimated size in bytes
}

// Cache provides thread-safe caching for analysis results
type Cache struct {
	mu          sync.RWMutex
	data        map[string]*CachedResult
	maxSize     int64         // Maximum cache size in bytes
	currentSize int64         // Current cache size in bytes
	maxEntries  int           // Maximum number of entries
	ttl         time.Duration // Time to live for entries
	hitCount    int64
	missCount   int64
}

// CacheConfig configures cache behavior
type CacheConfig struct {
	MaxSizeMB   int           // Maximum cache size in MB
	MaxEntries  int           // Maximum number of cache entries
	TTL         time.Duration // Time to live for entries
	CleanupFreq time.Duration // Frequency of cache cleanup
}

// DefaultCacheConfig returns sensible default cache configuration
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		MaxSizeMB:   100,  // 100MB default
		MaxEntries:  1000, // 1000 entries default
		TTL:         30 * time.Minute,
		CleanupFreq: 5 * time.Minute,
	}
}

// NewCache creates a new cache with the given configuration
func NewCache(config *CacheConfig) *Cache {
	if config == nil {
		config = DefaultCacheConfig()
	}

	cache := &Cache{
		data:       make(map[string]*CachedResult),
		maxSize:    int64(config.MaxSizeMB) * 1024 * 1024, // Convert MB to bytes
		maxEntries: config.MaxEntries,
		ttl:        config.TTL,
	}

	// Start cleanup goroutine
	go cache.startCleanupWorker(config.CleanupFreq)

	return cache
}

// Get retrieves a cached result by key
func (c *Cache) Get(key CacheKey) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keyStr := key.String()
	cached, exists := c.data[keyStr]

	if !exists {
		c.missCount++
		return nil, false
	}

	// Check if expired
	if c.isExpired(cached) {
		c.missCount++
		return nil, false
	}

	// Update access metadata
	cached.AccessedAt = time.Now()
	cached.AccessCount++
	c.hitCount++

	return cached.Result, true
}

// Put stores a result in the cache
func (c *Cache) Put(key CacheKey, result interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	keyStr := key.String()
	size := c.estimateSize(result)

	// Check if we need to evict entries
	c.makeRoom(size)

	// Store the new entry
	cached := &CachedResult{
		Key:         key,
		Result:      result,
		CreatedAt:   time.Now(),
		AccessedAt:  time.Now(),
		AccessCount: 1,
		Size:        size,
	}

	// Remove old entry if it exists
	if oldCached, exists := c.data[keyStr]; exists {
		c.currentSize -= oldCached.Size
	}

	c.data[keyStr] = cached
	c.currentSize += size
}

// Clear removes all entries from the cache
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data = make(map[string]*CachedResult)
	c.currentSize = 0
	c.hitCount = 0
	c.missCount = 0
}

// Stats returns cache statistics
func (c *Cache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total := c.hitCount + c.missCount
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(c.hitCount) / float64(total) * 100
	}

	return CacheStats{
		Entries:      len(c.data),
		CurrentSize:  c.currentSize,
		MaxSize:      c.maxSize,
		HitCount:     c.hitCount,
		MissCount:    c.missCount,
		HitRate:      hitRate,
		UsagePercent: float64(c.currentSize) / float64(c.maxSize) * 100,
	}
}

// CacheStats provides cache performance statistics
type CacheStats struct {
	Entries      int     `json:"entries"`
	CurrentSize  int64   `json:"current_size_bytes"`
	MaxSize      int64   `json:"max_size_bytes"`
	HitCount     int64   `json:"hit_count"`
	MissCount    int64   `json:"miss_count"`
	HitRate      float64 `json:"hit_rate_percent"`
	UsagePercent float64 `json:"usage_percent"`
}

// GenerateWorkflowKey creates a cache key for workflow analysis
func GenerateWorkflowKey(workflowContent string, config *ASTConfig, analysisType string) CacheKey {
	workflowHash := hashString(workflowContent)
	configHash := hashConfig(config)

	return CacheKey{
		WorkflowHash: workflowHash,
		ConfigHash:   configHash,
		AnalysisType: analysisType,
		Version:      "1.0", // Increment when analysis logic changes
	}
}

// makeRoom evicts entries to make room for new entry of given size
func (c *Cache) makeRoom(newEntrySize int64) {
	// Check if we need to evict by size
	for c.currentSize+newEntrySize > c.maxSize && len(c.data) > 0 {
		c.evictLRU()
	}

	// Check if we need to evict by count
	for len(c.data) >= c.maxEntries && c.maxEntries > 0 {
		c.evictLRU()
	}
}

// evictLRU removes the least recently used entry
func (c *Cache) evictLRU() {
	if len(c.data) == 0 {
		return
	}

	var oldestKey string
	var oldestTime time.Time = time.Now()

	// Find the least recently accessed entry
	for key, cached := range c.data {
		if cached.AccessedAt.Before(oldestTime) {
			oldestTime = cached.AccessedAt
			oldestKey = key
		}
	}

	// Remove the oldest entry
	if oldestKey != "" {
		if cached, exists := c.data[oldestKey]; exists {
			c.currentSize -= cached.Size
			delete(c.data, oldestKey)
		}
	}
}

// isExpired checks if a cached entry has expired
func (c *Cache) isExpired(cached *CachedResult) bool {
	if c.ttl <= 0 {
		return false // No expiration
	}
	return time.Since(cached.CreatedAt) > c.ttl
}

// startCleanupWorker starts a background worker to clean up expired entries
func (c *Cache) startCleanupWorker(frequency time.Duration) {
	if frequency <= 0 {
		return
	}

	ticker := time.NewTicker(frequency)
	defer ticker.Stop()

	for range ticker.C {
		c.cleanupExpired()
	}
}

// cleanupExpired removes all expired entries
func (c *Cache) cleanupExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ttl <= 0 {
		return
	}

	now := time.Now()
	for key, cached := range c.data {
		if now.Sub(cached.CreatedAt) > c.ttl {
			c.currentSize -= cached.Size
			delete(c.data, key)
		}
	}
}

// estimateSize estimates the memory size of a cached object
func (c *Cache) estimateSize(obj interface{}) int64 {
	// This is a rough estimation - in production you might want a more accurate method
	switch v := obj.(type) {
	case string:
		return int64(len(v))
	case []byte:
		return int64(len(v))
	case *ComprehensiveAnalysisResult:
		// Estimate based on number of findings and their content
		size := int64(1024) // Base overhead
		if v != nil {
			size += int64(len(v.SecurityRisks)) * 512
			size += int64(len(v.DataFlows)) * 256
			size += int64(len(v.ActionAnalyses)) * 128
			size += int64(len(v.ShellAnalyses)) * 128
		}
		return size
	default:
		return 1024 // Default estimate
	}
}

// hashString creates a SHA256 hash of a string
func hashString(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}

// hashConfig creates a hash of the configuration
func hashConfig(config *ASTConfig) string {
	if config == nil {
		return "default"
	}

	// Create a deterministic string representation of the config
	configStr := fmt.Sprintf(
		"action:%t,shell:%t,reachability:%t,marketplace:%t,complexity:%d,context:%t",
		config.EnableActionAnalysis,
		config.EnableShellAnalysis,
		config.EnableAdvancedReachability,
		config.TrustMarketplaceActions,
		config.MaxComplexityThreshold,
		config.EnableContextAnalysis,
	)

	return hashString(configStr)
}

// CachedAnalyzer wraps an AST analyzer with caching capabilities
type CachedAnalyzer struct {
	analyzer *ASTAnalyzer
	cache    *Cache
	metrics  *MetricsCollector
}

// NewCachedAnalyzer creates a new cached analyzer
func NewCachedAnalyzer(analyzer *ASTAnalyzer, cacheConfig *CacheConfig) *CachedAnalyzer {
	return &CachedAnalyzer{
		analyzer: analyzer,
		cache:    NewCache(cacheConfig),
		metrics:  NewMetricsCollector(),
	}
}

// AnalyzeWorkflow performs cached workflow analysis
func (ca *CachedAnalyzer) AnalyzeWorkflow(workflowContent string, config *ASTConfig) (*ComprehensiveAnalysisResult, error) {
	// Generate cache key
	key := GenerateWorkflowKey(workflowContent, config, "workflow")

	// Try to get from cache
	if cached, found := ca.cache.Get(key); found {
		ca.metrics.RecordCacheHit()
		if result, ok := cached.(*ComprehensiveAnalysisResult); ok {
			return result, nil
		}
	}

	ca.metrics.RecordCacheMiss()

	// Parse workflow first
	workflow, err := ca.analyzer.ParseWorkflow(workflowContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse workflow: %w", err)
	}

	// Perform analysis
	startTime := time.Now()
	result, err := ca.analyzer.AnalyzeWorkflowComprehensive(workflow)
	analysisTime := time.Since(startTime)

	// Record metrics
	ca.metrics.RecordAnalysis(0, analysisTime, "medium", err)

	// Cache the result if successful
	if err == nil && result != nil {
		ca.cache.Put(key, result)
	}

	return result, err
}

// GetCacheStats returns cache statistics
func (ca *CachedAnalyzer) GetCacheStats() CacheStats {
	return ca.cache.Stats()
}

// GetMetrics returns performance metrics
func (ca *CachedAnalyzer) GetMetrics() *Metrics {
	return ca.metrics.GetMetrics()
}

// ClearCache clears the analysis cache
func (ca *CachedAnalyzer) ClearCache() {
	ca.cache.Clear()
}
