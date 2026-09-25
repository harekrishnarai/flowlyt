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

package linenum

import (
	"regexp"
	"sort"
	"strings"
	"sync"
)

// LineMapper provides line number mapping and calculation services
type LineMapper struct {
	content     string
	lines       []string
	lineToChar  []int
	initialized bool
}

// MapperCache memoises mappers by content.
//
// Every rule builds a mapper for the workflow it is scanning, so without
// memoisation a single workflow is split into lines once per rule — around
// seventy times — which was the largest single source of allocation in a scan.
//
// A cache is a value that a caller owns, so its lifetime can be tied to a scan
// rather than to the process. The package keeps one default instance for
// callers that do not want to manage their own; see DefaultCache.
//
// Mappers are immutable once constructed, so a cached mapper is safe to share
// between rules and across goroutines.
type MapperCache struct {
	mu      sync.RWMutex
	entries map[uint64]*LineMapper
	limit   int
}

// DefaultMapperCacheLimit bounds the default cache. A repository has far fewer
// workflows than this, so in practice the cache holds an entire scan.
const DefaultMapperCacheLimit = 512

// NewMapperCache creates a cache holding at most limit mappers. A limit of zero
// or less uses DefaultMapperCacheLimit.
func NewMapperCache(limit int) *MapperCache {
	if limit <= 0 {
		limit = DefaultMapperCacheLimit
	}
	return &MapperCache{entries: make(map[uint64]*LineMapper), limit: limit}
}

// defaultCache backs NewLineMapper.
var defaultCache = NewMapperCache(DefaultMapperCacheLimit)

// DefaultCache returns the cache used by NewLineMapper, so that a caller can
// bound its lifetime — typically by resetting it at the start of a scan.
func DefaultCache() *MapperCache { return defaultCache }

// Get returns a mapper for the content, building one on a miss.
//
// A nil cache is valid and simply builds without memoising, so callers need no
// special case when they do not want caching.
func (c *MapperCache) Get(content []byte) *LineMapper {
	if c == nil {
		lm := &LineMapper{content: string(content)}
		lm.initialize()
		return lm
	}

	key := hashBytes(content)

	c.mu.RLock()
	cached, ok := c.entries[key]
	c.mu.RUnlock()

	// Compare the content as well as the hash: a collision must never return
	// line numbers belonging to a different file.
	if ok && cached.content == string(content) {
		return cached
	}

	lm := &LineMapper{content: string(content)}
	lm.initialize()

	c.mu.Lock()
	// Evict a single entry rather than clearing wholesale, which would discard
	// the workflow currently being scanned along with everything else.
	if len(c.entries) >= c.limit {
		for k := range c.entries {
			delete(c.entries, k)
			break
		}
	}
	c.entries[key] = lm
	c.mu.Unlock()

	return lm
}

// Len reports how many mappers are cached.
func (c *MapperCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Reset discards every cached mapper, releasing the memory held for a completed
// scan.
func (c *MapperCache) Reset() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.entries = make(map[uint64]*LineMapper)
	c.mu.Unlock()
}

// NewLineMapper creates a line mapper for the given content, memoised in the
// package default cache.
func NewLineMapper(content []byte) *LineMapper {
	return defaultCache.Get(content)
}

// hashBytes computes an FNV-1a 64-bit hash of content.
//
// This is a cache key only, never a security boundary: collisions are resolved
// by comparing the content itself.
func hashBytes(content []byte) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for _, b := range content {
		h ^= uint64(b)
		h *= prime64
	}
	return h
}

// NewLineMapperFromString creates a new line mapper from string content
func NewLineMapperFromString(content string) *LineMapper {
	lm := &LineMapper{
		content: content,
	}
	lm.initialize()
	return lm
}

// initialize builds the internal mappings between lines and character positions
func (lm *LineMapper) initialize() {
	if lm.initialized {
		return
	}

	lm.lines = strings.Split(lm.content, "\n")
	lm.lineToChar = make([]int, len(lm.lines)+1)

	// Build line-to-character position mapping. lineToChar is sorted by
	// construction, which is what lets CharToLine binary search it instead of
	// materializing a position-to-line table.
	lm.lineToChar[0] = 0
	for i, line := range lm.lines {
		lm.lineToChar[i+1] = lm.lineToChar[i] + len(line) + 1 // +1 for newline
	}

	lm.initialized = true
}

// FindPattern represents a search pattern for line number detection
type FindPattern struct {
	Key           string // YAML key (e.g., "run", "name")
	Value         string // The value to search for
	ContextBefore int    // Lines of context before the match
	ContextAfter  int    // Lines of context after the match
}

// LineResult contains the result of a line number search
type LineResult struct {
	LineNumber    int      // The line number where the pattern was found
	ColumnStart   int      // Starting column position
	ColumnEnd     int      // Ending column position
	LineContent   string   // The actual content of the line
	ContextBefore []string // Lines before the match
	ContextAfter  []string // Lines after the match
	MatchedText   string   // The exact text that was matched
}

// FindLineNumber finds the line number for a pattern with improved accuracy
func (lm *LineMapper) FindLineNumber(pattern FindPattern) *LineResult {
	if !lm.initialized {
		lm.initialize()
	}

	// Try multiple search strategies in order of preference
	strategies := []func(FindPattern) *LineResult{
		lm.findByKeyValuePair,
		lm.findByValueWithYAMLContext,
		lm.findByExactValue,
		lm.findByFuzzyMatch,
	}

	for _, strategy := range strategies {
		if result := strategy(pattern); result != nil {
			lm.addContext(result, pattern.ContextBefore, pattern.ContextAfter)
			return result
		}
	}

	return nil
}

// findByKeyValuePair searches for YAML key-value pairs
func (lm *LineMapper) findByKeyValuePair(pattern FindPattern) *LineResult {
	if pattern.Key == "" || pattern.Value == "" {
		return nil
	}

	// Try different YAML formatting patterns
	searchPatterns := []string{
		pattern.Key + ": " + pattern.Value,
		pattern.Key + ": '" + pattern.Value + "'",
		pattern.Key + ": \"" + pattern.Value + "\"",
		pattern.Key + ":" + pattern.Value,
		pattern.Key + ": |", // Multi-line string indicator
		pattern.Key + ": >", // Folded string indicator
	}

	for _, searchPattern := range searchPatterns {
		if result := lm.findExactMatch(searchPattern); result != nil {
			return result
		}
	}

	return nil
}

// findByValueWithYAMLContext searches for values within YAML structure context
func (lm *LineMapper) findByValueWithYAMLContext(pattern FindPattern) *LineResult {
	if pattern.Value == "" {
		return nil
	}

	// Search for the value in lines that look like YAML key-value pairs
	for i, line := range lm.lines {
		trimmedLine := strings.TrimSpace(line)

		// Skip empty lines and comments
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			continue
		}

		// Check if this line contains the value and looks like YAML
		if strings.Contains(line, pattern.Value) {
			// Prefer lines that have YAML structure (contain ":")
			if strings.Contains(line, ":") {
				return lm.createResult(i+1, line, pattern.Value)
			}
		}
	}

	return nil
}

// findByExactValue searches for exact value matches
func (lm *LineMapper) findByExactValue(pattern FindPattern) *LineResult {
	if pattern.Value == "" {
		return nil
	}

	return lm.findExactMatch(pattern.Value)
}

// findByFuzzyMatch performs fuzzy matching for complex scenarios
func (lm *LineMapper) findByFuzzyMatch(pattern FindPattern) *LineResult {
	if pattern.Value == "" {
		return nil
	}

	// Split the value into words and try to find lines containing most words
	words := strings.Fields(pattern.Value)
	if len(words) == 0 {
		return nil
	}

	bestMatch := -1
	bestScore := 0

	for i, line := range lm.lines {
		score := 0
		for _, word := range words {
			if strings.Contains(strings.ToLower(line), strings.ToLower(word)) {
				score++
			}
		}

		// Require at least half the words to match
		if score > bestScore && score >= len(words)/2 {
			bestScore = score
			bestMatch = i
		}
	}

	if bestMatch >= 0 {
		return lm.createResult(bestMatch+1, lm.lines[bestMatch], pattern.Value)
	}

	return nil
}

// findExactMatch finds an exact string match and returns line information
func (lm *LineMapper) findExactMatch(searchText string) *LineResult {
	index := strings.Index(lm.content, searchText)
	if index == -1 {
		return nil
	}

	lineNum := lm.CharToLine(index)
	if lineNum == 0 {
		return nil
	}

	return lm.createResult(lineNum, lm.lines[lineNum-1], searchText)
}

// createResult creates a LineResult from basic information
func (lm *LineMapper) createResult(lineNum int, lineContent, matchedText string) *LineResult {
	if lineNum <= 0 || lineNum > len(lm.lines) {
		return nil
	}

	// Find column positions
	colStart := strings.Index(lineContent, matchedText)
	colEnd := colStart + len(matchedText)
	if colStart == -1 {
		colStart = 0
		colEnd = len(lineContent)
	}

	return &LineResult{
		LineNumber:  lineNum,
		ColumnStart: colStart + 1, // 1-based column numbers
		ColumnEnd:   colEnd + 1,
		LineContent: lineContent,
		MatchedText: matchedText,
	}
}

// addContext adds context lines before and after the match
func (lm *LineMapper) addContext(result *LineResult, contextBefore, contextAfter int) {
	if result == nil {
		return
	}

	// Add context before
	startLine := result.LineNumber - contextBefore
	if startLine < 1 {
		startLine = 1
	}

	for i := startLine; i < result.LineNumber; i++ {
		if i > 0 && i <= len(lm.lines) {
			result.ContextBefore = append(result.ContextBefore, lm.lines[i-1])
		}
	}

	// Add context after
	endLine := result.LineNumber + contextAfter
	if endLine > len(lm.lines) {
		endLine = len(lm.lines)
	}

	for i := result.LineNumber + 1; i <= endLine; i++ {
		if i > 0 && i <= len(lm.lines) {
			result.ContextAfter = append(result.ContextAfter, lm.lines[i-1])
		}
	}
}

// CharToLine converts a character position to line number (1-based)
//
// lineToChar holds each line's start offset in ascending order, so the line
// containing a position is found by binary search in O(log lines). An explicit
// position-to-line table would answer in O(1) but costs O(content length) time
// and memory to build, which is a poor trade when the mapper is constructed
// once per rule per workflow.
func (lm *LineMapper) CharToLine(charPos int) int {
	if !lm.initialized {
		lm.initialize()
	}

	// Handle invalid positions
	if charPos < 0 || charPos >= len(lm.content) {
		return 0
	}

	// Smallest index whose start offset is beyond charPos; because
	// lineToChar[0] is 0 and charPos is non-negative, that index is also the
	// 1-based number of the line containing charPos.
	idx := sort.Search(len(lm.lineToChar), func(i int) bool {
		return lm.lineToChar[i] > charPos
	})
	if idx >= len(lm.lineToChar) {
		return 0
	}

	return idx
}

// LineToChar converts a line number to starting character position
func (lm *LineMapper) LineToChar(lineNum int) int {
	if !lm.initialized {
		lm.initialize()
	}

	if lineNum < 1 || lineNum > len(lm.lineToChar)-1 {
		return -1
	}

	return lm.lineToChar[lineNum-1]
}

// GetLine returns the content of a specific line (1-based)
func (lm *LineMapper) GetLine(lineNum int) string {
	if !lm.initialized {
		lm.initialize()
	}

	if lineNum < 1 || lineNum > len(lm.lines) {
		return ""
	}

	return lm.lines[lineNum-1]
}

// GetLines returns a range of lines (1-based, inclusive)
func (lm *LineMapper) GetLines(startLine, endLine int) []string {
	if !lm.initialized {
		lm.initialize()
	}

	if startLine < 1 {
		startLine = 1
	}
	if endLine > len(lm.lines) {
		endLine = len(lm.lines)
	}
	if startLine > endLine {
		return []string{}
	}

	result := make([]string, 0, endLine-startLine+1)
	for i := startLine; i <= endLine; i++ {
		result = append(result, lm.lines[i-1])
	}

	return result
}

// TotalLines returns the total number of lines in the content
func (lm *LineMapper) TotalLines() int {
	if !lm.initialized {
		lm.initialize()
	}
	return len(lm.lines)
}

// FindPattern searches for patterns using regular expressions
func (lm *LineMapper) FindPattern(regex *regexp.Regexp) []*LineResult {
	if !lm.initialized {
		lm.initialize()
	}

	var results []*LineResult
	matches := regex.FindAllStringIndex(lm.content, -1)

	for _, match := range matches {
		startPos := match[0]
		endPos := match[1]
		lineNum := lm.CharToLine(startPos)

		if lineNum > 0 {
			matchedText := lm.content[startPos:endPos]
			lineContent := lm.GetLine(lineNum)

			// Calculate column positions relative to the line
			lineStart := lm.LineToChar(lineNum)
			colStart := startPos - lineStart + 1 // 1-based
			colEnd := colStart + len(matchedText)

			result := &LineResult{
				LineNumber:  lineNum,
				ColumnStart: colStart,
				ColumnEnd:   colEnd,
				LineContent: lineContent,
				MatchedText: matchedText,
			}

			results = append(results, result)
		}
	}

	return results
}

// Helper functions for backward compatibility with existing code

// SimpleFindLineNumber provides a simple interface for basic line number finding
// This maintains compatibility with the existing findLineNumber function
func SimpleFindLineNumber(content, key, value string, lineToChar []int) int {
	lm := NewLineMapperFromString(content)

	pattern := FindPattern{
		Key:   key,
		Value: value,
	}

	result := lm.FindLineNumber(pattern)
	if result != nil {
		return result.LineNumber
	}

	return 0
}

// BuildLineToCharMap creates a character position mapping (for backward compatibility)
func BuildLineToCharMap(content string) []int {
	lines := strings.Split(content, "\n")
	lineToChar := make([]int, len(lines)+1)

	lineToChar[0] = 0
	for i, line := range lines {
		lineToChar[i+1] = lineToChar[i] + len(line) + 1 // +1 for newline
	}

	return lineToChar
}
