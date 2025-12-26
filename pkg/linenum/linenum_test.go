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
	"strings"
	"testing"
)

func TestNewLineMapper(t *testing.T) {
	content := []byte("line 1\nline 2\nline 3")
	lm := NewLineMapper(content)

	if lm.content != "line 1\nline 2\nline 3" {
		t.Errorf("Expected content to be set correctly")
	}

	if !lm.initialized {
		t.Errorf("Expected LineMapper to be initialized")
	}

	if lm.TotalLines() != 3 {
		t.Errorf("Expected 3 lines, got %d", lm.TotalLines())
	}
}

func TestLineMapper_GetLine(t *testing.T) {
	content := "first line\nsecond line\nthird line"
	lm := NewLineMapperFromString(content)

	tests := []struct {
		lineNum  int
		expected string
	}{
		{1, "first line"},
		{2, "second line"},
		{3, "third line"},
		{0, ""},  // Invalid line number
		{4, ""},  // Beyond content
		{-1, ""}, // Negative line number
	}

	for _, test := range tests {
		result := lm.GetLine(test.lineNum)
		if result != test.expected {
			t.Errorf("GetLine(%d) = %q, want %q", test.lineNum, result, test.expected)
		}
	}
}

func TestLineMapper_GetLines(t *testing.T) {
	content := "line 1\nline 2\nline 3\nline 4\nline 5"
	lm := NewLineMapperFromString(content)

	tests := []struct {
		startLine int
		endLine   int
		expected  []string
	}{
		{1, 3, []string{"line 1", "line 2", "line 3"}},
		{2, 4, []string{"line 2", "line 3", "line 4"}},
		{1, 1, []string{"line 1"}},
		{5, 5, []string{"line 5"}},
		{0, 2, []string{"line 1", "line 2"}},            // Auto-correct start
		{3, 10, []string{"line 3", "line 4", "line 5"}}, // Auto-correct end
		{4, 2, []string{}},                              // Invalid range
	}

	for _, test := range tests {
		result := lm.GetLines(test.startLine, test.endLine)
		if !slicesEqual(result, test.expected) {
			t.Errorf("GetLines(%d, %d) = %v, want %v", test.startLine, test.endLine, result, test.expected)
		}
	}
}

func TestLineMapper_CharToLine(t *testing.T) {
	content := "abc\ndef\nghi"
	lm := NewLineMapperFromString(content)

	tests := []struct {
		charPos  int
		expected int
	}{
		{0, 1},   // First character of line 1
		{3, 1},   // Last character of line 1
		{4, 2},   // First character of line 2 (newline position)
		{5, 2},   // Second character of line 2
		{8, 3},   // First character of line 3
		{10, 3},  // Last character of line 3
		{-1, 0},  // Invalid position
		{100, 0}, // Beyond content
	}

	for _, test := range tests {
		result := lm.CharToLine(test.charPos)
		if result != test.expected {
			t.Errorf("CharToLine(%d) = %d, want %d", test.charPos, result, test.expected)
		}
	}
}

func TestLineMapper_LineToChar(t *testing.T) {
	content := "abc\ndef\nghi"
	lm := NewLineMapperFromString(content)

	tests := []struct {
		lineNum  int
		expected int
	}{
		{1, 0},  // Start of line 1
		{2, 4},  // Start of line 2
		{3, 8},  // Start of line 3
		{0, -1}, // Invalid line
		{4, -1}, // Beyond content
	}

	for _, test := range tests {
		result := lm.LineToChar(test.lineNum)
		if result != test.expected {
			t.Errorf("LineToChar(%d) = %d, want %d", test.lineNum, result, test.expected)
		}
	}
}

func TestLineMapper_FindLineNumber_KeyValuePair(t *testing.T) {
	yamlContent := `name: CI Pipeline
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v2
      - name: Run tests
        run: npm test`

	lm := NewLineMapperFromString(yamlContent)

	tests := []struct {
		name     string
		pattern  FindPattern
		expected int
	}{
		{
			name: "Find YAML key-value pair",
			pattern: FindPattern{
				Key:   "name",
				Value: "CI Pipeline",
			},
			expected: 1,
		},
		{
			name: "Find trigger event",
			pattern: FindPattern{
				Key:   "on",
				Value: "push",
			},
			expected: 2,
		},
		{
			name: "Find step name",
			pattern: FindPattern{
				Key:   "name",
				Value: "Checkout",
			},
			expected: 7,
		},
		{
			name: "Find step command",
			pattern: FindPattern{
				Key:   "run",
				Value: "npm test",
			},
			expected: 10,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := lm.FindLineNumber(test.pattern)
			if result == nil {
				t.Errorf("Expected to find line number, got nil")
				return
			}
			if result.LineNumber != test.expected {
				t.Errorf("Expected line %d, got %d", test.expected, result.LineNumber)
			}
		})
	}
}

func TestLineMapper_FindLineNumber_ValueOnly(t *testing.T) {
	content := `pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
    }
}`

	lm := NewLineMapperFromString(content)

	tests := []struct {
		name     string
		value    string
		expected int
	}{
		{
			name:     "Find Jenkins pipeline keyword",
			value:    "pipeline",
			expected: 1,
		},
		{
			name:     "Find stage name",
			value:    "Build",
			expected: 4,
		},
		{
			name:     "Find shell command",
			value:    "make build",
			expected: 6,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pattern := FindPattern{Value: test.value}
			result := lm.FindLineNumber(pattern)
			if result == nil {
				t.Errorf("Expected to find line number for %q, got nil", test.value)
				return
			}
			if result.LineNumber != test.expected {
				t.Errorf("Expected line %d for %q, got %d", test.expected, test.value, result.LineNumber)
			}
		})
	}
}

func TestLineMapper_FindLineNumber_WithContext(t *testing.T) {
	content := `step1: command1
step2: command2
step3: command3
step4: command4
step5: command5`

	lm := NewLineMapperFromString(content)

	pattern := FindPattern{
		Key:           "step3",
		Value:         "command3",
		ContextBefore: 1,
		ContextAfter:  1,
	}

	result := lm.FindLineNumber(pattern)
	if result == nil {
		t.Fatal("Expected to find line number, got nil")
	}

	if result.LineNumber != 3 {
		t.Errorf("Expected line 3, got %d", result.LineNumber)
	}

	expectedBefore := []string{"step2: command2"}
	if !slicesEqual(result.ContextBefore, expectedBefore) {
		t.Errorf("Expected context before %v, got %v", expectedBefore, result.ContextBefore)
	}

	expectedAfter := []string{"step4: command4"}
	if !slicesEqual(result.ContextAfter, expectedAfter) {
		t.Errorf("Expected context after %v, got %v", expectedAfter, result.ContextAfter)
	}
}

func TestLineMapper_FindPattern_Regex(t *testing.T) {
	content := `This is line 1 with email user@example.com
Line 2 has another email: admin@test.org  
Line 3 has no email
Line 4: contact support@company.com for help`

	lm := NewLineMapperFromString(content)

	// Find email addresses
	emailRegex := regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`)
	results := lm.FindPattern(emailRegex)

	if len(results) != 3 {
		t.Errorf("Expected 3 email matches, got %d", len(results))
	}

	expectedEmails := []string{"user@example.com", "admin@test.org", "support@company.com"}
	expectedLines := []int{1, 2, 4}

	for i, result := range results {
		if i >= len(expectedEmails) {
			break
		}

		if result.MatchedText != expectedEmails[i] {
			t.Errorf("Expected email %q, got %q", expectedEmails[i], result.MatchedText)
		}

		if result.LineNumber != expectedLines[i] {
			t.Errorf("Expected email %q on line %d, got line %d", expectedEmails[i], expectedLines[i], result.LineNumber)
		}
	}
}

func TestLineMapper_FuzzyMatch(t *testing.T) {
	content := `step1:
  name: Build and test application
  run: |
    npm install
    npm run build
    npm test`

	lm := NewLineMapperFromString(content)

	// Try to find a command that spans multiple words
	pattern := FindPattern{Value: "npm run build"}
	result := lm.FindLineNumber(pattern)

	if result == nil {
		t.Fatal("Expected to find fuzzy match, got nil")
	}

	// Should find the line containing "npm run build"
	if !strings.Contains(result.LineContent, "npm run build") {
		t.Errorf("Expected line to contain 'npm run build', got: %q", result.LineContent)
	}
}

func TestSimpleFindLineNumber_BackwardCompatibility(t *testing.T) {
	content := `name: Test Workflow
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v2`

	// Test the backward compatibility function
	lineToChar := BuildLineToCharMap(content)

	tests := []struct {
		key      string
		value    string
		expected int
	}{
		{"name", "Test Workflow", 1},
		{"on", "push", 2},
		{"name", "Checkout", 7},
		{"uses", "actions/checkout@v2", 8},
		{"nonexistent", "value", 0},
	}

	for _, test := range tests {
		result := SimpleFindLineNumber(content, test.key, test.value, lineToChar)
		if result != test.expected {
			t.Errorf("SimpleFindLineNumber(%q, %q) = %d, want %d",
				test.key, test.value, result, test.expected)
		}
	}
}

func TestBuildLineToCharMap(t *testing.T) {
	content := "abc\ndef\nghi"
	lineToChar := BuildLineToCharMap(content)

	expected := []int{0, 4, 8, 12} // Start positions of each line + final position

	if len(lineToChar) != len(expected) {
		t.Errorf("Expected lineToChar length %d, got %d", len(expected), len(lineToChar))
	}

	for i, expectedPos := range expected {
		if i < len(lineToChar) && lineToChar[i] != expectedPos {
			t.Errorf("lineToChar[%d] = %d, want %d", i, lineToChar[i], expectedPos)
		}
	}
}

func TestLineMapper_EdgeCases(t *testing.T) {
	t.Run("Empty content", func(t *testing.T) {
		lm := NewLineMapperFromString("")
		if lm.TotalLines() != 1 { // Empty content still has 1 line
			t.Errorf("Expected 1 line for empty content, got %d", lm.TotalLines())
		}
	})

	t.Run("Single line without newline", func(t *testing.T) {
		lm := NewLineMapperFromString("single line")
		if lm.TotalLines() != 1 {
			t.Errorf("Expected 1 line, got %d", lm.TotalLines())
		}
		if lm.GetLine(1) != "single line" {
			t.Errorf("Expected 'single line', got %q", lm.GetLine(1))
		}
	})

	t.Run("Content with only newlines", func(t *testing.T) {
		lm := NewLineMapperFromString("\n\n\n")
		if lm.TotalLines() != 4 {
			t.Errorf("Expected 4 lines, got %d", lm.TotalLines())
		}
	})

	t.Run("Non-existent pattern", func(t *testing.T) {
		lm := NewLineMapperFromString("line 1\nline 2")
		pattern := FindPattern{Value: "non-existent"}
		result := lm.FindLineNumber(pattern)
		if result != nil {
			t.Errorf("Expected nil for non-existent pattern, got %v", result)
		}
	})
}

// Helper function to compare string slices
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
