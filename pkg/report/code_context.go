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

package report

import (
	"fmt"
	"strings"
)

// CodeLine represents a single line of code in a context snippet.
type CodeLine struct {
	Line      int    `json:"line"`
	Content   string `json:"content"`
	Highlight bool   `json:"highlight,omitempty"`
}

// CodeContext represents a snippet of code around a finding.
type CodeContext struct {
	LineNumber int        `json:"lineNumber"`
	StartLine  int        `json:"startLine"`
	EndLine    int        `json:"endLine"`
	Lines      []CodeLine `json:"lines"`
	Snippet    string     `json:"snippet"`
}

func buildCodeContext(filePath string, lineNumber int) *CodeContext {
	if filePath == "" || lineNumber == 0 {
		return nil
	}

	lines := loadFileLines(filePath, lineNumber)
	if len(lines) == 0 {
		return nil
	}

	minLine := lineNumber
	maxLine := lineNumber
	for lineNo := range lines {
		if lineNo < minLine {
			minLine = lineNo
		}
		if lineNo > maxLine {
			maxLine = lineNo
		}
	}

	orderedLines := make([]CodeLine, 0, len(lines))
	for i := minLine; i <= maxLine; i++ {
		content, exists := lines[i]
		if !exists {
			continue
		}
		orderedLines = append(orderedLines, CodeLine{
			Line:      i,
			Content:   content,
			Highlight: i == lineNumber,
		})
	}

	snippet := formatSnippet(orderedLines)

	return &CodeContext{
		LineNumber: lineNumber,
		StartLine:  minLine,
		EndLine:    maxLine,
		Lines:      orderedLines,
		Snippet:    snippet,
	}
}

func formatSnippet(lines []CodeLine) string {
	if len(lines) == 0 {
		return ""
	}

	var builder strings.Builder
	for i, line := range lines {
		prefix := "  "
		if line.Highlight {
			prefix = "> "
		}
		fmt.Fprintf(&builder, "%s%4d | %s", prefix, line.Line, line.Content)
		if i < len(lines)-1 {
			builder.WriteString("\n")
		}
	}

	return builder.String()
}

func formatSnippetRaw(lines []CodeLine) string {
	if len(lines) == 0 {
		return ""
	}

	var builder strings.Builder
	for i, line := range lines {
		builder.WriteString(line.Content)
		if i < len(lines)-1 {
			builder.WriteString("\n")
		}
	}

	return builder.String()
}
