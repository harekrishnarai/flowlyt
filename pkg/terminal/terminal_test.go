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

package terminal

import (
	"bytes"
	"testing"
)

func TestTerminalDetection(t *testing.T) {
	buf := &bytes.Buffer{}
	term := New(buf, buf)

	if term == nil {
		t.Fatal("Expected terminal to be created")
	}

	// Test width detection (should fall back to default)
	width := term.Width()
	if width <= 0 {
		t.Error("Expected positive width")
	}

	// Test height detection (should fall back to default)
	height := term.Height()
	if height <= 0 {
		t.Error("Expected positive height")
	}
}

func TestColorLevel(t *testing.T) {
	level := detectColorLevel()
	if level < ColorLevelNone || level > ColorLevelTrueColor {
		t.Errorf("Invalid color level: %v", level)
	}
}

func TestStyleApplication(t *testing.T) {
	buf := &bytes.Buffer{}
	term := New(buf, buf)

	style := NewStyle().WithForeground(ColorRed).WithBold()
	term.PrintStyled("Test", style)

	output := buf.String()
	if output == "" {
		t.Error("Expected styled output")
	}
}

func TestProgressBar(t *testing.T) {
	buf := &bytes.Buffer{}
	term := New(buf, buf)

	pb := term.NewProgressBar(100)
	pb.SetPrefix("Testing")
	pb.Add(50)
	pb.Finish()

	// Just ensure no panic occurs
}

func TestSpinner(t *testing.T) {
	buf := &bytes.Buffer{}
	term := New(buf, buf)

	spinner := term.NewSpinner(SpinnerDots)
	spinner.SetMessage("Loading...")
	spinner.Start()
	spinner.Stop()

	// Just ensure no panic occurs
}

func TestTableCreation(t *testing.T) {
	buf := &bytes.Buffer{}
	term := New(buf, buf)

	table := term.NewTable([]string{"Column1", "Column2"})
	table.AddRow("Value1", "Value2")
	table.AddRow("Value3", "Value4")
	table.Render()

	output := buf.String()
	if output == "" {
		t.Error("Expected table output")
	}
}

func TestListCreation(t *testing.T) {
	buf := &bytes.Buffer{}
	term := New(buf, buf)

	list := term.NewList()
	list.Add("Item 1")
	list.Add("Item 2")
	list.AddWithLevel("Nested Item", 1)
	list.Render()

	output := buf.String()
	if output == "" {
		t.Error("Expected list output")
	}
}

func TestRGBTo256(t *testing.T) {
	tests := []struct {
		r, g, b uint8
		want    int
	}{
		{0, 0, 0, 16},       // Black
		{255, 255, 255, 231}, // White (grayscale)
		{255, 0, 0, 196},     // Red
	}

	for _, tt := range tests {
		got := rgbTo256(tt.r, tt.g, tt.b)
		if got != tt.want {
			t.Errorf("rgbTo256(%d, %d, %d) = %d, want %d", tt.r, tt.g, tt.b, got, tt.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	buf := &bytes.Buffer{}
	term := New(buf, buf)

	tests := []struct {
		input    string
		width    int
		expected string
	}{
		{"short", 10, "short"},
		{"this is a very long string", 10, "this is..."},
		{"exact", 5, "exact"},
	}

	for _, tt := range tests {
		got := term.Truncate(tt.input, tt.width)
		if got != tt.expected {
			t.Errorf("Truncate(%q, %d) = %q, want %q", tt.input, tt.width, got, tt.expected)
		}
	}
}

func TestWrap(t *testing.T) {
	buf := &bytes.Buffer{}
	term := New(buf, buf)

	text := "This is a test string that needs to be wrapped"
	lines := term.Wrap(text, 20)

	if len(lines) == 0 {
		t.Error("Expected wrapped lines")
	}

	for _, line := range lines {
		if len(line) > 20 {
			t.Errorf("Line too long: %q (%d chars)", line, len(line))
		}
	}
}

func BenchmarkStyleApplication(b *testing.B) {
	buf := &bytes.Buffer{}
	term := New(buf, buf)
	style := NewStyle().WithForeground(ColorRed).WithBold()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		term.PrintStyled("Test", style)
		buf.Reset()
	}
}

func BenchmarkRGBTo256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		rgbTo256(128, 128, 128)
	}
}
