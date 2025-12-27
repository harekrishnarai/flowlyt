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
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/term"
)

// ColorLevel represents the terminal's color capability
type ColorLevel int

const (
	// ColorLevelNone represents no color support
	ColorLevelNone ColorLevel = iota
	// ColorLevelBasic represents 16-color support
	ColorLevelBasic
	// ColorLevel256 represents 256-color support
	ColorLevel256
	// ColorLevelTrueColor represents 24-bit true color support
	ColorLevelTrueColor
)

// Terminal provides intelligent terminal output capabilities
type Terminal struct {
	out        io.Writer
	err        io.Writer
	width      int
	height     int
	colorLevel ColorLevel
	isTTY      bool
	mu         sync.Mutex
}

// Style represents text styling options
type Style struct {
	Foreground Color
	Background Color
	Bold       bool
	Italic     bool
	Underline  bool
	Dim        bool
	Blink      bool
	Reverse    bool
	Hidden     bool
	Strike     bool
}

// Color represents a terminal color
type Color struct {
	R, G, B uint8
	IsRGB   bool
	Code    int // ANSI color code for non-RGB colors
}

var (
	// Standard ANSI colors
	ColorBlack   = Color{Code: 30}
	ColorRed     = Color{Code: 31}
	ColorGreen   = Color{Code: 32}
	ColorYellow  = Color{Code: 33}
	ColorBlue    = Color{Code: 34}
	ColorMagenta = Color{Code: 35}
	ColorCyan    = Color{Code: 36}
	ColorWhite   = Color{Code: 37}

	// Bright colors
	ColorBrightBlack   = Color{Code: 90}
	ColorBrightRed     = Color{Code: 91}
	ColorBrightGreen   = Color{Code: 92}
	ColorBrightYellow  = Color{Code: 93}
	ColorBrightBlue    = Color{Code: 94}
	ColorBrightMagenta = Color{Code: 95}
	ColorBrightCyan    = Color{Code: 96}
	ColorBrightWhite   = Color{Code: 97}

	// Presets for common use cases
	ColorCritical = Color{R: 220, G: 38, B: 38, IsRGB: true}   // Bright red
	ColorHigh     = Color{R: 251, G: 191, B: 36, IsRGB: true}  // Orange/Yellow
	ColorMedium   = Color{R: 251, G: 146, B: 60, IsRGB: true}  // Orange
	ColorLow      = Color{R: 59, G: 130, B: 246, IsRGB: true}  // Blue
	ColorInfo     = Color{R: 99, G: 102, B: 241, IsRGB: true}  // Indigo
	ColorSuccess  = Color{R: 34, G: 197, B: 94, IsRGB: true}   // Green
	ColorWarning  = Color{R: 234, G: 179, B: 8, IsRGB: true}   // Amber
	ColorError    = Color{R: 239, G: 68, B: 68, IsRGB: true}   // Red
)

var (
	defaultTerminal     *Terminal
	defaultTerminalOnce sync.Once
)

// New creates a new Terminal instance
func New(out, err io.Writer) *Terminal {
	t := &Terminal{
		out: out,
		err: err,
	}
	t.detect()
	return t
}

// Default returns the default terminal instance
func Default() *Terminal {
	defaultTerminalOnce.Do(func() {
		defaultTerminal = New(os.Stdout, os.Stderr)
	})
	return defaultTerminal
}

// detect determines terminal capabilities
func (t *Terminal) detect() {
	// Check if stdout is a terminal
	if f, ok := t.out.(*os.File); ok {
		t.isTTY = term.IsTerminal(int(f.Fd()))
		if t.isTTY {
			width, height, err := term.GetSize(int(f.Fd()))
			if err == nil {
				t.width = width
				t.height = height
			} else {
				// Default fallback
				t.width = 80
				t.height = 24
			}
		}
	}

	// Detect color level
	t.colorLevel = detectColorLevel()
}

// detectColorLevel determines the terminal's color capability
func detectColorLevel() ColorLevel {
	// Check NO_COLOR environment variable
	if os.Getenv("NO_COLOR") != "" {
		return ColorLevelNone
	}

	// Check TERM environment variable
	term := os.Getenv("TERM")
	colorTerm := os.Getenv("COLORTERM")

	// True color support
	if colorTerm == "truecolor" || colorTerm == "24bit" {
		return ColorLevelTrueColor
	}

	// 256 color support
	if strings.Contains(term, "256color") || strings.Contains(term, "256") {
		return ColorLevel256
	}

	// Check for xterm variants
	if strings.HasPrefix(term, "xterm") ||
		strings.HasPrefix(term, "screen") ||
		strings.HasPrefix(term, "tmux") ||
		term == "alacritty" ||
		term == "kitty" {
		return ColorLevel256
	}

	// Basic color support
	if term != "" && term != "dumb" {
		return ColorLevelBasic
	}

	return ColorLevelNone
}

// Width returns the terminal width
func (t *Terminal) Width() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.width == 0 {
		return 80 // Default
	}
	return t.width
}

// Height returns the terminal height
func (t *Terminal) Height() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.height == 0 {
		return 24 // Default
	}
	return t.height
}

// ColorLevel returns the terminal's color capability
func (t *Terminal) ColorLevel() ColorLevel {
	return t.colorLevel
}

// IsTTY returns true if the output is a terminal
func (t *Terminal) IsTTY() bool {
	return t.isTTY
}

// Print writes formatted text to the terminal
func (t *Terminal) Print(text string) {
	fmt.Fprint(t.out, text)
}

// Println writes formatted text with a newline to the terminal
func (t *Terminal) Println(text string) {
	fmt.Fprintln(t.out, text)
}

// Printf writes formatted text to the terminal
func (t *Terminal) Printf(format string, args ...interface{}) {
	fmt.Fprintf(t.out, format, args...)
}

// PrintStyled writes styled text to the terminal
func (t *Terminal) PrintStyled(text string, style Style) {
	if t.colorLevel == ColorLevelNone || !t.isTTY {
		fmt.Fprint(t.out, text)
		return
	}

	fmt.Fprint(t.out, t.applyStyle(text, style))
}

// PrintlnStyled writes styled text with a newline to the terminal
func (t *Terminal) PrintlnStyled(text string, style Style) {
	if t.colorLevel == ColorLevelNone || !t.isTTY {
		fmt.Fprintln(t.out, text)
		return
	}

	fmt.Fprintln(t.out, t.applyStyle(text, style))
}

// Error writes to stderr
func (t *Terminal) Error(text string) {
	fmt.Fprint(t.err, text)
}

// Errorln writes to stderr with a newline
func (t *Terminal) Errorln(text string) {
	fmt.Fprintln(t.err, text)
}

// Errorf writes formatted text to stderr
func (t *Terminal) Errorf(format string, args ...interface{}) {
	fmt.Fprintf(t.err, format, args...)
}

// applyStyle applies the style to text and returns the styled string
func (t *Terminal) applyStyle(text string, style Style) string {
	if t.colorLevel == ColorLevelNone {
		return text
	}

	var codes []string

	// Text attributes
	if style.Bold {
		codes = append(codes, "1")
	}
	if style.Dim {
		codes = append(codes, "2")
	}
	if style.Italic {
		codes = append(codes, "3")
	}
	if style.Underline {
		codes = append(codes, "4")
	}
	if style.Blink {
		codes = append(codes, "5")
	}
	if style.Reverse {
		codes = append(codes, "7")
	}
	if style.Hidden {
		codes = append(codes, "8")
	}
	if style.Strike {
		codes = append(codes, "9")
	}

	// Foreground color
	if style.Foreground.IsRGB && t.colorLevel >= ColorLevelTrueColor {
		codes = append(codes, fmt.Sprintf("38;2;%d;%d;%d",
			style.Foreground.R, style.Foreground.G, style.Foreground.B))
	} else if style.Foreground.IsRGB && t.colorLevel == ColorLevel256 {
		// Convert RGB to 256 color
		codes = append(codes, fmt.Sprintf("38;5;%d", rgbTo256(style.Foreground.R, style.Foreground.G, style.Foreground.B)))
	} else if style.Foreground.Code > 0 {
		codes = append(codes, fmt.Sprintf("%d", style.Foreground.Code))
	}

	// Background color
	if style.Background.IsRGB && t.colorLevel >= ColorLevelTrueColor {
		codes = append(codes, fmt.Sprintf("48;2;%d;%d;%d",
			style.Background.R, style.Background.G, style.Background.B))
	} else if style.Background.IsRGB && t.colorLevel == ColorLevel256 {
		// Convert RGB to 256 color
		codes = append(codes, fmt.Sprintf("48;5;%d", rgbTo256(style.Background.R, style.Background.G, style.Background.B)))
	} else if style.Background.Code > 0 {
		codes = append(codes, fmt.Sprintf("%d", style.Background.Code+10)) // Background codes are +10
	}

	if len(codes) == 0 {
		return text
	}

	return fmt.Sprintf("\x1b[%sm%s\x1b[0m", strings.Join(codes, ";"), text)
}

// rgbTo256 converts RGB values to the closest 256-color palette index
func rgbTo256(r, g, b uint8) int {
	// Grayscale
	if r == g && g == b {
		if r < 8 {
			return 16
		}
		if r > 248 {
			return 231
		}
		return int(((r-8)/10)+232)
	}

	// Color
	r6 := int(r) / 51
	g6 := int(g) / 51
	b6 := int(b) / 51

	return 16 + (36 * r6) + (6 * g6) + b6
}

// RGB creates a color from RGB values
func RGB(r, g, b uint8) Color {
	return Color{R: r, G: g, B: b, IsRGB: true}
}

// NewStyle creates a new style
func NewStyle() Style {
	return Style{}
}

// WithForeground sets the foreground color
func (s Style) WithForeground(c Color) Style {
	s.Foreground = c
	return s
}

// WithBackground sets the background color
func (s Style) WithBackground(c Color) Style {
	s.Background = c
	return s
}

// WithBold enables bold text
func (s Style) WithBold() Style {
	s.Bold = true
	return s
}

// WithItalic enables italic text
func (s Style) WithItalic() Style {
	s.Italic = true
	return s
}

// WithUnderline enables underlined text
func (s Style) WithUnderline() Style {
	s.Underline = true
	return s
}

// WithDim enables dim text
func (s Style) WithDim() Style {
	s.Dim = true
	return s
}

// ClearLine clears the current line
func (t *Terminal) ClearLine() {
	if !t.isTTY {
		return
	}
	fmt.Fprint(t.out, "\r\x1b[K")
}

// MoveCursor moves the cursor to the specified position
func (t *Terminal) MoveCursor(line, col int) {
	if !t.isTTY {
		return
	}
	fmt.Fprintf(t.out, "\x1b[%d;%dH", line, col)
}

// SaveCursor saves the current cursor position
func (t *Terminal) SaveCursor() {
	if !t.isTTY {
		return
	}
	fmt.Fprint(t.out, "\x1b[s")
}

// RestoreCursor restores the saved cursor position
func (t *Terminal) RestoreCursor() {
	if !t.isTTY {
		return
	}
	fmt.Fprint(t.out, "\x1b[u")
}

// HideCursor hides the cursor
func (t *Terminal) HideCursor() {
	if !t.isTTY {
		return
	}
	fmt.Fprint(t.out, "\x1b[?25l")
}

// ShowCursor shows the cursor
func (t *Terminal) ShowCursor() {
	if !t.isTTY {
		return
	}
	fmt.Fprint(t.out, "\x1b[?25h")
}

// Box characters for drawing
const (
	BoxTopLeft     = "┌"
	BoxTopRight    = "┐"
	BoxBottomLeft  = "└"
	BoxBottomRight = "┘"
	BoxHorizontal  = "─"
	BoxVertical    = "│"
	BoxTeeLeft     = "├"
	BoxTeeRight    = "┤"
	BoxTeeTop      = "┬"
	BoxTeeBottom   = "┴"
	BoxCross       = "┼"
)

// DrawBox draws a box with the given dimensions
func (t *Terminal) DrawBox(width, height int, title string) {
	if width < 4 || height < 3 {
		return
	}

	// Top border with title
	t.Print(BoxTopLeft)
	if title != "" {
		titleLen := len(title) + 2
		if titleLen < width-2 {
			t.Print(" " + title + " ")
			t.Print(strings.Repeat(BoxHorizontal, width-titleLen-2))
		} else {
			t.Print(strings.Repeat(BoxHorizontal, width-2))
		}
	} else {
		t.Print(strings.Repeat(BoxHorizontal, width-2))
	}
	t.Println(BoxTopRight)

	// Middle rows
	for i := 0; i < height-2; i++ {
		t.Print(BoxVertical)
		t.Print(strings.Repeat(" ", width-2))
		t.Println(BoxVertical)
	}

	// Bottom border
	t.Print(BoxBottomLeft)
	t.Print(strings.Repeat(BoxHorizontal, width-2))
	t.Println(BoxBottomRight)
}

// Truncate truncates text to fit the terminal width
func (t *Terminal) Truncate(text string, maxWidth int) string {
	if maxWidth <= 0 {
		maxWidth = t.Width()
	}
	if len(text) <= maxWidth {
		return text
	}
	if maxWidth < 4 {
		return text[:maxWidth]
	}
	return text[:maxWidth-3] + "..."
}

// Wrap wraps text to fit the terminal width
func (t *Terminal) Wrap(text string, width int) []string {
	if width <= 0 {
		width = t.Width()
	}

	var lines []string
	words := strings.Fields(text)
	if len(words) == 0 {
		return lines
	}

	currentLine := ""
	for _, word := range words {
		if currentLine == "" {
			currentLine = word
		} else if len(currentLine)+1+len(word) <= width {
			currentLine += " " + word
		} else {
			lines = append(lines, currentLine)
			currentLine = word
		}
	}

	if currentLine != "" {
		lines = append(lines, currentLine)
	}

	return lines
}
