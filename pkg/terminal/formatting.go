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
	"strings"
)

// Table represents a formatted table
type Table struct {
	terminal *Terminal
	headers  []string
	rows     [][]string
	widths   []int
	style    TableStyle
}

// TableStyle defines the visual style of the table
type TableStyle struct {
	HeaderColor Color
	BorderColor Color
	ShowBorder  bool
	Compact     bool
}

var (
	// DefaultTableStyle is the default table style
	DefaultTableStyle = TableStyle{
		HeaderColor: ColorCyan,
		BorderColor: ColorBrightBlack,
		ShowBorder:  true,
		Compact:     false,
	}

	// CompactTableStyle is a compact table style
	CompactTableStyle = TableStyle{
		HeaderColor: ColorCyan,
		BorderColor: ColorBrightBlack,
		ShowBorder:  false,
		Compact:     true,
	}
)

// NewTable creates a new table
func (t *Terminal) NewTable(headers []string) *Table {
	return &Table{
		terminal: t,
		headers:  headers,
		rows:     make([][]string, 0),
		widths:   make([]int, len(headers)),
		style:    DefaultTableStyle,
	}
}

// SetStyle sets the table style
func (tbl *Table) SetStyle(style TableStyle) *Table {
	tbl.style = style
	return tbl
}

// AddRow adds a row to the table
func (tbl *Table) AddRow(cells ...string) *Table {
	// Pad or truncate to match header count
	row := make([]string, len(tbl.headers))
	for i := range tbl.headers {
		if i < len(cells) {
			row[i] = cells[i]
		}
	}
	tbl.rows = append(tbl.rows, row)
	return tbl
}

// calculateWidths calculates optimal column widths
func (tbl *Table) calculateWidths() {
	// Initialize with header widths
	for i, header := range tbl.headers {
		tbl.widths[i] = len(header)
	}

	// Check all rows
	for _, row := range tbl.rows {
		for i, cell := range row {
			if i < len(tbl.widths) {
				if len(cell) > tbl.widths[i] {
					tbl.widths[i] = len(cell)
				}
			}
		}
	}

	// Add padding
	if !tbl.style.Compact {
		for i := range tbl.widths {
			tbl.widths[i] += 2
		}
	}

	// Adjust for terminal width if needed
	totalWidth := 0
	for _, w := range tbl.widths {
		totalWidth += w
	}
	totalWidth += len(tbl.widths) + 1 // Borders

	termWidth := tbl.terminal.Width()
	if totalWidth > termWidth && termWidth > 0 {
		// Scale down proportionally
		scale := float64(termWidth-len(tbl.widths)-1) / float64(totalWidth-len(tbl.widths)-1)
		for i := range tbl.widths {
			tbl.widths[i] = int(float64(tbl.widths[i]) * scale)
			if tbl.widths[i] < 3 {
				tbl.widths[i] = 3
			}
		}
	}
}

// Render renders the table
func (tbl *Table) Render() {
	tbl.calculateWidths()

	headerStyle := NewStyle().WithForeground(tbl.style.HeaderColor).WithBold()
	borderStyle := NewStyle().WithForeground(tbl.style.BorderColor)

	// Top border
	if tbl.style.ShowBorder {
		tbl.renderBorder(borderStyle, BoxTopLeft, BoxHorizontal, BoxTeeTop, BoxTopRight)
	}

	// Headers
	tbl.renderRow(tbl.headers, headerStyle, borderStyle, true)

	// Header separator
	if tbl.style.ShowBorder {
		tbl.renderBorder(borderStyle, BoxTeeLeft, BoxHorizontal, BoxCross, BoxTeeRight)
	} else {
		tbl.renderSeparator(borderStyle)
	}

	// Rows
	for _, row := range tbl.rows {
		tbl.renderRow(row, NewStyle(), borderStyle, false)
	}

	// Bottom border
	if tbl.style.ShowBorder {
		tbl.renderBorder(borderStyle, BoxBottomLeft, BoxHorizontal, BoxTeeBottom, BoxBottomRight)
	}
}

// renderRow renders a single row
func (tbl *Table) renderRow(cells []string, cellStyle, borderStyle Style, isHeader bool) {
	if tbl.style.ShowBorder {
		tbl.terminal.PrintStyled(BoxVertical, borderStyle)
	}

	for i, cell := range cells {
		width := tbl.widths[i]
		padding := width - len(cell)

		if padding < 0 {
			// Truncate
			if width > 3 {
				cell = cell[:width-3] + "..."
			} else {
				cell = cell[:width]
			}
			padding = 0
		}

		if tbl.style.Compact {
			if isHeader || cellStyle.Foreground.Code != 0 || cellStyle.Foreground.IsRGB {
				tbl.terminal.PrintStyled(cell, cellStyle)
			} else {
				tbl.terminal.Print(cell)
			}
			if i < len(cells)-1 {
				tbl.terminal.Print(strings.Repeat(" ", padding))
				if tbl.style.ShowBorder {
					tbl.terminal.PrintStyled(BoxVertical, borderStyle)
				} else {
					tbl.terminal.Print(" ")
				}
			}
		} else {
			tbl.terminal.Print(" ")
			if isHeader || cellStyle.Foreground.Code != 0 || cellStyle.Foreground.IsRGB {
				tbl.terminal.PrintStyled(cell, cellStyle)
			} else {
				tbl.terminal.Print(cell)
			}
			tbl.terminal.Print(strings.Repeat(" ", padding-1))
			if tbl.style.ShowBorder {
				tbl.terminal.PrintStyled(BoxVertical, borderStyle)
			}
		}
	}

	tbl.terminal.Println("")
}

// renderBorder renders a border line
func (tbl *Table) renderBorder(style Style, left, middle, cross, right string) {
	output := left
	for i, width := range tbl.widths {
		output += strings.Repeat(middle, width)
		if i < len(tbl.widths)-1 {
			output += cross
		}
	}
	output += right
	tbl.terminal.PrintlnStyled(output, style)
}

// renderSeparator renders a simple separator line
func (tbl *Table) renderSeparator(style Style) {
	totalWidth := 0
	for _, w := range tbl.widths {
		totalWidth += w
	}
	totalWidth += len(tbl.widths) - 1

	sep := strings.Repeat(BoxHorizontal, totalWidth)
	tbl.terminal.PrintlnStyled(sep, style)
}

// List represents a formatted list
type List struct {
	terminal *Terminal
	items    []ListItem
	style    ListStyle
}

// ListItem represents a single item in a list
type ListItem struct {
	Text   string
	Level  int
	Bullet string
	Color  Color
}

// ListStyle defines the visual style of the list
type ListStyle struct {
	BulletColor Color
	Indent      int
	Bullets     []string // Bullets for different levels
}

var (
	// DefaultListStyle is the default list style
	DefaultListStyle = ListStyle{
		BulletColor: ColorCyan,
		Indent:      2,
		Bullets:     []string{"•", "◦", "▸", "‣"},
	}

	// NumberedListStyle uses numbers
	NumberedListStyle = ListStyle{
		BulletColor: ColorCyan,
		Indent:      2,
		Bullets:     []string{"%d.", "%d)", "%d."},
	}
)

// NewList creates a new list
func (t *Terminal) NewList() *List {
	return &List{
		terminal: t,
		items:    make([]ListItem, 0),
		style:    DefaultListStyle,
	}
}

// SetStyle sets the list style
func (l *List) SetStyle(style ListStyle) *List {
	l.style = style
	return l
}

// Add adds an item to the list
func (l *List) Add(text string) *List {
	l.items = append(l.items, ListItem{
		Text:  text,
		Level: 0,
	})
	return l
}

// AddWithLevel adds an item with a specific indentation level
func (l *List) AddWithLevel(text string, level int) *List {
	l.items = append(l.items, ListItem{
		Text:  text,
		Level: level,
	})
	return l
}

// AddColored adds a colored item to the list
func (l *List) AddColored(text string, color Color) *List {
	l.items = append(l.items, ListItem{
		Text:  text,
		Level: 0,
		Color: color,
	})
	return l
}

// Render renders the list
func (l *List) Render() {
	bulletStyle := NewStyle().WithForeground(l.style.BulletColor)

	for i, item := range l.items {
		// Indent
		indent := strings.Repeat(" ", item.Level*l.style.Indent)
		l.terminal.Print(indent)

		// Bullet
		bulletIdx := item.Level % len(l.style.Bullets)
		bullet := l.style.Bullets[bulletIdx]

		// Format numbered bullets
		if strings.Contains(bullet, "%d") {
			bullet = fmt.Sprintf(bullet, i+1)
		}

		if item.Bullet != "" {
			bullet = item.Bullet
		}

		l.terminal.PrintStyled(bullet+" ", bulletStyle)

		// Text
		if item.Color.Code != 0 || item.Color.IsRGB {
			textStyle := NewStyle().WithForeground(item.Color)
			l.terminal.PrintlnStyled(item.Text, textStyle)
		} else {
			l.terminal.Println(item.Text)
		}
	}
}

// Banner prints a styled banner
func (t *Terminal) Banner(title string, width int) {
	if width <= 0 {
		width = t.Width()
		if width > 80 {
			width = 80
		}
	}

	if width < len(title)+4 {
		width = len(title) + 4
	}

	style := NewStyle().WithForeground(ColorCyan).WithBold()
	border := strings.Repeat("═", width-2)

	t.PrintlnStyled("╔"+border+"╗", style)

	padding := (width - 2 - len(title)) / 2
	leftPad := strings.Repeat(" ", padding)
	rightPad := strings.Repeat(" ", width-2-len(title)-padding)

	t.PrintStyled("║", style)
	t.Print(leftPad)
	t.PrintStyled(title, style)
	t.Print(rightPad)
	t.PrintlnStyled("║", style)

	t.PrintlnStyled("╚"+border+"╝", style)
}

// Section prints a section header
func (t *Terminal) Section(title string) {
	style := NewStyle().WithForeground(ColorCyan).WithBold()
	t.Println("")
	t.PrintStyled("► ", style)
	t.PrintlnStyled(strings.ToUpper(title), style)

	underline := strings.Repeat("━", len(title)+2)
	underlineStyle := NewStyle().WithForeground(ColorBrightBlack)
	t.PrintlnStyled(underline, underlineStyle)
}

// KeyValue prints a key-value pair
func (t *Terminal) KeyValue(key, value string, keyWidth int) {
	keyStyle := NewStyle().WithForeground(ColorBlue)
	format := fmt.Sprintf("%%-%ds ", keyWidth)
	t.PrintStyled(fmt.Sprintf(format, key+":"), keyStyle)
	t.Println(value)
}

// Success prints a success message
func (t *Terminal) Success(message string) {
	style := NewStyle().WithForeground(ColorSuccess).WithBold()
	t.PrintStyled("✓ ", style)
	t.Println(message)
}

// Error prints an error message (alias for Errorln)
func (t *Terminal) ErrorMsg(message string) {
	style := NewStyle().WithForeground(ColorError).WithBold()
	t.PrintStyled("✗ ", style)
	t.Errorln(message)
}

// Warning prints a warning message
func (t *Terminal) Warning(message string) {
	style := NewStyle().WithForeground(ColorWarning).WithBold()
	t.PrintStyled("⚠ ", style)
	t.Println(message)
}

// Info prints an info message
func (t *Terminal) Info(message string) {
	style := NewStyle().WithForeground(ColorInfo)
	t.PrintStyled("ℹ ", style)
	t.Println(message)
}

// Divider prints a horizontal divider
func (t *Terminal) Divider(char string, color Color) {
	if char == "" {
		char = "─"
	}
	width := t.Width()
	if width > 80 {
		width = 80
	}
	style := NewStyle().WithForeground(color)
	t.PrintlnStyled(strings.Repeat(char, width), style)
}

// Hyperlink creates a clickable terminal hyperlink (if supported)
// Falls back to just showing the URL if hyperlinks aren't supported
func (t *Terminal) Hyperlink(text, url string) string {
	if !t.isTTY {
		return fmt.Sprintf("%s (%s)", text, url)
	}
	
	// OSC 8 hyperlink escape sequence
	// Format: \033]8;;URL\033\\TEXT\033]8;;\033\\
	return fmt.Sprintf("\x1b]8;;%s\x1b\\%s\x1b]8;;\x1b\\", url, text)
}

// PrintHyperlink prints a clickable hyperlink
func (t *Terminal) PrintHyperlink(text, url string, style Style) {
	if !t.isTTY || t.colorLevel == ColorLevelNone {
		t.Printf("%s: %s\n", text, url)
		return
	}
	
	// Apply style and create hyperlink
	styledText := t.applyStyle(text, style)
	hyperlink := fmt.Sprintf("\x1b]8;;%s\x1b\\%s\x1b]8;;\x1b\\", url, styledText)
	t.Println(hyperlink)
}
