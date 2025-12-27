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
	"sync"
	"time"
)

// ProgressBar represents a progress indicator
type ProgressBar struct {
	terminal    *Terminal
	total       int
	current     int
	width       int
	prefix      string
	suffix      string
	mu          sync.Mutex
	startTime   time.Time
	showPercent bool
	showETA     bool
	style       ProgressStyle
}

// ProgressStyle defines the visual style of the progress bar
type ProgressStyle struct {
	FilledChar   string
	EmptyChar    string
	LeftBracket  string
	RightBracket string
	Color        Color
}

var (
	// DefaultProgressStyle is the default progress bar style
	DefaultProgressStyle = ProgressStyle{
		FilledChar:   "█",
		EmptyChar:    "░",
		LeftBracket:  "[",
		RightBracket: "]",
		Color:        ColorCyan,
	}

	// GradientProgressStyle uses gradient colors
	GradientProgressStyle = ProgressStyle{
		FilledChar:   "█",
		EmptyChar:    "░",
		LeftBracket:  "[",
		RightBracket: "]",
		Color:        ColorSuccess,
	}

	// ArrowProgressStyle uses arrows
	ArrowProgressStyle = ProgressStyle{
		FilledChar:   "▶",
		EmptyChar:    "▷",
		LeftBracket:  "⟨",
		RightBracket: "⟩",
		Color:        ColorBlue,
	}
)

// NewProgressBar creates a new progress bar
func (t *Terminal) NewProgressBar(total int) *ProgressBar {
	width := t.Width()
	if width > 80 {
		width = 80
	} else if width < 40 {
		width = 40
	}

	return &ProgressBar{
		terminal:    t,
		total:       total,
		current:     0,
		width:       width - 20, // Reserve space for percentage and other info
		startTime:   time.Now(),
		showPercent: true,
		showETA:     true,
		style:       DefaultProgressStyle,
	}
}

// SetPrefix sets the prefix text
func (pb *ProgressBar) SetPrefix(prefix string) *ProgressBar {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	pb.prefix = prefix
	return pb
}

// SetSuffix sets the suffix text
func (pb *ProgressBar) SetSuffix(suffix string) *ProgressBar {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	pb.suffix = suffix
	return pb
}

// SetStyle sets the progress bar style
func (pb *ProgressBar) SetStyle(style ProgressStyle) *ProgressBar {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	pb.style = style
	return pb
}

// Increment increments the progress by one
func (pb *ProgressBar) Increment() {
	pb.Add(1)
}

// Add adds to the current progress
func (pb *ProgressBar) Add(n int) {
	pb.mu.Lock()
	pb.current += n
	if pb.current > pb.total {
		pb.current = pb.total
	}
	pb.mu.Unlock()
	pb.render()
}

// Set sets the current progress
func (pb *ProgressBar) Set(current int) {
	pb.mu.Lock()
	pb.current = current
	if pb.current > pb.total {
		pb.current = pb.total
	}
	pb.mu.Unlock()
	pb.render()
}

// Finish completes the progress bar
func (pb *ProgressBar) Finish() {
	pb.Set(pb.total)
	pb.terminal.Println("")
}

// render draws the progress bar
func (pb *ProgressBar) render() {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	if !pb.terminal.IsTTY() {
		return
	}

	// Clear the line
	pb.terminal.ClearLine()

	var output strings.Builder

	// Prefix
	if pb.prefix != "" {
		output.WriteString(pb.prefix)
		output.WriteString(" ")
	}

	// Calculate progress
	percent := float64(pb.current) / float64(pb.total) * 100
	filled := int(float64(pb.width) * float64(pb.current) / float64(pb.total))
	if filled > pb.width {
		filled = pb.width
	}

	// Draw progress bar
	barStyle := NewStyle().WithForeground(pb.style.Color)
	output.WriteString(pb.style.LeftBracket)

	bar := strings.Repeat(pb.style.FilledChar, filled) +
		strings.Repeat(pb.style.EmptyChar, pb.width-filled)

	output.WriteString(pb.terminal.applyStyle(bar[:filled], barStyle))
	output.WriteString(bar[filled:])
	output.WriteString(pb.style.RightBracket)

	// Percentage
	if pb.showPercent {
		output.WriteString(fmt.Sprintf(" %.1f%%", percent))
	}

	// Progress count
	output.WriteString(fmt.Sprintf(" (%d/%d)", pb.current, pb.total))

	// ETA
	if pb.showETA && pb.current > 0 {
		elapsed := time.Since(pb.startTime)
		rate := float64(pb.current) / elapsed.Seconds()
		if rate > 0 {
			remaining := float64(pb.total-pb.current) / rate
			eta := time.Duration(remaining) * time.Second
			if eta > 0 {
				output.WriteString(fmt.Sprintf(" ETA: %s", formatDuration(eta)))
			}
		}
	}

	// Suffix
	if pb.suffix != "" {
		output.WriteString(" ")
		output.WriteString(pb.suffix)
	}

	pb.terminal.Print(output.String())
}

// Spinner represents an animated spinner
type Spinner struct {
	terminal *Terminal
	frames   []string
	message  string
	interval time.Duration
	mu       sync.Mutex
	running  bool
	stopCh   chan struct{}
	frame    int
	style    Style
}

var (
	// SpinnerDots is a simple dots spinner
	SpinnerDots = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

	// SpinnerLineFrames is a line spinner
	SpinnerLineFrames = []string{"-", "\\", "|", "/"}

	// SpinnerArrow is an arrow spinner
	SpinnerArrow = []string{"←", "↖", "↑", "↗", "→", "↘", "↓", "↙"}

	// SpinnerCircle is a circle spinner
	SpinnerCircle = []string{"◐", "◓", "◑", "◒"}

	// SpinnerGrowth is a growing spinner
	SpinnerGrowth = []string{"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█", "▇", "▆", "▅", "▄", "▃", "▂"}

	// SpinnerBounce is a bouncing spinner
	SpinnerBounce = []string{"⠁", "⠂", "⠄", "⡀", "⢀", "⠠", "⠐", "⠈"}
)

// NewSpinner creates a new spinner
func (t *Terminal) NewSpinner(frames []string) *Spinner {
	if len(frames) == 0 {
		frames = SpinnerDots
	}

	return &Spinner{
		terminal: t,
		frames:   frames,
		interval: 100 * time.Millisecond,
		stopCh:   make(chan struct{}),
		style:    NewStyle().WithForeground(ColorCyan),
	}
}

// SetMessage sets the spinner message
func (s *Spinner) SetMessage(message string) *Spinner {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.message = message
	return s
}

// SetStyle sets the spinner style
func (s *Spinner) SetStyle(style Style) *Spinner {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.style = style
	return s
}

// SetInterval sets the animation interval
func (s *Spinner) SetInterval(interval time.Duration) *Spinner {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.interval = interval
	return s
}

// Start starts the spinner animation
func (s *Spinner) Start() *Spinner {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return s
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.mu.Unlock()

	if !s.terminal.IsTTY() {
		// Just print the message once if not a TTY
		if s.message != "" {
			s.terminal.Println(s.message)
		}
		return s
	}

	s.terminal.HideCursor()

	go func() {
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()

		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.render()
			}
		}
	}()

	return s
}

// Stop stops the spinner animation
func (s *Spinner) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	close(s.stopCh)
	s.mu.Unlock()

	if s.terminal.IsTTY() {
		s.terminal.ClearLine()
		s.terminal.ShowCursor()
	}
}

// Success stops the spinner and shows a success message
func (s *Spinner) Success(message string) {
	s.Stop()
	style := NewStyle().WithForeground(ColorSuccess).WithBold()
	s.terminal.PrintStyled("✓ ", style)
	s.terminal.Println(message)
}

// Fail stops the spinner and shows a failure message
func (s *Spinner) Fail(message string) {
	s.Stop()
	style := NewStyle().WithForeground(ColorError).WithBold()
	s.terminal.PrintStyled("✗ ", style)
	s.terminal.Println(message)
}

// Warning stops the spinner and shows a warning message
func (s *Spinner) Warning(message string) {
	s.Stop()
	style := NewStyle().WithForeground(ColorWarning).WithBold()
	s.terminal.PrintStyled("⚠ ", style)
	s.terminal.Println(message)
}

// render draws the current frame of the spinner
func (s *Spinner) render() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.terminal.ClearLine()

	// Draw spinner frame
	frame := s.frames[s.frame%len(s.frames)]
	styledFrame := s.terminal.applyStyle(frame, s.style)
	s.terminal.Print(styledFrame + " ")

	// Draw message
	if s.message != "" {
		s.terminal.Print(s.message)
	}

	s.frame++
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// MultiSpinner manages multiple concurrent spinners
type MultiSpinner struct {
	terminal *Terminal
	spinners map[string]*SpinnerLine
	mu       sync.Mutex
	lines    int
}

// SpinnerLine represents a single line in a multi-spinner
type SpinnerLine struct {
	message string
	status  string // "running", "success", "error", "warning"
	spinner *Spinner
}

// NewMultiSpinner creates a new multi-spinner
func (t *Terminal) NewMultiSpinner() *MultiSpinner {
	return &MultiSpinner{
		terminal: t,
		spinners: make(map[string]*SpinnerLine),
	}
}

// Add adds a new spinner line
func (ms *MultiSpinner) Add(key, message string) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	spinner := ms.terminal.NewSpinner(SpinnerDots)
	spinner.SetMessage(message)

	ms.spinners[key] = &SpinnerLine{
		message: message,
		status:  "running",
		spinner: spinner,
	}
	ms.lines++

	if ms.terminal.IsTTY() {
		spinner.Start()
	}
}

// Update updates a spinner line's message
func (ms *MultiSpinner) Update(key, message string) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if line, ok := ms.spinners[key]; ok {
		line.message = message
		line.spinner.SetMessage(message)
	}
}

// Success marks a spinner as successful
func (ms *MultiSpinner) Success(key, message string) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if line, ok := ms.spinners[key]; ok {
		line.status = "success"
		line.spinner.Success(message)
	}
}

// Fail marks a spinner as failed
func (ms *MultiSpinner) Fail(key, message string) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if line, ok := ms.spinners[key]; ok {
		line.status = "error"
		line.spinner.Fail(message)
	}
}

// Stop stops all spinners
func (ms *MultiSpinner) Stop() {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	for _, line := range ms.spinners {
		line.spinner.Stop()
	}
}
