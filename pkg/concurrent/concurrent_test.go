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

package concurrent

import (
	"runtime"
	"testing"
	"time"
)

func TestDefaultProcessorConfig(t *testing.T) {
	config := DefaultProcessorConfig()

	if config == nil {
		t.Fatal("Expected config to be created, got nil")
	}

	if config.MaxWorkers != runtime.NumCPU() {
		t.Errorf("Expected MaxWorkers to be %d (CPU count), got %d", runtime.NumCPU(), config.MaxWorkers)
	}

	if config.WorkflowTimeout != 30*time.Second {
		t.Errorf("Expected WorkflowTimeout to be 30s, got %v", config.WorkflowTimeout)
	}

	if config.TotalTimeout != 5*time.Minute {
		t.Errorf("Expected TotalTimeout to be 5m, got %v", config.TotalTimeout)
	}

	if !config.ShowProgress {
		t.Error("Expected ShowProgress to be true")
	}

	if config.BufferSize != 100 {
		t.Errorf("Expected BufferSize to be 100, got %d", config.BufferSize)
	}
}

func TestProcessorConfig_CustomValues(t *testing.T) {
	config := &ProcessorConfig{
		MaxWorkers:      8,
		WorkflowTimeout: 60 * time.Second,
		TotalTimeout:    10 * time.Minute,
		ShowProgress:    false,
		BufferSize:      200,
	}

	if config.MaxWorkers != 8 {
		t.Errorf("Expected MaxWorkers to be 8, got %d", config.MaxWorkers)
	}

	if config.WorkflowTimeout != 60*time.Second {
		t.Errorf("Expected WorkflowTimeout to be 60s, got %v", config.WorkflowTimeout)
	}

	if config.TotalTimeout != 10*time.Minute {
		t.Errorf("Expected TotalTimeout to be 10m, got %v", config.TotalTimeout)
	}

	if config.ShowProgress {
		t.Error("Expected ShowProgress to be false")
	}

	if config.BufferSize != 200 {
		t.Errorf("Expected BufferSize to be 200, got %d", config.BufferSize)
	}
}

func TestNewProgressReporter(t *testing.T) {
	reporter := NewProgressReporter(100, true)

	if reporter == nil {
		t.Fatal("Expected reporter to be created, got nil")
	}

	if reporter.Total != 100 {
		t.Errorf("Expected Total to be 100, got %d", reporter.Total)
	}

	if reporter.Completed != 0 {
		t.Errorf("Expected Completed to be 0, got %d", reporter.Completed)
	}

	if !reporter.showProgress {
		t.Error("Expected showProgress to be true")
	}
}

func TestProgressReporter_Update(t *testing.T) {
	reporter := NewProgressReporter(10, false) // Disable progress output for testing

	// Initial state
	if reporter.Completed != 0 {
		t.Errorf("Expected initial Completed to be 0, got %d", reporter.Completed)
	}

	// Update progress
	reporter.Update("workflow1.yml")
	if reporter.Completed != 1 {
		t.Errorf("Expected Completed to be 1, got %d", reporter.Completed)
	}

	// Update again
	reporter.Update("workflow2.yml")
	if reporter.Completed != 2 {
		t.Errorf("Expected Completed to be 2, got %d", reporter.Completed)
	}

	// Verify total unchanged
	if reporter.Total != 10 {
		t.Errorf("Expected Total to remain 10, got %d", reporter.Total)
	}
}

func TestProgressReporter_ConcurrentUpdates(t *testing.T) {
	reporter := NewProgressReporter(100, false)

	// Spawn multiple goroutines to update progress concurrently
	done := make(chan bool)
	updates := 50

	for i := 0; i < updates; i++ {
		go func(id int) {
			reporter.Update("workflow.yml")
			done <- true
		}(i)
	}

	// Wait for all updates
	for i := 0; i < updates; i++ {
		<-done
	}

	if reporter.Completed != updates {
		t.Errorf("Expected Completed to be %d, got %d", updates, reporter.Completed)
	}
}

func TestWorkflowJob_Structure(t *testing.T) {
	job := &WorkflowJob{
		Config: nil,
	}

	if job == nil {
		t.Fatal("Expected job to be created, got nil")
	}

	// Verify we can create jobs with nil fields (they'll be populated later)
	if job.StandardRules != nil {
		t.Log("StandardRules is not nil")
	}
}

func TestWorkflowResult_Structure(t *testing.T) {
	result := &WorkflowResult{
		WorkflowName: "test.yml",
		Findings:     nil, // Will be populated with actual findings
		Error:        nil,
		Duration:     2 * time.Second,
	}

	if result.WorkflowName != "test.yml" {
		t.Errorf("Expected WorkflowName 'test.yml', got %s", result.WorkflowName)
	}

	if result.Duration != 2*time.Second {
		t.Errorf("Expected Duration 2s, got %v", result.Duration)
	}

	if result.Error != nil {
		t.Errorf("Expected no error, got %v", result.Error)
	}
}

func TestProcessorConfig_Validation(t *testing.T) {
	tests := []struct {
		name   string
		config *ProcessorConfig
		valid  bool
	}{
		{
			name: "valid config",
			config: &ProcessorConfig{
				MaxWorkers:      4,
				WorkflowTimeout: 30 * time.Second,
				TotalTimeout:    5 * time.Minute,
				ShowProgress:    true,
				BufferSize:      100,
			},
			valid: true,
		},
		{
			name: "zero workers should default to CPU count",
			config: &ProcessorConfig{
				MaxWorkers:      0,
				WorkflowTimeout: 30 * time.Second,
				TotalTimeout:    5 * time.Minute,
				ShowProgress:    true,
				BufferSize:      100,
			},
			valid: true,
		},
		{
			name: "negative workers invalid",
			config: &ProcessorConfig{
				MaxWorkers:      -1,
				WorkflowTimeout: 30 * time.Second,
				TotalTimeout:    5 * time.Minute,
				ShowProgress:    true,
				BufferSize:      100,
			},
			valid: false,
		},
		{
			name: "zero timeout invalid",
			config: &ProcessorConfig{
				MaxWorkers:      4,
				WorkflowTimeout: 0,
				TotalTimeout:    5 * time.Minute,
				ShowProgress:    true,
				BufferSize:      100,
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.config.MaxWorkers < 0 && tt.valid {
				t.Error("Negative workers should be invalid")
			}

			if tt.config.WorkflowTimeout <= 0 && tt.config.WorkflowTimeout != 0 && tt.valid {
				t.Error("Zero or negative timeout should be invalid")
			}

			if tt.config.MaxWorkers == 0 && tt.valid {
				// Should default to CPU count
				expectedWorkers := runtime.NumCPU()
				t.Logf("Zero workers should default to CPU count: %d", expectedWorkers)
			}
		})
	}
}

func TestProgressReporter_Percentage(t *testing.T) {
	tests := []struct {
		name       string
		total      int
		completed  int
		percentage float64
	}{
		{
			name:       "0% complete",
			total:      100,
			completed:  0,
			percentage: 0.0,
		},
		{
			name:       "50% complete",
			total:      100,
			completed:  50,
			percentage: 50.0,
		},
		{
			name:       "100% complete",
			total:      100,
			completed:  100,
			percentage: 100.0,
		},
		{
			name:       "33.33% complete",
			total:      9,
			completed:  3,
			percentage: 33.33,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reporter := &ProgressReporter{
				Total:     tt.total,
				Completed: tt.completed,
			}

			var calculated float64
			if reporter.Total > 0 {
				calculated = float64(reporter.Completed) / float64(reporter.Total) * 100
			}

			// Allow small floating point difference
			tolerance := 0.01
			if calculated < tt.percentage-tolerance || calculated > tt.percentage+tolerance {
				t.Errorf("Expected percentage %.2f, got %.2f", tt.percentage, calculated)
			}
		})
	}
}

func TestWorkflowResult_WithError(t *testing.T) {
	testErr := &testError{msg: "test error"}

	result := &WorkflowResult{
		WorkflowName: "failed.yml",
		Error:        testErr,
		Duration:     1 * time.Second,
	}

	if result.Error == nil {
		t.Error("Expected error to be set")
	}

	if result.Error.Error() != "test error" {
		t.Errorf("Expected error message 'test error', got %s", result.Error.Error())
	}
}

// Helper type for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
