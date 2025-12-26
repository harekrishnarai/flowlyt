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
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/harekrishnarai/flowlyt/pkg/config"
	"github.com/harekrishnarai/flowlyt/pkg/parser"
	"github.com/harekrishnarai/flowlyt/pkg/policies"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
	"github.com/harekrishnarai/flowlyt/pkg/shell"
)

// ProcessorConfig contains configuration for concurrent processing
type ProcessorConfig struct {
	// MaxWorkers defines the maximum number of concurrent workers
	// If 0, uses number of CPU cores
	MaxWorkers int

	// Timeout for processing a single workflow file
	WorkflowTimeout time.Duration

	// Timeout for the entire analysis operation
	TotalTimeout time.Duration

	// Enable progress reporting
	ShowProgress bool

	// Buffer size for worker channels
	BufferSize int
}

// DefaultProcessorConfig returns a default configuration
func DefaultProcessorConfig() *ProcessorConfig {
	return &ProcessorConfig{
		MaxWorkers:      runtime.NumCPU(),
		WorkflowTimeout: 30 * time.Second,
		TotalTimeout:    5 * time.Minute,
		ShowProgress:    true,
		BufferSize:      100,
	}
}

// WorkflowJob represents a single workflow analysis job
type WorkflowJob struct {
	Workflow      parser.WorkflowFile
	StandardRules []rules.Rule
	PolicyEngine  *policies.PolicyEngine
	Config        *config.Config
}

// WorkflowResult represents the result of workflow analysis
type WorkflowResult struct {
	WorkflowName string
	Findings     []rules.Finding
	Error        error
	Duration     time.Duration
}

// ProgressReporter handles progress reporting during concurrent processing
type ProgressReporter struct {
	Total        int
	Completed    int
	mutex        sync.RWMutex
	showProgress bool
}

// NewProgressReporter creates a new progress reporter
func NewProgressReporter(total int, showProgress bool) *ProgressReporter {
	return &ProgressReporter{
		Total:        total,
		Completed:    0,
		showProgress: showProgress,
	}
}

// Update increments the completed count and reports progress
func (pr *ProgressReporter) Update(workflowName string) {
	pr.mutex.Lock()
	defer pr.mutex.Unlock()

	pr.Completed++

	if pr.showProgress {
		percentage := float64(pr.Completed) / float64(pr.Total) * 100
		fmt.Printf("\r🔍 Analyzing workflows... [%d/%d] (%.1f%%) - %s",
			pr.Completed, pr.Total, percentage, workflowName)

		if pr.Completed == pr.Total {
			fmt.Println() // New line when complete
		}
	}
}

// GetProgress returns current progress information
func (pr *ProgressReporter) GetProgress() (completed, total int) {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	return pr.Completed, pr.Total
}

// ConcurrentProcessor handles concurrent workflow analysis
type ConcurrentProcessor struct {
	config   *ProcessorConfig
	reporter *ProgressReporter
}

// NewConcurrentProcessor creates a new concurrent processor
func NewConcurrentProcessor(config *ProcessorConfig) *ConcurrentProcessor {
	if config == nil {
		config = DefaultProcessorConfig()
	}

	// Ensure we have at least 1 worker
	if config.MaxWorkers <= 0 {
		config.MaxWorkers = runtime.NumCPU()
	}

	return &ConcurrentProcessor{
		config: config,
	}
}

// ProcessWorkflows processes multiple workflows concurrently
func (cp *ConcurrentProcessor) ProcessWorkflows(
	ctx context.Context,
	workflowFiles []parser.WorkflowFile,
	standardRules []rules.Rule,
	policyEngine *policies.PolicyEngine,
	cfg *config.Config,
) ([]rules.Finding, error) {

	if len(workflowFiles) == 0 {
		return []rules.Finding{}, nil
	}

	// Set up timeout context
	if cp.config.TotalTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cp.config.TotalTimeout)
		defer cancel()
	}

	// Initialize progress reporter
	cp.reporter = NewProgressReporter(len(workflowFiles), cp.config.ShowProgress)

	// For small numbers of workflows, use sequential processing
	if len(workflowFiles) <= 2 {
		return cp.processSequentially(ctx, workflowFiles, standardRules, policyEngine, cfg)
	}

	// Use concurrent processing for larger numbers
	return cp.processConcurrently(ctx, workflowFiles, standardRules, policyEngine, cfg)
}

// processSequentially processes workflows one by one (for small counts)
func (cp *ConcurrentProcessor) processSequentially(
	ctx context.Context,
	workflowFiles []parser.WorkflowFile,
	standardRules []rules.Rule,
	policyEngine *policies.PolicyEngine,
	cfg *config.Config,
) ([]rules.Finding, error) {

	var allFindings []rules.Finding

	for _, workflow := range workflowFiles {
		select {
		case <-ctx.Done():
			return allFindings, ctx.Err()
		default:
		}

		result := cp.processWorkflow(ctx, WorkflowJob{
			Workflow:      workflow,
			StandardRules: standardRules,
			PolicyEngine:  policyEngine,
			Config:        cfg,
		})

		cp.reporter.Update(workflow.Name)

		if result.Error != nil {
			fmt.Printf("Warning: error processing %s: %v\n", result.WorkflowName, result.Error)
			continue
		}

		allFindings = append(allFindings, result.Findings...)
	}

	return allFindings, nil
}

// processConcurrently processes workflows using worker pools
func (cp *ConcurrentProcessor) processConcurrently(
	ctx context.Context,
	workflowFiles []parser.WorkflowFile,
	standardRules []rules.Rule,
	policyEngine *policies.PolicyEngine,
	cfg *config.Config,
) ([]rules.Finding, error) {

	// Calculate optimal number of workers
	numWorkers := cp.config.MaxWorkers
	if numWorkers > len(workflowFiles) {
		numWorkers = len(workflowFiles)
	}

	// Create job and result channels
	jobs := make(chan WorkflowJob, cp.config.BufferSize)
	results := make(chan WorkflowResult, len(workflowFiles))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go cp.worker(ctx, &wg, jobs, results)
	}

	// Send jobs
	go func() {
		defer close(jobs)
		for _, workflow := range workflowFiles {
			select {
			case jobs <- WorkflowJob{
				Workflow:      workflow,
				StandardRules: standardRules,
				PolicyEngine:  policyEngine,
				Config:        cfg,
			}:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Collect results
	var allFindings []rules.Finding
	var errors []error

	for i := 0; i < len(workflowFiles); i++ {
		select {
		case result := <-results:
			cp.reporter.Update(result.WorkflowName)

			if result.Error != nil {
				errors = append(errors, fmt.Errorf("error processing %s: %w", result.WorkflowName, result.Error))
				continue
			}

			allFindings = append(allFindings, result.Findings...)

		case <-ctx.Done():
			// Wait for workers to finish
			go func() {
				wg.Wait()
				close(results)
			}()
			return allFindings, ctx.Err()
		}
	}

	// Wait for all workers to complete
	wg.Wait()
	close(results)

	// Report any errors that occurred
	if len(errors) > 0 {
		for _, err := range errors {
			fmt.Printf("Warning: %v\n", err)
		}
	}

	return allFindings, nil
}

// worker processes jobs from the job channel
func (cp *ConcurrentProcessor) worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan WorkflowJob, results chan<- WorkflowResult) {
	defer wg.Done()

	for job := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		result := cp.processWorkflow(ctx, job)

		select {
		case results <- result:
		case <-ctx.Done():
			return
		}
	}
}

// processWorkflow processes a single workflow with timeout
func (cp *ConcurrentProcessor) processWorkflow(ctx context.Context, job WorkflowJob) WorkflowResult {
	start := time.Now()

	// Set up workflow-level timeout
	workflowCtx := ctx
	if cp.config.WorkflowTimeout > 0 {
		var cancel context.CancelFunc
		workflowCtx, cancel = context.WithTimeout(ctx, cp.config.WorkflowTimeout)
		defer cancel()
	}

	result := WorkflowResult{
		WorkflowName: job.Workflow.Name,
		Findings:     []rules.Finding{},
	}

	// Check for cancellation
	select {
	case <-workflowCtx.Done():
		result.Error = workflowCtx.Err()
		result.Duration = time.Since(start)
		return result
	default:
	}

	// Process the workflow
	findings, err := cp.analyzeWorkflowConcurrently(workflowCtx, job)
	result.Findings = findings
	result.Error = err
	result.Duration = time.Since(start)

	return result
}

// analyzeWorkflowConcurrently analyzes a single workflow with concurrent rule evaluation
func (cp *ConcurrentProcessor) analyzeWorkflowConcurrently(ctx context.Context, job WorkflowJob) ([]rules.Finding, error) {
	var allFindings []rules.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Channel for collecting errors
	errChan := make(chan error, 3) // Standard rules, shell analysis, policy evaluation

	// Apply standard rules concurrently
	wg.Add(1)
	go func() {
		defer wg.Done()

		var standardFindings []rules.Finding
		for _, rule := range job.StandardRules {
			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
			}

			findings := rule.Check(job.Workflow)
			standardFindings = append(standardFindings, findings...)
		}

		mu.Lock()
		allFindings = append(allFindings, standardFindings...)
		mu.Unlock()
	}()

	// Apply shell analysis concurrently
	wg.Add(1)
	go func() {
		defer wg.Done()

		select {
		case <-ctx.Done():
			errChan <- ctx.Err()
			return
		default:
		}

		shellAnalyzer := shell.NewAnalyzer()
		shellFindings := shellAnalyzer.Analyze(job.Workflow)

		var filteredShellFindings []rules.Finding
		for _, finding := range shellFindings {
			if job.Config.IsRuleEnabled(finding.RuleID) {
				filteredShellFindings = append(filteredShellFindings, finding)
			}
		}

		mu.Lock()
		allFindings = append(allFindings, filteredShellFindings...)
		mu.Unlock()
	}()

	// Apply policy evaluation concurrently (if available)
	if job.PolicyEngine != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()

			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
			}

			policyFindings, err := job.PolicyEngine.EvaluateWorkflow(job.Workflow)
			if err != nil {
				errChan <- fmt.Errorf("policy evaluation error: %w", err)
				return
			}

			var filteredPolicyFindings []rules.Finding
			for _, finding := range policyFindings {
				if job.Config.IsRuleEnabled(finding.RuleID) {
					filteredPolicyFindings = append(filteredPolicyFindings, finding)
				}
			}

			mu.Lock()
			allFindings = append(allFindings, filteredPolicyFindings...)
			mu.Unlock()
		}()
	}

	// Wait for all analysis to complete
	wg.Wait()
	close(errChan)

	// Check for any errors
	for err := range errChan {
		if err != nil {
			return allFindings, err
		}
	}

	return allFindings, nil
}

// GetStats returns processing statistics
func (cp *ConcurrentProcessor) GetStats() (completed, total int, config *ProcessorConfig) {
	if cp.reporter != nil {
		completed, total = cp.reporter.GetProgress()
	}
	return completed, total, cp.config
}
