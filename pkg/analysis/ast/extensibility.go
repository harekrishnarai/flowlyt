package ast

import (
	"fmt"
	"sync"
)

// PluginManager manages analyzer plugins and extensions
type PluginManager struct {
	mu                sync.RWMutex
	analyzers         map[string]AnalyzerPlugin
	rules             map[string]RulePlugin
	reporters         map[string]ReporterPlugin
	middlewares       []MiddlewarePlugin
	config            *PluginConfig
	lifecycleHooks    map[LifecycleEvent][]LifecycleHook
	extensionRegistry *ExtensionRegistry
}

// PluginConfig configures plugin behavior
type PluginConfig struct {
	EnablePlugins      bool
	PluginTimeout      int64 // seconds
	MaxPluginMemoryMB  int64
	AllowedPluginTypes []string
	SecurityPolicy     PluginSecurityPolicy
}

// PluginSecurityPolicy defines security constraints for plugins
type PluginSecurityPolicy struct {
	AllowFileAccess    bool
	AllowNetworkAccess bool
	AllowedDomains     []string
	RestrictedCommands []string
	MaxExecutionTime   int64 // seconds
}

// AnalyzerPlugin interface for custom analyzers
type AnalyzerPlugin interface {
	Plugin
	Analyze(workflow *WorkflowAST, context *AnalysisContext) (*PluginResult, error)
	GetAnalysisType() string
	GetPriority() int
}

// RulePlugin interface for custom security rules
type RulePlugin interface {
	Plugin
	Evaluate(node interface{}, context *RuleContext) (*RuleResult, error)
	GetRuleID() string
	GetSeverity() string
	GetCategory() string
}

// ReporterPlugin interface for custom output formats
type ReporterPlugin interface {
	Plugin
	GenerateReport(results *ComprehensiveAnalysisResult, config *ReportConfig) ([]byte, error)
	GetFormat() string
	GetMimeType() string
}

// MiddlewarePlugin interface for analysis pipeline middleware
type MiddlewarePlugin interface {
	Plugin
	Process(workflow *WorkflowAST, next MiddlewareFunc) (*WorkflowAST, error)
	GetOrder() int
}

// Plugin base interface for all plugins
type Plugin interface {
	GetInfo() *PluginInfo
	Initialize(config interface{}) error
	Cleanup() error
	Validate() error
}

// PluginInfo contains metadata about a plugin
type PluginInfo struct {
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Author       string                 `json:"author"`
	Description  string                 `json:"description"`
	Homepage     string                 `json:"homepage"`
	License      string                 `json:"license"`
	Tags         []string               `json:"tags"`
	Dependencies []string               `json:"dependencies"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// AnalysisContext provides context for analyzer plugins
type AnalysisContext struct {
	WorkflowPath     string
	Platform         string
	ProjectMetadata  map[string]interface{}
	SecurityContext  *SecurityContext
	PerformanceHints *PerformanceHints
	UserConfig       map[string]interface{}
}

// SecurityContext provides security-related context
type SecurityContext struct {
	TrustedDomains     []string
	AllowedActions     []string
	SecurityLevel      string
	ComplianceProfiles []string
}

// PerformanceHints provides optimization hints
type PerformanceHints struct {
	MaxAnalysisTime   int64
	MemoryLimitMB     int64
	PreferredCaching  bool
	ParallelExecution bool
}

// RuleContext provides context for rule evaluation
type RuleContext struct {
	WorkflowAST   *WorkflowAST
	CurrentJob    *JobNode
	CurrentStep   *StepNode
	ParentNodes   []interface{}
	GlobalContext map[string]interface{}
}

// PluginResult represents the result of a plugin analysis
type PluginResult struct {
	PluginName    string                 `json:"plugin_name"`
	AnalysisType  string                 `json:"analysis_type"`
	Findings      []*SecurityFinding     `json:"findings"`
	Metrics       map[string]interface{} `json:"metrics"`
	Metadata      map[string]interface{} `json:"metadata"`
	ExecutionTime int64                  `json:"execution_time_ms"`
	Success       bool                   `json:"success"`
	Errors        []string               `json:"errors,omitempty"`
}

// RuleResult represents the result of a rule evaluation
type RuleResult struct {
	RuleID      string                 `json:"rule_id"`
	Passed      bool                   `json:"passed"`
	Severity    string                 `json:"severity"`
	Message     string                 `json:"message"`
	Location    *Location              `json:"location,omitempty"`
	Remediation *Remediation           `json:"remediation,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// SecurityFinding represents a security issue found by analysis
type SecurityFinding struct {
	ID          string       `json:"id"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Severity    string       `json:"severity"`
	Category    string       `json:"category"`
	Location    *Location    `json:"location"`
	Remediation *Remediation `json:"remediation"`
	References  []string     `json:"references"`
	CWE         []string     `json:"cwe,omitempty"`
	OWASP       []string     `json:"owasp,omitempty"`
}

// Location represents the location of an issue
type Location struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	JobID   string `json:"job_id,omitempty"`
	StepID  string `json:"step_id,omitempty"`
	Context string `json:"context,omitempty"`
}

// Remediation provides guidance on fixing issues
type Remediation struct {
	Summary     string   `json:"summary"`
	Description string   `json:"description"`
	Steps       []string `json:"steps"`
	Examples    []string `json:"examples"`
	Links       []string `json:"links"`
}

// ReportConfig configures report generation
type ReportConfig struct {
	Format         string                 `json:"format"`
	IncludeMetrics bool                   `json:"include_metrics"`
	FilterSeverity []string               `json:"filter_severity"`
	GroupBy        string                 `json:"group_by"`
	Template       string                 `json:"template,omitempty"`
	OutputPath     string                 `json:"output_path,omitempty"`
	CustomFields   map[string]interface{} `json:"custom_fields"`
}

// MiddlewareFunc represents the next middleware in the chain
type MiddlewareFunc func(*WorkflowAST) (*WorkflowAST, error)

// LifecycleEvent represents different phases of analysis
type LifecycleEvent string

const (
	BeforeAnalysis   LifecycleEvent = "before_analysis"
	AfterAnalysis    LifecycleEvent = "after_analysis"
	BeforeValidation LifecycleEvent = "before_validation"
	AfterValidation  LifecycleEvent = "after_validation"
	OnError          LifecycleEvent = "on_error"
	OnComplete       LifecycleEvent = "on_complete"
)

// LifecycleHook function for lifecycle events
type LifecycleHook func(event LifecycleEvent, data interface{}) error

// ExtensionRegistry manages plugin registration and discovery
type ExtensionRegistry struct {
	mu                sync.RWMutex
	registeredPlugins map[string]*PluginRegistration
	activePlugins     map[string]Plugin
}

// PluginRegistration contains plugin registration information
type PluginRegistration struct {
	Info        *PluginInfo
	Constructor func() Plugin
	Config      interface{}
	Enabled     bool
}

// NewPluginManager creates a new plugin manager
func NewPluginManager(config *PluginConfig) *PluginManager {
	if config == nil {
		config = DefaultPluginConfig()
	}

	return &PluginManager{
		analyzers:         make(map[string]AnalyzerPlugin),
		rules:             make(map[string]RulePlugin),
		reporters:         make(map[string]ReporterPlugin),
		middlewares:       []MiddlewarePlugin{},
		config:            config,
		lifecycleHooks:    make(map[LifecycleEvent][]LifecycleHook),
		extensionRegistry: NewExtensionRegistry(),
	}
}

// DefaultPluginConfig returns default plugin configuration
func DefaultPluginConfig() *PluginConfig {
	return &PluginConfig{
		EnablePlugins:      true,
		PluginTimeout:      30, // 30 seconds
		MaxPluginMemoryMB:  100,
		AllowedPluginTypes: []string{"analyzer", "rule", "reporter"},
		SecurityPolicy: PluginSecurityPolicy{
			AllowFileAccess:    false,
			AllowNetworkAccess: false,
			MaxExecutionTime:   10, // 10 seconds
		},
	}
}

// RegisterAnalyzer registers an analyzer plugin
func (pm *PluginManager) RegisterAnalyzer(name string, analyzer AnalyzerPlugin) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if err := analyzer.Validate(); err != nil {
		return fmt.Errorf("analyzer validation failed: %w", err)
	}

	pm.analyzers[name] = analyzer
	return nil
}

// RegisterRule registers a rule plugin
func (pm *PluginManager) RegisterRule(name string, rule RulePlugin) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if err := rule.Validate(); err != nil {
		return fmt.Errorf("rule validation failed: %w", err)
	}

	pm.rules[name] = rule
	return nil
}

// RegisterReporter registers a reporter plugin
func (pm *PluginManager) RegisterReporter(name string, reporter ReporterPlugin) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if err := reporter.Validate(); err != nil {
		return fmt.Errorf("reporter validation failed: %w", err)
	}

	pm.reporters[name] = reporter
	return nil
}

// RegisterMiddleware registers a middleware plugin
func (pm *PluginManager) RegisterMiddleware(middleware MiddlewarePlugin) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if err := middleware.Validate(); err != nil {
		return fmt.Errorf("middleware validation failed: %w", err)
	}

	// Insert middleware in order
	order := middleware.GetOrder()
	inserted := false

	for i, existing := range pm.middlewares {
		if order < existing.GetOrder() {
			pm.middlewares = append(pm.middlewares[:i], append([]MiddlewarePlugin{middleware}, pm.middlewares[i:]...)...)
			inserted = true
			break
		}
	}

	if !inserted {
		pm.middlewares = append(pm.middlewares, middleware)
	}

	return nil
}

// RunAnalyzers executes all registered analyzer plugins
func (pm *PluginManager) RunAnalyzers(workflow *WorkflowAST, context *AnalysisContext) ([]*PluginResult, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var results []*PluginResult

	for name, analyzer := range pm.analyzers {
		result, err := pm.runAnalyzerSafely(name, analyzer, workflow, context)
		if err != nil {
			result = &PluginResult{
				PluginName:   name,
				AnalysisType: analyzer.GetAnalysisType(),
				Success:      false,
				Errors:       []string{err.Error()},
			}
		}
		results = append(results, result)
	}

	return results, nil
}

// EvaluateRules runs all registered rule plugins
func (pm *PluginManager) EvaluateRules(workflow *WorkflowAST, context *RuleContext) ([]*RuleResult, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var results []*RuleResult

	// Evaluate rules against workflow nodes
	nodes := pm.extractNodes(workflow)

	for _, node := range nodes {
		for _, rule := range pm.rules {
			result, err := pm.evaluateRuleSafely(rule, node, context)
			if err != nil {
				result = &RuleResult{
					RuleID:   rule.GetRuleID(),
					Passed:   false,
					Severity: rule.GetSeverity(),
					Message:  fmt.Sprintf("Rule evaluation failed: %v", err),
				}
			}
			if result != nil {
				results = append(results, result)
			}
		}
	}

	return results, nil
}

// ProcessMiddleware runs workflow through middleware pipeline
func (pm *PluginManager) ProcessMiddleware(workflow *WorkflowAST) (*WorkflowAST, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	processedWorkflow := workflow

	for _, middleware := range pm.middlewares {
		var err error
		processedWorkflow, err = middleware.Process(processedWorkflow, func(w *WorkflowAST) (*WorkflowAST, error) {
			return w, nil
		})
		if err != nil {
			return nil, fmt.Errorf("middleware %s failed: %w", middleware.GetInfo().Name, err)
		}
	}

	return processedWorkflow, nil
}

// GenerateReports generates reports using all registered reporters
func (pm *PluginManager) GenerateReports(results *ComprehensiveAnalysisResult, config *ReportConfig) (map[string][]byte, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	reports := make(map[string][]byte)

	for name, reporter := range pm.reporters {
		report, err := reporter.GenerateReport(results, config)
		if err != nil {
			return nil, fmt.Errorf("reporter %s failed: %w", name, err)
		}
		reports[name] = report
	}

	return reports, nil
}

// AddLifecycleHook adds a hook for lifecycle events
func (pm *PluginManager) AddLifecycleHook(event LifecycleEvent, hook LifecycleHook) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.lifecycleHooks[event] = append(pm.lifecycleHooks[event], hook)
}

// TriggerLifecycleEvent triggers all hooks for a specific event
func (pm *PluginManager) TriggerLifecycleEvent(event LifecycleEvent, data interface{}) error {
	pm.mu.RLock()
	hooks := pm.lifecycleHooks[event]
	pm.mu.RUnlock()

	for _, hook := range hooks {
		if err := hook(event, data); err != nil {
			return fmt.Errorf("lifecycle hook failed for event %s: %w", event, err)
		}
	}

	return nil
}

// GetPluginInfo returns information about all registered plugins
func (pm *PluginManager) GetPluginInfo() map[string]*PluginInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	info := make(map[string]*PluginInfo)

	for name, analyzer := range pm.analyzers {
		info[name] = analyzer.GetInfo()
	}

	for name, rule := range pm.rules {
		info[name] = rule.GetInfo()
	}

	for name, reporter := range pm.reporters {
		info[name] = reporter.GetInfo()
	}

	for _, middleware := range pm.middlewares {
		info[middleware.GetInfo().Name] = middleware.GetInfo()
	}

	return info
}

// Cleanup cleans up all plugins
func (pm *PluginManager) Cleanup() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	var errors []string

	// Cleanup analyzers
	for name, analyzer := range pm.analyzers {
		if err := analyzer.Cleanup(); err != nil {
			errors = append(errors, fmt.Sprintf("analyzer %s cleanup failed: %v", name, err))
		}
	}

	// Cleanup rules
	for name, rule := range pm.rules {
		if err := rule.Cleanup(); err != nil {
			errors = append(errors, fmt.Sprintf("rule %s cleanup failed: %v", name, err))
		}
	}

	// Cleanup reporters
	for name, reporter := range pm.reporters {
		if err := reporter.Cleanup(); err != nil {
			errors = append(errors, fmt.Sprintf("reporter %s cleanup failed: %v", name, err))
		}
	}

	// Cleanup middlewares
	for _, middleware := range pm.middlewares {
		if err := middleware.Cleanup(); err != nil {
			errors = append(errors, fmt.Sprintf("middleware %s cleanup failed: %v", middleware.GetInfo().Name, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("plugin cleanup errors: %v", errors)
	}

	return nil
}

// Helper methods

func (pm *PluginManager) runAnalyzerSafely(name string, analyzer AnalyzerPlugin, workflow *WorkflowAST, context *AnalysisContext) (*PluginResult, error) {
	// TODO: Add timeout, memory limits, and security checks
	return analyzer.Analyze(workflow, context)
}

func (pm *PluginManager) evaluateRuleSafely(rule RulePlugin, node interface{}, context *RuleContext) (*RuleResult, error) {
	// TODO: Add timeout and security checks
	return rule.Evaluate(node, context)
}

func (pm *PluginManager) extractNodes(workflow *WorkflowAST) []interface{} {
	var nodes []interface{}
	nodes = append(nodes, workflow)

	for _, job := range workflow.Jobs {
		nodes = append(nodes, job)
		for _, step := range job.Steps {
			nodes = append(nodes, step)
		}
	}

	return nodes
}

// NewExtensionRegistry creates a new extension registry
func NewExtensionRegistry() *ExtensionRegistry {
	return &ExtensionRegistry{
		registeredPlugins: make(map[string]*PluginRegistration),
		activePlugins:     make(map[string]Plugin),
	}
}

// RegisterPlugin registers a plugin with the registry
func (er *ExtensionRegistry) RegisterPlugin(name string, constructor func() Plugin, config interface{}) error {
	er.mu.Lock()
	defer er.mu.Unlock()

	// Create a temporary instance to get plugin info
	plugin := constructor()
	info := plugin.GetInfo()

	if err := plugin.Validate(); err != nil {
		return fmt.Errorf("plugin validation failed: %w", err)
	}

	er.registeredPlugins[name] = &PluginRegistration{
		Info:        info,
		Constructor: constructor,
		Config:      config,
		Enabled:     true,
	}

	return nil
}

// LoadPlugin loads and activates a registered plugin
func (er *ExtensionRegistry) LoadPlugin(name string) (Plugin, error) {
	er.mu.Lock()
	defer er.mu.Unlock()

	registration, exists := er.registeredPlugins[name]
	if !exists {
		return nil, fmt.Errorf("plugin %s not registered", name)
	}

	if !registration.Enabled {
		return nil, fmt.Errorf("plugin %s is disabled", name)
	}

	plugin := registration.Constructor()
	if err := plugin.Initialize(registration.Config); err != nil {
		return nil, fmt.Errorf("plugin initialization failed: %w", err)
	}

	er.activePlugins[name] = plugin
	return plugin, nil
}

// UnloadPlugin unloads an active plugin
func (er *ExtensionRegistry) UnloadPlugin(name string) error {
	er.mu.Lock()
	defer er.mu.Unlock()

	plugin, exists := er.activePlugins[name]
	if !exists {
		return fmt.Errorf("plugin %s not active", name)
	}

	if err := plugin.Cleanup(); err != nil {
		return fmt.Errorf("plugin cleanup failed: %w", err)
	}

	delete(er.activePlugins, name)
	return nil
}

// GetActivePlugins returns all active plugins
func (er *ExtensionRegistry) GetActivePlugins() map[string]Plugin {
	er.mu.RLock()
	defer er.mu.RUnlock()

	plugins := make(map[string]Plugin)
	for name, plugin := range er.activePlugins {
		plugins[name] = plugin
	}

	return plugins
}

// GetRegisteredPlugins returns all registered plugins
func (er *ExtensionRegistry) GetRegisteredPlugins() map[string]*PluginRegistration {
	er.mu.RLock()
	defer er.mu.RUnlock()

	plugins := make(map[string]*PluginRegistration)
	for name, registration := range er.registeredPlugins {
		plugins[name] = registration
	}

	return plugins
}
