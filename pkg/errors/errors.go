package errors

import (
	"fmt"
	"strings"
)

// ErrorType represents different types of errors that can occur
type ErrorType int

const (
	// Configuration errors
	ErrorTypeConfig ErrorType = iota
	// Repository access errors
	ErrorTypeRepository
	// Workflow parsing errors
	ErrorTypeWorkflow
	// Rule execution errors
	ErrorTypeRule
	// Policy evaluation errors
	ErrorTypePolicy
	// Report generation errors
	ErrorTypeReport
	// Validation errors
	ErrorTypeValidation
	// Platform errors
	ErrorTypePlatform
)

// FlowlytError represents a structured error with context
type FlowlytError struct {
	Type        ErrorType
	Message     string
	Cause       error
	Details     map[string]interface{}
	Suggestions []string
}

// Error implements the error interface
func (e *FlowlytError) Error() string {
	var sb strings.Builder
	sb.WriteString(e.Message)

	if e.Cause != nil {
		sb.WriteString(": ")
		sb.WriteString(e.Cause.Error())
	}

	if len(e.Details) > 0 {
		sb.WriteString(" (")
		first := true
		for k, v := range e.Details {
			if !first {
				sb.WriteString(", ")
			}
			sb.WriteString(fmt.Sprintf("%s: %v", k, v))
			first = false
		}
		sb.WriteString(")")
	}

	return sb.String()
}

// Unwrap returns the underlying error
func (e *FlowlytError) Unwrap() error {
	return e.Cause
}

// Is checks if the error is of a specific type
func (e *FlowlytError) Is(target error) bool {
	if t, ok := target.(*FlowlytError); ok {
		return e.Type == t.Type
	}
	return false
}

// UserFriendlyMessage returns a user-friendly error message with suggestions
func (e *FlowlytError) UserFriendlyMessage() string {
	var sb strings.Builder
	sb.WriteString("❌ ")
	sb.WriteString(e.Message)

	if len(e.Suggestions) > 0 {
		sb.WriteString("\n\n💡 Suggestions:")
		for _, suggestion := range e.Suggestions {
			sb.WriteString("\n   • ")
			sb.WriteString(suggestion)
		}
	}

	return sb.String()
}

// Constructor functions for different error types

// NewConfigError creates a configuration error
func NewConfigError(message string, cause error, suggestions ...string) *FlowlytError {
	return &FlowlytError{
		Type:        ErrorTypeConfig,
		Message:     message,
		Cause:       cause,
		Suggestions: suggestions,
		Details:     make(map[string]interface{}),
	}
}

// NewRepositoryError creates a repository error
func NewRepositoryError(message string, cause error, repoPath string, suggestions ...string) *FlowlytError {
	details := make(map[string]interface{})
	if repoPath != "" {
		details["repository"] = repoPath
	}

	return &FlowlytError{
		Type:        ErrorTypeRepository,
		Message:     message,
		Cause:       cause,
		Details:     details,
		Suggestions: suggestions,
	}
}

// NewWorkflowError creates a workflow parsing error
func NewWorkflowError(message string, cause error, workflowPath string, suggestions ...string) *FlowlytError {
	details := make(map[string]interface{})
	if workflowPath != "" {
		details["workflow"] = workflowPath
	}

	return &FlowlytError{
		Type:        ErrorTypeWorkflow,
		Message:     message,
		Cause:       cause,
		Details:     details,
		Suggestions: suggestions,
	}
}

// NewRuleError creates a rule execution error
func NewRuleError(message string, cause error, ruleID string, suggestions ...string) *FlowlytError {
	details := make(map[string]interface{})
	if ruleID != "" {
		details["rule"] = ruleID
	}

	return &FlowlytError{
		Type:        ErrorTypeRule,
		Message:     message,
		Cause:       cause,
		Details:     details,
		Suggestions: suggestions,
	}
}

// NewPolicyError creates a policy evaluation error
func NewPolicyError(message string, cause error, policyPath string, suggestions ...string) *FlowlytError {
	details := make(map[string]interface{})
	if policyPath != "" {
		details["policy"] = policyPath
	}

	return &FlowlytError{
		Type:        ErrorTypePolicy,
		Message:     message,
		Cause:       cause,
		Details:     details,
		Suggestions: suggestions,
	}
}

// NewReportError creates a report generation error
func NewReportError(message string, cause error, outputPath string, suggestions ...string) *FlowlytError {
	details := make(map[string]interface{})
	if outputPath != "" {
		details["output"] = outputPath
	}

	return &FlowlytError{
		Type:        ErrorTypeReport,
		Message:     message,
		Cause:       cause,
		Details:     details,
		Suggestions: suggestions,
	}
}

// NewValidationError creates a validation error
func NewValidationError(message string, field string, value interface{}, suggestions ...string) *FlowlytError {
	details := make(map[string]interface{})
	if field != "" {
		details["field"] = field
	}
	if value != nil {
		details["value"] = value
	}

	return &FlowlytError{
		Type:        ErrorTypeValidation,
		Message:     message,
		Details:     details,
		Suggestions: suggestions,
	}
}

// NewPlatformError creates a platform error
func NewPlatformError(message string, cause error, platform string, suggestions ...string) *FlowlytError {
	details := make(map[string]interface{})
	if platform != "" {
		details["platform"] = platform
	}

	return &FlowlytError{
		Type:        ErrorTypePlatform,
		Message:     message,
		Cause:       cause,
		Details:     details,
		Suggestions: suggestions,
	}
}

// Predefined common errors

// ErrUnsupportedPlatform creates an unsupported platform error
func ErrUnsupportedPlatform(platform string, supportedPlatforms []string) *FlowlytError {
	return NewPlatformError(
		fmt.Sprintf("Unsupported platform: %s", platform),
		nil,
		platform,
		fmt.Sprintf("Use one of the supported platforms: %s", strings.Join(supportedPlatforms, ", ")),
		"Check the documentation for platform-specific requirements",
	)
}

// ErrNoInputSpecified creates a no input specified error
func ErrNoInputSpecified() *FlowlytError {
	return NewValidationError(
		"No input specified",
		"input",
		nil,
		"Specify either --repo for local repository, --url for remote repository, or --workflow for single file",
		"Use 'flowlyt --help' to see all available options",
	)
}

// ErrConfigNotFound creates a configuration not found error
func ErrConfigNotFound(configPath string) *FlowlytError {
	return NewConfigError(
		fmt.Sprintf("Configuration file not found: %s", configPath),
		nil,
		"Create a configuration file using 'flowlyt init-config'",
		"Check the file path and permissions",
		"Use default configuration by omitting the --config flag",
	)
}

// ErrInvalidOutputFormat creates an invalid output format error
func ErrInvalidOutputFormat(format string, supportedFormats []string) *FlowlytError {
	return NewValidationError(
		fmt.Sprintf("Invalid output format: %s", format),
		"output",
		format,
		fmt.Sprintf("Use one of the supported formats: %s", strings.Join(supportedFormats, ", ")),
	)
}
