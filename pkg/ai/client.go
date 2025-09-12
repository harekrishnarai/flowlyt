package ai

import (
	"context"
	"fmt"

	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

// Provider represents different AI providers
type Provider string

const (
	ProviderOpenAI Provider = "openai"
	ProviderGemini Provider = "gemini" 
	ProviderClaude Provider = "claude"
	ProviderGrok   Provider = "grok"
)

// VerificationResult represents the AI's assessment of a finding
type VerificationResult struct {
	IsLikelyFalsePositive bool    `json:"is_likely_false_positive"`
	Confidence            float64 `json:"confidence"` // 0.0 to 1.0
	Reasoning             string  `json:"reasoning"`
	Severity              string  `json:"suggested_severity,omitempty"`
}

// Client interface for AI providers
type Client interface {
	// VerifyFinding analyzes a security finding and determines if it's likely a false positive
	VerifyFinding(ctx context.Context, finding rules.Finding) (*VerificationResult, error)
	
	// GetProvider returns the provider name
	GetProvider() Provider
	
	// Close cleans up any resources
	Close() error
}

// Config holds configuration for AI clients
type Config struct {
	Provider Provider `yaml:"provider"`
	APIKey   string   `yaml:"api_key"`
	BaseURL  string   `yaml:"base_url,omitempty"`  // Custom endpoint for self-hosted models
	Model    string   `yaml:"model,omitempty"`     // Specific model to use
	
	// Request configuration
	MaxTokens   int     `yaml:"max_tokens,omitempty"`
	Temperature float64 `yaml:"temperature,omitempty"`
	Timeout     int     `yaml:"timeout,omitempty"` // seconds
}

// NewClient creates a new AI client based on the provider
func NewClient(config Config) (Client, error) {
	switch config.Provider {
	case ProviderOpenAI:
		return NewOpenAIClient(config)
	case ProviderGemini:
		return NewGeminiClient(config)
	case ProviderClaude:
		return NewClaudeClient(config)
	case ProviderGrok:
		return NewGrokClient(config)
	default:
		return nil, fmt.Errorf("unsupported AI provider: %s", config.Provider)
	}
}

// ValidateProvider checks if the provider is supported
func ValidateProvider(provider string) error {
	switch Provider(provider) {
	case ProviderOpenAI, ProviderGemini, ProviderClaude, ProviderGrok:
		return nil
	default:
		return fmt.Errorf("unsupported AI provider: %s. Supported providers: openai, gemini, claude, grok", provider)
	}
}

// GetSupportedProviders returns a list of supported AI providers
func GetSupportedProviders() []string {
	return []string{
		string(ProviderOpenAI),
		string(ProviderGemini),
		string(ProviderClaude),
		string(ProviderGrok),
	}
}