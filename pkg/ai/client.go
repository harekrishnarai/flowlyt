package ai

import (
	"context"
	"fmt"

	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

// Provider represents different AI providers
type Provider string

const (
	ProviderOpenAI     Provider = "openai"
	ProviderGemini     Provider = "gemini"
	ProviderClaude     Provider = "claude"
	ProviderGrok       Provider = "grok"
	ProviderPerplexity Provider = "perplexity"
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
	BaseURL  string   `yaml:"base_url,omitempty"` // Custom endpoint for self-hosted models
	Model    string   `yaml:"model,omitempty"`    // Specific model to use

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
	case ProviderPerplexity:
		return NewPerplexityClient(config)
	default:
		return nil, fmt.Errorf("unsupported AI provider: %s", config.Provider)
	}
}

// ValidateProvider checks if the provider is supported
func ValidateProvider(provider string) error {
	switch Provider(provider) {
	case ProviderOpenAI, ProviderGemini, ProviderClaude, ProviderGrok, ProviderPerplexity:
		return nil
	default:
		return fmt.Errorf("unsupported AI provider: %s. Supported providers: openai, gemini, claude, grok, perplexity", provider)
	}
}

// GetSupportedProviders returns a list of supported AI providers
func GetSupportedProviders() []string {
	return []string{
		string(ProviderOpenAI),
		string(ProviderGemini),
		string(ProviderClaude),
		string(ProviderGrok),
		string(ProviderPerplexity),
	}
}

// GetDefaultModel returns the default model for a given provider
func GetDefaultModel(provider Provider) string {
	switch provider {
	case ProviderOpenAI:
		return "gpt-4o-mini"
	case ProviderGemini:
		return "gemini-2.5-flash"
	case ProviderClaude:
		// Default to Claude Haiku latest stable for better quality/cost
		return "claude-3-5-haiku-20241022"
	case ProviderGrok:
		return "grok-beta"
	case ProviderPerplexity:
		return "sonar"
	default:
		return ""
	}
}

// GetAvailableModels returns a list of available models for a given provider
func GetAvailableModels(provider Provider) []string {
	switch provider {
	case ProviderOpenAI:
		return []string{
			"gpt-4o-mini",   // Cost-effective default
			"gpt-4o",        // Latest flagship model
			"gpt-4-turbo",   // Fast and capable
			"gpt-4",         // Original GPT-4
			"gpt-3.5-turbo", // Legacy but fast
		}
	case ProviderGemini:
		return []string{
			"gemini-2.5-flash", // Cost-effective default
			"gemini-1.5-pro",   // Higher quality
			"gemini-1.0-pro",   // Legacy version
		}
	case ProviderClaude:
		return []string{
			"claude-3-5-haiku-20241022", // Default (quality + speed)
			"claude-3-sonnet-20240229",  // Balanced performance
			"claude-3-opus-20240229",    // Highest quality
		}
	case ProviderGrok:
		return []string{
			"grok-beta", // Current default
		}
	case ProviderPerplexity:
		return []string{
			"llama-3.1-sonar-small-128k-online", // Cost-effective default
			"llama-3.1-sonar-large-128k-online", // Higher quality
			"llama-3.1-sonar-huge-128k-online",  // Highest quality
		}
	default:
		return []string{}
	}
}
