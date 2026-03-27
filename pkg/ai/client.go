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
		return "gemini-3.1-flash"
	case ProviderClaude:
		return "claude-sonnet-4-6"
	case ProviderGrok:
		return "grok-3"
	case ProviderPerplexity:
		return "sonar-pro"
	default:
		return ""
	}
}

// GetAvailableModels returns a list of available models for a given provider
func GetAvailableModels(provider Provider) []string {
	switch provider {
	case ProviderOpenAI:
		return []string{
			"gpt-4o-mini", // Cost-effective default
			"gpt-4o",      // Flagship model
			"o3-mini",     // Reasoning model, cost-effective
			"o3",          // Full reasoning model
		}
	case ProviderGemini:
		return []string{
			"gemini-3.1-flash", // Cost-effective default
			"gemini-3.1-pro",   // Higher quality
			"gemini-2.5-flash", // Previous generation
		}
	case ProviderClaude:
		return []string{
			"claude-sonnet-4-6",          // Default — balanced quality/cost
			"claude-opus-4-6",            // Highest quality
			"claude-haiku-4-5-20251001",  // Fastest, most cost-effective
		}
	case ProviderGrok:
		return []string{
			"grok-3",      // Current default
			"grok-3-mini", // Cost-effective
		}
	case ProviderPerplexity:
		return []string{
			"sonar-pro",      // Cost-effective default
			"sonar-reasoning", // Reasoning model
			"sonar",          // Legacy
		}
	default:
		return []string{}
	}
}
