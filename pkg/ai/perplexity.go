package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

// PerplexityClient implements the Client interface for Perplexity AI API
type PerplexityClient struct {
	apiKey      string
	baseURL     string
	model       string
	maxTokens   int
	temperature float64
	timeout     time.Duration
	httpClient  *http.Client
}

// Perplexity API structures
type perplexityRequest struct {
	Model       string              `json:"model"`
	Messages    []perplexityMessage `json:"messages"`
	MaxTokens   int                 `json:"max_tokens,omitempty"`
	Temperature float64             `json:"temperature,omitempty"`
	Stream      bool                `json:"stream"`
}

type perplexityMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type perplexityResponse struct {
	ID      string             `json:"id"`
	Object  string             `json:"object"`
	Created int64              `json:"created"`
	Model   string             `json:"model"`
	Choices []perplexityChoice `json:"choices"`
	Usage   perplexityUsage    `json:"usage"`
	Error   *perplexityError   `json:"error,omitempty"`
}

type perplexityChoice struct {
	Index        int                `json:"index"`
	FinishReason string             `json:"finish_reason"`
	Message      perplexityMessage  `json:"message"`
	Delta        *perplexityMessage `json:"delta,omitempty"`
}

type perplexityUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type perplexityError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code"`
}

// NewPerplexityClient creates a new Perplexity client
func NewPerplexityClient(config Config) (*PerplexityClient, error) {
	if config.APIKey == "" {
		return nil, fmt.Errorf("Perplexity API key is required")
	}

	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = "https://api.perplexity.ai"
	}

	model := config.Model
	if model == "" {
		model = "sonar" // Use cost-effective model by default
	}

	maxTokens := config.MaxTokens
	if maxTokens == 0 {
		maxTokens = 1000
	}

	temperature := config.Temperature
	if temperature == 0 {
		temperature = 0.3
	}

	timeout := time.Duration(config.Timeout) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &PerplexityClient{
		apiKey:      config.APIKey,
		baseURL:     baseURL,
		model:       model,
		maxTokens:   maxTokens,
		temperature: temperature,
		timeout:     timeout,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

// GetProvider returns the provider name
func (c *PerplexityClient) GetProvider() Provider {
	return ProviderPerplexity
}

// VerifyFinding analyzes a finding using Perplexity
func (c *PerplexityClient) VerifyFinding(ctx context.Context, finding rules.Finding) (*VerificationResult, error) {
	prompt := c.buildPrompt(finding)

	req := perplexityRequest{
		Model: c.model,
		Messages: []perplexityMessage{
			{
				Role:    "user",
				Content: prompt,
			},
		},
		MaxTokens:   c.maxTokens,
		Temperature: c.temperature,
		Stream:      false,
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/chat/completions", c.baseURL)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	var response perplexityResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if response.Error != nil {
		return nil, fmt.Errorf("Perplexity API error: %s", response.Error.Message)
	}

	if len(response.Choices) == 0 {
		return nil, fmt.Errorf("no response from Perplexity")
	}

	return c.parseResponse(response.Choices[0].Message.Content)
}

// buildPrompt creates the analysis prompt for the AI
func (c *PerplexityClient) buildPrompt(finding rules.Finding) string {
	return composeFindingPrompt(finding)
}

// parseResponse parses the AI response into a VerificationResult
func (c *PerplexityClient) parseResponse(content string) (*VerificationResult, error) {
	var result VerificationResult

	// First, try direct JSON parsing
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		// Try to extract JSON from the response if it's wrapped in markdown or other text
		start := bytes.Index([]byte(content), []byte("{"))
		end := bytes.LastIndex([]byte(content), []byte("}"))
		if start != -1 && end != -1 && end > start {
			jsonContent := content[start : end+1]

			// Clean up common escape sequence issues that cause JSON parsing to fail
			jsonContent = c.cleanJSONContent(jsonContent)

			if err := json.Unmarshal([]byte(jsonContent), &result); err != nil {
				return nil, fmt.Errorf("failed to parse AI response as JSON: %w. Content: %s", err, jsonContent)
			}
		} else {
			return nil, fmt.Errorf("failed to parse AI response: %w. Content: %s", err, content)
		}
	}

	// Validate confidence is in valid range
	if result.Confidence < 0 {
		result.Confidence = 0
	}
	if result.Confidence > 1 {
		result.Confidence = 1
	}

	return &result, nil
}

// cleanJSONContent cleans up common issues in JSON content that cause parsing errors
func (c *PerplexityClient) cleanJSONContent(content string) string {
	// Handle unescaped dollar signs and other escape sequence issues

	// First, look for obvious JSON structure
	content = bytes.NewBufferString(content).String()

	// Fix common escape sequence issues that cause JSON parsing to fail
	// Replace sequences like \$ that aren't valid JSON escape sequences
	content = string(bytes.ReplaceAll([]byte(content), []byte("\\$"), []byte("$")))
	content = string(bytes.ReplaceAll([]byte(content), []byte("\\'"), []byte("'")))
	content = string(bytes.ReplaceAll([]byte(content), []byte("\\`"), []byte("`")))

	return string(content)
}

// Close cleans up resources
func (c *PerplexityClient) Close() error {
	// No cleanup needed for HTTP client
	return nil
}
