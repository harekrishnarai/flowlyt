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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

// GrokClient implements the Client interface for xAI Grok API
type GrokClient struct {
	apiKey      string
	baseURL     string
	model       string
	maxTokens   int
	temperature float64
	timeout     time.Duration
	httpClient  *http.Client
}

// Grok API structures (similar to OpenAI API format)
type grokRequest struct {
	Model       string        `json:"model"`
	Messages    []grokMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Temperature float64       `json:"temperature,omitempty"`
}

type grokMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type grokResponse struct {
	Choices []grokChoice `json:"choices"`
	Error   *grokError   `json:"error,omitempty"`
}

type grokChoice struct {
	Message grokMessage `json:"message"`
}

type grokError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	// Code may be numeric or string depending on xAI response, so allow any.
	Code any `json:"code"`
}

const grokSystemPrompt = "You are a CI/CD security assistant. Respond ONLY with a single JSON object that matches the requested schema. Do not include any prose, markdown, comments, or additional text outside the JSON object."

// NewGrokClient creates a new Grok client
func NewGrokClient(config Config) (*GrokClient, error) {
	if config.APIKey == "" {
		return nil, fmt.Errorf("Grok API key is required")
	}

	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = "https://api.x.ai/v1"
	}

	model := config.Model
	if model == "" {
		model = "grok-beta" // Use default Grok model
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

	return &GrokClient{
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
func (c *GrokClient) GetProvider() Provider {
	return ProviderGrok
}

// VerifyFinding analyzes a finding using Grok
func (c *GrokClient) VerifyFinding(ctx context.Context, finding rules.Finding) (*VerificationResult, error) {
	prompt := c.buildPrompt(finding)

	req := grokRequest{
		Model:       c.model,
		MaxTokens:   c.maxTokens,
		Temperature: c.temperature,
		Messages: []grokMessage{
			{
				Role:    "system",
				Content: grokSystemPrompt,
			},
			{
				Role:    "user",
				Content: prompt,
			},
		},
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	const maxRetries = 3
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/chat/completions", bytes.NewBuffer(jsonData))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

		resp, err := c.httpClient.Do(httpReq)
		if err != nil {
			lastErr = fmt.Errorf("failed to make request: %w", err)
		} else {
			defer resp.Body.Close()

			var response grokResponse
			if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
				lastErr = fmt.Errorf("failed to decode response: %w", err)
			} else if response.Error != nil {
				lastErr = fmt.Errorf("Grok API error: %s", response.Error.Message)
			} else if len(response.Choices) == 0 {
				lastErr = fmt.Errorf("no response from Grok")
			} else {
				return c.parseResponse(response.Choices[0].Message.Content)
			}
		}

		if attempt < maxRetries-1 {
			backoff := time.Duration(1<<attempt) * time.Second
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, fmt.Errorf("Grok request cancelled during backoff: %w", ctx.Err())
			}
		}
	}

	return nil, lastErr
}

// buildPrompt creates the analysis prompt for the AI
func (c *GrokClient) buildPrompt(finding rules.Finding) string {
	return composeFindingPrompt(finding)
}

// parseResponse parses the AI response into a VerificationResult
func (c *GrokClient) parseResponse(content string) (*VerificationResult, error) {
	var result VerificationResult
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		// Try to extract JSON from the response if it's wrapped in markdown or other text
		start := bytes.Index([]byte(content), []byte("{"))
		end := bytes.LastIndex([]byte(content), []byte("}"))
		if start != -1 && end != -1 && end > start {
			jsonContent := content[start : end+1]
			if err := json.Unmarshal([]byte(jsonContent), &result); err != nil {
				return nil, fmt.Errorf("failed to parse AI response as JSON: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to parse AI response: %w", err)
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

// Close cleans up resources
func (c *GrokClient) Close() error {
	// No cleanup needed for HTTP client
	return nil
}
