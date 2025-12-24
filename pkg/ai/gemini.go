package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

// GeminiClient implements the Client interface for Google Gemini API
type GeminiClient struct {
	apiKey      string
	baseURL     string
	model       string
	maxTokens   int
	temperature float64
	timeout     time.Duration
	httpClient  *http.Client
}

// Gemini API structures
type geminiRequest struct {
	Contents         []geminiContent         `json:"contents"`
	GenerationConfig *geminiGenerationConfig `json:"generationConfig,omitempty"`
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiGenerationConfig struct {
	Temperature     *float64 `json:"temperature,omitempty"`
	MaxOutputTokens *int     `json:"maxOutputTokens,omitempty"`
}

type geminiResponse struct {
	Candidates []geminiCandidate `json:"candidates"`
	Error      *geminiError      `json:"error,omitempty"`
}

type geminiCandidate struct {
	Content geminiContent `json:"content"`
}

type geminiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// NewGeminiClient creates a new Gemini client
func NewGeminiClient(config Config) (*GeminiClient, error) {
	if config.APIKey == "" {
		return nil, fmt.Errorf("Gemini API key is required")
	}

	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = "https://generativelanguage.googleapis.com/v1beta"
	}

	model := config.Model
	if model == "" {
		model = "gemini-2.5-flash" // Use cost-effective model by default
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

	return &GeminiClient{
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
func (c *GeminiClient) GetProvider() Provider {
	return ProviderGemini
}

// VerifyFinding analyzes a finding using Gemini
func (c *GeminiClient) VerifyFinding(ctx context.Context, finding rules.Finding) (*VerificationResult, error) {
	prompt := c.buildPrompt(finding)

	req := geminiRequest{
		Contents: []geminiContent{
			{
				Parts: []geminiPart{
					{
						Text: prompt,
					},
				},
			},
		},
		GenerationConfig: &geminiGenerationConfig{
			Temperature:     &c.temperature,
			MaxOutputTokens: &c.maxTokens,
		},
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/models/%s:generateContent?key=%s", c.baseURL, c.model, c.apiKey)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	var response geminiResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if response.Error != nil {
		return nil, fmt.Errorf("Gemini API error: %s", response.Error.Message)
	}

	if len(response.Candidates) == 0 || len(response.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("no response from Gemini")
	}

	return c.parseResponse(response.Candidates[0].Content.Parts[0].Text)
}

// buildPrompt creates the analysis prompt for the AI
func (c *GeminiClient) buildPrompt(finding rules.Finding) string {
	return composeFindingPrompt(finding)
}

// parseResponse parses the AI response into a VerificationResult
func (c *GeminiClient) parseResponse(content string) (*VerificationResult, error) {
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
func (c *GeminiClient) cleanJSONContent(content string) string {
	// Handle unescaped dollar signs and other escape sequence issues

	// First, look for obvious JSON structure
	content = strings.TrimSpace(content)

	// Fix common escape sequence issues that cause JSON parsing to fail
	// Replace sequences like \$ that aren't valid JSON escape sequences
	content = strings.ReplaceAll(content, "\\$", "$")

	// Fix other problematic sequences
	content = strings.ReplaceAll(content, "\\'", "'")
	content = strings.ReplaceAll(content, "\\`", "`")

	return content
}

// Close cleans up resources
func (c *GeminiClient) Close() error {
	// No cleanup needed for HTTP client
	return nil
}
