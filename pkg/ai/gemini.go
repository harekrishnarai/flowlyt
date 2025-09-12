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
		model = "gemini-1.5-flash" // Use cost-effective model by default
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
	return fmt.Sprintf(`You are a cybersecurity expert specializing in CI/CD security, GitHub Actions hardening, and software supply chain security. Analyze this finding and determine if it's a false positive or true positive.

IMPORTANT CONTEXT:
- This analysis is performed on a repository that was temporarily cloned to a /tmp/ directory for scanning
- File paths containing /tmp/ are normal and expected - they do not indicate the actual repository location
- Focus on the security implications of the CI/CD configuration, not the temporary file location

Finding Details:
- Rule: %s (%s)
- Description: %s
- Severity: %s
- Category: %s
- File: %s
- Job: %s
- Step: %s
- Evidence: %s

Please analyze this finding and respond with JSON in this exact format:
{
  "is_likely_false_positive": boolean,
  "confidence": float (0.0 to 1.0),
  "reasoning": "detailed explanation of your analysis",
  "suggested_severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO (only if you suggest a different severity)"
}

Analyze from these critical security perspectives:

1. GITHUB ACTIONS HARDENING:
   - Are actions pinned to specific SHA commits to prevent supply chain attacks?
   - Are dangerous permissions (write, admin) properly scoped?
   - Are secrets handled securely and not exposed in logs?
   - Are workflow triggers properly restricted to prevent abuse?

2. SOFTWARE SUPPLY CHAIN SECURITY:
   - Can this configuration lead to dependency confusion attacks?
   - Are third-party actions from trusted publishers or properly vetted?
   - Could malicious code be injected through compromised dependencies?
   - Are build artifacts properly signed and verified?

3. RUNNER COMPROMISE & ATTACK VECTORS:
   - Could this configuration allow lateral movement if a runner is compromised?
   - Are self-hosted runners properly isolated and secured?
   - Can attackers persist in the environment or access other repositories?
   - Could this lead to credential theft or privilege escalation?

4. CI/CD PIPELINE SECURITY:
   - Is the evidence actually indicative of a security risk in the CI/CD pipeline?
   - Could this be legitimate usage in a CI/CD context?
   - Is the severity appropriate for the actual risk level?
   - Are there any context clues that suggest this is intentional/safe?
   - Does the /tmp/ path indicate a temporary scanning location rather than a security issue?

SEVERITY GUIDELINES:
- CRITICAL: Direct code execution, credential exposure, or full environment compromise
- HIGH: Supply chain compromise, privilege escalation, or significant attack surface
- MEDIUM: Configuration weaknesses that could facilitate attacks
- LOW: Minor security hygiene issues or potential information disclosure
- INFO: Best practice violations with minimal security impact

Be conservative - prefer false positive over missing real threats, especially for supply chain risks.`,
		finding.RuleName,
		finding.RuleID,
		finding.Description,
		string(finding.Severity),
		string(finding.Category),
		finding.FilePath,
		finding.JobName,
		finding.StepName,
		finding.Evidence,
	)
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
