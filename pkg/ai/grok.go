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
	Code    string `json:"code"`
}

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
				Content: "You are a cybersecurity expert analyzing CI/CD security findings. Your task is to determine if a security finding is a false positive or a true positive. Respond only with valid JSON.",
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

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/chat/completions", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	var response grokResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if response.Error != nil {
		return nil, fmt.Errorf("Grok API error: %s", response.Error.Message)
	}

	if len(response.Choices) == 0 {
		return nil, fmt.Errorf("no response from Grok")
	}

	return c.parseResponse(response.Choices[0].Message.Content)
}

// buildPrompt creates the analysis prompt for the AI
func (c *GrokClient) buildPrompt(finding rules.Finding) string {
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