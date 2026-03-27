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
	"strings"
	"testing"

	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

// MockClient implements the Client interface for testing
type MockClient struct {
	provider     Provider
	verifyResult *VerificationResult
	verifyError  error
	closeError   error
	callCount    int
}

func (m *MockClient) VerifyFinding(ctx context.Context, finding rules.Finding) (*VerificationResult, error) {
	m.callCount++
	if m.verifyError != nil {
		return nil, m.verifyError
	}
	return m.verifyResult, nil
}

func (m *MockClient) GetProvider() Provider {
	return m.provider
}

func (m *MockClient) Close() error {
	return m.closeError
}

func (m *MockClient) VerifyBatch(ctx context.Context, class string, findings []rules.Finding) ([]BatchVerificationResult, error) {
	results := make([]BatchVerificationResult, len(findings))
	for i := range findings {
		m.callCount++
		if m.verifyError != nil {
			results[i] = BatchVerificationResult{Index: i, Error: m.verifyError.Error()}
		} else {
			results[i] = BatchVerificationResult{Index: i, Result: m.verifyResult}
		}
	}
	return results, nil
}

func TestValidateProvider(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		wantErr  bool
	}{
		{
			name:     "valid openai",
			provider: "openai",
			wantErr:  false,
		},
		{
			name:     "valid gemini",
			provider: "gemini",
			wantErr:  false,
		},
		{
			name:     "valid claude",
			provider: "claude",
			wantErr:  false,
		},
		{
			name:     "valid grok",
			provider: "grok",
			wantErr:  false,
		},
		{
			name:     "invalid provider",
			provider: "invalid",
			wantErr:  true,
		},
		{
			name:     "empty provider",
			provider: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProvider(tt.provider)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateProvider() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetSupportedProviders(t *testing.T) {
	providers := GetSupportedProviders()
	expected := []string{"openai", "gemini", "claude", "grok", "perplexity"}

	if len(providers) != len(expected) {
		t.Fatalf("GetSupportedProviders() returned %d providers, expected %d", len(providers), len(expected))
	}

	for i, provider := range providers {
		if provider != expected[i] {
			t.Errorf("GetSupportedProviders()[%d] = %s, expected %s", i, provider, expected[i])
		}
	}
}

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid openai config",
			config: Config{
				Provider: ProviderOpenAI,
				APIKey:   "test-key",
			},
			wantErr: false,
		},
		{
			name: "valid gemini config",
			config: Config{
				Provider: ProviderGemini,
				APIKey:   "test-key",
			},
			wantErr: false,
		},
		{
			name: "valid claude config",
			config: Config{
				Provider: ProviderClaude,
				APIKey:   "test-key",
			},
			wantErr: false,
		},
		{
			name: "valid grok config",
			config: Config{
				Provider: ProviderGrok,
				APIKey:   "test-key",
			},
			wantErr: false,
		},
		{
			name: "valid perplexity config",
			config: Config{
				Provider: ProviderPerplexity,
				APIKey:   "test-key",
			},
			wantErr: false,
		},
		{
			name: "invalid provider",
			config: Config{
				Provider: "invalid",
				APIKey:   "test-key",
			},
			wantErr: true,
		},
		{
			name: "missing api key",
			config: Config{
				Provider: ProviderOpenAI,
				APIKey:   "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && client != nil {
				defer client.Close()
			}
		})
	}
}

func TestAnalyzer(t *testing.T) {
	// Create mock client
	mockClient := &MockClient{
		provider: ProviderOpenAI,
		verifyResult: &VerificationResult{
			IsLikelyFalsePositive: true,
			Confidence:            0.8,
			Reasoning:             "Test reasoning",
		},
	}

	analyzer := NewAnalyzer(mockClient, 2, 0)
	defer analyzer.Close()

	// Test single finding analysis
	finding := rules.Finding{
		RuleID:      "TEST_RULE",
		RuleName:    "Test Rule",
		Description: "Test description",
		Severity:    rules.Medium,
		Category:    rules.Misconfiguration,
		Evidence:    "Test evidence",
	}

	ctx := context.Background()
	enhanced, err := analyzer.AnalyzeSingleFinding(ctx, finding)
	if err != nil {
		t.Fatalf("AnalyzeSingleFinding() error = %v", err)
	}

	if enhanced.AIVerification == nil {
		t.Fatal("Expected AI verification result, got nil")
	}

	if !enhanced.AIVerification.IsLikelyFalsePositive {
		t.Error("Expected false positive, got true positive")
	}

	if enhanced.AIVerification.Confidence != 0.8 {
		t.Errorf("Expected confidence 0.8, got %f", enhanced.AIVerification.Confidence)
	}

	// Test multiple findings analysis
	findings := []rules.Finding{finding, finding}
	enhancedFindings, err := analyzer.AnalyzeFindings(ctx, findings)
	if err != nil {
		t.Fatalf("AnalyzeFindings() error = %v", err)
	}

	if len(enhancedFindings) != 2 {
		t.Errorf("Expected 2 enhanced findings, got %d", len(enhancedFindings))
	}

	// Test call count (cache is reused across single + batch analysis)
	expectedCalls := 1
	if mockClient.callCount != expectedCalls {
		t.Errorf("Expected %d API calls, got %d", expectedCalls, mockClient.callCount)
	}
}

func TestBatchVerificationResultIndexed(t *testing.T) {
	r := BatchVerificationResult{
		Index: 2,
		Result: &VerificationResult{
			IsLikelyFalsePositive: true,
			Confidence:            0.9,
			Remediation:           "use secrets.TOKEN",
		},
	}
	if r.Index != 2 {
		t.Errorf("expected index 2, got %d", r.Index)
	}
	if r.Result.Remediation == "" {
		t.Error("expected Remediation to be set")
	}
}

func TestShouldSkipAI(t *testing.T) {
	tests := []struct {
		name        string
		finding     rules.Finding
		wantSkip    bool
		wantContain string // substring expected in reason
	}{
		{
			name: "secrets expression reference skipped",
			finding: rules.Finding{
				Category: rules.SecretsExposure,
				Evidence: "value: ${{ secrets.MY_TOKEN }}",
			},
			wantSkip:    true,
			wantContain: "expression reference",
		},
		{
			name: "placeholder secret skipped",
			finding: rules.Finding{
				Category: rules.SecretsExposure,
				Evidence: "api_key: your-api-key-here",
			},
			wantSkip:    true,
			wantContain: "placeholder",
		},
		{
			name: "real token prefix sent",
			finding: rules.Finding{
				Category: rules.SecretsExposure,
				Evidence: "token: ghp_xxxxxxxxxxxxxxxxxxxx",
			},
			wantSkip: false,
		},
		{
			name: "pinned SHA skipped",
			finding: rules.Finding{
				Category: rules.Misconfiguration,
				Evidence: "uses: actions/checkout@abcdef1234567890abcdef1234567890abcdef12",
			},
			wantSkip:    true,
			wantContain: "SHA",
		},
		{
			name: "locked permissions skipped",
			finding: rules.Finding{
				Category: rules.Misconfiguration,
				Evidence: "permissions: read-all",
			},
			wantSkip:    true,
			wantContain: "permissions",
		},
		{
			name: "high entropy string sent",
			finding: rules.Finding{
				Category: rules.SecretsExposure,
				Evidence: "AKIA1234567890ABCDEF",
			},
			wantSkip: false,
		},
		{
			name: "env reference skipped",
			finding: rules.Finding{
				Category: rules.SecretsExposure,
				Evidence: "token: ${{ env.API_TOKEN }}",
			},
			wantSkip:    true,
			wantContain: "expression reference",
		},
		{
			// SecretExposure (singular) is the older constant used in most rules;
			// the filter must treat it identically to SecretsExposure (plural).
			name: "singular SecretExposure expression reference skipped",
			finding: rules.Finding{
				Category: rules.SecretExposure,
				Evidence: "api_key: ${{ secrets.API_KEY }}",
			},
			wantSkip:    true,
			wantContain: "expression reference",
		},
		{
			name: "vars reference skipped",
			finding: rules.Finding{
				Category: rules.SecretsExposure,
				Evidence: "token: ${{ vars.API_TOKEN }}",
			},
			wantSkip:    true,
			wantContain: "expression reference",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skip, reason := ShouldSkipAI(tt.finding)
			if skip != tt.wantSkip {
				t.Errorf("ShouldSkipAI() skip = %v, want %v (reason: %q)", skip, tt.wantSkip, reason)
			}
			if tt.wantContain != "" && !strings.Contains(reason, tt.wantContain) {
				t.Errorf("ShouldSkipAI() reason = %q, want it to contain %q", reason, tt.wantContain)
			}
		})
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		input   string
		wantGTE float64 // expect entropy >= this
		wantLT  float64 // expect entropy < this
	}{
		{"aaaaaaaaaa", 0, 0.1},               // all same char — near zero
		{"your-api-key-here", 0, 4.0},        // placeholder — low entropy
		{"AKIA1234567890ABCDEF", 4.0, 10},    // real token prefix — high entropy
		{"ghp_xxxxxxxxxxxxxxxxxxxx", 0, 4.0}, // repetitive x — low (but prefix catches it)
	}
	for _, tt := range tests {
		e := shannonEntropy(tt.input)
		if e < tt.wantGTE {
			t.Errorf("shannonEntropy(%q) = %f, want >= %f", tt.input, e, tt.wantGTE)
		}
		if e >= tt.wantLT {
			t.Errorf("shannonEntropy(%q) = %f, want < %f", tt.input, e, tt.wantLT)
		}
	}
}

func TestComposeBatchPrompt(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "TEST_RULE_1", Evidence: "evidence one", Category: rules.PrivilegeEscalation},
		{RuleID: "TEST_RULE_2", Evidence: "evidence two", Category: rules.PrivilegeEscalation},
	}

	system, user := composeBatchPrompt("escalation", findings)

	if system == "" {
		t.Error("expected non-empty system prompt")
	}
	if !strings.Contains(user, `"index": 0`) {
		t.Error("user prompt must contain index 0")
	}
	if !strings.Contains(user, `"index": 1`) {
		t.Error("user prompt must contain index 1")
	}
	if !strings.Contains(user, "evidence one") {
		t.Error("user prompt must contain first finding evidence")
	}
	// Verify the system prompt is class-specific, not generic
	if !strings.Contains(strings.ToLower(system), "escalation") {
		t.Error("escalation class system prompt must mention escalation")
	}
}

func TestCategoryToClass(t *testing.T) {
	tests := []struct {
		category  rules.Category
		wantClass string
	}{
		{rules.PrivilegeEscalation, "escalation"},
		{rules.AccessControl, "escalation"},
		{rules.InjectionAttack, "injection"},
		{rules.SecretExposure, "secrets_context"},
		{rules.SecretsExposure, "secrets_context"},
		{rules.SupplyChain, "supply_chain_trust"},
		{rules.Misconfiguration, "generic"},
		{rules.ShellObfuscation, "generic"},
		{rules.MaliciousPattern, "generic"},
		{rules.PolicyViolation, "generic"},
		{rules.DataExposure, "generic"},
	}

	for _, tt := range tests {
		t.Run(string(tt.category), func(t *testing.T) {
			got := categoryToClass(tt.category)
			if got != tt.wantClass {
				t.Errorf("categoryToClass(%q) = %q, want %q", tt.category, got, tt.wantClass)
			}
		})
	}
}

func TestParseBatchResponse(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		content := `[
            {"index": 0, "is_likely_false_positive": false, "confidence": 0.9, "reasoning": "real token", "suggested_severity": "HIGH", "remediation": "rotate key"},
            {"index": 1, "is_likely_false_positive": true,  "confidence": 0.7, "reasoning": "placeholder", "suggested_severity": "LOW",  "remediation": ""}
        ]`
		results, err := parseBatchResponse(content, 2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(results) != 2 {
			t.Fatalf("expected 2 results, got %d", len(results))
		}
		if results[0].Index != 0 || results[0].Result == nil {
			t.Errorf("result[0] not attributed correctly: %+v", results[0])
		}
		if results[0].Result.Confidence != 0.9 {
			t.Errorf("expected confidence 0.9, got %f", results[0].Result.Confidence)
		}
		if results[0].Result.Remediation != "rotate key" {
			t.Errorf("expected remediation 'rotate key', got %q", results[0].Result.Remediation)
		}
		if results[1].Index != 1 || results[1].Result == nil {
			t.Errorf("result[1] not attributed correctly: %+v", results[1])
		}
	})

	t.Run("markdown wrapped response", func(t *testing.T) {
		content := "```json\n[{\"index\": 0, \"is_likely_false_positive\": false, \"confidence\": 0.8, \"reasoning\": \"ok\", \"suggested_severity\": \"MEDIUM\", \"remediation\": \"fix it\"}]\n```"
		results, err := parseBatchResponse(content, 1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(results) != 1 || results[0].Result == nil {
			t.Errorf("expected 1 result with non-nil Result, got %+v", results)
		}
	})

	t.Run("missing index filled with error", func(t *testing.T) {
		content := `[{"index": 0, "is_likely_false_positive": false, "confidence": 0.9, "reasoning": "ok", "suggested_severity": "HIGH", "remediation": ""}]`
		results, err := parseBatchResponse(content, 3) // 3 expected but only 1 returned
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(results) != 3 {
			t.Fatalf("expected 3 results, got %d", len(results))
		}
		if results[1].Error == "" {
			t.Error("expected results[1] to have an error for missing index")
		}
		if results[2].Error == "" {
			t.Error("expected results[2] to have an error for missing index")
		}
	})

	t.Run("confidence clamped to 0-1", func(t *testing.T) {
		content := `[
            {"index": 0, "is_likely_false_positive": false, "confidence": 1.5, "reasoning": "over", "suggested_severity": "HIGH", "remediation": ""},
            {"index": 1, "is_likely_false_positive": false, "confidence": -0.3, "reasoning": "under", "suggested_severity": "LOW", "remediation": ""}
        ]`
		results, err := parseBatchResponse(content, 2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if results[0].Result.Confidence != 1.0 {
			t.Errorf("expected confidence clamped to 1.0, got %f", results[0].Result.Confidence)
		}
		if results[1].Result.Confidence != 0.0 {
			t.Errorf("expected confidence clamped to 0.0, got %f", results[1].Result.Confidence)
		}
	})

	t.Run("no JSON array returns error", func(t *testing.T) {
		_, err := parseBatchResponse("sorry, I cannot help with that", 2)
		if err == nil {
			t.Error("expected error for response with no JSON array")
		}
	})
}

func TestAnalyzerSkipsFilteredFindings(t *testing.T) {
	mockClient := &MockClient{
		provider:     ProviderOpenAI,
		verifyResult: &VerificationResult{Confidence: 0.9},
	}
	analyzer := NewAnalyzer(mockClient, 2, 0)
	defer analyzer.Close()

	findings := []rules.Finding{
		// This should be skipped (expression reference)
		{RuleID: "SECRET_1", Category: rules.SecretsExposure, Evidence: "token: ${{ secrets.MY_TOKEN }}"},
		// This should be sent
		{RuleID: "ESCALATION_1", Category: rules.PrivilegeEscalation, Evidence: "pull_request_target with write:contents"},
	}

	ctx := context.Background()
	enhanced, err := analyzer.AnalyzeFindings(ctx, findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(enhanced) != 2 {
		t.Fatalf("expected 2 EnhancedFindings (skipped + analyzed), got %d", len(enhanced))
	}

	summary := GetSummary(enhanced)
	if summary.SkippedByFilter != 1 {
		t.Errorf("expected SkippedByFilter=1, got %d", summary.SkippedByFilter)
	}

	// Find the skipped one
	var skipped *EnhancedFinding
	for i := range enhanced {
		if enhanced[i].AISkipped {
			skipped = &enhanced[i]
		}
	}
	if skipped == nil {
		t.Error("expected one finding with AISkipped=true")
	}
	if skipped.AISkipReason == "" {
		t.Error("expected AISkipReason to be set on skipped finding")
	}
}

func TestGetSummarySkippedByFilter(t *testing.T) {
	findings := []EnhancedFinding{
		{Finding: rules.Finding{RuleID: "A"}, AISkipped: true, AISkipReason: "expression reference"},
		{Finding: rules.Finding{RuleID: "B"}, AIVerification: &VerificationResult{IsLikelyFalsePositive: false, Confidence: 0.9}},
	}
	summary := GetSummary(findings)
	if summary.SkippedByFilter != 1 {
		t.Errorf("expected SkippedByFilter=1, got %d", summary.SkippedByFilter)
	}
	if summary.TotalAnalyzed != 2 {
		t.Errorf("expected TotalAnalyzed=2, got %d", summary.TotalAnalyzed)
	}
}

func TestGetSummary(t *testing.T) {
	enhancedFindings := []EnhancedFinding{
		{
			Finding: rules.Finding{RuleID: "test1"},
			AIVerification: &VerificationResult{
				IsLikelyFalsePositive: true,
				Confidence:            0.9,
			},
		},
		{
			Finding: rules.Finding{RuleID: "test2"},
			AIVerification: &VerificationResult{
				IsLikelyFalsePositive: false,
				Confidence:            0.7,
			},
		},
		{
			Finding: rules.Finding{RuleID: "test3"},
			AIError: "Test error",
		},
	}

	summary := GetSummary(enhancedFindings)

	if summary.TotalAnalyzed != 3 {
		t.Errorf("Expected TotalAnalyzed = 3, got %d", summary.TotalAnalyzed)
	}

	if summary.SuccessfullyAnalyzed != 2 {
		t.Errorf("Expected SuccessfullyAnalyzed = 2, got %d", summary.SuccessfullyAnalyzed)
	}

	if summary.AnalysisErrors != 1 {
		t.Errorf("Expected AnalysisErrors = 1, got %d", summary.AnalysisErrors)
	}

	if summary.LikelyFalsePositives != 1 {
		t.Errorf("Expected LikelyFalsePositives = 1, got %d", summary.LikelyFalsePositives)
	}

	if summary.LikelyTruePositives != 1 {
		t.Errorf("Expected LikelyTruePositives = 1, got %d", summary.LikelyTruePositives)
	}

	if summary.HighConfidence != 1 {
		t.Errorf("Expected HighConfidence = 1, got %d", summary.HighConfidence)
	}

	if summary.MediumConfidence != 1 {
		t.Errorf("Expected MediumConfidence = 1, got %d", summary.MediumConfidence)
	}
}
