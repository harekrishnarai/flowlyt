package ai

import (
	"context"
	"testing"

	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

// MockClient implements the Client interface for testing
type MockClient struct {
	provider        Provider
	verifyResult    *VerificationResult
	verifyError     error
	closeError      error
	callCount       int
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
	expected := []string{"openai", "gemini", "claude", "grok"}
	
	if len(providers) != len(expected) {
		t.Errorf("GetSupportedProviders() returned %d providers, expected %d", len(providers), len(expected))
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

	// Test call count
	expectedCalls := 3 // 1 from single + 2 from multiple
	if mockClient.callCount != expectedCalls {
		t.Errorf("Expected %d API calls, got %d", expectedCalls, mockClient.callCount)
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