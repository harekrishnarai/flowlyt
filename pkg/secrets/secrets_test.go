package secrets_test

import (
	"regexp"
	"testing"

	"github.com/harekrishnarai/flowlyt/pkg/parser"
	"github.com/harekrishnarai/flowlyt/pkg/secrets"
)

func TestSecretsDetector(t *testing.T) {
	// Initialize secrets detector
	detector := secrets.NewDetector()

	// Load the test insecure workflow
	repoPath := "../../test/sample-repo"
	workflows, err := parser.FindWorkflows(repoPath)
	if err != nil {
		t.Fatalf("Failed to find workflows: %v", err)
	}

	// Find the insecure workflow
	var insecureWorkflow parser.WorkflowFile
	for _, workflow := range workflows {
		if workflow.Name == "insecure_workflow.yml" {
			insecureWorkflow = workflow
			break
		}
	}

	if insecureWorkflow.Path == "" {
		t.Fatal("Failed to find insecure_workflow.yml in test files")
	}

	// Detect secrets
	findings := detector.Detect(insecureWorkflow)

	// We should have found at least one secret
	if len(findings) == 0 {
		t.Error("No secrets detected in insecure workflow")
	}
}

func TestCustomPatterns(t *testing.T) {
	// Initialize secrets detector
	detector := secrets.NewDetector()

	// Add a custom pattern for a specific format
	customPattern := regexp.MustCompile(`CUSTOM_SECRET_[A-Za-z0-9]{10}`)
	detector.AddCustomPattern(customPattern)

	// Create a workflow with a custom secret
	workflowContent := `
name: Test Workflow
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Step with custom secret
        env:
          SECRET: "CUSTOM_SECRET_1234567890"
        run: echo "Running with custom secret pattern"
`

	// Create a mock workflow file
	workflow := parser.WorkflowFile{
		Path:    "custom_secret_workflow.yml",
		Name:    "custom_secret_workflow.yml",
		Content: []byte(workflowContent),
	}

	// Detect secrets
	findings := detector.Detect(workflow)

	// We should have found at least one secret with our custom pattern
	customSecretFound := false
	for _, finding := range findings {
		if finding.RuleID == "SECRET_DETECTION_PATTERN" && finding.Category == "SECRET_EXPOSURE" {
			customSecretFound = true
		}
	}

	if !customSecretFound {
		t.Error("Failed to detect custom secret pattern")
	}
}

func TestEntropyThreshold(t *testing.T) {
	// Initialize secrets detector with a low entropy threshold to catch more
	detector := secrets.NewDetector()
	detector.SetEntropyThreshold(3.0) // Lower threshold to detect more potential secrets

	// Create a workflow with various strings of different entropy levels
	workflowContent := `
name: Entropy Test Workflow
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Low entropy string
        run: echo "aaaaaaaaaaaaaaaaaaaa" # Low entropy
      
      - name: High entropy string
        run: echo "a7f3bc91e5d28f75a6" # Higher entropy
`

	// Create a mock workflow file
	workflow := parser.WorkflowFile{
		Path:    "entropy_test_workflow.yml",
		Name:    "entropy_test_workflow.yml",
		Content: []byte(workflowContent),
	}

	// Detect secrets
	findings := detector.Detect(workflow)

	// With a low threshold, we should find at least one high-entropy string
	entropyFindings := 0
	for _, finding := range findings {
		if finding.RuleID == "SECRET_DETECTION_ENTROPY" {
			entropyFindings++
		}
	}

	// Now set a very high threshold, which should find fewer or no strings
	detector.SetEntropyThreshold(6.0)
	findings = detector.Detect(workflow)

	// With a high threshold, we should find fewer entropy-based findings
	highThresholdFindings := 0
	for _, finding := range findings {
		if finding.RuleID == "SECRET_DETECTION_ENTROPY" {
			highThresholdFindings++
		}
	}

	if highThresholdFindings > entropyFindings {
		t.Errorf("Higher threshold should result in fewer findings: got %d, expected less than or equal to %d",
			highThresholdFindings, entropyFindings)
	}
}

func TestCommonPatternsDetection(t *testing.T) {
	// Initialize secrets detector
	detector := secrets.NewDetector()

	// Create a workflow with various common secret patterns
	workflowContent := `
name: Common Secrets Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: AWS Credentials
        env:
          AWS_ACCESS_KEY: "AKIAIOSFODNN7EXAMPLE"
          AWS_SECRET_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        run: echo "Testing AWS credentials"
      
      - name: GitHub Token
        env:
          GITHUB_TOKEN: "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
        run: echo "Testing GitHub token"
        
      - name: API Key
        env:
          API_KEY: "aB9z1XyCpQr5tGhJ7890"
        run: echo "Testing API Key"
        
      - name: Private Key
        run: |
          echo "-----BEGIN RSA PRIVATE KEY----- 
          MIIEpAIBAAKCAQEAxzYuc1RV+rcbAHmlJv6GcA8MU9XlgVH3lFoICv1x1fbw4CC5
          -----END RSA PRIVATE KEY-----"
`

	// Create a mock workflow file
	workflow := parser.WorkflowFile{
		Path:    "common_secrets_workflow.yml",
		Name:    "common_secrets_workflow.yml",
		Content: []byte(workflowContent),
	}

	// Detect secrets
	findings := detector.Detect(workflow)

	// We should have found several secrets
	if len(findings) < 3 {
		t.Errorf("Expected to find at least 3 secrets, but found %d", len(findings))
	}
}

func TestEnvironmentVariableExclusion(t *testing.T) {
	// Initialize secrets detector
	detector := secrets.NewDetector()

	// Create a workflow that has environment variable references that shouldn't be detected as secrets
	workflowContent := `
name: Environment Variable Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Using env vars
        env:
          API_KEY: ${{ secrets.API_KEY }}
          TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: echo "Using environment variables safely"
`

	// Create a mock workflow file
	workflow := parser.WorkflowFile{
		Path:    "env_var_workflow.yml",
		Name:    "env_var_workflow.yml",
		Content: []byte(workflowContent),
	}

	// Detect secrets
	findings := detector.Detect(workflow)

	// We should NOT have found any secrets since these are proper environment variable usages
	if len(findings) > 0 {
		t.Errorf("Expected to find 0 secrets in environment variables, but found %d", len(findings))
	}
}
