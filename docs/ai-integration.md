# AI Integration Guide

Flowlyt integrates with leading AI providers to enhance security analysis by automatically verifying findings and helping distinguish between false positives and true positives. This guide covers how to configure and use AI-powered analysis.

## Supported AI Providers

### OpenAI
- **Models**: GPT-4, GPT-4 Turbo, GPT-4o, GPT-4o-mini (default)
- **API**: OpenAI API v1
- **Cost**: Pay-per-token pricing
- **Best for**: General-purpose security analysis

### Google Gemini
- **Models**: Gemini 1.5 Pro, Gemini 1.5 Flash (default)
- **API**: Google AI API
- **Cost**: Competitive token-based pricing
- **Best for**: Fast, cost-effective analysis

### Anthropic Claude
- **Models**: Claude 3 Opus, Claude 3 Sonnet, Claude 3 Haiku (default)
- **API**: Anthropic API
- **Cost**: Token-based pricing
- **Best for**: Detailed reasoning and nuanced analysis

### xAI Grok
- **Models**: Grok Beta (default)
- **API**: xAI API
- **Cost**: Token-based pricing
- **Best for**: Alternative analysis perspective

## Quick Start

### 1. Choose Your AI Provider

Select an AI provider and obtain an API key:
- **OpenAI**: Visit [OpenAI API](https://platform.openai.com/api-keys)
- **Gemini**: Visit [Google AI Studio](https://aistudio.google.com/app/apikey)
- **Claude**: Visit [Anthropic Console](https://console.anthropic.com/)
- **Grok**: Visit [xAI Console](https://console.x.ai/)

### 2. Basic Usage

```bash
# Set your API key
export AI_API_KEY=your-api-key

# Run analysis with AI verification
flowlyt scan --repo . --ai openai
```

### 3. Understanding AI Output

AI analysis adds the following information to each finding:

- **AI Verification Status**: Whether the finding was analyzed by AI
- **False Positive Assessment**: AI's determination if the finding is likely a false positive
- **Confidence Level**: How confident the AI is in its assessment (0.0 to 1.0)
- **Reasoning**: Detailed explanation of the AI's analysis
- **Suggested Severity**: If the AI suggests a different severity level

## Configuration Options

### Command Line Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--ai` | AI provider (openai, gemini, claude, grok) | None |
| `--ai-key` | API key for the AI provider | AI_API_KEY env var |
| `--ai-model` | Specific model to use | Provider default |
| `--ai-base-url` | Custom API endpoint | Provider default |
| `--ai-timeout` | Analysis timeout in seconds | 30 |
| `--ai-workers` | Concurrent analysis workers | 5 |

### Environment Variables

```bash
# API key (alternative to --ai-key flag)
export AI_API_KEY=your-api-key

# Optional: Custom timeout
export AI_TIMEOUT=60

# Optional: Custom worker count
export AI_WORKERS=10
```

### Configuration File

Add AI settings to your `.flowlyt.yml`:

```yaml
ai:
  provider: openai
  api_key: your-api-key  # Not recommended for version control
  model: gpt-4o-mini
  timeout: 30
  max_tokens: 1000
  temperature: 0.3
  workers: 5
```

## Advanced Usage

### Custom Models

```bash
# Use GPT-4 for more thorough analysis
flowlyt scan --repo . --ai openai --ai-model gpt-4

# Use Gemini Pro for complex scenarios
flowlyt scan --repo . --ai gemini --ai-model gemini-1.5-pro

# Use Claude Opus for detailed reasoning
flowlyt scan --repo . --ai claude --ai-model claude-3-opus-20240229
```

### Self-Hosted Models

```bash
# OpenAI-compatible endpoint
flowlyt scan --repo . \
  --ai openai \
  --ai-base-url https://your-server.com/v1 \
  --ai-key your-key

# Azure OpenAI
flowlyt scan --repo . \
  --ai openai \
  --ai-base-url https://your-resource.openai.azure.com/openai/deployments/your-deployment \
  --ai-key your-azure-key
```

### Performance Tuning

```bash
# High-throughput analysis
flowlyt scan --repo . \
  --ai gemini \
  --ai-workers 15 \
  --ai-timeout 20

# Conservative analysis with detailed reasoning
flowlyt scan --repo . \
  --ai claude \
  --ai-model claude-3-opus-20240229 \
  --ai-workers 2 \
  --ai-timeout 60
```

## Output Formats

### CLI Output

AI analysis appears directly in the CLI output:

```
⚠ [1] Hardcoded Secret (HARDCODED_SECRET)
  File:        .github/workflows/deploy.yml
  Line:        15
  Description: Potential secret found in workflow file

  🤖 AI Analysis: Likely FALSE POSITIVE (85% confidence)
  AI Reasoning: This appears to be a placeholder value 'your-api-key-here' 
                commonly used in documentation and examples, not an actual secret.
```

### JSON Output

AI fields are included in JSON output:

```json
{
  "findings": [
    {
      "ruleId": "HARDCODED_SECRET",
      "ruleName": "Hardcoded Secret",
      "severity": "CRITICAL",
      "ai_verified": true,
      "ai_likely_false_positive": true,
      "ai_confidence": 0.85,
      "ai_reasoning": "This appears to be a placeholder value...",
      "ai_suggested_severity": "LOW"
    }
  ]
}
```

## Best Practices

### 1. API Key Security

```bash
# ✅ Use environment variables
export AI_API_KEY=your-key
flowlyt scan --repo . --ai openai

# ❌ Avoid command line exposure
flowlyt scan --repo . --ai openai --ai-key your-key  # Visible in process list
```

### 2. Cost Management

```bash
# Use cost-effective models for routine scans
flowlyt scan --repo . --ai gemini --ai-model gemini-1.5-flash

# Reserve premium models for critical analysis
flowlyt scan --repo . --ai openai --ai-model gpt-4 --min-severity CRITICAL
```

### 3. Performance Optimization

```bash
# Balance speed and rate limits
flowlyt scan --repo . --ai openai --ai-workers 5 --ai-timeout 30

# For large repositories, consider filtering first
flowlyt scan --repo . --min-severity HIGH --ai claude
```

### 4. CI/CD Integration

```bash
# In CI/CD pipelines, use timeout and error handling
flowlyt scan --repo . \
  --ai openai \
  --ai-timeout 15 \
  --output json \
  --output-file scan-results.json || echo "AI analysis failed, continuing..."
```

## Understanding AI Analysis

### Confidence Levels

- **High (≥80%)**: Strong confidence in the assessment
- **Medium (60-79%)**: Moderate confidence, worth reviewing
- **Low (<60%)**: Uncertain assessment, manual review recommended

### False Positive Detection

The AI considers several factors:

1. **Context Analysis**: Is the code in a test file, documentation, or example?
2. **Pattern Recognition**: Does the pattern match known false positive signatures?
3. **Severity Assessment**: Is the assigned severity appropriate for the actual risk?
4. **Common Practices**: Does the code follow secure development practices?

### Limitations

- AI analysis is supplementary, not a replacement for human review
- Results may vary between providers and models
- API costs can accumulate with large-scale analysis
- Network connectivity required for analysis

## Troubleshooting

### Common Issues

**Authentication Errors**
```bash
# Verify API key is set correctly
echo $AI_API_KEY

# Test with a simple request
flowlyt scan --repo . --ai openai --ai-timeout 5
```

**Rate Limiting**
```bash
# Reduce concurrent workers
flowlyt scan --repo . --ai openai --ai-workers 2

# Increase timeout
flowlyt scan --repo . --ai openai --ai-timeout 60
```

**Analysis Failures**
```bash
# Check network connectivity
curl -I https://api.openai.com/v1/models

# Enable verbose output for debugging
flowlyt scan --repo . --ai openai --verbose
```

## Examples

### Basic Security Scan with AI
```bash
export AI_API_KEY=your-openai-key
flowlyt scan --repo . --ai openai
```

### High-Accuracy Analysis
```bash
flowlyt scan --repo . \
  --ai claude \
  --ai-model claude-3-opus-20240229 \
  --min-severity HIGH
```

### Automated CI/CD Integration
```bash
# In GitHub Actions
- name: Security Scan with AI
  run: |
    flowlyt scan --repo . \
      --ai gemini \
      --ai-key ${{ secrets.GEMINI_API_KEY }} \
      --output json \
      --output-file security-scan.json
  continue-on-error: true
```

### Custom Endpoint
```bash
flowlyt scan --repo . \
  --ai openai \
  --ai-base-url https://your-llm-gateway.com/v1 \
  --ai-key your-gateway-key
```

## Next Steps

- Review the [CLI Reference](cli-reference.md) for complete flag documentation
- Check [Configuration Guide](configuration.md) for advanced setup options
- See [Examples](examples.md) for real-world usage scenarios