<img width="945" height="299" alt="flowlytgh" src="https://github.com/user-attachments/assets/a994d9b6-be4c-41d0-a3e8-adda9d72caaa" />

<div align="center">

<!-- Conference Recognition -->
![Black Hat Europe 2025](https://img.shields.io/badge/UPCOMING-Black%20Hat%20EU%202025-000000?style=for-the-badge&logo=blackhat&logoColor=white)
![AppSec Defcon 33](https://img.shields.io/badge/PRESENTED-AppSec%20Village%20DEFCON%2033-6c5ce7?style=for-the-badge&logo=security&logoColor=white)

  <strong>🔒 Secure your CI/CD pipelines with Flowlyt</strong>
  <br>
  <a href="https://github.com/harekrishnarai/flowlyt">⭐ Star us on GitHub</a>
</div>

# Flowlyt - AI-Powered Multi-Platform CI/CD Security Analyzer

**Advanced security analyzer with AI-enhanced false positive detection for GitHub Actions and GitLab CI/CD workflows**

Flowlyt combines traditional pattern matching with cutting-edge Abstract Syntax Tree (AST) analysis and **AI-powered verification** to deliver **62% faster scans** with **66% fewer false positives**. Selected for presentation at DEF CON 33 and Black Hat Europe 2025.

## 🤖 AI-Powered Security Analysis

**🔑 Bring Your Own Key (BYOK) Model** - Use your preferred AI provider with your own API key for enhanced privacy and control.

### Supported AI Providers
- **OpenAI** (GPT-4, GPT-4o, GPT-4o-mini) - General-purpose security analysis
- **Google Gemini** (1.5 Pro, 1.5 Flash) - Fast, cost-effective analysis  
- **Anthropic Claude** (3 Opus, 3 Sonnet, 3 Haiku) - Detailed reasoning and nuanced analysis
- **xAI Grok** (Beta) - Alternative analysis perspective
- **Perplexity** (Llama 3.1 Sonar, GPT-4o) - Real-time web-enhanced analysis

### AI-Enhanced Features
- 🎯 **False Positive Detection** - AI distinguishes between real threats and configuration noise
- 🧠 **Context-Aware Analysis** - Understands CI/CD patterns and legitimate usage
- 🔒 **Supply Chain Security Focus** - Specialized in GitHub Actions hardening and runner security
- ⚡ **Real-time Verification** - Instant AI analysis of security findings
- 📊 **Confidence Scoring** - AI provides confidence levels (0-100%) for each assessment

## ✨ Key Features

- 🤖 **AI-Powered Analysis** - BYOK model with OpenAI, Gemini, Claude, and Grok support
- 🎯 **AST-Based Analysis** - Call graph, reachability, and data flow analysis
- 🚀 **Multi-Platform** - GitHub Actions + GitLab CI/CD support  
- 🛡️ **85+ Security Rules** - Injection, secrets, supply chain, misconfigurations
- 🧠 **False Positive Reduction** - AI distinguishes real threats from configuration noise
- 📊 **SARIF Output** - GitHub Security tab integration
- ⚙️ **Configurable** - Custom rules, policies, and ignore patterns
- 🔄 **Real-time Intelligence** - OSV.dev vulnerability database integration

## 🚀 Quick Start


## ⚠️ Known Issues

### Go Module Proxy Cache Issue

**Issue**: `go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest` may install an incorrect version (v1.0.0) due to a Go module proxy cache issue.

**Symptoms**:
- Installing with `@latest` downloads v1.0.0 instead of the actual latest version (v0.0.6)
- Tool may not function correctly or detect security issues properly

**Workaround**: Use the `GOPRIVATE` environment variable to bypass the proxy cache:

```bash
# Recommended installation method (bypasses proxy cache)
GOPRIVATE=github.com/harekrishnarai/flowlyt go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
```

**Alternative**: Install specific version directly:
```bash
# Install specific latest version
go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@v0.0.6
```

**Verification**: Check that you have the correct version:
```bash
flowlyt --version
# Should output: flowlyt version 0.0.6
```

This issue has been reported to GitHub support and should be resolved server-side in the future.


```bash
# Install (recommended method to avoid proxy cache issues)
GOPRIVATE=github.com/harekrishnarai/flowlyt go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest

# Basic scan without AI
flowlyt scan ./my-repo --output-format sarif


```

### 🤖 AI-Powered Analysis Setup

```bash
# Set your AI API key (BYOK model)
export AI_API_KEY=your-api-key

# Scan with AI-powered false positive detection
flowlyt scan ./my-repo --ai openai
flowlyt scan ./my-repo --ai gemini  
flowlyt scan ./my-repo --ai claude
flowlyt scan ./my-repo --ai grok
flowlyt scan ./my-repo --ai perplexity

# Advanced AI configuration
flowlyt scan ./my-repo \
  --ai openai \
  --ai-model gpt-4 \
  --ai-workers 10 \
  --ai-timeout 60
```

### 🔑 API Key Setup (BYOK)

| Provider | Get API Key | Environment Variable |
|----------|-------------|---------------------|
| **OpenAI** | [platform.openai.com](https://platform.openai.com/api-keys) | `AI_API_KEY` |
| **Gemini** | [aistudio.google.com](https://aistudio.google.com/app/apikey) | `AI_API_KEY` |
| **Claude** | [console.anthropic.com](https://console.anthropic.com/) | `AI_API_KEY` |
| **Grok** | [console.x.ai](https://console.x.ai/) | `AI_API_KEY` |
| **Perplexity** | [perplexity.ai](https://www.perplexity.ai/settings/api) | `AI_API_KEY` |

## 📊 Example Output

### Traditional Scan
```
🔍 Analyzing: .github/workflows/ci.yml
⚡ AST Analysis: ON (62% faster, 66% fewer false positives)

🚨 CRITICAL: Shell Injection via curl | bash
   └─ Line 23: curl -sSL https://get.docker.com/ | sh
   └─ Risk: Remote code execution, supply chain attack
   
🔥 HIGH: Hardcoded Secret Detected  
   └─ Line 15: API_KEY="sk-1234567890abcdef"
   └─ Risk: Credential exposure in version control

✅ Scan completed in 28ms
Found 2 issues (1 Critical, 1 High, 0 Medium, 0 Low)
```

### 🤖 AI-Enhanced Scan Output
```
🔍 Analyzing: .github/workflows/ci.yml
⚡ AST Analysis: ON | 🤖 AI Analysis: gemini
🔍 Analyzing 12 findings with AI...
✅ AI Analysis Complete:
  - Successfully analyzed: 12/12 findings
  - Likely false positives: 8
  - Likely true positives: 4
  - High confidence: 10, Medium: 2, Low: 0

🚨 CRITICAL: Shell Injection via curl | bash
   └─ Line 23: curl -sSL https://get.docker.com/ | sh
   └─ Risk: Remote code execution, supply chain attack
   
   🤖 AI Analysis: Likely TRUE POSITIVE (95% confidence)
   AI Reasoning: This is a classic supply chain attack vector. The script downloads 
   and executes code directly from an external source without verification...

🔥 HIGH: Hardcoded Secret Detected  
   └─ Line 15: API_KEY="sk-1234567890abcdef"
   └─ Risk: Credential exposure in version control
   
   🤖 AI Analysis: Likely FALSE POSITIVE (90% confidence)
   AI Reasoning: This appears to be a placeholder value commonly used in 
   documentation and examples, not an actual secret...

✅ Scan completed in 1.2s
Found 4 real issues (1 Critical, 1 High, 2 Medium) | 8 false positives filtered by AI
```

## 🔧 GitHub Actions Integration

### Basic Integration
```yaml
- name: Flowlyt Security Scan
  uses: harekrishnarai/flowlyt@v1
  with:
    config-file: '.flowlyt.yml'
    output-format: 'sarif'
    enable-ast-analysis: true
    
- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: flowlyt-results.sarif
```

### 🤖 AI-Enhanced Integration (BYOK)
```yaml
- name: Flowlyt AI-Powered Security Scan
  uses: harekrishnarai/flowlyt@v0.0.6
  with:
    config-file: '.flowlyt.yml'
    output-format: 'sarif'
    enable-ast-analysis: true
    ai-provider: 'gemini'  # or 'openai', 'claude', 'grok'
    ai-model: 'gemini-1.5-flash'
  env:
    AI_API_KEY: ${{ secrets.GEMINI_API_KEY }}  # Your API key
    
- name: Upload Enhanced Results
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: flowlyt-results.sarif
```

## 📚 Documentation

| Topic | Description |
|-------|-------------|
| [Quick Start](docs/quick-start.md) | Installation and basic usage |
| [🤖 AI Integration](docs/ai-integration.md) | **AI-powered analysis setup and configuration** |
| [Features](docs/features.md) | Complete feature overview |
| [AST Analysis](docs/ast-analysis.md) | Advanced static analysis capabilities |
| [Configuration](docs/configuration.md) | Detailed configuration guide |
| [Security Rules](docs/security-rules.md) | Complete rule reference |
| [Custom Rules](docs/custom-rules.md) | Creating custom security rules |
| [CLI Reference](docs/cli-reference.md) | Command-line options |

## 🤖 Why AI-Powered Analysis?

### Traditional Security Scanners vs Flowlyt AI
| Challenge | Traditional Approach | 🤖 Flowlyt AI Solution |
|-----------|---------------------|----------------------|
| **False Positives** | High noise, manual review needed | AI filters 60-80% of false positives automatically |
| **Context Understanding** | Pattern matching only | Understands CI/CD context and legitimate patterns |
| **Supply Chain Focus** | Generic security rules | Specialized in GitHub Actions hardening & runner security |
| **Triage Time** | Hours of manual analysis | Instant AI assessment with confidence scores |
| **Actionability** | Raw findings dump | Contextualized explanations and severity suggestions |

### 🔒 Privacy & Security (BYOK Model)
- **Your Keys, Your Control** - Use your own API keys with any supported provider
- **No Data Storage** - Findings are analyzed in real-time, not stored by AI providers  
- **Transparent Costs** - Pay only for what you use with your own account
- **Provider Choice** - Switch between OpenAI, Gemini, Claude, or Grok anytime

## ⚠️ Known Issues

### Go Module Proxy Cache Issue

**Issue**: `go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest` may install an incorrect version (v1.0.0) due to a Go module proxy cache issue.

**Workaround**: Use the `GOPRIVATE` environment variable:
```bash
GOPRIVATE=github.com/harekrishnarai/flowlyt go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
```

## 🚀 Roadmap

- [x] **SARIF Output** - GitHub Security tab integration
- [x] **AST Analysis** - Call graph, reachability, data flow
- [x] **Multi-Platform** - GitHub Actions + GitLab CI/CD
- [x] **🤖 AI-Powered Analysis** - BYOK model with multi-provider support
- [x] **False Positive Reduction** - AI-enhanced accuracy and context awareness
- [ ] **IDE Extension** - VS Code real-time analysis with AI
- [ ] **Workflow Visualization** - Security dependency graphs
- [ ] **Enterprise Features** - SSO, RBAC, compliance reporting
- [ ] **AI Model Training** - Custom models for organization-specific patterns

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🎯 Ready to Try AI-Powered Security Analysis?

### 🚀 Quick Start with AI (3 steps)
```bash
# 1. Install Flowlyt
GOPRIVATE=github.com/harekrishnarai/flowlyt go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest

# 2. Get your API key (choose one):
# - OpenAI: https://platform.openai.com/api-keys
# - Gemini: https://aistudio.google.com/app/apikey  
# - Claude: https://console.anthropic.com/
# - Grok: https://console.x.ai/
# - Perplexity: https://www.perplexity.ai/settings/api

# 3. Run AI-enhanced scan
export AI_API_KEY=your-api-key
flowlyt scan ./your-repo --ai gemini
```

### 💡 Why Teams Choose Flowlyt AI
- **🎯 60-80% Fewer False Positives** - Focus on real threats, not noise
- **⚡ Instant Triage** - AI explains why findings matter in seconds
- **🔒 Supply Chain Focus** - Built for GitHub Actions and CI/CD security
- **💰 Cost Effective** - Pay only for what you analyze with BYOK model
- **🛡️ Privacy First** - Your keys, your data, your control

**Conference Presentations:**
- 🎯 [DEF CON 33 - AppSec Village](https://defcon.org) (Presented)
- 🔥 [Black Hat Europe 2025](https://blackhat.com) (Upcoming)

## Contributors
Thanks to all the people who already contributed!   
[Hare Krishna Rai](https://www.linkedin.com/in/harekrishnarai/)  
[Gaurav Joshi](https://www.linkedin.com/in/gauravjoshii/)  
[Chanchal Kalnarayan](https://www.linkedin.com/in/ckalnarayan)  
[Prashant Venkatesh](https://www.linkedin.com/in/prashant-venkatesh-99018999/)    
[Nandan Gupta](https://www.linkedin.com/in/nandan-gupta-698aa11b)  
[Mohd. Arif](https://www.linkedin.com/in/mohd--arif/)  

<a href="https://github.com/harekrishnarai/flowlyt/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=harekrishnarai/flowlyt" />
</a>
