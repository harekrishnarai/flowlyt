<img width="945" height="299" alt="flowlytgh" src="https://github.com/user-attachments/assets/a994d9b6-be4c-41d0-a3e8-adda9d72caaa" />

<div align="center">

<!-- Conference Recognition -->
![Black Hat Europe 2025](https://img.shields.io/badge/UPCOMING-Black%20Hat%20EU%202025-000000?style=for-the-badge&logo=blackhat&logoColor=white)
![AppSec Defcon 33](https://img.shields.io/badge/PRESENTED-AppSec%20Village%20DEFCON%2033-6c5ce7?style=for-the-badge&logo=security&logoColor=white)

  <strong>🔒 Secure your CI/CD pipelines with Flowlyt</strong>
  <br>
  <a href="https://github.com/harekrishnarai/flowlyt">⭐ Star us on GitHub</a>
</div>

# Flowlyt - Multi-Platform CI/CD Security Analyzer

**Advanced AST-powered security analyzer for GitHub Actions and GitLab CI/CD workflows**

Flowlyt combines traditional pattern matching with cutting-edge Abstract Syntax Tree (AST) analysis to deliver **62% faster scans** with **66% fewer false positives**. Selected for presentation at DEF CON 33 and Black Hat Europe 2025.

## ✨ Key Features

- 🎯 **AST-Based Analysis** - Call graph, reachability, and data flow analysis
- 🚀 **Multi-Platform** - GitHub Actions + GitLab CI/CD support  
- 🛡️ **85+ Security Rules** - Injection, secrets, supply chain, misconfigurations
- 📊 **SARIF Output** - GitHub Security tab integration
- ⚙️ **Configurable** - Custom rules, policies, and ignore patterns
- 🔄 **Real-time Intelligence** - OSV.dev vulnerability database integration

## 🚀 Quick Start


## ⚠️ Known Issues

### Go Module Proxy Cache Issue

**Issue**: `go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest` may install an incorrect version (v1.0.0) due to a Go module proxy cache issue.

**Symptoms**:
- Installing with `@latest` downloads v1.0.0 instead of the actual latest version (v0.0.4)
- Tool may not function correctly or detect security issues properly

**Workaround**: Use the `GOPRIVATE` environment variable to bypass the proxy cache:

```bash
# Recommended installation method (bypasses proxy cache)
GOPRIVATE=github.com/harekrishnarai/flowlyt go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
```

**Alternative**: Install specific version directly:
```bash
# Install specific latest version
go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@v0.0.3
```

**Verification**: Check that you have the correct version:
```bash
flowlyt --version
# Should output: flowlyt version 0.0.4
```

This issue has been reported to GitHub support and should be resolved server-side in the future.


```bash
# Install
go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest

# Analyze a workflow
flowlyt analyze .github/workflows/ci.yml --enable-ast-analysis

# Scan entire repository  
flowlyt scan ./my-repo --output-format sarif
```

## 📊 Example Output

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

## 🔧 GitHub Actions Integration

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

## 📚 Documentation

| Topic | Description |
|-------|-------------|
| [Quick Start](docs/quick-start.md) | Installation and basic usage |
| [Features](docs/features.md) | Complete feature overview |
| [AST Analysis](docs/ast-analysis.md) | Advanced static analysis capabilities |
| [Configuration](docs/configuration.md) | Detailed configuration guide |
| [Security Rules](docs/security-rules.md) | Complete rule reference |
| [Custom Rules](docs/custom-rules.md) | Creating custom security rules |
| [CLI Reference](docs/cli-reference.md) | Command-line options |

## 🚀 Roadmap

- [x] **SARIF Output** - GitHub Security tab integration
- [x] **AST Analysis** - Call graph, reachability, data flow
- [x] **Multi-Platform** - GitHub Actions + GitLab CI/CD
- [ ] **IDE Extension** - VS Code real-time analysis
- [ ] **Workflow Visualization** - Security dependency graphs
- [ ] **Enterprise Features** - SSO, RBAC, compliance reporting

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

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
