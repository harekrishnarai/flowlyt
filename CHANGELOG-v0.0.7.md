# Flowlyt v0.0.7 Release Notes

**Release Date**: November 19, 2025

## 🚀 Highlights

### 🤖 Advanced AI Enhancements
- **False Positive Reduction Improvements**: Major tuning to AST + AI hybrid engine further lowers noise (commit: 6a7b978).
- **Multi-Provider Expansion**: Added **Perplexity** AI provider support with flexible model selection (`Llama 3.1 Sonar`, `GPT-4o`) (commit: ddc54ea).
- **Credential Persistence & Permissions Context**: Enhanced repository context enrichment to better detect credential misuse and permission escalation patterns (commit: dee6bea).
- **Cost Optimization**: Smarter batching / reuse of AI context reduces API call volume for large workflow sets (commit: dee6bea).
- **Branch-Aware URLs Fix**: Corrected branch-aware repository URL handling improving remote scans (commit: dee6bea).

### 🔍 Detection & Analysis
- Improved reasoning across injection + supply chain rules when AI verification enabled.
- Confidence scoring refinements for high-risk findings.

### 📄 Documentation
- Expanded AI setup instructions and BYOK guidance (commit: 6f12c26).
- Updated examples to include new provider and optimized flags.

## 🛠 Internal / Developer Improvements
- Refined hybrid analysis pipeline for better parallelism with `--ai-workers`.
- Preparation for future enterprise features (permission graph groundwork).

## 🔧 Upgrade Notes
No breaking CLI changes in this release. Standard upgrade path:
```bash
go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@v0.0.7
flowlyt --version  # should show 0.0.7
```

If you previously pinned `v0.0.6` in a GitHub Actions workflow:
```yaml
- name: Flowlyt AI-Powered Security Scan
  uses: harekrishnarai/flowlyt@v0.0.7
```

## ✅ Verification Checklist
- `flowlyt --version` outputs `0.0.7`
- AI scan runs successfully with any supported provider
- Perplexity provider selectable via `--ai perplexity`
- Reduced duplicate / low-confidence findings compared to v0.0.6

## 📈 Next (Roadmap Focus)
- VS Code live workflow hardening extension
- Visualization of action permission graphs
- Organization-wide policy aggregation & reporting

---
Thank you for using Flowlyt! Star the repo to support continued development.
