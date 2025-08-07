---
name: "\U0001F41E Bug Report"
about: Report an issue with Flowlyt CLI or CI/CD usage
title: "[BUG] <brief description>"
labels: bug
assignees: ''

---

## 🐛 Bug Description
A clear and concise description of the bug you're experiencing while using **Flowlyt**.

---

## 📋 Reproduction Steps
List the steps to reproduce the issue:

1. What command did you run?
   ```bash
   flowlyt <your-command> --flags
   ```
2. What was the context? (e.g. running in GitHub Actions, GitLab CI, local terminal)
3. What was the expected behavior?
4. What actually happened? Any error messages?

---

## 💻 Environment Details

| Item              | Value                       |
|-------------------|-----------------------------|
| Flowlyt Version   | e.g., `v0.0.1`              |
| OS / Distro       | e.g., `Ubuntu 22.04` / `macOS 14` |
| Go Version        | e.g., `go1.21.0`            |
| CI/CD Platform    | e.g., `GitHub Actions`, `GitLab CI`, `Jenkins`, `Local` |
| Shell Used        | e.g., `bash`, `zsh`, `sh`   |

---

## 📜 Logs & Terminal Output
Paste any terminal output or error logs here (use triple backticks for formatting):

<details>
<summary>Click to expand logs</summary>

```
flowlyt analyze --all
Error: unexpected token at line 24
```

</details>

---

## 📦 Config or YAML Snippets (if applicable)
If the issue involves a config file or YAML you used with Flowlyt, paste the relevant part here:

```yaml
# flowlyt.yaml or .flowlyt config
analyze:
  packages:
    - ./cmd
    - ./pkg
```

---

## 📁 Minimal Repro (Optional but Helpful)
If possible, provide a link to a minimal project or repository that reproduces the issue.

---

## 💡 Additional Notes
Anything else you’d like to add? Workarounds? Related issues?
