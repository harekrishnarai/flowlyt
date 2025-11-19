# Implementation Summary (Non-SARIF Enhancements)

This document summarizes the recent improvements applied to Flowlyt, with a focus on token efficiency, AI call optimization, and correct repository URL generation. No SARIF structure changes were made, per request.

## 1) AI: Token & Cost Optimizations

Implemented across `pkg/ai/*`:

- Shared compact prompt

  - File: `pkg/ai/prompt.go` (new)
  - All providers call `composeFindingPrompt` for a short, structured prompt.
  - Evidence is auto‑trimmed to ~600 chars to avoid oversized prompts.

- Remove repeated long system prompt (OpenAI)

  - File: `pkg/ai/openai.go`
  - Use a single compact user message.
  - Enforce JSON responses with `response_format: { "type": "json_object" }`.
  - Dynamic `max_tokens` based on prompt length + context headroom.

- In‑run de‑duplication of AI work

  - File: `pkg/ai/analyzer.go`
  - A `sync.Map` cache keyed by fingerprint (rule/file/job/step/trigger/runner/file‑context + hashed evidence) prevents duplicate AI calls for identical findings within the same scan.

- Configurable AI scope (env‑driven)

  - File: `pkg/ai/analyzer.go`
  - Env vars (temporary interface):
    - `AI_MIN_SEVERITY` → one of `INFO|LOW|MEDIUM|HIGH|CRITICAL`
    - `AI_INCLUDE_RULES` → comma‑separated rule IDs (overrides min severity)
    - `AI_EXCLUDE_RULES` → comma‑separated rule IDs
  - Only findings that pass filters are queued for AI analysis.

- Persistent cache across runs (JSONL)
  - File: `pkg/ai/analyzer.go`
  - Env var: `AI_CACHE_FILE` → path to JSONL cache (one line per `{ "fp": "<fingerprint>", "result": { ... } }`).
  - On start: loads & seeds the in‑run cache. On finish: appends new results.

### Verification

1. Set env:
   ```powershell
   $env:AI_MIN_SEVERITY = "MEDIUM"
   $env:AI_EXCLUDE_RULES = "UNPINNED_ACTION,REF_CONFUSION"
   $env:AI_CACHE_FILE = ".flowlyt-ai-cache.jsonl"
   ```
2. Run `flowlyt scan --repo <repo> --ai openai` twice and observe that the second run uses the cache (fewer AI calls).
3. Inspect `results.json` for `ai_verified`, `ai_confidence`, etc.

---

## 2) Correct GitHub/GitLab File URLs (Branch/SHA aware)

Problem: links were built with static `main/master`, causing broken URLs when repos use different defaults or when scanning a specific commit/branch.

Implemented:

- GitHub URL builder (branch/SHA aware)

  - File: `pkg/github/github.go` → `GenerateFileURL` now:
    - Prefers `GITHUB_SHA` → else `GITHUB_REF_NAME` → else local `git rev-parse HEAD` → else GitHub API `default_branch` → fallback to `main`.
    - Produces `https://github.com/{owner}/{repo}/blob/{ref}/{path}#L{line}`.
  - Helpers:
    - `detectGitHubRef`, `localGitHeadSHA`, `fetchGitHubDefaultBranch`.

- GitLab URL builder (branch/SHA aware)

  - File: `pkg/gitlab/client.go` → `GenerateFileURL` now:
    - Prefers `CI_COMMIT_SHA` → else `CI_COMMIT_REF_NAME` → else local `git rev-parse HEAD` → else GitLab API `/api/v4/projects/:id` `default_branch` → fallback to `master`.
    - Produces `{instance}/namespace/repo/-/blob/{ref}/{path}#L{line}`.
  - Helpers:
    - `detectGitLabRef`, `fetchGitLabDefaultBranch`, `localGitHeadSHA`, `getenvCompat`.

- Organization scan wiring
  - File: `pkg/organization/organization.go`
  - Replaced hardcoded `main` with `github.GenerateFileURL` so org output links are ref‑aware.

### Verification

- Public GitHub repo with `default_branch = master`:
  - Run: `flowlyt scan --url https://github.com/<owner>/<repo>`
  - Check `results.json` → `findings[].gitHubUrl` uses `/blob/master/...`.
- GitHub Actions CI:
  - With `GITHUB_SHA` set, links use `/blob/<SHA>/...`.
- GitLab CI:
  - With `CI_COMMIT_REF_NAME` or `CI_COMMIT_SHA` set, links use the actual ref.

---

## 3) What we deliberately did NOT change

- No SARIF schema/structure changes (no region/snippet/help/provenance edits), as requested.
- CLI and Markdown reporting already include coloring/formatting; left as‑is.

---

## Files Touched

- AI & Prompting:

  - `pkg/ai/prompt.go` (new)
  - `pkg/ai/openai.go`
  - `pkg/ai/analyzer.go`
  - `pkg/ai/gemini.go`, `pkg/ai/claude.go`, `pkg/ai/grok.go`, `pkg/ai/perplexity.go` (switch to shared prompt)

- URL Builders & Org Scan:
  - `pkg/github/github.go`
  - `pkg/gitlab/client.go`
  - `pkg/organization/organization.go`

---

## Operational Notes

- Network: default‑branch API calls use anonymous GitHub/GitLab APIs (respect rate limits). If `GITHUB_TOKEN`/`GITLAB_TOKEN` is set, requests include auth headers for higher limits.
- Fallbacks: URL builders always attempt to find an immutable SHA; branch fallback is only used when a SHA is unknown.
- Windows/Unix: local `git rev-parse` is attempted only if `git` is available.

---

## Rollback

- To revert ref‑aware URLs to static branches, restore the previous `GenerateFileURL` implementations in `pkg/github/github.go` and `pkg/gitlab/client.go` and remove the new helpers.
- To disable AI caching or scoping, unset `AI_*` environment variables; the analyzer will behave as before (but still with in‑run de‑dup).
