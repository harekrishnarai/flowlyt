# Flowlyt AI Prompting & Analysis Improvements

This document captures the concrete improvements we proposed, their implementation status, and the impact on token usage, cost, and accuracy.

## Summary of Implemented Changes

- Prompt consolidation
  - Shared compact prompt template added at `pkg/ai/prompt.go` and used by all providers.
  - Evidence is trimmed automatically to reduce tokens while keeping signal.
  - Status: IMPLEMENTED

- Remove verbose system prompt per call (OpenAI)
  - OpenAI request now omits the previous long system prompt; uses a concise, single user message.
  - Enforced JSON output via `response_format: { type: "json_object" }`.
  - Status: IMPLEMENTED

- In-run AI de-duplication cache
  - Analyzer caches results by a stable fingerprint (rule, file, job, step, trigger/runner/file-context, hashed evidence) to avoid duplicate calls within the same run.
  - Implemented in `pkg/ai/analyzer.go` (`sync.Map`-backed cache, used by workers).
  - Status: IMPLEMENTED

- Concurrency preserved
  - Existing worker pool kept; de-duplication happens inside each worker.
  - Status: IMPLEMENTED

## Proposed Improvements (Next)

1. AI scope control (config-driven)
   - Add `ai.min_severity`, `ai.include_rules`, `ai.exclude_rules` to limit which findings go to AI.
   - Impact: Reduces calls on low-signal rules (e.g., mass unpinned actions).
   - Status: IMPLEMENTED (via env variables for now)
     - `AI_MIN_SEVERITY`: INFO|LOW|MEDIUM|HIGH|CRITICAL
     - `AI_INCLUDE_RULES`: comma-separated rule IDs (overrides min severity)
     - `AI_EXCLUDE_RULES`: comma-separated rule IDs
     - Location: filtering in `pkg/ai/analyzer.go`

2. Persistent cache across runs
   - Optional sqlite/jsonl cache keyed by fingerprint for reuse between scans.
   - Impact: Reuses prior decisions for unchanged findings.
   - Status: IMPLEMENTED (JSONL)
     - `AI_CACHE_FILE`: path to jsonl cache file
     - Format: `{"fp":"<fingerprint>","result":{...}}` one per line
     - Location: `pkg/ai/analyzer.go` (load, seed in-run cache, append new results on flush)

3. Dynamic token guardrails
   - Compute safe `max_tokens` per call based on prompt length and model limits.
   - Progressive evidence reduction when nearing limits.
   - Status: IMPLEMENTED (OpenAI)
     - Heuristic token estimation and headroom in `pkg/ai/openai.go`
     - Evidence trimming already in `pkg/ai/prompt.go`

4. Rate limiting/backoff
   - Provider-aware limiter with exponential backoff and jitter.
   - Status: PLANNED

5. Telemetry
   - Metrics for attempted/succeeded/cached/skipped, avg tokens/call, and top rules analyzed.
   - Status: PLANNED

## Implementation Details (Current)

- Files touched
  - `pkg/ai/prompt.go`: shared compact prompt, evidence trimming.
  - `pkg/ai/openai.go`: removed verbose system prompt, added `response_format=json_object`.
  - `pkg/ai/gemini.go`, `pkg/ai/claude.go`, `pkg/ai/grok.go`, `pkg/ai/perplexity.go`: unified to use the shared prompt builder.
  - `pkg/ai/analyzer.go`: in-run cache and fingerprinting to avoid duplicate AI calls.

- Resulting behavior
  - Prompt tokens reduced significantly (no repeated long system prompt; compact user prompt).
  - Duplicate/near-duplicate findings within a scan reuse the same AI decision.
  - Responses are strongly steered to valid JSON (OpenAI). Parsing is more robust.

## Supported Output Formats

- CLI summary (stdout)
- JSON (`--output json` → e.g., `results.json`)
- SARIF (`--output sarif`)
- Markdown summary (`--output md` or written via reporting pipeline)

These are generated via the reporting layer (`pkg/report/...`) depending on flags.

## Validation Checklist

- Prompt consolidation (all providers use `composeFindingPrompt`): ✅
- Trimmed evidence in prompts: ✅
- OpenAI system prompt removed and JSON enforced: ✅
- In-run cache to avoid duplicate calls: ✅
- Output formats available: JSON, SARIF, Markdown, CLI: ✅

## Next-Steps Plan

1) Add config options to control AI scope (filters by severity and rule allow/deny lists).
2) Add optional persistent cache for cross-run reuse.
3) Implement dynamic token headroom and progressive evidence truncation.
4) Add provider backoff/limiting and telemetry.

These will further reduce cost and latency while maintaining or improving accuracy.


