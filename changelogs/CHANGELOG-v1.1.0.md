# v1.1.0 — 2026-03-27

## Summary

Three-layer AI architecture redesign that reduces token cost by ≥60%, produces class-specific analysis quality, and delivers a modern streaming CLI experience.

## What's Changed

### New: Heuristic Pre-filter (`pkg/ai/filter.go`)

`ShouldSkipAI(f rules.Finding) (bool, string)` replaces the old `shouldSendToAI` severity/rule-list gate. Zero API cost — pure Go pattern matching.

**Skip conditions (obvious false positives):**
- `${{ secrets.X }}`, `${{ env.X }}`, `${{ vars.X }}` — expression references, not hardcoded values
- Known placeholder patterns: `your-*-here`, `<token>`, `example-`, `changeme`, `dummy`
- Actions already pinned to a 40-char SHA (`@abcdef1234...`) — static analysis fired incorrectly
- `permissions: read-all` or `permissions: {}` — already locked down

**Always send (high-value signals):**
- Evidence containing real token prefixes: `ghp_`, `ghs_`, `gho_`, `sk-`, `AKIA`
- High-entropy blobs: any 20+ char word with Shannon entropy ≥4.0 bits/char

**Env-based gate preserved:** `AI_MIN_SEVERITY`, `AI_INCLUDE_RULES`, `AI_EXCLUDE_RULES` behaviour is unchanged — `envBasedFilter` runs first inside `ShouldSkipAI`.

### New: Class-Specific Prompt Templates (`pkg/ai/prompt.go`)

Replaces the single `sharedPromptTemplate` (~500 tokens) with four specialist system prompts (~150 tokens each) plus a generic fallback (~200 tokens).

| Category | Prompt class |
|---|---|
| `PRIVILEGE_ESCALATION`, `ACCESS_CONTROL` | `escalation` |
| `INJECTION_ATTACK` | `injection` |
| `SECRET_EXPOSURE`, `SECRETS_EXPOSURE` | `secrets_context` |
| `SUPPLY_CHAIN` | `supply_chain_trust` |
| All others | `generic` |

**`escalation`** — Reasons about trigger × permissions × steps combinations. Identifies when an unprivileged actor can reach attacker-controlled code in a privileged job.

**`injection`** — Traces user-controlled sources (`github.event.pull_request.title`, `github.head_ref`, etc.) to dangerous sinks (`run:` steps, action inputs). Detects tainted env vars.

**`secrets_context`** — Distinguishes live credentials (high entropy, known prefix) from expression references, test fixtures, and example values.

**`supply_chain_trust`** — Trust context beyond SHA pinning: is the action used in a privileged job? Is the publisher suspicious? Are artifacts consumed unsafely?

**`composeBatchPrompt(class, findings)`** builds the system + user prompt pair. User turn is a numbered JSON array with `index`, `rule_id`, `evidence`, and `file_context` per finding.

**`parseBatchResponse(content, count)`** is the shared JSON array parser used by all providers. Attributes results by echoed `index` field (not array position), handles markdown-wrapped responses, clamps confidence to 0–1, and fills `"missing from batch response"` for any omitted index.

### New: Batch Dispatcher (`pkg/ai/analyzer.go`)

Replaces the goroutine worker pool with a synchronous per-class batch dispatch loop.

**Batch size:** Fixed at 5 findings per API call.

**Dispatch flow:**
1. `ShouldSkipAI` pre-filter — skipped findings get `AISkipped: true` and `AISkipReason` set; appended to results at the end
2. Cache pre-check (in-run `sync.Map` + persistent JSONL) — cached findings skip the API
3. Group remaining findings by class; build stable `classOrder`
4. For each class, dispatch batches of up to 5 via `VerifyBatch`
5. On batch failure, fall back to individual `VerifyFinding` per finding
6. Attribute results by `BatchVerificationResult.Index`
7. Stage new results to persistent cache

**Context timeout:** Created after the pre-filter + cache pre-check, sized `timeout × dispatchCount` (only counts findings actually dispatched).

**Partial failure handling:** On timeout or cancellation, `flushPersistentCache()` is called first, then partial results are returned with a warning — the scan completes and produces a report.

### New: `VerifyBatch` on All 5 Providers

| Provider | System prompt delivery |
|---|---|
| Claude | Top-level `"system"` key in request body |
| OpenAI, Grok, Perplexity | `{"role": "system", "content": "..."}` as first message |
| Gemini | Prepended to first user turn (`system + "\n\n---\n\n" + user`) |

Each provider uses `parseBatchResponse` from `prompt.go` — no per-provider duplicate.

### New: Streaming UX

**Progress bar:** Created after pre-filter and cache pre-check; `total` = findings actually dispatched.

```
🤖 AI analysis  [████████░░░░░░░░]  8/20 findings  (escalation batch 2/3)
```

**Per-finding streaming output** (`printFindingResult`): After each batch resolves, findings print immediately:

```
  ✗  PULL_REQUEST_TARGET_INJECTION          CRITICAL  TRUE POSITIVE   94%
     Escalation: pull_request_target + write:contents + PR code checkout
     Fix: isolate checkout in unprivileged job, remove write permissions

  ~  HARDCODED_SECRET                       HIGH      FALSE POSITIVE  81%
     Placeholder pattern matches 'your-api-key-here', not a live credential
```

**`PrintAISummary` box** at scan end:

```
┌─ AI Analysis Summary ─────────────────────────────┐
│  Analyzed     12     Skipped by filter   8         │
│  True pos      7     False pos           5         │
│  High conf     9     Low conf            3         │
│  Provider  claude · claude-sonnet-4-6              │
└────────────────────────────────────────────────────┘
```

Non-TTY / CI mode: degrades gracefully via `term.IsTTY()` checks.

### New Fields on `rules.Finding`

| Field | Type | Description |
|---|---|---|
| `AISkipped` | `bool` | True when `ShouldSkipAI` skipped this finding |
| `AISkipReason` | `string` | Human-readable skip reason |
| `AIRemediation` | `string` | AI-suggested concrete fix |

`AIVerified` is only set to `true` when AI actually ran. Skipped findings leave it `false`.

### Report Output

- `report.go`: Renders `AIRemediation` as `"AI Fix: ..."` and `AISkipped` / `AISkipReason` in terminal output
- `sarif.go`: Serializes `ai.skipped`, `ai.skip_reason`, and `ai.remediation` as SARIF rule properties
- `AISummary.SkippedByFilter` counts findings skipped by pre-filter

## Breaking Changes

- `--ai-workers` flag removed (synchronous batch design; no goroutine pool)
- `NewAnalyzer` signature changed: `maxWorkers int` parameter removed

## Upgrade Notes

- Remove `--ai-workers` from any wrapper scripts or CI invocations — it will produce an "unknown flag" error
- `AI_MIN_SEVERITY`, `AI_INCLUDE_RULES`, `AI_EXCLUDE_RULES` env vars continue to work unchanged
- Existing `.flowlyt.yml` configuration files are fully compatible
- `VerificationResult.Remediation` is a new field — JSON/SARIF consumers may see it in output
