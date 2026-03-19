# False Positive Reduction v2 — Design Spec

**Date:** 2026-03-20
**Branch:** fix/noise-reduction
**Status:** Approved for implementation

---

## Background

Flowlyt v1.0.10 addressed the first wave of false positives (REF_CONFUSION semver tags, EXTERNAL_TRIGGER_DEBUG read-only permissions, SHELL_SCRIPT_ISSUES dangerous-position scoping). This spec covers the second wave, discovered by scanning real-world repos (kubernetes/kubernetes, microsoft/vscode, git/git) with the v1.0.10 binary.

Real-world finding counts before fixes (selected noisy rules):

| Rule | k8s | vscode | git/git |
|------|-----|--------|---------|
| CACHE_WRITE_IN_PR_WORKFLOW | 18 | 2 | 0 |
| MATRIX_INJECTION | 10 | 0 | 3 |
| DANGEROUS_WRITE_OPERATION | 0 | 2 | 2 |
| IMPOSTOR_COMMIT | 4 | 0 | 0 |

**Suppression note:** `.flowlyt.yml` already provides `false_positives.rules.<ID>.patterns/strings/files` for per-rule suppression. This spec does NOT add a new suppression mechanism — it fixes detection logic so correct behaviour requires no configuration.

**Core constraint:** Every fix must preserve all true positives. Where a fix reduces severity (not suppresses), the finding must still appear.

---

## Fixes In Scope

### Fix 1 — CACHE_WRITE_IN_PR_WORKFLOW: Deduplication

**File:** `pkg/rules/cache_poisoning.go` → `checkCacheWriteInPR`

**Problem:** The rule iterates over all jobs × steps. In a matrix workflow, `actions/cache@v3` at one YAML line is visited once per matrix-expanded job context, producing N identical findings at the same `file:line`.

**Root cause:** `linenum.FindLineNumber` always returns the first occurrence of the pattern in the file. Two jobs using the same `uses: actions/cache@v3` resolve to the same line number, so the same finding is emitted multiple times.

**Fix:** Add `seen map[string]bool` (keyed on `step.Uses + ":" + lineNumber`) before the job loop. Check and set before appending each finding — identical to the pattern already applied to `ARTIPACKED_VULNERABILITY` and `STALE_ACTION_REFS`.

**Invariant preserved:** Two distinct cache steps at different YAML lines still produce separate findings.

**False negative risk:** None.

---

### Fix 2 — DANGEROUS_WRITE_OPERATION: Deduplication

**File:** `pkg/rules/rules.go` → `checkDangerousWriteOperation` (or equivalent)

**Problem:** Same step (same `run:` block, same line) is visited from multiple job contexts, producing duplicate CRITICAL findings.

**Fix:** Add `seen map[string]bool` keyed on `filePath + ":" + lineNumber + ":" + ruleVariant` before the job loop.

**Important constraint — do NOT tighten the detection pattern.** The current pattern correctly catches cases like `echo "${{ matrix.os }}" >> $GITHUB_ENV` when the workflow is triggered by an untrusted event. Pattern tightening would be a false negative risk.

**False negative risk:** None — only deduplication, no logic change.

---

### Fix 3 — MATRIX_INJECTION: Arithmetic Expression Context

**File:** `pkg/rules/rules.go` → `checkMatrixInjection` (or equivalent)

**Problem:** `$((${{ matrix.nr }} + 1))` fires as MEDIUM ("Unquoted matrix variable usage"). This is bash arithmetic expansion — the `$((...))` context cannot execute arbitrary shell commands via string injection the way a bare `${{ matrix.var }}` in a command string can.

**Fix:** Before emitting a MATRIX_INJECTION finding, check whether the matrix expression is enclosed in `$((` ... `))` (arithmetic expansion). If so, skip the finding.

**Pattern to detect safe arithmetic context:**
```
\$\(\(\s*[^)]*\$\{\{\s*matrix\.[^}]+\}\}[^)]*\)\)
```

**Critical scoping constraint:** Only apply this exemption when the matrix strategy values are **statically defined** in the workflow YAML. If `strategy.matrix` uses `fromJSON(inputs.*)` or `fromJSON(github.event.*)`, the matrix values are user-controlled and arithmetic injection remains a real risk. Detection: check whether the job's `strategy.matrix` block contains `fromJSON` referencing `inputs.` or `github.event.`.

**What still fires:**
- `run: curl ${{ matrix.url }}` — bare interpolation in dangerous command
- `run: eval ${{ matrix.cmd }}` — execution context
- `run: $((${{ matrix.nr }} + 1))` when matrix comes from `fromJSON(inputs.matrix)` — user-controlled arithmetic
- Any matrix var in a non-arithmetic shell context

**False negative risk:** Low. Arithmetic context in bash (`$((expr))`) is not a code execution vector for string injection. The `fromJSON(inputs.*)` guard preserves the truly dangerous case.

---

### Fix 4 — SHELL_SCRIPT_ISSUES: Quoted Variable in File Operations

**File:** `pkg/rules/rules.go` → per-line unquoted variable scan

**Problem:** The unquoted variable regex `\$([A-Za-z_][A-Za-z0-9_]*)` matches `$VAR` inside `rm "$VAR"`. The surrounding double-quotes are not checked, so `rm "$VAR"` fires identically to `rm $VAR` despite being safe (quoting prevents word splitting and glob expansion for file-operation commands).

**Fix:** After matching a bare `$VAR` pattern on a dangerous line, check whether the matched variable reference is wrapped in double-quotes on that line. Specifically: if the line contains `"$VAR"` or `"...$VAR..."` (the `$` immediately preceded by `"` or other chars within a `"..."` span), skip the finding.

**Quoted-check pattern:** `"\$VARNAME[^A-Za-z0-9_]` — if the variable name is immediately preceded by `"` (opening double-quote), the variable is quoted.

**Command-type scoping — CRITICAL:**

This exemption applies ONLY to file-operation commands where quoting provides actual safety:
- `rm`, `cp`, `mv`, `mkdir`, `chmod`, `chown`, `ln`, `rsync`, `tar`, `zip`, `unzip`

This exemption does NOT apply to execution/network commands even when quoted, because the value is executed or transmitted regardless:
- `eval` — `eval "$VAR"` still executes arbitrary code
- `bash -c` / `sh -c` — same
- `curl` / `wget` — `curl "$URL"` still sends to attacker-controlled URL
- `sudo`-prefixed variants

**What still fires:**
- `rm $VAR` — unquoted, fires as before
- `eval "$VAR"` — quoted but execution context, always fires
- `curl "$URL"` — quoted but network transmission, always fires
- `rm "$VAR"` where VAR is used in multiple places (only the specific quoted occurrence is skipped)

**False negative risk:** None for the excluded command types. For file-operation commands: `rm "$VAR"` with an attacker-controlled `VAR` set via environment injection is a theoretical risk, but the injection vector (how `VAR` gets its value) would be caught by other rules (`GITHUB_ENV_UNTRUSTED_WRITE`, `INJECTION_VULNERABILITY`). The SHELL_SCRIPT_ISSUES rule is not the right place to catch environment injection chains.

---

### Fix 5 — IMPOSTOR_COMMIT: Known Bot Identities → Severity Downgrade

**File:** `pkg/rules/rules.go` → `checkImpostorCommit`

**Problem:** kubernetes/kubernetes (and many other large repos) legitimately configure `git config user.name "github-actions[bot]"` for automated release commits. This fires as CRITICAL today.

**Precision analysis:**
- Setting git identity to `github-actions[bot]` in a workflow you control is a known-safe, widely used pattern for automated commits
- Setting git identity to a human developer's name IS impersonation and should remain HIGH/CRITICAL
- Setting git identity via a variable (`${{ github.actor }}`) remains CRITICAL — attacker-controlled identity
- The risk of suppressing `github-actions[bot]` is low: an attacker using this identity makes their commits look like they came from the official bot, not a human — still visible and auditable

**Fix:** When the matched git identity string is one of the known official GitHub service bot names, downgrade severity from CRITICAL/HIGH to LOW rather than suppressing the finding entirely.

**Known safe bot identity strings (exact match, case-insensitive):**
- `github-actions[bot]`
- `dependabot[bot]`
- `renovate[bot]`
- `github-actions` (without [bot] suffix — also common)

**What still fires at original severity:**
- Any human-style name: `"John Smith"`, `"octocat"` — HIGH
- Variable-based identity: `${{ github.actor }}`, `${{ env.GIT_AUTHOR }}` — CRITICAL
- Any unknown bot name not in the allow-list — HIGH
- Known bots — LOW (still visible, just deprioritised)

**False negative risk:** None. True impersonation (human names, variable injection) still fires at full severity. Known bots appear at LOW so security teams can still review them in a full report.

---

### Fix 6 — AST_SENSITIVE_DATA_FLOW: Deferred

**Scope:** Excluded from this spec.

**Reason:** 21 findings on vscode require hands-on investigation of specific source/sink pairs before any suppression logic is safe to write. A broad fix risks suppressing real taint flows (secrets → network, secrets → logs). This will be addressed in a dedicated spec after the specific FP patterns are catalogued.

---

## Files Changed

| File | Changes |
|------|---------|
| `pkg/rules/cache_poisoning.go` | Fix 1: dedup in `checkCacheWriteInPR` |
| `pkg/rules/rules.go` | Fix 2: dedup in `checkDangerousWriteOperation`; Fix 3: arithmetic context in matrix injection check; Fix 4: quoted-var exemption for file-ops in unquoted-var scan; Fix 5: severity downgrade for known bots in `checkImpostorCommit` |
| `pkg/rules/rules_test.go` | New table-driven tests for all 5 fixes |

---

## Testing Strategy

Each fix requires a mustFire / mustNotFire pair:

**Fix 1:** Two-job matrix workflow with same `actions/cache@v3` → assert 1 finding, not 2.

**Fix 2:** Two-job workflow with same step writing `$VAR >> $GITHUB_ENV` → assert 1 finding, not 2.

**Fix 3:**
- `run: $((${{ matrix.nr }} + 1))` with static matrix → 0 MATRIX_INJECTION findings
- `run: $((${{ matrix.nr }} + 1))` with `fromJSON(inputs.matrix)` → 1 finding
- `run: curl ${{ matrix.url }}` → 1 finding (unaffected)

**Fix 4:**
- `run: rm "$DIR"` → 0 SHELL_SCRIPT_ISSUES unquoted-var findings
- `run: rm $DIR` → 1 finding
- `run: eval "$CMD"` → 1 finding (quoted eval still fires)
- `run: curl "$URL"` → 1 finding (quoted curl still fires)

**Fix 5:**
- `git config user.name "github-actions[bot]"` → 1 LOW finding (not CRITICAL)
- `git config user.name "${{ github.actor }}"` → 1 CRITICAL finding (unchanged)
- `git config user.name "John Smith"` → 1 HIGH finding (unchanged)

---

## Success Criteria

Scanning kubernetes/kubernetes after these fixes:
- `CACHE_WRITE_IN_PR_WORKFLOW`: 18 → ≤3 findings
- `MATRIX_INJECTION`: 10 → ≤5 findings (only non-arithmetic, non-static-matrix cases)
- `IMPOSTOR_COMMIT`: 4 → 4 findings remaining but at LOW severity (not CRITICAL)

No new false negatives introduced — verified by running the full existing test suite.
