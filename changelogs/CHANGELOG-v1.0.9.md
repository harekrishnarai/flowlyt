# Changelog - Version 1.0.9

**Release Date:** March 17, 2026

## 🎉 What's New

Version 1.0.9 introduces **Expression Taint Analysis** and **11 new security rules** targeting 2024-2025 real-world attack classes, including the March 2025 tj-actions/reviewdog supply chain attack (CVE-2025-30066). False positives from safe patterns are eliminated at the root.

---

## ✨ Major Features

### Track A: Expression Taint Analysis Engine

New `ExprTaintTracker` in `pkg/analysis/ast/taint.go` tracks `${{ untrusted_expr }}` expressions through a **source → transform → sink** pipeline, understanding when an expression is safe vs. unsafe:

- **Safe (no finding)**: Expression assigned to an `env:` block variable first, then the variable (not the raw expression) used in `run:`
  ```yaml
  env:
    TITLE: ${{ github.event.pull_request.title }}  # safe transform
  run: echo "$TITLE"                               # safe sink
  ```
- **Unsafe (finding)**: Expression interpolated directly into a `run:` command
  ```yaml
  run: echo "${{ github.event.pull_request.title }}"  # CRITICAL
  ```

**24 untrusted expression sources** tracked across PR, issue, commit, release, discussion, and `workflow_run` contexts. This eliminates the most common class of injection false positives.

### Track B: 11 New Security Rules

#### `workflow_run` Trust Boundary Rules (`pkg/rules/workflow_run_trust.go`)

The exact attack class used in the March 2025 tj-actions supply chain attack:

| Rule ID | Severity | Description |
|---|---|---|
| `WORKFLOW_RUN_ARTIFACT_UNTRUSTED` | CRITICAL | `workflow_run` downloads artifacts without constraining `run_id` — attacker who controls the triggering workflow controls artifact content |
| `WORKFLOW_RUN_ENV_INJECTION` | CRITICAL | `workflow_run` job downloads artifact then pipes content to `$GITHUB_ENV` or `$GITHUB_PATH` — enables arbitrary env-var injection |
| `WORKFLOW_RUN_ELEVATED_CONTEXT` | HIGH | `workflow_run` job combines write permissions with artifact download — amplifies blast radius of a compromised artifact |

#### OIDC Token Abuse Rules (`pkg/rules/oidc_abuse.go`)

| Rule ID | Severity | Description |
|---|---|---|
| `OIDC_WORKFLOW_LEVEL_PERMISSION` | HIGH | `id-token: write` at workflow level exposes all jobs to OIDC token access, not just the one that needs it |
| `OIDC_WITHOUT_ENVIRONMENT_SCOPE` | MEDIUM | Job has `id-token: write` but is not scoped to a GitHub deployment environment — token can be exchanged by any step in the job |

#### Cache Poisoning Rules (`pkg/rules/cache_poisoning.go`)

| Rule ID | Severity | Description |
|---|---|---|
| `CACHE_RESTORE_KEYS_TOO_BROAD` | MEDIUM | `restore-keys` without `hashFiles()` allows a PR branch to poison the cache for future privileged runs |
| `CACHE_WRITE_IN_PR_WORKFLOW` | LOW | `actions/cache` (write) in a `pull_request` workflow — untrusted code can write attacker-controlled entries to the shared cache |

#### Injection Sub-Rules (`pkg/rules/injection.go`)

| Rule ID | Severity | Description |
|---|---|---|
| `GITHUB_ENV_UNTRUSTED_WRITE` | CRITICAL | Untrusted `${{ }}` expression or `LD_PRELOAD` written directly to `$GITHUB_ENV` — all subsequent steps inherit the injected environment |
| `MEMDUMP_EXFILTRATION_SIGNATURE` | CRITICAL | memdump.py signature and `/proc/*/mem` process memory reading — the exact technique used in the March 2025 tj-actions attack to steal runner secrets |
| `INDIRECT_PPE_BUILD_TOOL` | HIGH | Checkout of untrusted PR head SHA followed by `npm install`, `pip install -e .`, `make`, `mvn`, `gradle`, etc. — attacker controls `package.json` scripts, `setup.py`, or `Makefile` targets |

#### `pull_request_target` 3-Tier Severity Refinement

The old binary CRITICAL/no-finding model is replaced with a risk-proportionate 3-tier system:

| Condition | Severity | Rationale |
|---|---|---|
| `pull_request_target` + checkout of `head.sha` / `head.ref` / `github.head_ref` | **CRITICAL** | Attacker-controlled code runs with write token |
| `pull_request_target` + checkout of base `sha` / `github.sha` | **MEDIUM** | Code is trusted (base branch), but write token context warrants attention |
| `pull_request_target` + no checkout (labeler, commenter) | *(no finding)* | Safe by design — no PR code executes |

---

## 🐛 False Positive Fixes

- **Env-var indirection**: `env: VAR: ${{ expr }}` + `run: echo "$VAR"` no longer fires `INJECTION_VULNERABILITY`. The taint engine correctly classifies this as a safe transform.
- **`pull_request_target` labelers**: Workflows using `pull_request_target` solely for labeling or commenting (no checkout) no longer generate any finding.
- **`GITHUB_TOKEN` in PRT `with:` blocks**: Auto-provisioned `secrets.GITHUB_TOKEN` passed to an action in a labeler workflow no longer fires `PR_TARGET_ABUSE`.
- **cmake**: `cmake` invocations no longer matched by the `make` indirect PPE pattern.

---

## 🔧 Bug Fixes (Post-Code-Review)

- **Duplicate cache findings eliminated**: `CACHE_RESTORE_KEYS_TOO_BROAD` and `CACHE_WRITE_IN_PR_WORKFLOW` previously both called `CheckCachePoisoning`, producing 2× every finding. Each entry now calls a distinct function.
- **EI-001/002/003 wired into StandardRules**: `GITHUB_ENV_UNTRUSTED_WRITE`, `MEMDUMP_EXFILTRATION_SIGNATURE`, and `INDIRECT_PPE_BUILD_TOOL` were missing from the main rule engine dispatch. Now registered as independent entries.
- **`classifyExpression` precedence**: `github.event.workflow_run.head_commit.message` was misclassified as `TaintCommitContent` (matched `"commit"` before `"workflow_run"`). Fixed by evaluating `workflow_run` first.
- **WRT-002 false positive**: Static `echo "KEY=value" >> $GITHUB_ENV` after an artifact download no longer fires — new `looksLikeDynamicEnvWrite` guard requires shell expansion or file reads on the GITHUB_ENV write line.
- **Step name corruption for index ≥ 9**: `string(rune('1'+stepIdx))` produced garbage characters (`:`/`;`) for step index ≥ 9. Fixed with `fmt.Sprintf("Step %d", stepIdx+1)`.

---

## 📦 New Files

| File | Purpose |
|---|---|
| `pkg/analysis/ast/taint.go` | Expression taint tracker — source/transform/sink engine |
| `pkg/analysis/ast/taint_test.go` | 32 unit tests for all taint path scenarios |
| `pkg/rules/workflow_run_trust.go` | WRT-001/002/003 workflow_run trust boundary rules |
| `pkg/rules/workflow_run_trust_test.go` | Unit tests for WRT rules |
| `pkg/rules/oidc_abuse.go` | OA-001/002 OIDC token abuse rules |
| `pkg/rules/oidc_abuse_test.go` | Unit tests for OIDC rules |
| `pkg/rules/cache_poisoning.go` | CP-001/002 cache poisoning rules |
| `pkg/rules/cache_poisoning_test.go` | Unit tests for cache poisoning rules |
| `pkg/rules/injection_test.go` | Unit tests for new EI-001/002/003 rules |
| `pkg/rules/prt_test.go` | Unit tests for 3-tier PRT severity |
| `pkg/rules/integration_test.go` | End-to-end fixture tests — safe and vulnerable YAMLs |
| `testdata/workflows/safe_env_var_indirection.yml` | FP regression fixture — must produce zero injection findings |
| `testdata/workflows/safe_prt_labeler.yml` | FP regression fixture — must produce zero CRITICAL findings |
| `testdata/workflows/vuln_workflow_run_artifact.yml` | Detection fixture — must trigger WRT-001/002 |
| `testdata/workflows/vuln_memdump.yml` | Detection fixture — must trigger MEMDUMP_EXFILTRATION_SIGNATURE |
