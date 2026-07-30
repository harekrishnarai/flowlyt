/*
Copyright 2025 Hare Krishna Rai

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package rules_test

import (
	"strings"
	"testing"

	"github.com/harekrishnarai/flowlyt/v2/pkg/rules"
)

// ---------------------------------------------------------------------------
// ADHOC_PACKAGE_INSTALL
// ---------------------------------------------------------------------------

func TestAdhocInstall_NpmWithPackage(t *testing.T) {
	findings := findingsFor(t, "ADHOC_PACKAGE_INSTALL", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm install left-pad
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for ad-hoc npm install, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "left-pad") {
		t.Errorf("evidence should name the package, got: %q", findings[0].Evidence)
	}
}

// A bare `npm install` resolves from the committed manifest and is correct.
func TestAdhocInstall_BareInstallIsClean(t *testing.T) {
	findings := findingsFor(t, "ADHOC_PACKAGE_INSTALL", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm install
      - run: bundle install
      - run: npm ci
`)

	if len(findings) != 0 {
		t.Fatalf("expected no findings for manifest-driven installs, got %d", len(findings))
	}
}

func TestAdhocInstall_PipRequirementsFileIsClean(t *testing.T) {
	findings := findingsFor(t, "ADHOC_PACKAGE_INSTALL", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: pip install -r requirements.txt
`)

	if len(findings) != 0 {
		t.Fatalf("expected no findings for requirements-file install, got %d", len(findings))
	}
}

// Installs buried in a && chain must still be detected.
func TestAdhocInstall_InCommandChain(t *testing.T) {
	findings := findingsFor(t, "ADHOC_PACKAGE_INSTALL", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: cd app && gem install rake && rake test
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for install inside a command chain, got %d", len(findings))
	}
}

// A commented-out example must not produce a finding.
func TestAdhocInstall_CommentIgnored(t *testing.T) {
	findings := findingsFor(t, "ADHOC_PACKAGE_INSTALL", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          # npm install left-pad
          npm ci
`)

	if len(findings) != 0 {
		t.Fatalf("expected no findings for commented-out install, got %d", len(findings))
	}
}

// Global installs are tool installs and belong to UNPINNED_TOOL_INSTALL, so
// they must not be double-reported here.
func TestAdhocInstall_GlobalInstallNotDoubleReported(t *testing.T) {
	findings := findingsFor(t, "ADHOC_PACKAGE_INSTALL", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm install -g typescript
`)

	if len(findings) != 0 {
		t.Fatalf("expected global install to be excluded from ADHOC_PACKAGE_INSTALL, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// UNPINNED_TOOL_INSTALL
// ---------------------------------------------------------------------------

func TestUnpinnedTool_GoInstallLatest(t *testing.T) {
	findings := findingsFor(t, "UNPINNED_TOOL_INSTALL", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: go install github.com/foo/bar@latest
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for go install @latest, got %d", len(findings))
	}
}

func TestUnpinnedTool_GoInstallPinnedIsClean(t *testing.T) {
	findings := findingsFor(t, "UNPINNED_TOOL_INSTALL", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: go install github.com/foo/bar@v1.2.3
`)

	if len(findings) != 0 {
		t.Fatalf("expected no findings for version-pinned go install, got %d", len(findings))
	}
}

func TestUnpinnedTool_CargoWithVersionIsClean(t *testing.T) {
	findings := findingsFor(t, "UNPINNED_TOOL_INSTALL", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: cargo install cargo-audit --version 0.18.3 --locked
`)

	if len(findings) != 0 {
		t.Fatalf("expected no findings for cargo install with --version, got %d", len(findings))
	}
}

func TestUnpinnedTool_CargoWithoutVersion(t *testing.T) {
	findings := findingsFor(t, "UNPINNED_TOOL_INSTALL", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: cargo install cargo-audit
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for unpinned cargo install, got %d", len(findings))
	}
}

func TestUnpinnedTool_NpmGlobalUnpinned(t *testing.T) {
	findings := findingsFor(t, "UNPINNED_TOOL_INSTALL", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm install -g typescript
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for unpinned global npm install, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// GITHUB_APP_TOKEN_MISUSE
// ---------------------------------------------------------------------------

func TestAppToken_OwnerWithoutRepositories(t *testing.T) {
	findings := findingsFor(t, "GITHUB_APP_TOKEN_MISUSE", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/create-github-app-token@v1
        with:
          app-id: ${{ vars.APP_ID }}
          private-key: ${{ secrets.APP_KEY }}
          owner: my-org
          permission-contents: read
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for owner-wide token, got %d", len(findings))
	}
	if findings[0].Severity != rules.High {
		t.Errorf("expected HIGH severity for org-wide token, got %s", findings[0].Severity)
	}
}

func TestAppToken_SkipRevoke(t *testing.T) {
	findings := findingsFor(t, "GITHUB_APP_TOKEN_MISUSE", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/create-github-app-token@v1
        with:
          app-id: ${{ vars.APP_ID }}
          private-key: ${{ secrets.APP_KEY }}
          repositories: one
          permission-contents: read
          skip-token-revoke: true
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for skip-token-revoke, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "revocation is disabled") {
		t.Errorf("unexpected evidence: %q", findings[0].Evidence)
	}
}

func TestAppToken_NoPermissionNarrowing(t *testing.T) {
	findings := findingsFor(t, "GITHUB_APP_TOKEN_MISUSE", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/create-github-app-token@v1
        with:
          app-id: ${{ vars.APP_ID }}
          private-key: ${{ secrets.APP_KEY }}
          repositories: one
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for missing permission narrowing, got %d", len(findings))
	}
}

func TestAppToken_WellScopedIsClean(t *testing.T) {
	findings := findingsFor(t, "GITHUB_APP_TOKEN_MISUSE", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/create-github-app-token@v1
        with:
          app-id: ${{ vars.APP_ID }}
          private-key: ${{ secrets.APP_KEY }}
          owner: my-org
          repositories: just-this-one
          permission-contents: read
`)

	if len(findings) != 0 {
		t.Fatalf("expected no findings for a well-scoped token request, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// SECRETS_OUTSIDE_ENV
// ---------------------------------------------------------------------------

func TestSecretsOutsideEnv_InlineInRun(t *testing.T) {
	findings := findingsFor(t, "SECRETS_OUTSIDE_ENV", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh --token ${{ secrets.DEPLOY_TOKEN }}
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for inline secret, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "DEPLOY_TOKEN") {
		t.Errorf("evidence should name the secret, got: %q", findings[0].Evidence)
	}
}

func TestSecretsOutsideEnv_ViaEnvIsClean(t *testing.T) {
	findings := findingsFor(t, "SECRETS_OUTSIDE_ENV", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh --token "$DEPLOY_TOKEN"
        env:
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
`)

	if len(findings) != 0 {
		t.Fatalf("expected no findings when the secret is passed via env, got %d", len(findings))
	}
}

// GITHUB_TOKEN is conventionally passed inline to the gh CLI.
func TestSecretsOutsideEnv_GithubTokenExempt(t *testing.T) {
	findings := findingsFor(t, "SECRETS_OUTSIDE_ENV", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets.GITHUB_TOKEN }} | gh auth login --with-token
`)

	if len(findings) != 0 {
		t.Fatalf("expected GITHUB_TOKEN to be exempt, got %d findings", len(findings))
	}
}

// ---------------------------------------------------------------------------
// MISFEATURE
// ---------------------------------------------------------------------------

func TestMisfeature_CheckoutSubmodules(t *testing.T) {
	findings := findingsFor(t, "MISFEATURE", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: true
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for submodule checkout, got %d", len(findings))
	}
}

func TestMisfeature_SubmodulesFalseIsClean(t *testing.T) {
	findings := findingsFor(t, "MISFEATURE", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: false
`)

	if len(findings) != 0 {
		t.Fatalf("expected no findings for submodules: false, got %d", len(findings))
	}
}

func TestMisfeature_SecretsInherit(t *testing.T) {
	findings := findingsFor(t, "MISFEATURE", `
name: CI
on: push
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
    secrets: inherit
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for secrets: inherit, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// ANONYMOUS_DEFINITION / UNDOCUMENTED_PERMISSIONS
// ---------------------------------------------------------------------------

func TestAnonymousDefinition_MissingName(t *testing.T) {
	findings := findingsFor(t, "ANONYMOUS_DEFINITION", `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for unnamed workflow, got %d", len(findings))
	}
}

func TestAnonymousDefinition_NamedIsClean(t *testing.T) {
	findings := findingsFor(t, "ANONYMOUS_DEFINITION", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
`)

	if len(findings) != 0 {
		t.Fatalf("expected no findings for named workflow, got %d", len(findings))
	}
}

func TestUndocumentedPermissions_WriteWithoutComment(t *testing.T) {
	findings := findingsFor(t, "UNDOCUMENTED_PERMISSIONS", `
name: CI
on: push
permissions:
  contents: write
  issues: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (contents: write only), got %d", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "contents") {
		t.Errorf("evidence should name the scope, got: %q", findings[0].Evidence)
	}
}

func TestUndocumentedPermissions_CommentedIsClean(t *testing.T) {
	findings := findingsFor(t, "UNDOCUMENTED_PERMISSIONS", `
name: CI
on: push
permissions:
  contents: write # needed to push release tags
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
`)

	if len(findings) != 0 {
		t.Fatalf("expected no findings when the grant is documented, got %d", len(findings))
	}
}

// permissions: {} confers no authority and needs no justification.
func TestUndocumentedPermissions_EmptyIsClean(t *testing.T) {
	findings := findingsFor(t, "UNDOCUMENTED_PERMISSIONS", `
name: CI
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
`)

	if len(findings) != 0 {
		t.Fatalf("expected no findings for permissions: {}, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// FORBIDDEN_USES
// ---------------------------------------------------------------------------

// The rule is opt-in and must not exist until configured.
func TestForbiddenUses_NilWhenUnconfigured(t *testing.T) {
	if rule := rules.NewForbiddenUsesRule(nil, nil); rule != nil {
		t.Fatal("expected nil rule when neither allow nor deny is configured")
	}
	if rule := rules.NewForbiddenUsesRule([]string{"  "}, nil); rule != nil {
		t.Fatal("expected nil rule when the allowlist contains only blank entries")
	}
}

func TestForbiddenUses_AllowlistBlocksOthers(t *testing.T) {
	rule := rules.NewForbiddenUsesRule([]string{"actions/*"}, nil)
	if rule == nil {
		t.Fatal("expected a rule to be constructed")
	}

	wf := makeWorkflow(t, `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sketchy/action@v1
`)

	findings := rule.Check(wf)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for the non-allowlisted action, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "sketchy/action") {
		t.Errorf("expected the non-allowlisted action to be reported, got: %q", findings[0].Evidence)
	}
}

func TestForbiddenUses_DenylistBlocksMatches(t *testing.T) {
	rule := rules.NewForbiddenUsesRule(nil, []string{"sketchy/action"})
	if rule == nil {
		t.Fatal("expected a rule to be constructed")
	}

	wf := makeWorkflow(t, `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sketchy/action@v1
`)

	findings := rule.Check(wf)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for the denied action, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "sketchy/action") {
		t.Errorf("expected the denied action to be reported, got: %q", findings[0].Evidence)
	}
}

// Local actions and Docker references are not repository `uses:` clauses.
func TestForbiddenUses_LocalAndDockerIgnored(t *testing.T) {
	rule := rules.NewForbiddenUsesRule([]string{"actions/*"}, nil)

	wf := makeWorkflow(t, `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/local
      - uses: docker://alpine:3.19
`)

	if findings := rule.Check(wf); len(findings) != 0 {
		t.Fatalf("expected local and docker refs to be ignored, got %d findings", len(findings))
	}
}

// Subdirectory actions must be matched by their owner/repo.
func TestForbiddenUses_SubdirectoryActionMatching(t *testing.T) {
	rule := rules.NewForbiddenUsesRule([]string{"github/codeql-action"}, nil)

	wf := makeWorkflow(t, `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: github/codeql-action/init@v3
`)

	if findings := rule.Check(wf); len(findings) != 0 {
		t.Fatalf("expected subdirectory action to match its owner/repo allowlist entry, got %d findings", len(findings))
	}
}
