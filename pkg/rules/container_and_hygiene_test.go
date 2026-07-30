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

// findingsFor runs the named rule against the given workflow YAML and returns
// only the findings that rule produced.
func findingsFor(t *testing.T, ruleID, yamlContent string) []rules.Finding {
	t.Helper()
	rule := findRule(t, ruleID)
	wf := makeWorkflow(t, yamlContent)

	var out []rules.Finding
	for _, f := range rule.Check(wf) {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// CONCURRENCY_LIMITS_MISSING
// ---------------------------------------------------------------------------

func TestConcurrencyLimits_MissingBlockOnPush(t *testing.T) {
	findings := findingsFor(t, "CONCURRENCY_LIMITS_MISSING", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for workflow with no concurrency block, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "no `concurrency:` block") {
		t.Errorf("evidence should identify the missing block, got: %q", findings[0].Evidence)
	}
}

func TestConcurrencyLimits_CancelInProgressTrue(t *testing.T) {
	findings := findingsFor(t, "CONCURRENCY_LIMITS_MISSING", `
name: CI
on: pull_request
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
`)

	if len(findings) != 0 {
		t.Fatalf("expected no findings when cancel-in-progress is true, got %d", len(findings))
	}
}

func TestConcurrencyLimits_CancelInProgressFalse(t *testing.T) {
	findings := findingsFor(t, "CONCURRENCY_LIMITS_MISSING", `
name: CI
on: push
concurrency:
  group: ci
  cancel-in-progress: false
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding when cancel-in-progress is false, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "without cancel-in-progress") {
		t.Errorf("evidence should identify the disabled cancellation, got: %q", findings[0].Evidence)
	}
}

// The shorthand string form is equivalent to cancel-in-progress: false.
func TestConcurrencyLimits_ShorthandStringForm(t *testing.T) {
	findings := findingsFor(t, "CONCURRENCY_LIMITS_MISSING", `
name: CI
on: push
concurrency: ci-group
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for shorthand concurrency string, got %d", len(findings))
	}
}

// An expression is a deliberate, context-sensitive choice and is accepted.
func TestConcurrencyLimits_CancelInProgressExpression(t *testing.T) {
	findings := findingsFor(t, "CONCURRENCY_LIMITS_MISSING", `
name: CI
on: push
concurrency:
  group: ci
  cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
`)

	if len(findings) != 0 {
		t.Fatalf("expected no findings for expression-based cancel-in-progress, got %d", len(findings))
	}
}

// A job-level concurrency block protecting the expensive work is sufficient.
func TestConcurrencyLimits_JobLevelSatisfies(t *testing.T) {
	findings := findingsFor(t, "CONCURRENCY_LIMITS_MISSING", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    concurrency:
      group: build-${{ github.ref }}
      cancel-in-progress: true
    steps:
      - run: make build
`)

	if len(findings) != 0 {
		t.Fatalf("expected no findings when a job configures cancellation, got %d", len(findings))
	}
}

// Schedule- and dispatch-only workflows cannot be rapidly re-triggered by an
// external party, so they are out of scope.
func TestConcurrencyLimits_ScheduleOnlyIgnored(t *testing.T) {
	findings := findingsFor(t, "CONCURRENCY_LIMITS_MISSING", `
name: Nightly
on:
  schedule:
    - cron: '0 0 * * *'
  workflow_dispatch:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
`)

	if len(findings) != 0 {
		t.Fatalf("expected no findings for schedule-only workflow, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// INSECURE_URL_SCHEME
// ---------------------------------------------------------------------------

func TestInsecureURL_HTTPInRunCommand(t *testing.T) {
	findings := findingsFor(t, "INSECURE_URL_SCHEME", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -sSL http://example.com/install.sh | bash
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for plaintext HTTP download, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "http://example.com/install.sh") {
		t.Errorf("evidence should contain the offending URL, got: %q", findings[0].Evidence)
	}
}

func TestInsecureURL_HTTPSIsClean(t *testing.T) {
	findings := findingsFor(t, "INSECURE_URL_SCHEME", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -sSL https://example.com/install.sh | bash
`)

	if len(findings) != 0 {
		t.Fatalf("expected no findings for HTTPS URL, got %d", len(findings))
	}
}

func TestInsecureURL_LoopbackIgnored(t *testing.T) {
	findings := findingsFor(t, "INSECURE_URL_SCHEME", `
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl http://localhost:8080/health
          curl http://127.0.0.1:3000/ready
`)

	if len(findings) != 0 {
		t.Fatalf("expected no findings for loopback URLs, got %d", len(findings))
	}
}

// XML namespace and license identifiers are opaque strings, never fetched.
func TestInsecureURL_NamespaceIdentifiersIgnored(t *testing.T) {
	findings := findingsFor(t, "INSECURE_URL_SCHEME", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "http://www.w3.org/2001/XMLSchema http://maven.apache.org/POM/4.0.0"
`)

	if len(findings) != 0 {
		t.Fatalf("expected no findings for namespace identifiers, got %d", len(findings))
	}
}

func TestInsecureURL_InActionInput(t *testing.T) {
	findings := findingsFor(t, "INSECURE_URL_SCHEME", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some/downloader@v1
        with:
          url: http://downloads.example.org/tool.tar.gz
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for HTTP action input, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "Input `url`") {
		t.Errorf("evidence should name the input field, got: %q", findings[0].Evidence)
	}
}

func TestInsecureURL_InEnvVar(t *testing.T) {
	findings := findingsFor(t, "INSECURE_URL_SCHEME", `
name: CI
on: push
env:
  REGISTRY: http://registry.example.org
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo build
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for HTTP workflow env var, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// UNPINNED_CONTAINER_IMAGE
// ---------------------------------------------------------------------------

func TestUnpinnedImage_JobContainerWithTag(t *testing.T) {
	findings := findingsFor(t, "UNPINNED_CONTAINER_IMAGE", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container: node:18
    steps:
      - run: node --version
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for tag-pinned container, got %d", len(findings))
	}
	if findings[0].Severity != rules.Low {
		t.Errorf("expected LOW severity for a version tag, got %s", findings[0].Severity)
	}
}

func TestUnpinnedImage_LatestTagIsHigherSeverity(t *testing.T) {
	findings := findingsFor(t, "UNPINNED_CONTAINER_IMAGE", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: node:latest
    steps:
      - run: node --version
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for latest tag, got %d", len(findings))
	}
	if findings[0].Severity != rules.Medium {
		t.Errorf("expected MEDIUM severity for latest tag, got %s", findings[0].Severity)
	}
}

func TestUnpinnedImage_DigestPinnedIsClean(t *testing.T) {
	findings := findingsFor(t, "UNPINNED_CONTAINER_IMAGE", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: node@sha256:8e5f2a5a1d2f9c7b6a4e3d2c1b0a9f8e7d6c5b4a3928170695847362514fa0b1
    steps:
      - run: node --version
`)

	if len(findings) != 0 {
		t.Fatalf("expected no findings for digest-pinned image, got %d", len(findings))
	}
}

func TestUnpinnedImage_ServiceContainer(t *testing.T) {
	findings := findingsFor(t, "UNPINNED_CONTAINER_IMAGE", `
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
    steps:
      - run: make test
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for unpinned service image, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "Service `postgres`") {
		t.Errorf("evidence should name the service, got: %q", findings[0].Evidence)
	}
}

func TestUnpinnedImage_UntaggedImage(t *testing.T) {
	findings := findingsFor(t, "UNPINNED_CONTAINER_IMAGE", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container: ubuntu
    steps:
      - run: uname -a
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for untagged image, got %d", len(findings))
	}
	if findings[0].Severity != rules.Medium {
		t.Errorf("expected MEDIUM severity for untagged image, got %s", findings[0].Severity)
	}
}

// A registry host with a port must not be mistaken for a tag separator.
func TestUnpinnedImage_RegistryPortNotTreatedAsTag(t *testing.T) {
	findings := findingsFor(t, "UNPINNED_CONTAINER_IMAGE", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container: registry.example.com:5000/team/app
    steps:
      - run: true
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "has no tag") {
		t.Errorf("registry port should not be parsed as a tag, got: %q", findings[0].Evidence)
	}
}

func TestUnpinnedImage_DockerStepAction(t *testing.T) {
	findings := findingsFor(t, "UNPINNED_CONTAINER_IMAGE", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://alpine:3.19
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for docker:// step action, got %d", len(findings))
	}
}

// Images resolved from expressions cannot be evaluated statically.
func TestUnpinnedImage_ExpressionSkipped(t *testing.T) {
	findings := findingsFor(t, "UNPINNED_CONTAINER_IMAGE", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: ${{ matrix.image }}
    steps:
      - run: true
`)

	if len(findings) != 0 {
		t.Fatalf("expected no findings for expression-based image, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// HARDCODED_CONTAINER_CREDENTIALS
// ---------------------------------------------------------------------------

func TestContainerCredentials_HardcodedPassword(t *testing.T) {
	findings := findingsFor(t, "HARDCODED_CONTAINER_CREDENTIALS", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/team/app:1.0
      credentials:
        username: ci-bot
        password: hunter2supersecret
    steps:
      - run: true
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for hardcoded container password, got %d", len(findings))
	}
	if findings[0].Severity != rules.Critical {
		t.Errorf("expected CRITICAL severity, got %s", findings[0].Severity)
	}
	if strings.Contains(findings[0].Evidence, "hunter2supersecret") {
		t.Errorf("evidence must redact the credential, got: %q", findings[0].Evidence)
	}
}

func TestContainerCredentials_SecretReferenceIsClean(t *testing.T) {
	findings := findingsFor(t, "HARDCODED_CONTAINER_CREDENTIALS", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/team/app:1.0
      credentials:
        username: ci-bot
        password: ${{ secrets.REGISTRY_PASSWORD }}
    steps:
      - run: true
`)

	if len(findings) != 0 {
		t.Fatalf("expected no findings when password comes from secrets, got %d", len(findings))
	}
}

func TestContainerCredentials_ServiceCredentials(t *testing.T) {
	findings := findingsFor(t, "HARDCODED_CONTAINER_CREDENTIALS", `
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    services:
      redis:
        image: private.registry/redis:7
        credentials:
          username: svc
          password: literalpassword123
    steps:
      - run: make test
`)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for hardcoded service credentials, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "Service `redis`") {
		t.Errorf("evidence should name the service, got: %q", findings[0].Evidence)
	}
}

// A username alone is not a secret and must not trigger the rule.
func TestContainerCredentials_UsernameOnlyIsClean(t *testing.T) {
	findings := findingsFor(t, "HARDCODED_CONTAINER_CREDENTIALS", `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/team/app:1.0
      credentials:
        username: ci-bot
        password: ${{ secrets.PW }}
    steps:
      - run: true
`)

	if len(findings) != 0 {
		t.Fatalf("expected no findings for username-only literal, got %d", len(findings))
	}
}
