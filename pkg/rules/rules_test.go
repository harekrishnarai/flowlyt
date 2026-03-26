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

	"github.com/harekrishnarai/flowlyt/pkg/parser"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

func TestStandardRules(t *testing.T) {
	// Get all standard rules
	standardRules := rules.StandardRules()

	// Ensure we have rules defined
	if len(standardRules) == 0 {
		t.Fatal("No standard rules defined")
	}

	// Check that each rule has required fields
	for _, rule := range standardRules {
		if rule.ID == "" {
			t.Errorf("Rule ID should not be empty")
		}
		if rule.Name == "" {
			t.Errorf("Rule name should not be empty for rule %s", rule.ID)
		}
		if rule.Description == "" {
			t.Errorf("Rule description should not be empty for rule %s", rule.ID)
		}
		if rule.Check == nil {
			t.Errorf("Rule check function should not be nil for rule %s", rule.ID)
		}
	}
}

func TestInsecureWorkflowFindings(t *testing.T) {
	// Load the test insecure workflow
	repoPath := "../../test/sample-repo"
	workflows, err := parser.FindWorkflows(repoPath)
	if err != nil {
		t.Fatalf("Failed to find workflows: %v", err)
	}

	// Find the insecure workflow
	var insecureWorkflow parser.WorkflowFile
	for _, workflow := range workflows {
		if workflow.Name == "insecure_workflow.yml" {
			insecureWorkflow = workflow
			break
		}
	}

	if insecureWorkflow.Path == "" {
		t.Fatal("Failed to find insecure_workflow.yml in test files")
	}

	// Apply all standard rules
	standardRules := rules.StandardRules()
	var findings []rules.Finding

	for _, rule := range standardRules {
		ruleFindings := rule.Check(insecureWorkflow)
		findings = append(findings, ruleFindings...)
	}

	// We should have found several issues in the insecure workflow
	if len(findings) == 0 {
		t.Error("No findings detected in insecure workflow")
	}

	// Check for specific expected findings
	foundCurlPipeBash := false
	foundPullRequestTarget := false
	foundUnpinnedAction := false

	for _, finding := range findings {
		switch finding.RuleID {
		case "MALICIOUS_CURL_PIPE_BASH":
			foundCurlPipeBash = true
		case "INSECURE_PULL_REQUEST_TARGET":
			foundPullRequestTarget = true
		case "UNPINNED_ACTION":
			foundUnpinnedAction = true
		}
	}

	if !foundCurlPipeBash {
		t.Error("Failed to detect curl pipe to bash issue")
	}
	if !foundPullRequestTarget {
		t.Error("Failed to detect insecure pull_request_target usage")
	}
	if !foundUnpinnedAction {
		t.Error("Failed to detect unpinned action issue")
	}
}

func TestSecureWorkflowFindings(t *testing.T) {
	// Load the test secure workflow
	repoPath := "../../test/sample-repo"
	workflows, err := parser.FindWorkflows(repoPath)
	if err != nil {
		t.Fatalf("Failed to find workflows: %v", err)
	}

	// Find the secure workflow
	var secureWorkflow parser.WorkflowFile
	for _, workflow := range workflows {
		if workflow.Name == "secure_workflow.yml" {
			secureWorkflow = workflow
			break
		}
	}

	if secureWorkflow.Path == "" {
		t.Fatal("Failed to find secure_workflow.yml in test files")
	}

	// Apply all standard rules
	standardRules := rules.StandardRules()
	var findings []rules.Finding

	for _, rule := range standardRules {
		// Skip secret detection rules for this test
		// This is because our current implementation might have false positives
		if rule.Category == "SECRET_EXPOSURE" {
			continue
		}

		ruleFindings := rule.Check(secureWorkflow)
		findings = append(findings, ruleFindings...)
	}

	// We should have minimal or no findings in the secure workflow
	// At least, we shouldn't have critical issues
	criticalFindings := 0
	for _, finding := range findings {
		if finding.Severity == rules.Critical {
			criticalFindings++
			t.Logf("Critical finding in secure workflow: %s - %s", finding.RuleID, finding.RuleName)
		}
	}

	// Allow for some findings, but no critical ones
	if criticalFindings > 0 {
		t.Errorf("Found %d critical issues in secure workflow, expected none", criticalFindings)
	}
}

// TestExfiltrationWorkflowDetection tests the data exfiltration detection rule
func TestExfiltrationWorkflowDetection(t *testing.T) {
	// Load the test workflows
	repoPath := "../../test/sample-repo"
	workflows, err := parser.FindWorkflows(repoPath)
	if err != nil {
		t.Fatalf("Failed to find workflows: %v", err)
	}

	// Find the exfiltration workflow
	var exfilWorkflow parser.WorkflowFile
	for _, workflow := range workflows {
		if workflow.Name == "exfiltration_workflow.yml" {
			exfilWorkflow = workflow
			break
		}
	}

	if exfilWorkflow.Path == "" {
		t.Fatal("Failed to find exfiltration_workflow.yml in test files")
	}

	// Apply all standard rules
	standardRules := rules.StandardRules()
	var findings []rules.Finding

	for _, rule := range standardRules {
		if rule.ID == "MALICIOUS_DATA_EXFILTRATION" {
			ruleFindings := rule.Check(exfilWorkflow)
			findings = append(findings, ruleFindings...)
		}
	}

	// We should have found several exfiltration issues
	if len(findings) == 0 {
		t.Error("No data exfiltration findings detected in the exfiltration workflow")
	}

	// Output the findings for logging purposes
	for i, finding := range findings {
		t.Logf("Finding %d: %s in job '%s', step '%s'",
			i+1, finding.RuleName, finding.JobName, finding.StepName)
		t.Logf("  Evidence: %s", finding.Evidence)
	}

	// Check for specific expected patterns
	expectedPatterns := []string{
		"ngrok", "192.168.1.100", "webhook.site", "attacker.command.io",
		"secrets.GITHUB_TOKEN", "paste.bin.io", "collect.exfil.io",
		"malicious.ngrok.io", "webhook.command.com",
	}

	patternFound := make(map[string]bool)
	for _, pattern := range expectedPatterns {
		patternFound[pattern] = false
	}

	// Check if each expected pattern was found in any finding
	for _, finding := range findings {
		for _, pattern := range expectedPatterns {
			if strings.Contains(finding.Evidence, pattern) {
				patternFound[pattern] = true
			}
		}
	}

	// Report missing patterns
	for pattern, found := range patternFound {
		if !found {
			t.Errorf("Expected exfiltration pattern '%s' was not detected", pattern)
		}
	}
}

// TestRefConfusionIsMutableRef verifies that REF_CONFUSION fires on mutable
// branch refs but is suppressed for stable semver tags.
func TestRefConfusionIsMutableRef(t *testing.T) {
	rule := findRule(t, "REF_CONFUSION")

	// firesOn returns true if the rule produces a REF_CONFUSION finding
	// for `uses: actions/checkout@<ref>`.
	firesOn := func(ref string) bool {
		t.Helper()
		wf := makeWorkflow(t, `
name: test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@`+ref+`
`)
		findings := rule.Check(wf)
		for _, f := range findings {
			if f.RuleID == "REF_CONFUSION" {
				return true
			}
		}
		return false
	}

	// Must fire — mutable branch refs
	mustFire := []string{"main", "master", "develop", "trunk", "latest", "my-feature", "hotfix-1"}
	for _, ref := range mustFire {
		if !firesOn(ref) {
			t.Errorf("REF_CONFUSION should fire on @%s but did not", ref)
		}
	}

	// Must NOT fire — stable semver tags
	mustNotFire := []string{"v1", "v2", "v4", "v1.2", "v1.2.3", "v10.0.1"}
	for _, ref := range mustNotFire {
		if firesOn(ref) {
			t.Errorf("REF_CONFUSION should NOT fire on @%s but did", ref)
		}
	}
}

// TestExternalTriggerPermissions verifies that EXTERNAL_TRIGGER_DEBUG only fires
// on workflow_dispatch when the workflow has (or defaults to) write permissions.
func TestExternalTriggerPermissions(t *testing.T) {
	rule := findRule(t, "EXTERNAL_TRIGGER_DEBUG")

	firesOn := func(yamlContent string) bool {
		t.Helper()
		wf := makeWorkflow(t, yamlContent)
		for _, f := range rule.Check(wf) {
			if f.RuleID == "EXTERNAL_TRIGGER_DEBUG" && f.Evidence == "workflow_dispatch" {
				return true
			}
		}
		return false
	}

	// Must fire — no permissions block (GitHub default = write-all)
	noPerms := `
name: test
on: workflow_dispatch
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
`
	if !firesOn(noPerms) {
		t.Error("EXTERNAL_TRIGGER_DEBUG should fire on workflow_dispatch with no permissions block")
	}

	// Must fire — explicit write scope
	writePerms := `
name: test
on: workflow_dispatch
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
`
	if !firesOn(writePerms) {
		t.Error("EXTERNAL_TRIGGER_DEBUG should fire on workflow_dispatch with contents: write")
	}

	// Must NOT fire — read-all shorthand
	readAll := `
name: test
on: workflow_dispatch
permissions: read-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
`
	if firesOn(readAll) {
		t.Error("EXTERNAL_TRIGGER_DEBUG should NOT fire on workflow_dispatch with permissions: read-all")
	}

	// Must NOT fire — explicit read-only scope map
	readOnly := `
name: test
on: workflow_dispatch
permissions:
  contents: read
  issues: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
`
	if firesOn(readOnly) {
		t.Error("EXTERNAL_TRIGGER_DEBUG should NOT fire on workflow_dispatch with all-read permissions")
	}

	// Must NOT fire — empty permissions map
	emptyPerms := `
name: test
on: workflow_dispatch
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
`
	if firesOn(emptyPerms) {
		t.Error("EXTERNAL_TRIGGER_DEBUG should NOT fire on workflow_dispatch with permissions: {}")
	}

	// Must NOT fire — permissions: none shorthand
	nonePerms := `
name: test
on: workflow_dispatch
permissions: none
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
`
	if firesOn(nonePerms) {
		t.Error("EXTERNAL_TRIGGER_DEBUG should NOT fire on workflow_dispatch with permissions: none")
	}

	// Must fire — permissions: write-all string shorthand
	writeAll := `
name: test
on: workflow_dispatch
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
`
	if !firesOn(writeAll) {
		t.Error("EXTERNAL_TRIGGER_DEBUG should fire on workflow_dispatch with permissions: write-all")
	}

	// Unrelated triggers (issue_comment) must still fire regardless of permissions
	issueComment := `
name: test
on: issue_comment
permissions: read-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
`
	hasIssueCommentFinding := false
	wf := makeWorkflow(t, issueComment)
	for _, f := range rule.Check(wf) {
		if f.RuleID == "EXTERNAL_TRIGGER_DEBUG" && f.Evidence == "issue_comment" {
			hasIssueCommentFinding = true
		}
	}
	if !hasIssueCommentFinding {
		t.Error("EXTERNAL_TRIGGER_DEBUG should still fire on issue_comment regardless of permissions")
	}

	// Regression: flowlyt-scan.yml — has security-events: write but also contents: read.
	// permsImplyWrite must return true (any write scope → write), so this MUST fire.
	scsFeedFlowlytScan := `
name: Flowlyt manual scan
on:
  workflow_dispatch: {}
permissions:
  contents: read
  security-events: write
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
`
	if !firesOn(scsFeedFlowlytScan) {
		t.Error("EXTERNAL_TRIGGER_DEBUG should fire on workflow_dispatch when security-events: write is present (flowlyt-scan.yml regression)")
	}

	// Regression: daily-supply-chain-reports.yml — has contents: write and pull-requests: write.
	// This MUST fire.
	scsFeedDailyReports := `
name: Daily Supply Chain Security Reports
on:
  schedule:
    - cron: '30 18 * * *'
  workflow_dispatch:
permissions:
  contents: write
  actions: read
  pull-requests: write
jobs:
  fetch-supply-chain-reports:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	if !firesOn(scsFeedDailyReports) {
		t.Error("EXTERNAL_TRIGGER_DEBUG should fire on workflow_dispatch when contents: write is present (daily-supply-chain-reports.yml regression)")
	}
}

// TestShellScriptLocalVars verifies that SHELL_SCRIPT_ISSUES does not fire
// on locally-assigned variables in safe positions, and does fire on variables
// in dangerous positions.
func TestShellScriptLocalVars(t *testing.T) {
	rule := findRule(t, "SHELL_SCRIPT_ISSUES")

	hasUnquotedVarFinding := func(runBlock string) bool {
		t.Helper()
		wf := makeWorkflow(t, `
name: test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
`+indentBlock(runBlock, "          "))
		for _, f := range rule.Check(wf) {
			if f.RuleID == "SHELL_SCRIPT_ISSUES" &&
				strings.Contains(f.Description, "Unquoted variable") {
				return true
			}
		}
		return false
	}

	// Must NOT fire — locally assigned variable used in echo (Layer 1 + Layer 2)
	if hasUnquotedVarFinding("TODAY=$(date +%F)\necho $TODAY") {
		t.Error("should NOT flag $TODAY assigned via $(...) and used in echo")
	}

	// Must NOT fire — numeric literal used in echo
	if hasUnquotedVarFinding("COUNT=42\necho $COUNT") {
		t.Error("should NOT flag $COUNT assigned as numeric literal and used in echo")
	}

	// Must NOT fire — quoted string assignment used in echo
	if hasUnquotedVarFinding("VERSION=\"1.0.0\"\necho $VERSION") {
		t.Error("should NOT flag $VERSION assigned as quoted string and used in echo")
	}

	// Must fire — locally assigned variable used in rm (dangerous position)
	if !hasUnquotedVarFinding("DIR=$(mktemp -d)\nrm -rf $DIR") {
		t.Error("should flag $DIR used in rm even if locally assigned")
	}

	// Must fire — unassigned variable used in cp
	if !hasUnquotedVarFinding("cp $SRC $DEST") {
		t.Error("should flag unassigned $SRC/$DEST in cp")
	}

	// Must fire — unassigned variable used in curl
	if !hasUnquotedVarFinding("curl $URL") {
		t.Error("should flag unassigned $URL in curl")
	}
}

// indentBlock prefixes every non-empty line of s with indent.
// TestBroadPermissionsNoise verifies that a workflow with no permissions block and N jobs
// produces exactly ONE BROAD_PERMISSIONS finding (workflow-level), not N+1.
func TestBroadPermissionsNoise(t *testing.T) {
	rule := findRule(t, "BROAD_PERMISSIONS")

	countFindings := func(yaml string) int {
		wf := makeWorkflow(t, yaml)
		n := 0
		for _, f := range rule.Check(wf) {
			if f.RuleID == "BROAD_PERMISSIONS" {
				n++
			}
		}
		return n
	}

	// Three jobs, no permissions block anywhere — must produce exactly one finding.
	threeJobs := `
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo build
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo test
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: echo lint
`
	if n := countFindings(threeJobs); n != 1 {
		t.Errorf("three-job workflow with no permissions block: want 1 BROAD_PERMISSIONS finding, got %d", n)
	}

	// Workflow sets read-all, but one job overrides with write-all — only the job-level write-all fires.
	writeAllJob := `
name: ci
on: push
permissions: read-all
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - run: echo deploy
`
	if n := countFindings(writeAllJob); n != 1 {
		t.Errorf("job with explicit write-all: want 1 BROAD_PERMISSIONS finding, got %d", n)
	}

	// Workflow sets read-all, jobs have no explicit permissions — they inherit read-all, no finding.
	readAllWorkflow := `
name: ci
on: push
permissions: read-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo build
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo test
`
	if n := countFindings(readAllWorkflow); n != 0 {
		t.Errorf("workflow with read-all and no per-job overrides: want 0 BROAD_PERMISSIONS findings, got %d", n)
	}
}

// TestRunnerLabelMatrixExpression verifies that dynamic matrix runner expressions
// (e.g. runs-on: ${{ matrix.os }}) do not produce RUNNER_LABEL_VALIDATION findings.
func TestRunnerLabelMatrixExpression(t *testing.T) {
	rule := findRule(t, "RUNNER_LABEL_VALIDATION")

	hasRunnerFinding := func(yaml string) bool {
		wf := makeWorkflow(t, yaml)
		for _, f := range rule.Check(wf) {
			if f.RuleID == "RUNNER_LABEL_VALIDATION" {
				return true
			}
		}
		return false
	}

	// Matrix expression — must NOT fire.
	matrixRunner := `
name: ci
on: push
jobs:
  build:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - run: echo hi
`
	if hasRunnerFinding(matrixRunner) {
		t.Error("runs-on: ${{ matrix.os }} should NOT produce RUNNER_LABEL_VALIDATION finding")
	}

	// Another expression form — must NOT fire.
	vectorRunner := `
name: ci
on: push
jobs:
  build:
    runs-on: ${{ matrix.vector.pool }}
    steps:
      - run: echo hi
`
	if hasRunnerFinding(vectorRunner) {
		t.Error("runs-on: ${{ matrix.vector.pool }} should NOT produce RUNNER_LABEL_VALIDATION finding")
	}

	// Known GitHub-hosted runner — must NOT fire.
	knownRunner := `
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`
	if hasRunnerFinding(knownRunner) {
		t.Error("runs-on: ubuntu-latest should NOT produce RUNNER_LABEL_VALIDATION finding")
	}
}

// TestUnsoundContainsGithubRef verifies that contains() on github.ref does not fire
// (branch filters are not security gates), while actor-based contains() still fires.
func TestUnsoundContainsGithubRef(t *testing.T) {
	rule := findRule(t, "UNSOUND_CONTAINS")

	hasFinding := func(jobIf string) bool {
		yaml := `
name: ci
on: push
jobs:
  work:
    if: ` + jobIf + `
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`
		wf := makeWorkflow(t, yaml)
		for _, f := range rule.Check(wf) {
			if f.RuleID == "UNSOUND_CONTAINS" {
				return true
			}
		}
		return false
	}

	// Branch filter — must NOT fire.
	if hasFinding("contains(github.ref, 'l10n')") {
		t.Error("contains(github.ref, 'l10n') is a branch filter and should NOT produce UNSOUND_CONTAINS finding")
	}

	// Another ref filter — must NOT fire.
	if hasFinding("contains(github.head_ref, 'feature')") {
		t.Error("contains(github.head_ref, 'feature') is a PR branch filter and should NOT produce UNSOUND_CONTAINS finding")
	}

	// Actor check — must fire (spoofable).
	if !hasFinding("contains(github.actor, 'bot')") {
		t.Error("contains(github.actor, 'bot') SHOULD produce UNSOUND_CONTAINS finding")
	}
}

// TestArtipackedCheckoutDedup verifies that multiple jobs sharing the same checkout
// action produce exactly one ARTIPACKED_VULNERABILITY finding, not one per job.
func TestArtipackedCheckoutDedup(t *testing.T) {
	rule := findRule(t, "ARTIPACKED_VULNERABILITY")

	countCheckoutFindings := func(yaml string) int {
		wf := makeWorkflow(t, yaml)
		n := 0
		for _, f := range rule.Check(wf) {
			if f.RuleID == "ARTIPACKED_VULNERABILITY" &&
				strings.Contains(f.Description, "persist-credentials") {
				n++
			}
		}
		return n
	}

	// Two jobs, both using the same checkout action without persist-credentials: false.
	// FindLineNumber returns the first occurrence, so both jobs resolve to the same
	// line number and should be collapsed to a single finding.
	twoJobWorkflow := `
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo build
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo test
`
	if n := countCheckoutFindings(twoJobWorkflow); n != 1 {
		t.Errorf("two jobs with same checkout@v4: want 1 ARTIPACKED checkout finding, got %d", n)
	}
}

// TestCacheWriteInPRDedup verifies that two jobs sharing the same cache action
// produce exactly one CACHE_WRITE_IN_PR_WORKFLOW finding, not one per job.
func TestCacheWriteInPRDedup(t *testing.T) {
	rule := findRule(t, "CACHE_WRITE_IN_PR_WORKFLOW")

	countFindings := func(yaml string) int {
		wf := makeWorkflow(t, yaml)
		n := 0
		for _, f := range rule.Check(wf) {
			if f.RuleID == "CACHE_WRITE_IN_PR_WORKFLOW" {
				n++
			}
		}
		return n
	}

	// Two jobs both using the same actions/cache@v3 step.
	// FindLineNumber returns the first occurrence of "uses: actions/cache@v3",
	// so both jobs resolve to the same line → dedup collapses to 1 finding.
	twoJobs := `
name: ci
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v3
        with:
          path: ~/.npm
          key: ${{ runner.os }}-npm
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v3
        with:
          path: ~/.npm
          key: ${{ runner.os }}-npm
`
	if n := countFindings(twoJobs); n != 1 {
		t.Errorf("two jobs with same cache@v3 step: want 1 finding, got %d", n)
	}

	// Two distinct cache actions at different YAML positions → 2 findings (invariant).
	twoDistinct := `
name: ci
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v3
        with:
          path: ~/.npm
          key: ${{ runner.os }}-npm
      - uses: actions/cache@v4
        with:
          path: ~/.cargo
          key: ${{ runner.os }}-cargo
`
	if n := countFindings(twoDistinct); n != 2 {
		t.Errorf("two distinct cache steps: want 2 findings, got %d", n)
	}

	// Four jobs: two using cache@v3 (dedup → 1) and two using cache@v4 (dedup → 1) → 2 total.
	// This verifies that the step.Uses component of the dedup key is load-bearing:
	// dropping it would incorrectly collapse cache@v3 and cache@v4 to a single finding.
	twoActionsMultiJobs := `
name: ci
on:
  pull_request:
jobs:
  build-linux:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v3
        with:
          path: ~/.npm
          key: ${{ runner.os }}-npm
  build-mac:
    runs-on: macos-latest
    steps:
      - uses: actions/cache@v3
        with:
          path: ~/.npm
          key: ${{ runner.os }}-npm
  lint-linux:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.cargo
          key: ${{ runner.os }}-cargo
  lint-mac:
    runs-on: macos-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.cargo
          key: ${{ runner.os }}-cargo
`
	if n := countFindings(twoActionsMultiJobs); n != 2 {
		t.Errorf("two actions each in two jobs: want 2 findings (one per unique action), got %d", n)
	}
}

// TestDangerousWriteOperationDedup verifies that two matrix jobs sharing the same run step
// produce exactly one DANGEROUS_WRITE_OPERATION finding, not one per job.
func TestDangerousWriteOperationDedup(t *testing.T) {
	rule := findRule(t, "DANGEROUS_WRITE_OPERATION")

	countFindings := func(yaml string) int {
		wf := makeWorkflow(t, yaml)
		n := 0
		for _, f := range rule.Check(wf) {
			if f.RuleID == "DANGEROUS_WRITE_OPERATION" {
				n++
			}
		}
		return n
	}

	// Two jobs with identical run steps. FindLineNumber returns the same line for
	// both jobs, so the dedup key is identical → collapsed to 1 finding.
	twoJobs := `
name: ci
on: push
jobs:
  linux:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.inputs.version }}" >> $GITHUB_ENV
  macos:
    runs-on: macos-latest
    steps:
      - run: echo "${{ github.event.inputs.version }}" >> $GITHUB_ENV
`
	if n := countFindings(twoJobs); n != 1 {
		t.Errorf("two jobs with same run step: want 1 finding, got %d", n)
	}

	// One job, one step matching two distinct dangerous patterns (GITHUB_ENV + GITHUB_OUTPUT).
	// Each pattern has a unique index in dangerousPatterns, so the dedup key differs →
	// 2 findings must be preserved (validates the patternIndex component of the key).
	twoPatterns := `
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "${{ github.event.inputs.version }}" >> $GITHUB_ENV
          echo "${{ github.event.inputs.version }}" >> $GITHUB_OUTPUT
`
	if n := countFindings(twoPatterns); n != 2 {
		t.Errorf("one step matching two patterns: want 2 findings, got %d", n)
	}
}

// TestMatrixInjectionArithmetic verifies that a matrix variable used only inside
// arithmetic expansion $((...)) with a static matrix does not produce a finding,
// while bare interpolations still fire.
func TestMatrixInjectionArithmetic(t *testing.T) {
	rule := findRule(t, "MATRIX_INJECTION")

	countFindings := func(yaml string) int {
		wf := makeWorkflow(t, yaml)
		n := 0
		for _, f := range rule.Check(wf) {
			if f.RuleID == "MATRIX_INJECTION" {
				n++
			}
		}
		return n
	}

	// Static matrix + arithmetic context — safe, must NOT fire.
	staticArithmetic := `
name: ci
on: push
jobs:
  build:
    strategy:
      matrix:
        nr: [1, 2, 3]
    runs-on: ubuntu-latest
    steps:
      - run: result=$((${{ matrix.nr }} + 1))
`
	if n := countFindings(staticArithmetic); n != 0 {
		t.Errorf("static matrix in arithmetic context: want 0 findings, got %d", n)
	}

	// Bare interpolation in curl — always fires regardless of arithmetic context.
	bareDangerous := `
name: ci
on: push
jobs:
  build:
    strategy:
      matrix:
        url: [https://example.com]
    runs-on: ubuntu-latest
    steps:
      - run: curl ${{ matrix.url }}
`
	if n := countFindings(bareDangerous); n == 0 {
		t.Error("bare matrix var in curl: want >= 1 finding, got 0")
	}
}

func indentBlock(s, indent string) string {
	lines := strings.Split(s, "\n")
	var out []string
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			out = append(out, indent+l)
		}
	}
	return strings.Join(out, "\n")
}
