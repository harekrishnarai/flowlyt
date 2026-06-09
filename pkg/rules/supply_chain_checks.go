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

package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/github"
	"github.com/harekrishnarai/flowlyt/pkg/linenum"
	"github.com/harekrishnarai/flowlyt/pkg/parser"
)

// checkUnpinnedAction checks for GitHub Actions without pinned versions
func checkUnpinnedAction(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	content := string(workflow.Content)
	lines := strings.Split(content, "\n")

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Uses == "" {
				continue
			}

			// Skip if it's a local action (starts with ./ or ../)
			if strings.HasPrefix(step.Uses, "./") || strings.HasPrefix(step.Uses, "../") {
				continue
			}

			// Extract action owner to check if it's an internal action
			actionParts := strings.Split(step.Uses, "@")
			actionName := actionParts[0]
			actionOwner := ""
			if strings.Contains(actionName, "/") {
				parts := strings.Split(actionName, "/")
				if len(parts) >= 2 {
					actionOwner = parts[0]
				}
			}

			// Skip internal organization actions - they're trusted and don't need SHA pinning
			if workflow.RepositoryOwner != "" && actionOwner != "" && actionOwner == workflow.RepositoryOwner {
				continue
			}

			// Allow trusted semantic version pins for well-known publishers
			if isTrustedSemverReference(step.Uses) {
				continue
			}

			// Check if the action is pinned with a commit SHA (40 hex characters)
			shaPattern := regexp.MustCompile(`@[a-f0-9]{40}$`)
			if !shaPattern.MatchString(step.Uses) {
				// Find the line number by searching for the uses statement
				lineNumber := 1
				searchPattern := "uses: " + step.Uses

				for i, line := range lines {
					if strings.Contains(line, searchPattern) {
						lineNumber = i + 1
						break
					}
				}

				// Determine the type of reference being used
				evidenceType := "unpinned reference"
				if strings.Contains(step.Uses, "@v") {
					evidenceType = "version tag (not SHA)"
				} else if strings.Contains(step.Uses, "@main") || strings.Contains(step.Uses, "@master") {
					evidenceType = "branch reference"
				}

				findings = append(findings, Finding{
					RuleID:      "UNPINNED_ACTION",
					RuleName:    "Unpinned GitHub Action",
					Description: "GitHub Action is not pinned to a specific SHA commit, which may lead to supply chain attacks",
					Severity:    Medium,
					Category:    Misconfiguration,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    step.Name,
					Evidence:    fmt.Sprintf("uses: %s (%s)", step.Uses, evidenceType),
					LineNumber:  lineNumber,
					Remediation: "Pin the action to a full 40-character commit SHA instead of a version tag or branch reference. Example: uses: actions/checkout@a12a3943b4bdde767164f792f33f40b04645d846",
				})
			}
		}
	}

	return findings
}

// checkLocalActionUsage checks for usage of local actions which may pose security risks
func checkLocalActionUsage(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Uses == "" {
				continue
			}

			// Check for local action patterns (relative paths)
			if strings.HasPrefix(step.Uses, "./") || strings.HasPrefix(step.Uses, "../") ||
				(!strings.Contains(step.Uses, "/") && !strings.Contains(step.Uses, "@")) {

				// For test workflows or workflows that explicitly test the action itself,
				// reduce severity as it's expected behavior
				severity := Medium
				description := "Usage of local actions may pose security risks as they are not version-controlled externally"

				if strings.Contains(workflow.Path, "test") || strings.Contains(workflow.Path, "action") {
					severity = Low
					description = "Local action usage in test workflow - ensure proper validation"
				}

				lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
					Key:   "uses",
					Value: step.Uses,
				})

				lineNumber := 0
				if lineResult != nil {
					lineNumber = lineResult.LineNumber
				}

				findings = append(findings, Finding{
					RuleID:      "LOCAL_ACTION_USAGE",
					RuleName:    "Local Action Usage",
					Description: description,
					Severity:    severity,
					Category:    Misconfiguration,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    step.Name,
					Evidence:    fmt.Sprintf("uses: %s", step.Uses),
					LineNumber:  lineNumber,
					Remediation: "Consider using versioned actions from GitHub Marketplace or pin local actions to specific commits",
				})
			}
		}
	}

	return findings
}

// checkRepoJacking verifies external actions point to valid repositories
func checkRepoJacking(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Pattern to match action references
	actionPattern := regexp.MustCompile(`^([^/]+)/([^@]+)@(.+)$`)

	// Known trusted organizations
	trustedOrgs := map[string]bool{
		"actions":     true,
		"github":      true,
		"microsoft":   true,
		"azure":       true,
		"docker":      true,
		"aws-actions": true,
	}

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Uses != "" {
				matches := actionPattern.FindStringSubmatch(step.Uses)
				if len(matches) == 4 {
					org := matches[1]
					repo := matches[2]
					ref := matches[3]

					// Check if action is from the same organization as the repository
					// If it is, consider it internal and trusted - skip repo-jacking check
					if workflow.RepositoryOwner != "" && org == workflow.RepositoryOwner {
						continue
					}

					// Check for potential repo-jacking indicators
					suspiciousPatterns := []*regexp.Regexp{
						regexp.MustCompile(`^\d+$`),                   // Numeric usernames
						regexp.MustCompile(`^[a-zA-Z]+\d+$`),          // Username with trailing numbers
						regexp.MustCompile(`(?i)(test|demo|example)`), // Test/demo repos
						regexp.MustCompile(`^.{1,2}$`),                // Very short usernames
					}

					var isSuspicious bool
					var suspiciousReason string

					// Check if organization is trusted
					if !trustedOrgs[org] {
						// Check for suspicious patterns
						for _, pattern := range suspiciousPatterns {
							if pattern.MatchString(org) {
								isSuspicious = true
								suspiciousReason = fmt.Sprintf("Suspicious organization name pattern: %s", org)
								break
							}
							if pattern.MatchString(repo) {
								isSuspicious = true
								suspiciousReason = fmt.Sprintf("Suspicious repository name pattern: %s", repo)
								break
							}
						}

						// Check for unpinned references to untrusted sources
						if ref == "main" || ref == "master" || regexp.MustCompile(`^v\d+$`).MatchString(ref) {
							isSuspicious = true
							suspiciousReason = fmt.Sprintf("Unpinned reference to untrusted source: %s@%s", org, ref)
						}
					}

					if isSuspicious {
						lineResult := lineMapper.FindLineNumber(linenum.FindPattern{
							Key:   "uses",
							Value: step.Uses,
						})

						lineNumber := 0
						if lineResult != nil {
							lineNumber = lineResult.LineNumber
						}

						findings = append(findings, Finding{
							RuleID:      "REPO_JACKING_VULNERABILITY",
							RuleName:    "Repository Jacking Vulnerability",
							Description: suspiciousReason,
							Severity:    High,
							Category:    SupplyChain,
							FilePath:    workflow.Path,
							JobName:     jobName,
							StepName:    step.Name,
							Evidence:    step.Uses,
							LineNumber:  lineNumber,
							Remediation: "Verify the action source is legitimate and pin to specific SHA for security",
						})
					}
				}
			}
		}
	}

	return findings
}

// isMutableRef returns true if ref is a mutable git reference that poses
// a real supply-chain attack surface (branch names, bare non-semver tags).
// Returns false for stable semver tags (v1, v1.2, v1.2.3) and full SHAs.
//
// Severity guidance for callers:
//   - main / master → High (default branches, highest-value targets)
//   - develop / trunk / latest + bare branch-style names → Medium
func isMutableRef(ref string) bool {
	// Full 40-char hex SHAs are immutable and safe — not a mutable ref.
	if len(ref) == 40 {
		allHex := true
		for _, c := range ref {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				allHex = false
				break
			}
		}
		if allHex {
			return false
		}
	}

	// Stable semver tags: start with 'v' followed immediately by a digit.
	// Covers @v1, @v1.2, @v1.2.3, @v10.0.1 — all stable release markers.
	if len(ref) >= 2 && ref[0] == 'v' && ref[1] >= '0' && ref[1] <= '9' {
		return false
	}

	// Known mutable branch names (exact match).
	switch ref {
	case "main", "master", "develop", "trunk", "latest":
		return true
	}

	// Any other ref with no dots and no leading 'v' is a bare branch-style name.
	return !strings.Contains(ref, ".")
}

// checkRefConfusion detects git reference confusion vulnerabilities
func checkRefConfusion(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			if step.Uses == "" && step.Run == "" {
				continue
			}

			stepName := step.Name
			if stepName == "" {
				stepName = fmt.Sprintf("Step %d", stepIdx+1)
			}

			// Check for actions using ambiguous refs
			if step.Uses != "" {
				actionParts := strings.Split(step.Uses, "@")
				if len(actionParts) > 1 {
					ref := actionParts[1]

					// Extract action owner to check if it's an internal action
					actionName := actionParts[0]
					actionOwner := ""
					if strings.Contains(actionName, "/") {
						parts := strings.Split(actionName, "/")
						if len(parts) >= 2 {
							actionOwner = parts[0]
						}
					}

					// Skip internal organization actions - they're trusted and using @main is acceptable
					if workflow.RepositoryOwner != "" && actionOwner != "" && actionOwner == workflow.RepositoryOwner {
						continue
					}

					// Check for potentially confusing refs — only mutable branch-style
					// refs pose a supply-chain risk; semver tags are stable.
					if isMutableRef(ref) {

						pattern := linenum.FindPattern{
							Key:   "uses",
							Value: step.Uses,
						}
						lineResult := lineMapper.FindLineNumber(pattern)
						lineNumber := 0
						if lineResult != nil {
							lineNumber = lineResult.LineNumber
						}

						severity := Medium
						if ref == "master" || ref == "main" {
							severity = High
						}

						findings = append(findings, Finding{
							RuleID:      "REF_CONFUSION",
							RuleName:    "Git Reference Confusion",
							Description: "Action uses ambiguous git reference that could be subject to confusion attacks",
							Severity:    severity,
							Category:    SupplyChain,
							FilePath:    workflow.Path,
							JobName:     jobName,
							StepName:    stepName,
							Evidence:    step.Uses,
							Remediation: "Pin actions to specific commit SHA instead of branch or tag names",
							LineNumber:  lineNumber,
						})
					}
				}
			}

			// Check for git commands with potentially confusing refs in run steps
			if step.Run != "" && strings.Contains(step.Run, "git") {
				gitRefPatterns := []string{
					`git\s+checkout\s+(master|main|develop)`,
					`git\s+pull\s+origin\s+(master|main)`,
					`git\s+fetch\s+.*\s+(master|main)`,
				}

				for _, pattern := range gitRefPatterns {
					re := regexp.MustCompile(`(?i)` + pattern)
					if re.MatchString(step.Run) {
						linePattern := linenum.FindPattern{
							Key:   "run",
							Value: step.Run,
						}
						lineResult := lineMapper.FindLineNumber(linePattern)
						lineNumber := 0
						if lineResult != nil {
							lineNumber = lineResult.LineNumber
						}

						findings = append(findings, Finding{
							RuleID:      "REF_CONFUSION",
							RuleName:    "Git Reference Confusion",
							Description: "Git command uses ambiguous branch reference",
							Severity:    Medium,
							Category:    SupplyChain,
							FilePath:    workflow.Path,
							JobName:     jobName,
							StepName:    stepName,
							Evidence:    step.Run,
							Remediation: "Use specific commit SHAs instead of branch names",
							LineNumber:  lineNumber,
						})
					}
				}
			}
		}
	}

	return findings
}

// checkImpostorCommit detects commits that may be impersonating legitimate authors
func checkImpostorCommit(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			stepName := step.Name
			if stepName == "" {
				stepName = fmt.Sprintf("Step %d", stepIdx+1)
			}

			// Check for git config commands that might impersonate others
			gitConfigPatterns := []string{
				`git\s+config\s+.*user\.name.*github-actions`,
				`git\s+config\s+.*user\.email.*github-actions`,
				`git\s+config\s+.*user\.name.*dependabot`,
				`git\s+config\s+.*user\.email.*dependabot`,
				`git\s+config\s+.*user\.name.*\$\{`,  // Variable-based user names
				`git\s+config\s+.*user\.email.*\$\{`, // Variable-based emails
			}

			for _, pattern := range gitConfigPatterns {
				re := regexp.MustCompile(`(?i)` + pattern)
				if re.MatchString(step.Run) {
					linePattern := linenum.FindPattern{
						Key:   "run",
						Value: step.Run,
					}
					lineResult := lineMapper.FindLineNumber(linePattern)
					lineNumber := 0
					if lineResult != nil {
						lineNumber = lineResult.LineNumber
					}

					severity := High
					if strings.Contains(step.Run, "${") {
						severity = Critical // Variable-based identity is more dangerous
					} else {
						// Known official GitHub service bots are legitimate automation.
						// Still emit the finding but at LOW so it can be triaged separately.
						runLower := strings.ToLower(step.Run)
						if knownBotRe.MatchString(runLower) {
							severity = Low
						}
					}

					findings = append(findings, Finding{
						RuleID:      "IMPOSTOR_COMMIT",
						RuleName:    "Impostor Commit Detection",
						Description: "Git configuration may impersonate legitimate authors or services",
						Severity:    severity,
						Category:    SupplyChain,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    stepName,
						Evidence:    step.Run,
						Remediation: "Use official actions for git operations or verify committer identity",
						LineNumber:  lineNumber,
					})
				}
			}
		}
	}

	return findings
}

// checkStaleActionRefs detects actions referenced by outdated or non-existent versions
func checkStaleActionRefs(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Create GitHub client for API calls
	ghClient := github.NewClient()

	// Deduplicate: same action@version at the same line can appear across multiple job contexts
	// (e.g. matrix jobs sharing one step definition) — emit at most one finding per unique key.
	seen := make(map[string]bool)

	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			if step.Uses == "" {
				continue
			}

			stepName := step.Name
			if stepName == "" {
				stepName = fmt.Sprintf("Step %d", stepIdx+1)
			}

			actionParts := strings.Split(step.Uses, "@")
			if len(actionParts) != 2 {
				continue
			}

			actionName := actionParts[0]
			currentVersion := actionParts[1]

			// Skip local actions (e.g., ./.github/actions/my-action)
			if strings.HasPrefix(actionName, "./") || strings.HasPrefix(actionName, "../") {
				continue
			}

			// Parse owner/repo from action name
			ownerRepoParts := strings.Split(actionName, "/")
			if len(ownerRepoParts) < 2 {
				continue
			}
			owner := ownerRepoParts[0]
			repo := ownerRepoParts[1]

			// Skip if version is a SHA (40 character hex string)
			if len(currentVersion) == 40 && isHexString(currentVersion) {
				continue
			}

			// Fetch latest release from GitHub API
			latestVersion, publishedAt, err := ghClient.GetLatestRelease(owner, repo)
			if err != nil {
				// Skip if we can't fetch latest release (private repos, rate limits, etc.)
				continue
			}

			// Compare versions - flag if current is significantly outdated
			isOutdated, severity := compareVersions(currentVersion, latestVersion, publishedAt)
			if isOutdated {
				pattern := linenum.FindPattern{
					Key:   "uses",
					Value: step.Uses,
				}
				lineResult := lineMapper.FindLineNumber(pattern)
				lineNumber := 0
				if lineResult != nil {
					lineNumber = lineResult.LineNumber
				}

				// Deduplicate: matrix jobs share step definitions at the same line.
				dedupKey := fmt.Sprintf("%s:%d", step.Uses, lineNumber)
				if seen[dedupKey] {
					continue
				}
				seen[dedupKey] = true

				findings = append(findings, Finding{
					RuleID:      "STALE_ACTION_REFS",
					RuleName:    "Stale Action References",
					Description: fmt.Sprintf("Action uses outdated version %s (latest: %s)", currentVersion, latestVersion),
					Severity:    severity,
					Category:    SupplyChain,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    stepName,
					Evidence:    step.Uses,
					Remediation: fmt.Sprintf("Update %s to %s", actionName, latestVersion),
					LineNumber:  lineNumber,
				})
			}
		}
	}

	return findings
}

// checkUseTrustedPublishing detects PyPI publishing without trusted publishing
func checkUseTrustedPublishing(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			stepName := step.Name
			if stepName == "" {
				stepName = fmt.Sprintf("Step %d", stepIdx+1)
			}

			// Check for PyPI publishing actions
			if step.Uses != "" && (strings.Contains(step.Uses, "pypi") ||
				strings.Contains(step.Uses, "twine") ||
				strings.Contains(step.Uses, "pypa/gh-action-pypi-publish")) {

				usingOIDC := false
				hasCredentials := false

				// Check for OIDC token usage
				if step.With != nil {
					for key, value := range step.With {
						keyLower := strings.ToLower(key)
						valueStr := fmt.Sprintf("%v", value)

						if keyLower == "password" || keyLower == "token" {
							hasCredentials = true
						}
						if keyLower == "use-trusted-publishing" ||
							strings.Contains(valueStr, "id-token") {
							usingOIDC = true
						}
					}
				}

				// Check job permissions for id-token
				if job.Permissions != nil {
					if permMap, ok := job.Permissions.(map[string]interface{}); ok {
						if idToken, exists := permMap["id-token"]; exists {
							if idTokenStr, ok := idToken.(string); ok && idTokenStr == "write" {
								usingOIDC = true
							}
						}
					}
				}

				// Flag if using credentials without OIDC
				if hasCredentials && !usingOIDC {
					pattern := linenum.FindPattern{
						Key:   "uses",
						Value: step.Uses,
					}
					lineResult := lineMapper.FindLineNumber(pattern)
					lineNumber := 0
					if lineResult != nil {
						lineNumber = lineResult.LineNumber
					}

					findings = append(findings, Finding{
						RuleID:      "USE_TRUSTED_PUBLISHING",
						RuleName:    "Missing Trusted Publishing",
						Description: "PyPI publishing uses credentials instead of OIDC trusted publishing",
						Severity:    Medium,
						Category:    SupplyChain,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    stepName,
						Evidence:    step.Uses,
						Remediation: "Configure OIDC trusted publishing instead of using API tokens",
						LineNumber:  lineNumber,
					})
				}
			}

			// Check for manual twine upload in run commands
			if step.Run != "" && strings.Contains(step.Run, "twine upload") {
				if !strings.Contains(step.Run, "--trusted-publishing") {
					pattern := linenum.FindPattern{
						Key:   "run",
						Value: step.Run,
					}
					lineResult := lineMapper.FindLineNumber(pattern)
					lineNumber := 0
					if lineResult != nil {
						lineNumber = lineResult.LineNumber
					}

					findings = append(findings, Finding{
						RuleID:      "USE_TRUSTED_PUBLISHING",
						RuleName:    "Missing Trusted Publishing",
						Description: "Manual twine upload without trusted publishing configuration",
						Severity:    Medium,
						Category:    SupplyChain,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    stepName,
						Evidence:    step.Run,
						Remediation: "Use trusted publishing with --trusted-publishing flag",
						LineNumber:  lineNumber,
					})
				}
			}
		}
	}

	return findings
}

// checkArtipackedVulnerability detects vulnerabilities in artifact processes
// jobUploadsGitDir reports whether a job uploads an artifact whose path can
// include the repository root (and therefore the .git directory, where
// actions/checkout persists its access token). Narrow, specific paths such as
// "dist/" or "coverage.out" do not include .git and are not considered risky.
func jobUploadsGitDir(job parser.Job) bool {
	for _, step := range job.Steps {
		if step.Uses == "" || !strings.Contains(step.Uses, "upload-artifact") {
			continue
		}
		if step.With == nil {
			continue
		}
		p, ok := step.With["path"]
		if !ok {
			continue
		}
		path := strings.TrimSpace(fmt.Sprintf("%v", p))
		switch path {
		case ".", "./", "", "**", "**/*", "${{ github.workspace }}":
			return true
		}
		if strings.Contains(path, "github.workspace") {
			return true
		}
	}
	return false
}

func checkArtipackedVulnerability(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Deduplicate checkout findings: same uses: line appears in every matrix-expanded job context.
	seenCheckout := make(map[string]bool)

	for jobName, job := range workflow.Workflow.Jobs {
		// The credentials that actions/checkout persists into .git/config only
		// leak if this job also uploads an artifact that can include the .git
		// directory. Compute that once per job so the checkout finding can be
		// gated to HIGH only when the exposure is real (the actual ArtiPACKED
		// vulnerability), and reported as a LOW hardening note otherwise.
		jobUploadsGit := jobUploadsGitDir(job)

		for stepIdx, step := range job.Steps {
			stepName := step.Name
			if stepName == "" {
				stepName = fmt.Sprintf("Step %d", stepIdx+1)
			}

			// Check for actions/checkout without persist-credentials: false
			// This is critical for preventing credential persistence in artifacts
			if step.Uses != "" && strings.Contains(step.Uses, "checkout") {
				hasPersistCredentials := false
				persistCredentialsValue := ""

				if step.With != nil {
					if pc, exists := step.With["persist-credentials"]; exists {
						hasPersistCredentials = true
						persistCredentialsValue = fmt.Sprintf("%v", pc)
					}
				}

				// Flag if persist-credentials is not explicitly set to false
				if !hasPersistCredentials || persistCredentialsValue != "false" {
					pattern := linenum.FindPattern{
						Key:   "uses",
						Value: step.Uses,
					}
					lineResult := lineMapper.FindLineNumber(pattern)
					lineNumber := 0
					if lineResult != nil {
						lineNumber = lineResult.LineNumber
					}

					// Deduplicate: same checkout step fires once per matrix job variant.
					// Safe to `continue` here: checkout and upload/download-artifact checks are
					// mutually exclusive on step.Uses, so this cannot suppress artifact findings.
					checkoutKey := fmt.Sprintf("%s:%d", step.Uses, lineNumber)
					if seenCheckout[checkoutKey] {
						continue
					}
					seenCheckout[checkoutKey] = true

					// Default persist-credentials behaviour is only HIGH-risk when
					// this job uploads an artifact that may include .git (where
					// the token is stored). Otherwise it is a LOW hardening note,
					// so we don't flag every checkout in the world at HIGH.
					severity := Low
					description := "actions/checkout does not set persist-credentials: false (hardening recommendation; no risky artifact upload detected in this job)"
					if !hasPersistCredentials {
						description = "actions/checkout missing persist-credentials: false (hardening recommendation; no risky artifact upload detected in this job)"
					}
					if jobUploadsGit {
						severity = High
						description = "actions/checkout persists credentials and this job uploads an artifact that may include the .git directory, which can leak the access token (ArtiPACKED)"
					}

					findings = append(findings, Finding{
						RuleID:      "ARTIPACKED_VULNERABILITY",
						RuleName:    "Credential Persistence Risk",
						Description: description,
						Severity:    severity,
						Category:    SecretsExposure,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    stepName,
						Evidence:    fmt.Sprintf("uses: %s (persist-credentials: %s)", step.Uses, persistCredentialsValue),
						Remediation: "Add 'persist-credentials: false' to actions/checkout to prevent credential persistence in artifacts",
						LineNumber:  lineNumber,
					})
				}
			}

			// Check for artifact upload/download actions
			if step.Uses != "" && (strings.Contains(step.Uses, "upload-artifact") ||
				strings.Contains(step.Uses, "download-artifact")) {

				if step.With != nil {
					// Check for overly broad path patterns
					if path, exists := step.With["path"]; exists {
						pathStr := fmt.Sprintf("%v", path)

						// Dangerous patterns
						if pathStr == "." || pathStr == "/*" || pathStr == "**" ||
							strings.Contains(pathStr, "../") ||
							strings.Contains(pathStr, "~") {

							pattern := linenum.FindPattern{
								Key:   "path",
								Value: pathStr,
							}
							lineResult := lineMapper.FindLineNumber(pattern)
							lineNumber := 0
							if lineResult != nil {
								lineNumber = lineResult.LineNumber
							}

							severity := Medium
							if strings.Contains(pathStr, "../") {
								severity = High // Path traversal is more dangerous
							}

							findings = append(findings, Finding{
								RuleID:      "ARTIPACKED_VULNERABILITY",
								RuleName:    "Artifact Packing Vulnerability",
								Description: "Artifact path pattern may include sensitive files or enable path traversal",
								Severity:    severity,
								Category:    SupplyChain,
								FilePath:    workflow.Path,
								JobName:     jobName,
								StepName:    stepName,
								Evidence:    fmt.Sprintf("path: %s", pathStr),
								Remediation: "Use specific file paths instead of wildcards for artifact upload",
								LineNumber:  lineNumber,
							})
						}
					}

					// Check for missing retention policies
					if strings.Contains(step.Uses, "upload-artifact") {
						if _, hasRetention := step.With["retention-days"]; !hasRetention {
							pattern := linenum.FindPattern{
								Key:   "uses",
								Value: step.Uses,
							}
							lineResult := lineMapper.FindLineNumber(pattern)
							lineNumber := 0
							if lineResult != nil {
								lineNumber = lineResult.LineNumber
							}

							findings = append(findings, Finding{
								RuleID:      "ARTIPACKED_VULNERABILITY",
								RuleName:    "Artifact Packing Vulnerability",
								Description: "Artifact upload without explicit retention policy may store sensitive data indefinitely",
								Severity:    Low,
								Category:    SupplyChain,
								FilePath:    workflow.Path,
								JobName:     jobName,
								StepName:    stepName,
								Evidence:    step.Uses,
								Remediation: "Set explicit retention-days to limit artifact storage time",
								LineNumber:  lineNumber,
							})
						}
					}
				}
			}
		}
	}

	return findings
}

// Helper functions for complex pattern detection
