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

	"github.com/harekrishnarai/flowlyt/v2/pkg/linenum"
	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
)

// CheckPackageInstallHygiene runs both install-related supply chain checks.
func CheckPackageInstallHygiene(workflow parser.WorkflowFile) []Finding {
	findings := make([]Finding, 0, 2)
	findings = append(findings, checkAdhocPackageInstall(workflow)...)
	findings = append(findings, checkUnpinnedToolInstall(workflow)...)
	return findings
}

// runCommandLine is a single logical shell line taken from a `run:` block,
// carried along with enough context to report a precise finding.
type runCommandLine struct {
	jobName  string
	stepName string
	line     string
	// anchor is the text used to locate the enclosing `run:` block.
	anchor string
}

// collectRunCommandLines flattens every `run:` block in the workflow into
// individual shell command lines.
//
// Line continuations are joined so that a command split across several physical
// lines is analyzed as one unit, and comments are stripped so that commented-out
// examples do not produce findings.
func collectRunCommandLines(workflow parser.WorkflowFile) []runCommandLine {
	var out []runCommandLine

	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			stepName := step.Name
			if stepName == "" {
				stepName = fmt.Sprintf("Step %d", stepIdx+1)
			}
			anchor := firstNonEmptyLine(step.Run)

			for _, line := range splitShellCommands(step.Run) {
				if line == "" {
					continue
				}
				out = append(out, runCommandLine{
					jobName:  jobName,
					stepName: stepName,
					line:     line,
					anchor:   anchor,
				})
			}
		}
	}

	return out
}

// splitShellCommands normalises a `run:` block into individual commands.
//
// Backslash continuations are joined first, then each resulting line is split on
// the shell separators `&&`, `||`, `;` and `|` so that a command buried in a
// chain is still examined.
func splitShellCommands(script string) []string {
	// Join backslash-newline continuations.
	joined := strings.ReplaceAll(script, "\\\n", " ")

	var commands []string
	for _, physical := range strings.Split(joined, "\n") {
		line := stripShellComment(physical)
		if strings.TrimSpace(line) == "" {
			continue
		}

		for _, part := range shellSeparatorPattern.Split(line, -1) {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				commands = append(commands, trimmed)
			}
		}
	}

	return commands
}

// shellSeparatorPattern splits on shell command separators.
var shellSeparatorPattern = regexp.MustCompile(`\s*(?:&&|\|\||[;|])\s*`)

// stripShellComment removes a trailing `#` comment while leaving `#` characters
// that appear inside quotes intact.
func stripShellComment(line string) string {
	var inSingle, inDouble bool

	for i, r := range line {
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if inSingle || inDouble {
				continue
			}
			// Only treat `#` as a comment when it starts a word.
			if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
				return line[:i]
			}
		}
	}

	return line
}

// adhocInstallPattern matches a package-manager install command. The manager and
// the argument list are captured so that arguments can be inspected for actual
// package names.
var adhocInstallPattern = regexp.MustCompile(
	`(?i)^(?:sudo\s+)?(npm|pnpm|yarn|gem|pip|pip3|bundle)\s+(install|i|add)\b(.*)$`,
)

// lockfileFlagPattern matches flags indicating the command is driven by a
// manifest or lockfile rather than by ad-hoc package arguments.
var lockfileFlagPattern = regexp.MustCompile(`(?i)(^|\s)(-r|--requirement|-e|--editable|--frozen-lockfile|--immutable|--no-save)(\s|=|$)`)

// checkAdhocPackageInstall detects `run:` steps that install project
// dependencies ad hoc rather than from a committed lockfile.
//
// An unpinned ad-hoc install resolves to whatever version the registry serves at
// that moment, so a compromised release published minutes earlier is pulled into
// the build automatically. Even a version-pinned ad-hoc install leaves the
// package's own transitive dependencies floating, which is the layer most
// commonly targeted in registry compromises. Installing from a committed
// lockfile makes the entire dependency graph reproducible and reviewable.
func checkAdhocPackageInstall(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)
	seen := make(map[string]bool)

	for _, cmd := range collectRunCommandLines(workflow) {
		match := adhocInstallPattern.FindStringSubmatch(cmd.line)
		if match == nil {
			continue
		}

		manager := strings.ToLower(match[1])
		args := match[3]

		// Manifest-driven installs are exactly what this rule recommends.
		if lockfileFlagPattern.MatchString(args) {
			continue
		}

		packages := installTargetPackages(args)
		if len(packages) == 0 {
			// A bare `npm install` / `bundle install` resolves from the
			// committed manifest, which is the desired behavior.
			continue
		}

		// Global installs are tool installs, handled by UNPINNED_TOOL_INSTALL
		// so that a single command is not reported twice.
		if hasGlobalInstallFlag(args) {
			continue
		}

		lineNumber := 0
		if result := lineMapper.FindLineNumber(linenum.FindPattern{
			Key:   "run",
			Value: cmd.anchor,
		}); result != nil {
			lineNumber = result.LineNumber
		}

		dedupKey := fmt.Sprintf("%s|%d", cmd.line, lineNumber)
		if seen[dedupKey] {
			continue
		}
		seen[dedupKey] = true

		findings = append(findings, Finding{
			RuleID:      "ADHOC_PACKAGE_INSTALL",
			RuleName:    "Ad-hoc Package Installation",
			Description: "Dependencies are installed ad hoc instead of from a committed lockfile, leaving the resolved versions unpinned",
			Severity:    Low,
			Category:    SupplyChain,
			FilePath:    workflow.Path,
			JobName:     cmd.jobName,
			StepName:    cmd.stepName,
			Evidence:    fmt.Sprintf("Ad-hoc install of %s: %s", strings.Join(packages, ", "), cmd.line),
			Remediation: adhocRemediation(manager),
			LineNumber:  lineNumber,
		})
	}

	return findings
}

// adhocRemediation returns ecosystem-appropriate guidance.
func adhocRemediation(manager string) string {
	switch manager {
	case "npm":
		return "Add the package to package.json, commit package-lock.json, and install with `npm ci`"
	case "pnpm":
		return "Add the package to package.json, commit pnpm-lock.yaml, and install with `pnpm install --frozen-lockfile`"
	case "yarn":
		return "Add the package to package.json, commit yarn.lock, and install with `yarn install --immutable`"
	case "gem", "bundle":
		return "Add the gem to your Gemfile, commit Gemfile.lock, and install with `bundle install`"
	case "pip", "pip3":
		return "Pin the dependency in a fully-hashed requirements file and install with `pip install -r requirements.txt --require-hashes`"
	default:
		return "Install dependencies from a committed lockfile so the full dependency graph is reproducible"
	}
}

// installTargetPackages extracts positional package arguments from an install
// command, discarding flags and their values.
func installTargetPackages(args string) []string {
	var packages []string

	for _, field := range strings.Fields(args) {
		// Skip flags. A flag written as `--flag=value` is self-contained.
		if strings.HasPrefix(field, "-") {
			continue
		}
		// Runtime-resolved names cannot be evaluated statically.
		if strings.Contains(field, "${{") || strings.Contains(field, "$") {
			continue
		}
		// A path argument refers to a local manifest, not a registry package.
		if strings.HasPrefix(field, ".") || strings.HasPrefix(field, "/") {
			continue
		}
		packages = append(packages, field)
	}

	return packages
}

// hasGlobalInstallFlag reports whether the install targets a global tool
// location rather than the project's dependency tree.
func hasGlobalInstallFlag(args string) bool {
	for _, field := range strings.Fields(args) {
		switch field {
		case "-g", "--global":
			return true
		}
	}
	return false
}

// toolInstallPattern matches commands that install a standalone executable.
//
// `gem install` is deliberately excluded: it is handled by
// ADHOC_PACKAGE_INSTALL, and matching it here too would report one command twice.
var toolInstallPattern = regexp.MustCompile(
	`(?i)^(?:sudo\s+)?(go\s+install|cargo\s+install|pipx\s+install|npm\s+install\s+-g|npm\s+i\s+-g|npm\s+install\s+--global)\s+(.+)$`,
)

// checkUnpinnedToolInstall detects developer tools installed without a version
// constraint.
//
// A workflow that installs a tool without pinning it silently adopts whatever
// version the registry publishes next. This makes builds non-reproducible and,
// more importantly, means a compromised tool release executes with full access
// to the job's secrets and source tree the moment it is published — with no
// change to the repository to review.
func checkUnpinnedToolInstall(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)
	seen := make(map[string]bool)

	for _, cmd := range collectRunCommandLines(workflow) {
		match := toolInstallPattern.FindStringSubmatch(cmd.line)
		if match == nil {
			continue
		}

		installer := normalizeWhitespace(strings.ToLower(match[1]))
		args := match[2]

		unpinned := unpinnedToolTargets(installer, args)
		if len(unpinned) == 0 {
			continue
		}

		lineNumber := 0
		if result := lineMapper.FindLineNumber(linenum.FindPattern{
			Key:   "run",
			Value: cmd.anchor,
		}); result != nil {
			lineNumber = result.LineNumber
		}

		dedupKey := fmt.Sprintf("%s|%d", cmd.line, lineNumber)
		if seen[dedupKey] {
			continue
		}
		seen[dedupKey] = true

		findings = append(findings, Finding{
			RuleID:      "UNPINNED_TOOL_INSTALL",
			RuleName:    "Unpinned Tool Installation",
			Description: "Workflow installs a tool without a version constraint, so a newly published release executes automatically",
			Severity:    Medium,
			Category:    SupplyChain,
			FilePath:    workflow.Path,
			JobName:     cmd.jobName,
			StepName:    cmd.stepName,
			Evidence:    fmt.Sprintf("Unpinned tool install (%s): %s", strings.Join(unpinned, ", "), cmd.line),
			Remediation: toolPinRemediation(installer),
			LineNumber:  lineNumber,
		})
	}

	return findings
}

// unpinnedToolTargets returns the tool arguments that carry no version pin.
func unpinnedToolTargets(installer, args string) []string {
	fields := strings.Fields(args)

	// `cargo install` accepts the version as a separate flag.
	if strings.HasPrefix(installer, "cargo") {
		for _, f := range fields {
			if f == "--version" || f == "--vers" || strings.HasPrefix(f, "--version=") {
				return nil
			}
			// `--git` with `--rev`/`--tag` is also an immutable reference.
			if f == "--rev" || f == "--tag" || strings.HasPrefix(f, "--rev=") || strings.HasPrefix(f, "--tag=") {
				return nil
			}
		}
	}

	var unpinned []string

	for _, field := range fields {
		if strings.HasPrefix(field, "-") {
			continue
		}
		if strings.Contains(field, "${{") || strings.Contains(field, "$") {
			continue
		}
		// Local paths are built from the checked-out source, not fetched.
		if strings.HasPrefix(field, ".") || strings.HasPrefix(field, "/") {
			continue
		}

		if isVersionPinnedToolRef(field) {
			continue
		}

		unpinned = append(unpinned, field)
	}

	return unpinned
}

// isVersionPinnedToolRef reports whether a tool reference carries an explicit,
// non-floating version.
//
// `@latest` and `@main` are explicitly treated as unpinned: they name a moving
// target, which is exactly the risk this rule exists to surface.
func isVersionPinnedToolRef(ref string) bool {
	// Go module syntax: example.com/tool@v1.2.3
	if idx := strings.LastIndex(ref, "@"); idx != -1 {
		version := strings.ToLower(ref[idx+1:])
		switch version {
		case "latest", "main", "master", "head", "":
			return false
		}
		return true
	}

	// Python/npm syntax: tool==1.2.3, tool@1.2.3, tool:1.2.3
	if strings.Contains(ref, "==") {
		return true
	}

	return false
}

// toolPinRemediation returns installer-specific pinning guidance.
func toolPinRemediation(installer string) string {
	switch {
	case strings.HasPrefix(installer, "go install"):
		return "Pin the module to an exact version, e.g. `go install example.com/tool@v1.2.3`, rather than `@latest`"
	case strings.HasPrefix(installer, "cargo install"):
		return "Pin the crate with `--version` and use `--locked` so the crate's own lockfile is honored"
	case strings.HasPrefix(installer, "pipx"):
		return "Pin the tool to an exact version, e.g. `pipx install tool==1.2.3`"
	default:
		return "Pin the tool to an exact version, e.g. `npm install -g tool@1.2.3`"
	}
}

// normalizeWhitespace collapses runs of whitespace into single spaces so that
// multi-word installers match consistently.
func normalizeWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
