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
	"regexp"
	"strings"

	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
)

// Indirect injection detection.
//
// These techniques cover injection shapes that the direct-interpolation rules
// miss because the expression and the execution are not adjacent. Injection
// forms that INJECTION_VULNERABILITY, SHELL_INJECTION, SHELL_EVAL_USAGE and
// MALICIOUS_BASE64_DECODE already report — variable indirection, command
// substitution, and base64-decode-to-shell — are deliberately not repeated
// here: emitting a second rule for a line that is already flagged adds noise
// without adding information.

// heredocOpenPattern matches a heredoc opening, capturing the quote character
// (if any) and the delimiter word.
//
// A quoted delimiter (<<'EOF') disables expansion inside the body, which is
// precisely the recommended mitigation, so those are not reported.
var heredocOpenPattern = regexp.MustCompile(`<<-?\s*(['"]?)(\w+)['"]?`)

// heredocExpandsUntrustedInput returns the offending body line when the script
// contains an unquoted heredoc whose body interpolates a workflow expression.
//
// This is done line by line rather than with one regular expression: a heredoc
// spans multiple lines, and pairing an opening delimiter with its terminator
// requires a backreference, which Go's regexp engine does not support.
func heredocExpandsUntrustedInput(lines []string) string {
	for i, line := range lines {
		m := heredocOpenPattern.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		quote, delimiter := m[1], m[2]
		if quote != "" {
			// Quoted delimiter: the body is taken literally, so an expression
			// inside it is never expanded by the shell.
			continue
		}

		for _, body := range lines[i+1:] {
			if strings.TrimSpace(body) == delimiter {
				break
			}
			if containsExpression(body) {
				return body
			}
		}
	}

	return ""
}

var (
	// A redirection or tee writing an expression into a file, capturing the
	// destination path.
	writeExpressionToFile = regexp.MustCompile(`\$\{\{[^}]+\}\}[^|;]*?(?:>>?|\|\s*tee(?:\s+-a)?)\s*["']?([\w./~-]+)`)

	// Execution of a named path, either by an interpreter or directly.
	executePathPattern = regexp.MustCompile(`(?:\b(?:bash|sh|zsh|source|python3?|node|ruby|perl)\s+|(?:^|[;&|]\s*)\.?/)["']?([\w./~-]+)`)
)

// multiStageInjection returns the offending line when the script writes an
// expression into a file and later executes that same file.
//
// Splitting the write from the execution defeats rules that look for an
// expression and an execution on the same line, yet the result is identical:
// attacker-controlled text runs as code. Requiring the *same* path keeps this
// precise — writing a log file and separately running an unrelated script is
// ordinary and must not be reported.
func multiStageInjection(lines []string) string {
	// Paths that received untrusted content, mapped to the line that wrote them.
	tainted := make(map[string]string)

	for _, line := range lines {
		if m := writeExpressionToFile.FindStringSubmatch(line); m != nil {
			tainted[normalizeScriptPath(m[1])] = line
		}

		for _, m := range executePathPattern.FindAllStringSubmatch(line, -1) {
			path := normalizeScriptPath(m[1])
			if writeLine, ok := tainted[path]; ok {
				return writeLine
			}
		}
	}

	return ""
}

// normalizeScriptPath trims decoration so that `./run.sh`, `run.sh` and
// `"run.sh"` refer to the same file.
func normalizeScriptPath(path string) string {
	path = strings.Trim(path, `"'`)
	path = strings.TrimPrefix(path, "./")
	return strings.TrimSpace(path)
}

// injectionTechniques enumerates the indirect injection shapes detected.
//
// To cover a new technique, add an entry here: the shared scanner supplies line
// pinpointing, comment handling, and deduplication.
func injectionTechniques() []shellTechnique {
	return []shellTechnique{
		{
			ID:          "HEREDOC_INJECTION",
			Name:        "Command Injection via Heredoc",
			Severity:    High,
			Category:    InjectionAttack,
			Description: "An unquoted heredoc interpolates a workflow expression, so attacker-controlled text is expanded by the shell inside the document body",
			Remediation: "Quote the delimiter (`<<'EOF'`) so the body is taken literally, or pass the value through an `env:` variable and reference it as \"$VAR\" inside the heredoc.",
			MatchScript: heredocExpandsUntrustedInput,
		},
		{
			ID:          "MULTI_STAGE_INJECTION",
			Name:        "Multi-Stage Command Injection",
			Severity:    High,
			Category:    InjectionAttack,
			Description: "A workflow expression is written to a file that is subsequently executed, so attacker-controlled text runs as code even though no single command interpolates it into a shell",
			Remediation: "Do not build executable files from workflow expressions. Pass the value through an `env:` variable and have the script read it at runtime, so it is never treated as code.",
			MatchScript: multiStageInjection,
		},
	}
}

// CheckAdvancedInjection detects indirect command injection in `run:` steps.
func CheckAdvancedInjection(workflow parser.WorkflowFile) []Finding {
	return scanShellTechniques(workflow, injectionTechniques())
}

// Each technique is also exposed as an individually registrable rule so users
// can enable or disable it by ID.
func checkHeredocInjection(workflow parser.WorkflowFile) []Finding {
	return scanShellTechniques(workflow, selectTechniques(injectionTechniques(), "HEREDOC_INJECTION"))
}

func checkMultiStageInjection(workflow parser.WorkflowFile) []Finding {
	return scanShellTechniques(workflow, selectTechniques(injectionTechniques(), "MULTI_STAGE_INJECTION"))
}

// truncate shortens a string for use as finding evidence.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
