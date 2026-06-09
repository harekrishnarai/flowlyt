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

// checkUnsoundCondition detects logic vulnerabilities in workflow conditions
func checkUnsoundCondition(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	for jobName, job := range workflow.Workflow.Jobs {
		// Check job-level conditions
		if job.If != "" {
			if hasUnsoundLogic(job.If) {
				pattern := linenum.FindPattern{
					Key:   "if",
					Value: job.If,
				}
				lineResult := lineMapper.FindLineNumber(pattern)
				lineNumber := 0
				if lineResult != nil {
					lineNumber = lineResult.LineNumber
				}

				findings = append(findings, Finding{
					RuleID:      "UNSOUND_CONDITION",
					RuleName:    "Unsound Condition Logic",
					Description: "Job condition contains potentially vulnerable logic patterns",
					Severity:    High,
					Category:    InjectionAttack,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    "job_condition",
					Evidence:    job.If,
					Remediation: "Review condition logic for potential bypasses or injection vulnerabilities",
					LineNumber:  lineNumber,
				})
			}
		}

		// Check step-level conditions
		for stepIdx, step := range job.Steps {
			if step.If != "" {
				stepName := step.Name
				if stepName == "" {
					stepName = fmt.Sprintf("Step %d", stepIdx+1)
				}

				if hasUnsoundLogic(step.If) {
					pattern := linenum.FindPattern{
						Key:   "if",
						Value: step.If,
					}
					lineResult := lineMapper.FindLineNumber(pattern)
					lineNumber := 0
					if lineResult != nil {
						lineNumber = lineResult.LineNumber
					}

					findings = append(findings, Finding{
						RuleID:      "UNSOUND_CONDITION",
						RuleName:    "Unsound Condition Logic",
						Description: "Step condition contains potentially vulnerable logic patterns",
						Severity:    High,
						Category:    InjectionAttack,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    stepName,
						Evidence:    step.If,
						Remediation: "Review condition logic for potential bypasses or injection vulnerabilities",
						LineNumber:  lineNumber,
					})
				}
			}
		}
	}

	return findings
}

// checkUnsoundContains detects vulnerable contains() expressions
func checkUnsoundContains(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	for jobName, job := range workflow.Workflow.Jobs {
		// Check job-level conditions for contains()
		if job.If != "" && strings.Contains(job.If, "contains(") {
			if hasVulnerableContains(job.If) {
				pattern := linenum.FindPattern{
					Key:   "if",
					Value: job.If,
				}
				lineResult := lineMapper.FindLineNumber(pattern)
				lineNumber := 0
				if lineResult != nil {
					lineNumber = lineResult.LineNumber
				}

				findings = append(findings, Finding{
					RuleID:      "UNSOUND_CONTAINS",
					RuleName:    "Unsound Contains Logic",
					Description: "Job condition uses contains() in a way that can be bypassed",
					Severity:    High,
					Category:    InjectionAttack,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    "job_condition",
					Evidence:    job.If,
					Remediation: "Use exact string matching or startsWith() instead of contains() for security checks",
					LineNumber:  lineNumber,
				})
			}
		}

		// Check step-level conditions for contains()
		for stepIdx, step := range job.Steps {
			if step.If != "" && strings.Contains(step.If, "contains(") {
				stepName := step.Name
				if stepName == "" {
					stepName = fmt.Sprintf("Step %d", stepIdx+1)
				}

				if hasVulnerableContains(step.If) {
					pattern := linenum.FindPattern{
						Key:   "if",
						Value: step.If,
					}
					lineResult := lineMapper.FindLineNumber(pattern)
					lineNumber := 0
					if lineResult != nil {
						lineNumber = lineResult.LineNumber
					}

					findings = append(findings, Finding{
						RuleID:      "UNSOUND_CONTAINS",
						RuleName:    "Unsound Contains Logic",
						Description: "Step condition uses contains() in a way that can be bypassed",
						Severity:    High,
						Category:    InjectionAttack,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    stepName,
						Evidence:    step.If,
						Remediation: "Use exact string matching or startsWith() instead of contains() for security checks",
						LineNumber:  lineNumber,
					})
				}
			}
		}
	}

	return findings
}

func hasUnsoundLogic(condition string) bool {
	// Check for actually dangerous condition patterns, not just any use of github.event
	unsoundPatterns := []string{
		// Only flag unquoted usage in shell context or dangerous equality checks
		`\$\{\{\s*github\.event\.[^}]*\s*\}\}\s*\|\s*sh`,         // Unquoted github.event piped to shell
		`\$\{\{\s*github\.event\.[^}]*\s*\}\}\s*\|\s*bash`,       // Unquoted github.event piped to bash
		`eval.*\$\{\{\s*github\.event`,                           // github.event in eval context
		`github\.event\.pull_request\.head\.ref.*==.*[^'].*[^']`, // Unquoted ref comparison (not quoted string)
		`github\.event\.issue\.title.*==.*[^'].*[^']`,            // Unquoted issue title comparison
		`github\.event\.comment\.body.*==.*[^'].*[^']`,           // Unquoted comment body comparison
		`\|\|.*always\(\).*github\.event`,                        // Combining always() with event data unsafely
		`&&.*\!.*cancelled\(\).*github\.event`,                   // Complex negation with event data
	}

	for _, pattern := range unsoundPatterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		if re.MatchString(condition) {
			return true
		}
	}

	return false
}

func hasVulnerableContains(condition string) bool {
	// Check for contains() patterns that can be bypassed in security-sensitive contexts.
	//
	// github.ref is intentionally excluded: ref-based conditions (e.g. contains(github.ref, 'l10n'))
	// are almost always branch/environment filters, not security gates. Flagging them produces
	// high false-positive rates. Note: pull_request_target workflows where an attacker controls the
	// source branch ref are covered by the dedicated INSECURE_PULL_REQUEST_TARGET rule instead.
	vulnerablePatterns := []string{
		`contains\(.*github\.event.*,\s*'[^']*'\)`,      // Contains with event data (user-controlled)
		`contains\(.*github\.actor.*,\s*'[^']*'\)`,      // Contains with actor (spoofable username)
		`contains\(.*steps\..*\.outputs.*,\s*'[^']*'\)`, // Contains with step outputs (taint source)
	}

	for _, pattern := range vulnerablePatterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		if re.MatchString(condition) {
			return true
		}
	}

	return false
}
