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
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/linenum"
	"github.com/harekrishnarai/flowlyt/pkg/parser"
	"github.com/harekrishnarai/flowlyt/pkg/vulndb"
)

// CheckSupplyChainVulnerabilities checks for supply chain security issues
func CheckSupplyChainVulnerabilities(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	// Basic supply chain checks
	findings = append(findings, checkKnownVulnerableActions(workflow)...)
	findings = append(findings, checkTyposquattingActions(workflow)...)
	findings = append(findings, checkUntrustedActionSources(workflow)...)
	findings = append(findings, checkDeprecatedActions(workflow)...)
	findings = append(findings, checkUnpinnableActions(workflow)...)

	// Advanced supply chain checks with real-time intelligence
	findings = append(findings, checkAdvancedVulnerableActions(workflow)...)
	findings = append(findings, checkAdvancedTyposquattingActions(workflow)...)
	findings = append(findings, checkActionVersionPinning(workflow)...)
	findings = append(findings, checkSupplyChainBestPractices(workflow)...)

	return findings
}

// checkKnownVulnerableActions detects usage of actions with known vulnerabilities
func checkKnownVulnerableActions(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)
	vdb := vulndb.NewVulnerabilityDatabase()

	// Check each job
	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			if step.Uses == "" {
				continue
			}

			stepName := step.Name
			if stepName == "" {
				stepName = "Step " + string(rune('1'+stepIdx))
			}

			// Parse action name and version
			actionParts := strings.Split(step.Uses, "@")
			actionName := actionParts[0]
			version := ""
			if len(actionParts) > 1 {
				version = actionParts[1]
			}

			// Check for known vulnerabilities
			vulnerabilities := vdb.CheckActionVulnerability(actionName, version)
			for _, vuln := range vulnerabilities {
				pattern := linenum.FindPattern{
					Key:   "uses",
					Value: step.Uses,
				}
				lineResult := lineMapper.FindLineNumber(pattern)
				lineNumber := 0
				if lineResult != nil {
					lineNumber = lineResult.LineNumber
				}

				severity := High
				if vuln.Severity == "CRITICAL" {
					severity = Critical
				} else if vuln.Severity == "LOW" {
					severity = Medium
				}

				findings = append(findings, Finding{
					RuleID:      "KNOWN_VULNERABLE_ACTION",
					RuleName:    "Known Vulnerable Action",
					Description: vuln.Summary,
					Severity:    severity,
					Category:    SupplyChain,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    stepName,
					Evidence:    step.Uses,
					Remediation: "Update to a newer version of the action that addresses this vulnerability",
					LineNumber:  lineNumber,
				})
			}
		}
	}

	return findings
}

// checkUnpinnableActions detects usage of actions that cannot be pinned to specific versions
func checkUnpinnableActions(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)
	vdb := vulndb.NewVulnerabilityDatabase()

	// Check each job
	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			if step.Uses == "" {
				continue
			}

			stepName := step.Name
			if stepName == "" {
				stepName = "Step " + string(rune('1'+stepIdx))
			}

			// Parse action name
			actionParts := strings.Split(step.Uses, "@")
			actionName := actionParts[0]

			// Check if action is unpinnable
			if vdb.IsActionUnpinnable(actionName) {
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
					RuleID:      "UNPINNABLE_ACTION",
					RuleName:    "Unpinnable Action",
					Description: "This action cannot be pinned to a specific version, making it vulnerable to supply chain attacks",
					Severity:    Medium,
					Category:    SupplyChain,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    stepName,
					Evidence:    step.Uses,
					Remediation: "Consider using an alternative action that supports version pinning, or accept the risk if from a trusted source",
					LineNumber:  lineNumber,
				})
			}
		}
	}

	return findings
}

// checkTyposquattingActions detects potential typosquatting in action names
func checkTyposquattingActions(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)
	vdb := vulndb.NewVulnerabilityDatabase()

	// Check each job
	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			if step.Uses == "" {
				continue
			}

			stepName := step.Name
			if stepName == "" {
				stepName = "Step " + string(rune('1'+stepIdx))
			}

			// Parse action name
			actionParts := strings.Split(step.Uses, "@")
			actionName := actionParts[0]

			// Check for potential typosquatting
			if vdb.CheckTyposquatting(actionName) {
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
					RuleID:      "TYPOSQUATTING_ACTION",
					RuleName:    "Potential Typosquatting Action",
					Description: "This action name appears to be similar to a popular action and might be a typosquatting attempt",
					Severity:    High,
					Category:    SupplyChain,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    stepName,
					Evidence:    step.Uses,
					Remediation: "Verify the action name is correct and from the intended publisher",
					LineNumber:  lineNumber,
				})
			}
		}
	}

	return findings
}

// checkUntrustedActionSources detects actions from untrusted sources
func checkUntrustedActionSources(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)
	vdb := vulndb.NewVulnerabilityDatabase()

	// Check each job
	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			if step.Uses == "" {
				continue
			}

			stepName := step.Name
			if stepName == "" {
				stepName = "Step " + string(rune('1'+stepIdx))
			}

			// Parse action name
			actionParts := strings.Split(step.Uses, "@")
			actionName := actionParts[0]

			// Check if action is from an untrusted source
			if !vdb.IsTrustedPublisher(actionName) {
				// Additional checks for suspicious patterns
				isSuspicious := false
				suspiciousReason := ""

				// Check for actions using tags instead of SHA
				if len(actionParts) > 1 {
					version := actionParts[1]
					if !strings.HasPrefix(version, "v") && len(version) != 40 {
						// Not a semantic version or SHA - might be a branch name
						isSuspicious = true
						suspiciousReason = "uses branch name instead of pinned version"
					}
				}

				// Check for actions with unusual naming patterns
				if strings.Contains(actionName, "..") || strings.Contains(actionName, "--") {
					isSuspicious = true
					suspiciousReason = "unusual naming pattern"
				}

				severity := Medium
				description := "Action is from an untrusted or unknown publisher"
				if isSuspicious {
					severity = High
					description = "Action is from an untrusted publisher and " + suspiciousReason
				}

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
					RuleID:      "UNTRUSTED_ACTION_SOURCE",
					RuleName:    "Untrusted Action Source",
					Description: description,
					Severity:    severity,
					Category:    SupplyChain,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    stepName,
					Evidence:    step.Uses,
					Remediation: "Verify the action is from a trusted source and consider pinning to a specific SHA",
					LineNumber:  lineNumber,
				})
			}
		}
	}

	return findings
}

// checkDeprecatedActions detects usage of deprecated actions
func checkDeprecatedActions(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	// Known deprecated actions
	deprecatedActions := map[string]string{
		"actions/setup-node@v1":                   "Use actions/setup-node@v2 or later",
		"actions/setup-python@v1":                 "Use actions/setup-python@v2 or later",
		"actions/setup-go@v1":                     "Use actions/setup-go@v2 or later",
		"actions/setup-java@v1":                   "Use actions/setup-java@v2 or later",
		"actions/cache@v1":                        "Use actions/cache@v2 or later",
		"actions/upload-artifact@v1":              "Use actions/upload-artifact@v2 or later",
		"actions/download-artifact@v1":            "Use actions/download-artifact@v2 or later",
		"stefanzweifel/git-auto-commit-action@v2": "Use stefanzweifel/git-auto-commit-action@v4 or later",
	}

	// Check each job
	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			if step.Uses == "" {
				continue
			}

			stepName := step.Name
			if stepName == "" {
				stepName = "Step " + string(rune('1'+stepIdx))
			}

			// Check if action is deprecated
			if reason, isDeprecated := deprecatedActions[step.Uses]; isDeprecated {
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
					RuleID:      "DEPRECATED_ACTION",
					RuleName:    "Deprecated Action",
					Description: "This action version is deprecated and may have security vulnerabilities",
					Severity:    Medium,
					Category:    SupplyChain,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    stepName,
					Evidence:    step.Uses,
					Remediation: reason,
					LineNumber:  lineNumber,
				})
			}

			// Check for actions using v1 versions generically
			actionParts := strings.Split(step.Uses, "@")
			if len(actionParts) > 1 && actionParts[1] == "v1" {
				// Skip if already covered in deprecated actions map
				if _, exists := deprecatedActions[step.Uses]; exists {
					continue
				}

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
					RuleID:      "DEPRECATED_ACTION",
					RuleName:    "Potentially Deprecated Action",
					Description: "This action uses v1 which is often deprecated in favor of newer versions",
					Severity:    Low,
					Category:    SupplyChain,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    stepName,
					Evidence:    step.Uses,
					Remediation: "Check if a newer version of this action is available",
					LineNumber:  lineNumber,
				})
			}
		}
	}

	return findings
}
