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
)

// CheckCachePoisoning is the public entry point that detects cache poisoning
// attack vectors (CP-001 and CP-002).
func CheckCachePoisoning(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	findings = append(findings, checkBroadRestoreKeys(workflow)...)
	findings = append(findings, checkCacheWriteInPR(workflow)...)
	return findings
}

// checkCachePoisoning is the unexported alias used by the CACHE_POISONING
// StandardRules entry (which predates the CP-001/002 split).
func checkCachePoisoning(workflow parser.WorkflowFile) []Finding {
	return CheckCachePoisoning(workflow)
}

// isCacheAction returns true if the uses value refers to any actions/cache variant
// (e.g. actions/cache@v3, actions/cache@v4) but NOT restore-only
// (actions/cache/restore) or save-only (actions/cache/save) sub-actions.
func isCacheAction(uses string) bool {
	return strings.HasPrefix(uses, "actions/cache")
}

// hasPRTrigger returns true if the workflow is triggered by pull_request or
// pull_request_target.
func hasPRTrigger(workflow parser.WorkflowFile) bool {
	on := workflow.Workflow.On
	if on == nil {
		return false
	}

	prTriggers := []string{"pull_request", "pull_request_target"}

	switch v := on.(type) {
	case string:
		for _, t := range prTriggers {
			if v == t {
				return true
			}
		}
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				for _, t := range prTriggers {
					if s == t {
						return true
					}
				}
			}
		}
	case map[interface{}]interface{}:
		for key := range v {
			if s, ok := key.(string); ok {
				for _, t := range prTriggers {
					if s == t {
						return true
					}
				}
			}
		}
	case map[string]interface{}:
		for key := range v {
			for _, t := range prTriggers {
				if key == t {
					return true
				}
			}
		}
	}

	return false
}

// checkBroadRestoreKeys implements CP-001: CACHE_RESTORE_KEYS_TOO_BROAD.
//
// Detects actions/cache usage where restore-keys contains fallback entries
// with no content hash (hashFiles), which allows cache poisoning from
// branches with attacker-controlled content.
func checkBroadRestoreKeys(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	lineMapper := linenum.NewLineMapper(workflow.Content)

	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			if step.Uses == "" || !isCacheAction(step.Uses) {
				continue
			}

			stepName := step.Name
			if stepName == "" {
				stepName = "Step " + string(rune('1'+stepIdx))
			}

			restoreKeysRaw, ok := step.With["restore-keys"]
			if !ok || restoreKeysRaw == nil {
				continue
			}

			restoreKeys, ok := restoreKeysRaw.(string)
			if !ok {
				continue
			}

			// Check each line of restore-keys for missing hashFiles
			hasBroadKey := false
			var broadExample string
			for _, line := range strings.Split(restoreKeys, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				if !strings.Contains(line, "hashFiles") {
					hasBroadKey = true
					broadExample = line
					break
				}
			}

			if !hasBroadKey {
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

			evidence := step.Uses
			if broadExample != "" {
				evidence = step.Uses + " — restore-key without hashFiles: " + broadExample
			}

			findings = append(findings, Finding{
				RuleID:      "CACHE_RESTORE_KEYS_TOO_BROAD",
				RuleName:    "Cache restore-keys Too Broad",
				Description: "Broad restore-keys without content hash enables cache poisoning from PR branches",
				Severity:    Medium,
				Category:    SupplyChain,
				FilePath:    workflow.Path,
				JobName:     jobName,
				StepName:    stepName,
				Evidence:    evidence,
				Remediation: "Add hashFiles() to all restore-keys entries, e.g. ${{ runner.os }}-npm-${{ hashFiles('**/package-lock.json') }}",
				LineNumber:  lineNumber,
			})
		}
	}

	return findings
}

// checkCacheWriteInPR implements CP-002: CACHE_WRITE_IN_PR_WORKFLOW.
//
// Detects actions/cache (write-capable) usage in workflows triggered by
// pull_request or pull_request_target. Restore-only actions
// (actions/cache/restore) are excluded as they cannot write to the cache.
func checkCacheWriteInPR(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	if !hasPRTrigger(workflow) {
		return findings
	}

	lineMapper := linenum.NewLineMapper(workflow.Content)

	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			if step.Uses == "" {
				continue
			}

			// actions/cache/restore is read-only; skip it
			if strings.HasPrefix(step.Uses, "actions/cache/restore") {
				continue
			}

			// Must be a cache write action
			if !isCacheAction(step.Uses) {
				continue
			}

			stepName := step.Name
			if stepName == "" {
				stepName = "Step " + string(rune('1'+stepIdx))
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
				RuleID:      "CACHE_WRITE_IN_PR_WORKFLOW",
				RuleName:    "Cache Write in Pull Request Workflow",
				Description: "Writing to the cache from a pull_request workflow can allow untrusted code to poison the cache for future runs",
				Severity:    Low,
				Category:    SupplyChain,
				FilePath:    workflow.Path,
				JobName:     jobName,
				StepName:    stepName,
				Evidence:    step.Uses + " used in a PR-triggered workflow",
				Remediation: "Use actions/cache/restore (read-only) in PR workflows, or restrict cache writes to trusted push/merge triggers",
				LineNumber:  lineNumber,
			})
		}
	}

	return findings
}
