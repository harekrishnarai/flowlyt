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

package dependabot

import (
	"fmt"
	"strings"

	"github.com/harekrishnarai/flowlyt/v2/pkg/linenum"
	"github.com/harekrishnarai/flowlyt/v2/pkg/rules"
)

// DefaultCooldownDays is the minimum cooldown this analyzer recommends.
//
// Dependabot's own default is shorter. A week is used here because the
// opportunistic package compromises this protects against are typically
// detected and yanked by the registry within a few days of publication.
const DefaultCooldownDays = 7

// Rule is a security rule that operates on a Dependabot configuration file.
//
// It mirrors rules.Rule but takes a ConfigFile, because Dependabot config has
// no jobs or steps to fit the workflow rule signature.
type Rule struct {
	ID          string
	Name        string
	Description string
	Severity    rules.Severity
	Category    rules.Category
	Check       func(file ConfigFile) []rules.Finding
}

// StandardRules returns the built-in Dependabot configuration rules.
func StandardRules() []Rule {
	return []Rule{
		{
			ID:          "DEPENDABOT_COOLDOWN_MISSING",
			Name:        "Missing Dependabot Cooldown",
			Description: "Dependency updates are adopted without a cooldown period, increasing exposure to freshly published malicious releases",
			Severity:    rules.Medium,
			Category:    rules.SupplyChain,
			Check:       checkCooldown,
		},
		{
			ID:          "DEPENDABOT_INSECURE_EXECUTION",
			Name:        "Dependabot External Code Execution Enabled",
			Description: "Dependabot is permitted to execute external dependency code during resolution, exposing its credentials to that code",
			Severity:    rules.High,
			Category:    rules.SupplyChain,
			Check:       checkInsecureExternalCodeExecution,
		},
	}
}

// CheckAll runs every Dependabot rule against every discovered config file,
// honouring the enabled/disabled and ignore settings from configuration.
//
// The config parameter may be nil, in which case all rules run unfiltered.
func CheckAll(files []ConfigFile, cfg rules.ConfigInterface) []rules.Finding {
	var findings []rules.Finding

	for _, rule := range StandardRules() {
		if cfg != nil && !cfg.IsRuleEnabled(rule.ID) {
			continue
		}

		for _, file := range files {
			for _, finding := range rule.Check(file) {
				if cfg != nil && cfg.ShouldIgnoreForRule(finding.RuleID, finding.Evidence, file.Path) {
					continue
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// checkCooldown detects update entries with no cooldown, or one shorter than
// the recommended minimum.
//
// Adopting a release the moment it is published is risky for two distinct
// reasons. Operationally, brand-new releases carry the highest chance of
// regressions. From a security standpoint, package compromises are usually
// opportunistic: the attacker expects the malicious version to be yanked
// quickly, so the window of exposure is short. A repository that updates
// immediately is precisely the target such an attack captures, while one with a
// cooldown never sees the release at all.
func checkCooldown(file ConfigFile) []rules.Finding {
	var findings []rules.Finding

	lineMapper := linenum.NewLineMapper(file.Content)

	for _, update := range file.Config.Updates {
		// An entry with no ecosystem is malformed; skip rather than guess.
		if strings.TrimSpace(update.PackageEcosystem) == "" {
			continue
		}

		var evidence, remediation string

		switch {
		case update.Cooldown == nil:
			evidence = fmt.Sprintf("Update entry for %s declares no `cooldown`, so new releases are proposed immediately", update.EcosystemLabel())
			remediation = fmt.Sprintf("Add a cooldown to this entry:\n    cooldown:\n      default-days: %d", DefaultCooldownDays)

		case update.Cooldown.DefaultDays < DefaultCooldownDays:
			evidence = fmt.Sprintf(
				"Update entry for %s sets `cooldown.default-days: %d`, below the recommended minimum of %d",
				update.EcosystemLabel(), update.Cooldown.DefaultDays, DefaultCooldownDays,
			)
			remediation = fmt.Sprintf("Raise `cooldown.default-days` to at least %d", DefaultCooldownDays)

		default:
			continue
		}

		lineNumber := 0
		if result := lineMapper.FindLineNumber(linenum.FindPattern{
			Key:   "package-ecosystem",
			Value: update.PackageEcosystem,
		}); result != nil {
			lineNumber = result.LineNumber
		}

		findings = append(findings, rules.Finding{
			RuleID:      "DEPENDABOT_COOLDOWN_MISSING",
			RuleName:    "Missing Dependabot Cooldown",
			Description: "Dependency updates are adopted without a sufficient cooldown period, increasing exposure to freshly published malicious releases",
			Severity:    rules.Medium,
			Category:    rules.SupplyChain,
			FilePath:    file.Path,
			Evidence:    evidence,
			Remediation: remediation,
			LineNumber:  lineNumber,
		})
	}

	return findings
}

// checkInsecureExternalCodeExecution detects entries that opt in to running
// dependency code during resolution.
//
// Several ecosystems execute code from manifests while resolving dependencies.
// Dependabot disables this by default. Re-enabling it means a compromised
// dependency gains code execution inside a Dependabot job, which holds the
// credentials needed to read the repository and reach any configured private
// registries — all triggered automatically, with no human in the loop.
func checkInsecureExternalCodeExecution(file ConfigFile) []rules.Finding {
	var findings []rules.Finding

	lineMapper := linenum.NewLineMapper(file.Content)

	for _, update := range file.Config.Updates {
		if !strings.EqualFold(strings.TrimSpace(update.InsecureExternalCodeExecution), "allow") {
			continue
		}

		lineNumber := 0
		if result := lineMapper.FindLineNumber(linenum.FindPattern{
			Key:   "insecure-external-code-execution",
			Value: update.InsecureExternalCodeExecution,
		}); result != nil {
			lineNumber = result.LineNumber
		}

		findings = append(findings, rules.Finding{
			RuleID:      "DEPENDABOT_INSECURE_EXECUTION",
			RuleName:    "Dependabot External Code Execution Enabled",
			Description: "Dependabot is permitted to execute external dependency code during resolution, exposing its credentials to that code",
			Severity:    rules.High,
			Category:    rules.SupplyChain,
			FilePath:    file.Path,
			Evidence: fmt.Sprintf(
				"Update entry for %s sets `insecure-external-code-execution: allow`",
				update.EcosystemLabel(),
			),
			Remediation: "Set `insecure-external-code-execution: deny`, or remove the key to rely on the secure default. If resolution genuinely requires code execution, pin and vet the dependencies involved.",
			LineNumber:  lineNumber,
		})
	}

	return findings
}
