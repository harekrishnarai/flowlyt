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

import "testing"

// knownCategories is the closed set of category values the engine may emit.
// Findings carry this value into JSON and SARIF output, so an unrecognized or
// inconsistently-spelled value breaks downstream filtering.
var knownCategories = map[Category]bool{
	MaliciousPattern:    true,
	Misconfiguration:    true,
	SecretExposure:      true,
	ShellObfuscation:    true,
	PolicyViolation:     true,
	SupplyChain:         true,
	InjectionAttack:     true,
	AccessControl:       true,
	PrivilegeEscalation: true,
	DataExposure:        true,
}

// Two spellings of the same concept previously coexisted, and code matching
// only one of them silently skipped findings carrying the other.
func TestSecretsExposureAliasIsUnified(t *testing.T) {
	if SecretsExposure != SecretExposure {
		t.Fatalf("SecretsExposure = %q, want it to equal SecretExposure (%q)", SecretsExposure, SecretExposure)
	}
	if string(SecretExposure) != "SECRET_EXPOSURE" {
		t.Errorf("SecretExposure = %q, want SECRET_EXPOSURE", SecretExposure)
	}
}

// Every registered rule must use a defined category constant. Raw string
// literals such as "injection" were previously emitted by some rules, which
// made those findings impossible to filter by category.
func TestStandardRulesUseKnownCategories(t *testing.T) {
	for _, rule := range StandardRules() {
		if !knownCategories[rule.Category] {
			t.Errorf("rule %s has unknown category %q", rule.ID, rule.Category)
		}
	}
}

// Severities must likewise come from the defined constants.
func TestStandardRulesUseKnownSeverities(t *testing.T) {
	known := map[Severity]bool{Critical: true, High: true, Medium: true, Low: true, Info: true}
	for _, rule := range StandardRules() {
		if !known[rule.Severity] {
			t.Errorf("rule %s has unknown severity %q", rule.ID, rule.Severity)
		}
	}
}
