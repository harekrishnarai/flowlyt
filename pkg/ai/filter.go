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

package ai

import (
	"math"
	"os"
	"regexp"
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

var (
	shaRe         = regexp.MustCompile(`@[0-9a-f]{40}`)
	realTokenRe   = regexp.MustCompile(`(?i)(ghp_|ghs_|gho_|sk-|AKIA)[A-Za-z0-9]{16,}`)
	placeholderRe = regexp.MustCompile(`(?i)(your[-_].*[-_]here|<token>|example[-_]|changeme|dummy|placeholder|fake[-_]key|test[-_]key)`)
)

// ShouldSkipAI returns (true, reason) when a finding does not need AI analysis.
// It subsumes the previous shouldSendToAI severity/rule-list gate — env-based
// filters (AI_MIN_SEVERITY, AI_INCLUDE_RULES, AI_EXCLUDE_RULES) run first.
func ShouldSkipAI(f rules.Finding) (bool, string) {
	// 1. Env-based filters (run first, preserve existing behaviour)
	if skip, reason := envBasedFilter(f); skip {
		return true, reason
	}

	ev := f.Evidence

	// 2. Always send: real token prefixes — cannot be overridden by skip logic
	if realTokenRe.MatchString(ev) {
		return false, ""
	}

	// 3. Always send: high-entropy blobs — cannot be overridden by skip logic
	// NOTE: SHA check (step 4) must come before entropy check within skip logic
	// because action URLs with 40-char SHAs have high entropy (~4.5 bits/char).
	// But "always send" gates (steps 2-3) run before any skip check.
	if hasHighEntropyBlob(ev) {
		return false, ""
	}

	cat := strings.ToUpper(string(f.Category))

	// 4. Secrets: expression references are never hardcoded secrets
	if strings.Contains(cat, "SECRET") {
		if strings.Contains(ev, "${{ secrets.") ||
			strings.Contains(ev, "${{ env.") ||
			strings.Contains(ev, "vars.") {
			return true, "expression reference — not a hardcoded value"
		}
		if placeholderRe.MatchString(ev) {
			return true, "placeholder pattern — not a real credential"
		}
	}

	// 5. Pinning: SHA already present means static analysis fired incorrectly
	if shaRe.MatchString(ev) {
		return true, "SHA pin already present — static analysis false positive"
	}

	// 6. Permissions: already locked down
	if strings.Contains(ev, "permissions: read-all") || strings.Contains(ev, "permissions: {}") {
		return true, "permissions already locked down"
	}

	return false, ""
}

// envBasedFilter preserves the existing AI_MIN_SEVERITY / AI_INCLUDE_RULES /
// AI_EXCLUDE_RULES environment variable behaviour.
func envBasedFilter(f rules.Finding) (bool, string) {
	excludeRules := parseCSVSet(os.Getenv("AI_EXCLUDE_RULES"))
	if _, denied := excludeRules[strings.ToUpper(f.RuleID)]; denied {
		return true, "rule in AI_EXCLUDE_RULES"
	}

	includeRules := parseCSVSet(os.Getenv("AI_INCLUDE_RULES"))
	if len(includeRules) > 0 {
		if _, ok := includeRules[strings.ToUpper(f.RuleID)]; !ok {
			return true, "rule not in AI_INCLUDE_RULES"
		}
		return false, ""
	}

	minSev := strings.ToUpper(strings.TrimSpace(os.Getenv("AI_MIN_SEVERITY")))
	if minSev == "" {
		return false, ""
	}
	levels := map[string]int{"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
	if levels[strings.ToUpper(string(f.Severity))] < levels[minSev] {
		return true, "below AI_MIN_SEVERITY threshold"
	}
	return false, ""
}

// hasHighEntropyBlob returns true if any 20+ char token in evidence has
// Shannon entropy >= 4.0 bits/char over its raw characters.
// SHA-pinned actions are excluded — those are handled by the SHA skip check.
func hasHighEntropyBlob(evidence string) bool {
	// Don't flag entropy on SHA-pinned actions — those are handled by the SHA skip check.
	if shaRe.MatchString(evidence) {
		return false
	}
	for _, word := range strings.Fields(evidence) {
		if len(word) >= 20 && shannonEntropy(word) >= 4.0 {
			return true
		}
	}
	return false
}

// shannonEntropy computes Shannon entropy in bits/char over the raw string.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, count := range freq {
		p := count / n
		h -= p * math.Log2(p)
	}
	return h
}

// parseCSVSet splits a comma-separated string into a set (map[string]struct{}).
func parseCSVSet(s string) map[string]struct{} {
	result := make(map[string]struct{})
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			result[strings.ToUpper(item)] = struct{}{}
		}
	}
	return result
}
