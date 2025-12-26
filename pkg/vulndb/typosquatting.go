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

package vulndb

import (
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// TyposquattingDetector provides advanced algorithms for detecting malicious action names
type TyposquattingDetector struct {
	popularActions     []string
	commonPrefixes     []string
	suspiciousPatterns []*regexp.Regexp
	trustedNamespaces  []string
}

// NewTyposquattingDetector creates a new typosquatting detector
func NewTyposquattingDetector() *TyposquattingDetector {
	detector := &TyposquattingDetector{
		popularActions: getPopularActions(),
		commonPrefixes: getCommonPrefixes(),
		trustedNamespaces: []string{
			"actions", "github", "microsoft", "azure", "docker", "aws-actions",
			"google-github-actions", "hashicorp", "codecov", "step-security",
		},
	}

	// Compile suspicious patterns
	patterns := []string{
		// Character substitution patterns
		`[0o]ctions`,         // "0ctions" instead of "actions"
		`[il1]ctions`,        // "lctions" instead of "actions"
		`act[il1]ons`,        // "actlons" instead of "actions"
		`github-act[il1]ons`, // Variations of "github-actions"

		// Common typos in popular actions
		`setup-n[o0]de`,   // "setup-node" typos
		`setup-pyth[o0]n`, // "setup-python" typos
		`ch[e3]ckout`,     // "checkout" typos
		`c[a4]che`,        // "cache" typos

		// Unicode lookalikes (homograph attacks)
		`[а-я]`, // Cyrillic characters
		`[αβγδεζηθικλμνξοπρστυφχψω]`, // Greek characters

		// Suspicious naming patterns
		`.*-[0o]{2,}`,  // Multiple zeros (e.g., "action-000")
		`.*[_-]{2,}.*`, // Multiple consecutive separators
		`.*\d{3,}.*`,   // Excessive numbers
	}

	for _, pattern := range patterns {
		if compiled, err := regexp.Compile(`(?i)` + pattern); err == nil {
			detector.suspiciousPatterns = append(detector.suspiciousPatterns, compiled)
		}
	}

	return detector
}

// TyposquattingResult contains the analysis results
type TyposquattingResult struct {
	IsTyposquatting   bool            `json:"is_typosquatting"`
	Confidence        float64         `json:"confidence"`
	SuspiciousReasons []string        `json:"suspicious_reasons"`
	SimilarActions    []SimilarAction `json:"similar_actions"`
	RecommendedAction string          `json:"recommended_action"`
	RiskLevel         string          `json:"risk_level"`
}

type SimilarAction struct {
	Name       string  `json:"name"`
	Similarity float64 `json:"similarity"`
	Distance   int     `json:"edit_distance"`
}

// AnalyzeAction performs comprehensive typosquatting analysis
func (td *TyposquattingDetector) AnalyzeAction(actionName string) *TyposquattingResult {
	result := &TyposquattingResult{
		SuspiciousReasons: []string{},
		SimilarActions:    []SimilarAction{},
	}

	// Parse action namespace and name
	parts := strings.Split(actionName, "/")
	if len(parts) < 2 {
		result.SuspiciousReasons = append(result.SuspiciousReasons, "Invalid action format")
		result.Confidence = 0.3
		result.IsTyposquatting = true
		result.RiskLevel = "MEDIUM"
		return result
	}

	namespace := parts[0]
	name := parts[1]
	fullAction := namespace + "/" + name

	// Check against suspicious patterns
	for _, pattern := range td.suspiciousPatterns {
		if pattern.MatchString(fullAction) {
			result.SuspiciousReasons = append(result.SuspiciousReasons,
				"Contains suspicious character patterns")
			result.Confidence += 0.3
		}
	}

	// Check namespace trust
	if !td.isTrustedNamespace(namespace) {
		// Check for namespace similarity to trusted ones
		for _, trusted := range td.trustedNamespaces {
			if similarity := td.calculateStringSimilarity(namespace, trusted); similarity > 0.8 {
				result.SuspiciousReasons = append(result.SuspiciousReasons,
					"Namespace similar to trusted publisher: "+trusted)
				result.Confidence += 0.4
			}
		}
	}

	// Find similar popular actions
	result.SimilarActions = td.findSimilarActions(fullAction)

	// Analyze similarity scores
	maxSimilarity := 0.0
	var mostSimilar string
	for _, similar := range result.SimilarActions {
		if similar.Similarity > maxSimilarity {
			maxSimilarity = similar.Similarity
			mostSimilar = similar.Name
		}
	}

	// Determine if this is likely typosquatting
	if maxSimilarity > 0.85 && fullAction != mostSimilar {
		result.IsTyposquatting = true
		result.Confidence += 0.5
		result.RecommendedAction = mostSimilar
		result.SuspiciousReasons = append(result.SuspiciousReasons,
			"Very similar to popular action: "+mostSimilar)
	}

	// Additional checks
	result.Confidence += td.checkAdditionalSuspiciousPatterns(fullAction, namespace, name)

	// Normalize confidence to 0-1 range
	result.Confidence = math.Min(1.0, result.Confidence)

	// Determine final result
	if result.Confidence > 0.7 {
		result.IsTyposquatting = true
		result.RiskLevel = "HIGH"
	} else if result.Confidence > 0.5 {
		result.IsTyposquatting = true
		result.RiskLevel = "MEDIUM"
	} else if result.Confidence > 0.3 {
		result.RiskLevel = "LOW"
	} else {
		result.RiskLevel = "NONE"
	}

	return result
}

// findSimilarActions finds actions similar to the given action
func (td *TyposquattingDetector) findSimilarActions(actionName string) []SimilarAction {
	var similar []SimilarAction

	for _, popular := range td.popularActions {
		distance := td.calculateLevenshteinDistance(actionName, popular)
		similarity := td.calculateStringSimilarity(actionName, popular)

		// Include if similarity is high enough or edit distance is small
		if similarity > 0.6 || (distance <= 3 && distance > 0) {
			similar = append(similar, SimilarAction{
				Name:       popular,
				Similarity: similarity,
				Distance:   distance,
			})
		}
	}

	// Sort by similarity (highest first)
	sort.Slice(similar, func(i, j int) bool {
		return similar[i].Similarity > similar[j].Similarity
	})

	// Return top 5 similar actions
	if len(similar) > 5 {
		similar = similar[:5]
	}

	return similar
}

// calculateStringSimilarity calculates Jaro-Winkler similarity
func (td *TyposquattingDetector) calculateStringSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}

	if len(s1) == 0 || len(s2) == 0 {
		return 0.0
	}

	// Jaro similarity
	jaro := td.calculateJaroSimilarity(s1, s2)

	// Winkler prefix bonus
	prefixLength := 0
	maxPrefix := int(math.Min(4, math.Min(float64(len(s1)), float64(len(s2)))))

	for i := 0; i < maxPrefix && s1[i] == s2[i]; i++ {
		prefixLength++
	}

	return jaro + (0.1 * float64(prefixLength) * (1 - jaro))
}

// calculateJaroSimilarity calculates Jaro similarity
func (td *TyposquattingDetector) calculateJaroSimilarity(s1, s2 string) float64 {
	len1, len2 := len(s1), len(s2)

	if len1 == 0 && len2 == 0 {
		return 1.0
	}

	if len1 == 0 || len2 == 0 {
		return 0.0
	}

	matchWindow := int(math.Max(float64(len1), float64(len2))/2) - 1
	if matchWindow < 0 {
		matchWindow = 0
	}

	s1Matches := make([]bool, len1)
	s2Matches := make([]bool, len2)

	matches := 0
	transpositions := 0

	// Find matches
	for i := 0; i < len1; i++ {
		start := int(math.Max(0, float64(i-matchWindow)))
		end := int(math.Min(float64(i+matchWindow+1), float64(len2)))

		for j := start; j < end; j++ {
			if s2Matches[j] || s1[i] != s2[j] {
				continue
			}
			s1Matches[i] = true
			s2Matches[j] = true
			matches++
			break
		}
	}

	if matches == 0 {
		return 0.0
	}

	// Count transpositions
	k := 0
	for i := 0; i < len1; i++ {
		if !s1Matches[i] {
			continue
		}
		for !s2Matches[k] {
			k++
		}
		if s1[i] != s2[k] {
			transpositions++
		}
		k++
	}

	jaro := (float64(matches)/float64(len1) +
		float64(matches)/float64(len2) +
		(float64(matches)-float64(transpositions)/2)/float64(matches)) / 3.0

	return jaro
}

// calculateLevenshteinDistance calculates edit distance between two strings
func (td *TyposquattingDetector) calculateLevenshteinDistance(s1, s2 string) int {
	len1, len2 := len(s1), len(s2)

	if len1 == 0 {
		return len2
	}
	if len2 == 0 {
		return len1
	}

	matrix := make([][]int, len1+1)
	for i := range matrix {
		matrix[i] = make([]int, len2+1)
	}

	for i := 0; i <= len1; i++ {
		matrix[i][0] = i
	}
	for j := 0; j <= len2; j++ {
		matrix[0][j] = j
	}

	for i := 1; i <= len1; i++ {
		for j := 1; j <= len2; j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}

			matrix[i][j] = minInt(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len1][len2]
}

// checkAdditionalSuspiciousPatterns performs additional checks
func (td *TyposquattingDetector) checkAdditionalSuspiciousPatterns(fullAction, namespace, name string) float64 {
	suspicion := 0.0

	// Check for excessive use of numbers
	numberCount := 0
	for _, char := range fullAction {
		if unicode.IsDigit(char) {
			numberCount++
		}
	}
	if numberCount > 3 {
		suspicion += 0.2
	}

	// Check for mixed case in unexpected places
	if strings.Contains(fullAction, "Action") || strings.Contains(fullAction, "GitHub") {
		if !strings.HasPrefix(fullAction, strings.ToLower(fullAction)) {
			suspicion += 0.1
		}
	}

	// Check for homograph attacks (non-ASCII characters)
	for _, char := range fullAction {
		if char > 127 {
			suspicion += 0.4
			break
		}
	}

	// Check for domain typosquatting patterns
	if strings.Contains(name, "github") && namespace != "github" {
		suspicion += 0.3
	}

	// Check for action name padding
	if len(name) > 30 {
		suspicion += 0.1
	}

	// Check for excessive hyphens or underscores
	separatorCount := strings.Count(fullAction, "-") + strings.Count(fullAction, "_")
	if separatorCount > 3 {
		suspicion += 0.1
	}

	return suspicion
}

// isTrustedNamespace checks if a namespace is trusted
func (td *TyposquattingDetector) isTrustedNamespace(namespace string) bool {
	for _, trusted := range td.trustedNamespaces {
		if namespace == trusted {
			return true
		}
	}
	return false
}

// getPopularActions returns a list of popular GitHub Actions
func getPopularActions() []string {
	return []string{
		"actions/checkout",
		"actions/setup-node",
		"actions/setup-python",
		"actions/setup-go",
		"actions/setup-java",
		"actions/cache",
		"actions/upload-artifact",
		"actions/download-artifact",
		"actions/github-script",
		"actions/setup-dotnet",
		"docker/build-push-action",
		"docker/setup-buildx-action",
		"docker/setup-qemu-action",
		"codecov/codecov-action",
		"github/super-linter",
		"microsoft/setup-msbuild",
		"azure/login",
		"azure/webapps-deploy",
		"aws-actions/configure-aws-credentials",
		"aws-actions/amazon-ecr-login",
		"google-github-actions/setup-gcloud",
		"hashicorp/setup-terraform",
		"ruby/setup-ruby",
		"gradle/gradle-build-action",
		"step-security/harden-runner",
		"snyk/actions",
		"anchore/scan-action",
		"securecodewarrior/github-action-add-sarif",
		"github/codeql-action/init",
		"github/codeql-action/analyze",
		"sonarqube-quality-gate-action",
		"coverallsapp/github-action",
		"stefanzweifel/git-auto-commit-action",
		"peter-evans/create-pull-request",
		"actions/labeler",
		"actions/first-interaction",
		"actions/stale",
		"release-drafter/release-drafter",
		"softprops/action-gh-release",
		"peaceiris/actions-gh-pages",
	}
}

// getCommonPrefixes returns common action prefixes
func getCommonPrefixes() []string {
	return []string{
		"setup-", "build-", "deploy-", "test-", "lint-", "format-",
		"publish-", "release-", "upload-", "download-", "install-",
		"configure-", "verify-", "validate-", "scan-", "analyze-",
	}
}

// Helper function
func minInt(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// Export results to JSON for external analysis
func (tr *TyposquattingResult) ToJSON() ([]byte, error) {
	return json.Marshal(tr)
}
