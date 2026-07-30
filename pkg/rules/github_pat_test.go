package rules

import (
	"strings"
	"testing"
)

const fineGrainedPAT = "github_pat_11ABCDEFG0aaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// Fine-grained personal access tokens are GitHub's recommended token type and
// appear in modern repositories far more often than the classic ghp_ format.
// A bare token, not adjacent to a "token:" key, is the case the generic
// key-value patterns cannot catch — so this asserts the dedicated pattern is
// what covers it.
func TestFineGrainedPAT_HasDedicatedPattern(t *testing.T) {
	bare := "curl -H \"Authorization: Bearer " + fineGrainedPAT + "\" https://api.github.com"

	var matchedBy []int
	for i, sp := range hardcodedSecretPatterns {
		if sp.re.MatchString(bare) {
			matchedBy = append(matchedBy, i)
		}
	}
	if len(matchedBy) == 0 {
		t.Fatal("a bare fine-grained PAT is not detected by any pattern")
	}

	// Confirm the match comes from the github_pat_ pattern specifically.
	var viaDedicated bool
	for _, i := range matchedBy {
		if strings.Contains(hardcodedSecretPatterns[i].re.String(), "github_pat_") {
			viaDedicated = true
		}
	}
	if !viaDedicated {
		t.Errorf("expected the dedicated github_pat_ pattern to match; matched patterns: %v", matchedBy)
	}
}

// The prefix is specific enough that the length is matched permissively, so
// tokens of differing lengths are still caught.
func TestFineGrainedPAT_LengthIsPermissive(t *testing.T) {
	var pat *secretPattern
	for i := range hardcodedSecretPatterns {
		if strings.Contains(hardcodedSecretPatterns[i].re.String(), "github_pat_") {
			pat = &hardcodedSecretPatterns[i]
			break
		}
	}
	if pat == nil {
		t.Fatal("github_pat_ pattern not found")
	}

	for _, tok := range []string{
		fineGrainedPAT,
		"github_pat_" + strings.Repeat("a", 22),
		"github_pat_" + strings.Repeat("z", 120),
	} {
		if !pat.re.MatchString(tok) {
			t.Errorf("expected %q... to match", tok[:25])
		}
	}

	// Too short to be a credential, and the bare prefix alone, must not match.
	for _, notToken := range []string{"github_pat_", "github_pat_short"} {
		if pat.re.MatchString(notToken) {
			t.Errorf("%q must not match", notToken)
		}
	}
}

// Severity classification must treat it like the other GitHub credentials.
func TestFineGrainedPAT_IsCritical(t *testing.T) {
	if got := determineSecretSeverity(fineGrainedPAT, hardcodedSecretPatterns[0].re); got != Critical {
		t.Errorf("severity = %s, want CRITICAL", got)
	}
}
