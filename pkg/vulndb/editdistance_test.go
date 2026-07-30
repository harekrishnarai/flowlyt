package vulndb

import (
	"math/rand"
	"testing"
)

// referenceEditDistance is the textbook full-matrix Levenshtein implementation,
// used only to validate the optimised bounded version.
func referenceEditDistance(a, b string) int {
	m := make([][]int, len(a)+1)
	for i := range m {
		m[i] = make([]int, len(b)+1)
		m[i][0] = i
	}
	for j := 0; j <= len(b); j++ {
		m[0][j] = j
	}
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			m[i][j] = min(m[i-1][j]+1, m[i][j-1]+1, m[i-1][j-1]+cost)
		}
	}
	return m[len(a)][len(b)]
}

func TestEditDistanceWithin_MatchesReference(t *testing.T) {
	cases := []struct{ a, b string }{
		{"", ""}, {"", "a"}, {"a", ""}, {"a", "a"}, {"a", "b"},
		{"actions/checkout", "action/checkout"},
		{"actions/checkout", "actions/checkotu"},
		{"actions/checkout", "actions/chekout"},
		{"actions/checkout", "aactions/checkout"},
		{"actions/checkout", "actions/setup-node"},
		{"docker/build-push-action", "docker/build-push-actions"},
		{"kitten", "sitting"},
		{"flaw", "lawn"},
		{"abcdef", "fedcba"},
		{"same", "same"},
	}

	for _, c := range cases {
		want := referenceEditDistance(c.a, c.b)
		for _, maxDist := range []int{0, 1, 2, 3, 5} {
			got := editDistanceWithin(c.a, c.b, maxDist)
			if got != (want <= maxDist) {
				t.Errorf("editDistanceWithin(%q,%q,%d) = %v, want %v (true distance %d)",
					c.a, c.b, maxDist, got, want <= maxDist, want)
			}
		}
	}
}

// Randomised differential test: the bounded result must agree with the
// reference for every input, which is what makes the band and early-exit
// pruning safe.
func TestEditDistanceWithin_RandomisedAgainstReference(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	alphabet := []byte("abcde/-")

	randStr := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = alphabet[rng.Intn(len(alphabet))]
		}
		return string(b)
	}

	for i := 0; i < 3000; i++ {
		a := randStr(rng.Intn(12))
		b := randStr(rng.Intn(12))
		want := referenceEditDistance(a, b)
		for maxDist := 0; maxDist <= 4; maxDist++ {
			if got := editDistanceWithin(a, b, maxDist); got != (want <= maxDist) {
				t.Fatalf("mismatch: a=%q b=%q max=%d got=%v want=%v (distance %d)",
					a, b, maxDist, got, want <= maxDist, want)
			}
		}
	}
}

func TestEditDistanceWithin_NegativeBound(t *testing.T) {
	if editDistanceWithin("a", "a", -1) {
		t.Error("a negative bound should never be satisfied")
	}
}

func BenchmarkEditDistanceWithin(b *testing.B) {
	for i := 0; i < b.N; i++ {
		editDistanceWithin("actions/chekcout", "actions/checkout", 2)
	}
}

func BenchmarkReferenceEditDistance(b *testing.B) {
	for i := 0; i < b.N; i++ {
		referenceEditDistance("actions/chekcout", "actions/checkout")
	}
}
