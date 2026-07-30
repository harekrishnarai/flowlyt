package matcher

import (
	"math/rand"
	"strings"
	"testing"
)

// bruteForce is the obvious O(literals * n) implementation, used to validate
// the automaton.
func bruteForce(literals []string, text string) Set {
	out := make(Set, len(literals))
	for i, lit := range literals {
		if lit != "" && strings.Contains(text, lit) {
			out[i] = true
		}
	}
	return out
}

func assertSame(t *testing.T, literals []string, text string) {
	t.Helper()
	got := New(literals).Scan(text)
	want := bruteForce(literals, text)
	for i := range want {
		if got.Has(i) != want.Has(i) {
			t.Fatalf("literal %q in %q: automaton=%v brute=%v", literals[i], text, got.Has(i), want.Has(i))
		}
	}
}

func TestScan_BasicMatches(t *testing.T) {
	lits := []string{"secret", "token", "key", "aws"}
	assertSame(t, lits, "my aws_secret_access_key is here")
	assertSame(t, lits, "nothing to see")
	assertSame(t, lits, "")
}

// Overlapping and nested literals are where a naive failure-link
// implementation typically goes wrong.
func TestScan_OverlappingAndNestedLiterals(t *testing.T) {
	lits := []string{"he", "she", "his", "hers", "ushers", "s"}
	for _, text := range []string{"ushers", "she", "hishers", "xxhersxx", "h", "s"} {
		assertSame(t, lits, text)
	}
}

// A literal that is a suffix of another must still be reported, which is what
// output merging along failure links provides.
func TestScan_SuffixLiteralIsFound(t *testing.T) {
	m := New([]string{"abcdef", "def", "ef"})
	got := m.Scan("zzabcdefzz")
	for id, lit := range []string{"abcdef", "def", "ef"} {
		if !got.Has(id) {
			t.Errorf("expected %q to be found", lit)
		}
	}
}

func TestScan_EmptyAndDegenerateInputs(t *testing.T) {
	if New(nil).Scan("anything").HasAny([]int{0}) {
		t.Error("an empty automaton must match nothing")
	}
	// An empty literal would match everywhere and carries no information.
	m := New([]string{"", "abc"})
	got := m.Scan("abc")
	if got.Has(0) {
		t.Error("empty literal must never be reported")
	}
	if !got.Has(1) {
		t.Error("expected abc to be found")
	}
}

func TestSet_HasAnyAndBounds(t *testing.T) {
	s := New([]string{"a", "b"}).Scan("b")
	if s.Has(-1) || s.Has(99) {
		t.Error("out-of-range IDs must report false, not panic")
	}
	if !s.HasAny([]int{0, 1}) {
		t.Error("HasAny should find b")
	}
	if s.HasAny([]int{0}) {
		t.Error("HasAny should not report a")
	}
}

// Randomised differential test against the brute-force implementation. This is
// what makes the optimisation safe to rely on.
func TestScan_RandomisedAgainstBruteForce(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	alphabet := "abcde_-"

	randStr := func(maxLen int) string {
		n := rng.Intn(maxLen + 1)
		b := make([]byte, n)
		for i := range b {
			b[i] = alphabet[rng.Intn(len(alphabet))]
		}
		return string(b)
	}

	for trial := 0; trial < 500; trial++ {
		lits := make([]string, 1+rng.Intn(12))
		for i := range lits {
			lits[i] = randStr(5)
		}
		for k := 0; k < 10; k++ {
			assertSame(t, lits, randStr(40))
		}
	}
}

// The real workload: many literals, most absent from the text.
func benchLiterals() []string {
	return []string{
		"apikey", "api_key", "api-key", "secret", "token", "password", "pwd",
		"credential", "authkey", "auth_key", "auth-key", "aws", "amazon", "gcp",
		"google", "azure", "microsoft", "github", "gitlab", "bitbucket", "ghp_",
		"gho_", "ghu_", "ghs_", "ghr_", "database", "dburl", "db_url", "db-url",
		"connection", "mongodb", "postgres", "mysql", "redis", "eyj", "-----begin",
		"oauth", "bearer", "client", "hooks.slack.com", "discord", "bitcoin",
		"btc", "ethereum", "eth", "sendgrid", "mailgun", "ses",
	}
}

const benchText = `name: CI
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && make build && make test
      - run: ./scripts/package.sh --output dist/
      - run: echo "done"
`

func BenchmarkScan(b *testing.B) {
	m := New(benchLiterals())
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m.Scan(benchText)
	}
}

func BenchmarkBruteForceContains(b *testing.B) {
	lits := benchLiterals()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		bruteForce(lits, benchText)
	}
}
