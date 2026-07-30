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

// Package matcher finds which of a fixed set of literals occur in a text, in a
// single pass.
//
// Rules commonly gate an expensive regular expression behind a set of cheap
// literal checks: if none of the words a pattern requires appear, the pattern
// cannot match and need not run. Done naively that is one full scan of the
// content per literal — and the scans all run to completion precisely in the
// common case where nothing matches.
//
// An Aho-Corasick automaton answers the whole question in one pass: O(n) in the
// text length regardless of how many literals are being searched for, after an
// O(total literal length) build that happens once at package initialisation.
package matcher

// Matcher is an Aho-Corasick automaton over a fixed literal set.
//
// A Matcher is immutable once built and safe for concurrent use.
type Matcher struct {
	// trans is a flat transition table of numNodes*256 entries: the next state
	// for (node, byte) is trans[node<<8|b].
	//
	// Failure links are folded into this table at build time, so matching is
	// one array index per byte with no hashing and no failure-chain walking.
	// An earlier version stored children in a map per node, which was
	// measurably *slower* than simply calling strings.Contains once per
	// literal, because Go's Contains is SIMD-optimised while a map lookup per
	// input byte is not. The table costs numNodes*256*4 bytes, built once.
	trans []int32
	// output lists the literal IDs that end at a node, including those
	// inherited through failure links.
	output [][]int

	count int
}

// New builds an automaton for the given literals.
//
// Literal IDs correspond to positions in the slice. Empty literals are skipped,
// since they would match everywhere and carry no information.
//
// Matching is byte-exact: callers wanting case-insensitive behaviour should
// supply lowercase literals and lowercase the text.
func New(literals []string) *Matcher {
	// Build the trie with sparse children first; the dense table is derived
	// from it once the shape is known.
	children := []map[byte]int{{}}
	output := [][]int{nil}

	for id, lit := range literals {
		if lit == "" {
			continue
		}
		node := 0
		for i := 0; i < len(lit); i++ {
			b := lit[i]
			next, ok := children[node][b]
			if !ok {
				next = len(children)
				children = append(children, map[byte]int{})
				output = append(output, nil)
				children[node][b] = next
			}
			node = next
		}
		output[node] = append(output[node], id)
	}

	m := &Matcher{
		trans:  make([]int32, len(children)*256),
		output: output,
		count:  len(literals),
	}
	m.buildTransitions(children)
	return m
}

// buildTransitions folds failure links into a dense transition table by
// breadth-first traversal.
//
// For a node without an explicit child for a byte, the transition is whatever
// the failure target does with that byte. Because the failure target is always
// processed before the node itself in BFS order, its row is already complete,
// so each entry is filled in constant time.
//
// Outputs are merged the same way, so reporting matches never walks the failure
// chain.
func (m *Matcher) buildTransitions(children []map[byte]int) {
	fail := make([]int32, len(children))

	// Root row: explicit children, everything else back to the root.
	queue := make([]int32, 0, len(children))
	for b := 0; b < 256; b++ {
		if next, ok := children[0][byte(b)]; ok {
			m.trans[b] = int32(next)
			fail[next] = 0
			queue = append(queue, int32(next))
		}
	}

	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]

		base := int(node) << 8
		failBase := int(fail[node]) << 8

		for b := 0; b < 256; b++ {
			if next, ok := children[node][byte(b)]; ok {
				m.trans[base+b] = int32(next)
				fail[next] = m.trans[failBase+b]
				m.output[next] = append(m.output[next], m.output[fail[next]]...)
				queue = append(queue, int32(next))
			} else {
				// No explicit edge: behave as the failure target does.
				m.trans[base+b] = m.trans[failBase+b]
			}
		}
	}
}

// Set is the result of a scan: membership by literal ID.
type Set []bool

// Has reports whether the literal with the given ID was found.
func (s Set) Has(id int) bool {
	if id < 0 || id >= len(s) {
		return false
	}
	return s[id]
}

// HasAny reports whether any of the given literal IDs was found.
func (s Set) HasAny(ids []int) bool {
	for _, id := range ids {
		if s.Has(id) {
			return true
		}
	}
	return false
}

// Scan returns the set of literals occurring in the text.
//
// Runs in O(len(text)) with one array index per byte, independent of how many
// literals the automaton holds.
func (m *Matcher) Scan(text string) Set {
	found := make(Set, m.count)
	if m.count == 0 || len(m.trans) == 0 {
		return found
	}

	node := int32(0)
	for i := 0; i < len(text); i++ {
		node = m.trans[int(node)<<8|int(text[i])]
		if outs := m.output[node]; len(outs) > 0 {
			for _, id := range outs {
				found[id] = true
			}
		}
	}

	return found
}

// Count returns the number of literals the automaton was built with.
func (m *Matcher) Count() int { return m.count }
