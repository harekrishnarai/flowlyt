package linenum

import (
	"fmt"
	"sync"
	"testing"
)

// Mappers are memoised and shared, so concurrent construction and use must be
// race-free and must never return a mapper built from different content.
func TestNewLineMapper_ConcurrentUseIsSafeAndCorrect(t *testing.T) {
	const workers = 32

	contents := make([][]byte, 8)
	for i := range contents {
		contents[i] = []byte(fmt.Sprintf("name: wf%d\nline-a-%d\nline-b-%d\nline-c-%d\n", i, i, i, i))
	}

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				idx := (w + i) % len(contents)
				lm := NewLineMapper(contents[idx])

				// The mapper must correspond to the content requested.
				want := fmt.Sprintf("name: wf%d", idx)
				if got := lm.GetLine(1); got != want {
					t.Errorf("GetLine(1) = %q, want %q", got, want)
					return
				}
				if lm.TotalLines() != 5 {
					t.Errorf("TotalLines = %d, want 5", lm.TotalLines())
					return
				}
			}
		}(w)
	}
	wg.Wait()
}

// A cache hit must return the identical instance; that reuse is the entire
// point of the memo.
func TestNewLineMapper_ReusesInstanceForSameContent(t *testing.T) {
	content := []byte("a\nb\nc\n")
	first := NewLineMapper(content)
	second := NewLineMapper(content)
	if first != second {
		t.Error("expected the same mapper instance to be reused for identical content")
	}

	other := NewLineMapper([]byte("x\ny\nz\n"))
	if other == first {
		t.Error("different content must not share a mapper")
	}
}

// The cache must stay bounded rather than growing with every workflow scanned.
func TestNewLineMapper_CacheIsBounded(t *testing.T) {
	for i := 0; i < DefaultMapperCacheLimit+50; i++ {
		NewLineMapper([]byte(fmt.Sprintf("unique content %d\n", i)))
	}

	if size := DefaultCache().Len(); size > DefaultMapperCacheLimit {
		t.Errorf("cache grew to %d entries, expected at most %d", size, DefaultMapperCacheLimit)
	}
}

// A cache is a value a caller owns, so its lifetime can be tied to a scan
// rather than to the process.
func TestMapperCache_IsOwnableAndResettable(t *testing.T) {
	c := NewMapperCache(4)

	first := c.Get([]byte("a\nb\n"))
	if c.Get([]byte("a\nb\n")) != first {
		t.Error("expected the same instance from one cache")
	}
	if c.Len() != 1 {
		t.Errorf("Len = %d, want 1", c.Len())
	}

	// A separate cache is genuinely separate.
	other := NewMapperCache(4)
	if other.Get([]byte("a\nb\n")) == first {
		t.Error("distinct caches must not share entries")
	}

	c.Reset()
	if c.Len() != 0 {
		t.Errorf("Len after Reset = %d, want 0", c.Len())
	}
	if c.Get([]byte("a\nb\n")) == first {
		t.Error("Reset must discard cached mappers")
	}
}

// A nil cache is valid and simply does not memoise, so callers need no special
// case when they do not want caching.
func TestMapperCache_NilIsUsable(t *testing.T) {
	var c *MapperCache
	lm := c.Get([]byte("x\ny\n"))
	if lm == nil || lm.TotalLines() != 3 {
		t.Fatalf("nil cache should still build a working mapper, got %+v", lm)
	}
	if c.Len() != 0 {
		t.Error("nil cache should report zero length")
	}
	c.Reset() // must not panic
}

// Eviction must not discard the whole cache, which would throw away the
// workflow currently being scanned along with everything else.
func TestMapperCache_EvictsOneEntryNotAll(t *testing.T) {
	c := NewMapperCache(4)
	for i := 0; i < 10; i++ {
		c.Get([]byte(fmt.Sprintf("content %d\n", i)))
	}
	if got := c.Len(); got != 4 {
		t.Errorf("Len = %d, want the cache held at its limit of 4", got)
	}
}
