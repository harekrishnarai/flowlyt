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
	for i := 0; i < mapperCacheLimit+50; i++ {
		NewLineMapper([]byte(fmt.Sprintf("unique content %d\n", i)))
	}

	mapperCacheMu.RLock()
	size := len(mapperCache)
	mapperCacheMu.RUnlock()

	if size > mapperCacheLimit {
		t.Errorf("cache grew to %d entries, expected at most %d", size, mapperCacheLimit)
	}
}
