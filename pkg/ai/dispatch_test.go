package ai

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harekrishnarai/flowlyt/v2/pkg/rules"
)

// slowClient records concurrency and optionally stalls the first batch.
type slowClient struct {
	delay       time.Duration
	firstStalls time.Duration

	inFlight    atomic.Int64
	maxInFlight atomic.Int64
	batches     atomic.Int64
}

func (s *slowClient) VerifyFinding(ctx context.Context, f rules.Finding) (*VerificationResult, error) {
	return &VerificationResult{Confidence: 0.5, Reasoning: "single"}, nil
}

func (s *slowClient) VerifyBatch(ctx context.Context, class string, findings []ContextualFinding) ([]BatchVerificationResult, error) {
	cur := s.inFlight.Add(1)
	for {
		max := s.maxInFlight.Load()
		if cur <= max || s.maxInFlight.CompareAndSwap(max, cur) {
			break
		}
	}
	defer s.inFlight.Add(-1)

	d := s.delay
	if s.batches.Add(1) == 1 && s.firstStalls > 0 {
		d = s.firstStalls
	}

	select {
	case <-time.After(d):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	out := make([]BatchVerificationResult, len(findings))
	for i, cf := range findings {
		out[i] = BatchVerificationResult{
			Index:  i,
			Result: &VerificationResult{Confidence: 0.9, Reasoning: cf.Finding.RuleID},
		}
	}
	return out, nil
}

func (s *slowClient) GetProvider() Provider { return ProviderOpenAI }
func (s *slowClient) Close() error          { return nil }

func makeFindings(n int) []rules.Finding {
	out := make([]rules.Finding, n)
	for i := range out {
		out[i] = rules.Finding{
			RuleID:   fmt.Sprintf("RULE_%03d", i),
			Evidence: fmt.Sprintf("evidence %d", i),
			Category: rules.InjectionAttack,
			FilePath: "wf.yml",
		}
	}
	return out
}

// Batches must actually be dispatched concurrently; they previously ran one
// after another, so a hundred findings cost twenty sequential round-trips.
func TestAnalyzeFindings_DispatchesBatchesConcurrently(t *testing.T) {
	client := &slowClient{delay: 50 * time.Millisecond}
	a := NewAnalyzerWithOptions(client, Options{RequestTimeout: 5 * time.Second, Workers: 4})

	// 40 findings at batchSize 5 = 8 batches.
	start := time.Now()
	got, err := a.AnalyzeFindings(context.Background(), makeFindings(40))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 40 {
		t.Fatalf("expected 40 results, got %d", len(got))
	}

	if max := client.maxInFlight.Load(); max < 2 {
		t.Errorf("expected concurrent dispatch, peak in-flight was %d", max)
	}
	// Sequentially this would be 8 x 50ms = 400ms.
	if elapsed > 300*time.Millisecond {
		t.Errorf("dispatch looks sequential: took %v for 8 batches of 50ms with 4 workers", elapsed)
	}
}

// Results must be assembled in a deterministic order regardless of which batch
// finishes first, or reports would shuffle between runs.
func TestAnalyzeFindings_OrderIsDeterministic(t *testing.T) {
	var reference []string
	for run := 0; run < 5; run++ {
		client := &slowClient{delay: time.Millisecond}
		a := NewAnalyzerWithOptions(client, Options{RequestTimeout: time.Second, Workers: 4})

		got, err := a.AnalyzeFindings(context.Background(), makeFindings(30))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		order := make([]string, len(got))
		for i, ef := range got {
			order[i] = ef.Finding.RuleID
		}
		if run == 0 {
			reference = order
			continue
		}
		for i := range order {
			if order[i] != reference[i] {
				t.Fatalf("run %d differs at %d: %s vs %s", run, i, order[i], reference[i])
			}
		}
	}
}

// A single stalled batch must not consume the time budget of the others. The
// old code derived one deadline from the total finding count, so an early stall
// failed everything after it.
func TestAnalyzeFindings_SlowBatchDoesNotStarveOthers(t *testing.T) {
	client := &slowClient{delay: 10 * time.Millisecond, firstStalls: 2 * time.Second}
	a := NewAnalyzerWithOptions(client, Options{RequestTimeout: 100 * time.Millisecond, Workers: 4})

	got, err := a.AnalyzeFindings(context.Background(), makeFindings(40))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 40 {
		t.Fatalf("expected all 40 findings back, got %d", len(got))
	}

	// The stalled batch falls back to individual calls; every other batch must
	// still have produced a verification.
	verified := 0
	for _, ef := range got {
		if ef.AIVerification != nil {
			verified++
		}
	}
	if verified < 30 {
		t.Errorf("expected the non-stalled batches to succeed, only %d/40 verified", verified)
	}
}
