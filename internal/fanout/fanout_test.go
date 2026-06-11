package fanout

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunLimitsConcurrencyContinuesAfterErrorsAndSortsResults(t *testing.T) {
	t.Parallel()

	targets := []Target[int]{
		{Name: "charlie", Host: "charlie.example:22", Value: 3},
		{Name: "alpha", Host: "alpha.example:22", Value: 1},
		{Name: "bravo", Host: "bravo.example:22", Value: 2},
	}
	var active atomic.Int32
	var maximum atomic.Int32
	var mu sync.Mutex
	started := make([]string, 0, len(targets))

	results := Run(context.Background(), targets, 2, func(_ context.Context, target Target[int]) (any, error) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			previous := maximum.Load()
			if current <= previous || maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		mu.Lock()
		started = append(started, target.Name)
		mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		if target.Name == "bravo" {
			return nil, context.DeadlineExceeded
		}
		return target.Value, nil
	})

	if maximum.Load() != 2 {
		t.Fatalf("maximum concurrency = %d, want 2", maximum.Load())
	}
	if len(started) != len(targets) {
		t.Fatalf("started = %#v, want every target", started)
	}
	if len(results) != 3 ||
		results[0].Target != "alpha" ||
		results[1].Target != "bravo" ||
		results[2].Target != "charlie" {
		t.Fatalf("results = %#v, want target order alpha, bravo, charlie", results)
	}
	if results[1].Err == nil || results[0].Data != 1 || results[2].Data != 3 {
		t.Fatalf("results = %#v", results)
	}
}
