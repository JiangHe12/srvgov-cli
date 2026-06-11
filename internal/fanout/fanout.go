// Package fanout runs bounded, independent work across named targets.
package fanout

import (
	"context"
	"sort"
	"sync"
)

// Target carries one named target and its command-specific value.
type Target[T any] struct {
	Name  string
	Host  string
	Value T
}

// Result is one target's independent result.
type Result struct {
	Target string
	Host   string
	Data   any
	Err    error
}

// Run executes every target with bounded concurrency and returns target-sorted results.
func Run[T any](
	ctx context.Context,
	targets []Target[T],
	concurrency int,
	run func(context.Context, Target[T]) (any, error),
) []Result {
	if len(targets) == 0 {
		return []Result{}
	}
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > len(targets) {
		concurrency = len(targets)
	}

	jobs := make(chan Target[T])
	results := make(chan Result, len(targets))
	var workers sync.WaitGroup
	workers.Add(concurrency)
	for range concurrency {
		go func() {
			defer workers.Done()
			for target := range jobs {
				data, err := run(ctx, target)
				results <- Result{
					Target: target.Name,
					Host:   target.Host,
					Data:   data,
					Err:    err,
				}
			}
		}()
	}

	go func() {
		for _, target := range targets {
			jobs <- target
		}
		close(jobs)
		workers.Wait()
		close(results)
	}()

	out := make([]Result, 0, len(targets))
	for result := range results {
		out = append(out, result)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Target < out[j].Target
	})
	return out
}
