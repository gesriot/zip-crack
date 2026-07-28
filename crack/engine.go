package crack

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Result of a crack run.
type Result struct {
	Password  string
	Found     bool
	Cancelled bool
	Tried     uint64
	Elapsed   time.Duration
}

// ProgressFunc is invoked periodically (from a side goroutine).
// tried is the approximate number of attempts so far.
type ProgressFunc func(tried uint64)

// Crack tries all passwords defined by dict against the tester.
// workers <= 0 → WorkersFor is not used here; caller should pass WorkersFor(backend).
// If workers <= 0, defaults to NumCPU*2.
func Crack(ctx context.Context, tester PasswordTester, dict Dict, workers int, onProgress ProgressFunc) (Result, error) {
	start := time.Now()
	if tester == nil {
		return Result{Elapsed: time.Since(start)}, fmt.Errorf("nil tester")
	}
	cs := dict.Charset()
	if len(cs) == 0 {
		return Result{Elapsed: time.Since(start)}, fmt.Errorf("empty charset")
	}
	if dict.MinLen <= 0 || dict.MinLen > dict.MaxLen {
		return Result{Elapsed: time.Since(start)}, fmt.Errorf("invalid length range")
	}
	total, err := dict.CombinationCount()
	if err != nil {
		return Result{Elapsed: time.Since(start)}, err
	}
	if total == 0 {
		return Result{Elapsed: time.Since(start)}, fmt.Errorf("no combinations")
	}
	if total > MaxCombinations {
		return Result{Elapsed: time.Since(start)}, fmt.Errorf(
			"too many combinations (%d); limit is %d", total, MaxCombinations)
	}

	if workers <= 0 {
		workers = WorkersFor(BackendZipCrypto)
	}

	charset := []byte(cs)
	var tried atomic.Uint64
	var found atomic.Value // stores string when discovered

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stopProgress := make(chan struct{})
	if onProgress != nil {
		go func() {
			t := time.NewTicker(100 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-stopProgress:
					onProgress(tried.Load())
					return
				case <-t.C:
					onProgress(tried.Load())
				}
			}
		}()
	}
	defer close(stopProgress)

	for length := dict.MinLen; length <= dict.MaxLen; length++ {
		if ctx.Err() != nil {
			break
		}
		if found.Load() != nil {
			break
		}

		base := uint64(len(charset))
		span := PowU64(base, length)
		var next atomic.Uint64
		var wg sync.WaitGroup
		wg.Add(workers)

		for w := 0; w < workers; w++ {
			go func() {
				defer wg.Done()
				for {
					if ctx.Err() != nil {
						return
					}
					if found.Load() != nil {
						return
					}
					i := next.Add(1) - 1
					if i >= span {
						return
					}
					pwd := IndexToPassword(i, charset, length)
					if tester.TestPassword(pwd) {
						if found.CompareAndSwap(nil, pwd) {
							cancel()
						}
						tried.Add(1)
						return
					}
					tried.Add(1)
				}
			}()
		}
		wg.Wait()
	}

	elapsed := time.Since(start)
	if p, ok := found.Load().(string); ok && p != "" {
		return Result{Password: p, Found: true, Tried: tried.Load(), Elapsed: elapsed}, nil
	}
	cancelled := ctx.Err() != nil
	return Result{Found: false, Cancelled: cancelled, Tried: tried.Load(), Elapsed: elapsed}, nil
}
