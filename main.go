// Command zip_crack: high-performance password search for ZIP / 7z / Office.
//
// Usage:
//
//	zip_crack [flags] <archive>
//
// Flags mirror the desktop UI: character classes and length range.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"zip_crack/crack"
)

func main() {
	digits := flag.Bool("digits", true, "use digits 0-9")
	lower := flag.Bool("lower", false, "use latin a-z")
	upper := flag.Bool("upper", false, "use latin A-Z")
	symbols := flag.Bool("symbols", false, "use symbol characters")
	minLen := flag.Int("min", 1, "minimum password length")
	maxLen := flag.Int("max", 4, "maximum password length")
	workers := flag.Int("workers", 0, "worker goroutines (0 = auto by backend)")
	quiet := flag.Bool("q", false, "quiet: only print the password or failure")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] <archive>\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(2)
	}
	path := flag.Arg(0)

	dict := crack.Dict{
		UseDigits:     *digits,
		UseLatinLower: *lower,
		UseLatinUpper: *upper,
		UseSymbols:    *symbols,
		MinLen:        *minLen,
		MaxLen:        *maxLen,
	}

	total, err := dict.CombinationCount()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if total == 0 {
		fmt.Fprintln(os.Stderr, "error: no combinations (check charset / length)")
		os.Exit(1)
	}
	if total > crack.MaxCombinations {
		fmt.Fprintf(os.Stderr, "error: too many combinations (%d); limit %d\n", total, crack.MaxCombinations)
		os.Exit(1)
	}

	info, err := crack.Probe(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	w := *workers
	if w <= 0 {
		w = crack.WorkersFor(info.Backend)
	}

	if !*quiet {
		fmt.Fprintf(os.Stderr, "archive: %s\n", path)
		fmt.Fprintf(os.Stderr, "type:    %s · %s\n", info.TypeLabel, info.Backend)
		if info.Warning != "" {
			fmt.Fprintf(os.Stderr, "note:    %s\n", info.Warning)
		}
		fmt.Fprintf(os.Stderr, "charset: %q (%d chars)\n", dict.Charset(), len(dict.Charset()))
		fmt.Fprintf(os.Stderr, "length:  %d..%d  combinations: %d  workers: %d\n",
			dict.MinLen, dict.MaxLen, total, w)
		if total > crack.WarnCombinations {
			fmt.Fprintf(os.Stderr, "warning: large search space (%d)\n", total)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var lastTried atomic.Uint64
	var onProgress crack.ProgressFunc
	if !*quiet {
		onProgress = func(tried uint64) {
			lastTried.Store(tried)
			fmt.Fprintf(os.Stderr, "\rtried: %d / %d", tried, total)
		}
	}

	res, err := crack.Crack(ctx, info.Tester, dict, w, onProgress)
	if !*quiet {
		fmt.Fprintln(os.Stderr)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	if res.Found {
		if *quiet {
			fmt.Println(res.Password)
		} else {
			fmt.Printf("password: %s\n", res.Password)
			fmt.Printf("time: %.3fs  tried: %d\n", res.Elapsed.Seconds(), res.Tried)
		}
		os.Exit(0)
	}

	if !*quiet {
		if res.Cancelled {
			fmt.Fprintf(os.Stderr, "cancelled (tried %d in %.3fs)\n", res.Tried, res.Elapsed.Seconds())
		} else {
			fmt.Fprintf(os.Stderr, "password not found (tried %d in %.3fs)\n", res.Tried, res.Elapsed.Seconds())
		}
	}
	os.Exit(1)
}
