package crack

import "fmt"

const (
	Digits     = "0123456789"
	LatinLower = "abcdefghijklmnopqrstuvwxyz"
	LatinUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	Symbols    = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"

	// Soft limit: show a warning, still allow start.
	WarnCombinations uint64 = 2_000_000
	// Hard limit: refuse to start (too large for interactive use).
	MaxCombinations uint64 = 50_000_000
)

// Dict is the password-alphabet configuration (mirrors the Rust UI).
type Dict struct {
	UseDigits     bool
	UseLatinLower bool
	UseLatinUpper bool
	UseSymbols    bool
	MinLen        int
	MaxLen        int
}

func DefaultDict() Dict {
	return Dict{
		UseDigits: true,
		MinLen:    1,
		MaxLen:    4,
	}
}

func (d Dict) Charset() string {
	var s string
	if d.UseDigits {
		s += Digits
	}
	if d.UseLatinLower {
		s += LatinLower
	}
	if d.UseLatinUpper {
		s += LatinUpper
	}
	if d.UseSymbols {
		s += Symbols
	}
	return s
}

// CombinationCount returns total candidates, or an error on overflow / empty.
func (d Dict) CombinationCount() (uint64, error) {
	cs := d.Charset()
	n := uint64(len(cs))
	if n == 0 || d.MinLen <= 0 || d.MinLen > d.MaxLen {
		return 0, nil
	}
	var total uint64
	for length := d.MinLen; length <= d.MaxLen; length++ {
		part := uint64(1)
		for i := 0; i < length; i++ {
			if part > (^uint64(0))/n {
				return 0, fmt.Errorf("combination count overflow")
			}
			part *= n
		}
		if total > (^uint64(0))-part {
			return 0, fmt.Errorf("combination count overflow")
		}
		total += part
	}
	return total, nil
}

// IndexToPassword maps a dense index in [0, base^len) to a password string.
func IndexToPassword(idx uint64, charset []byte, length int) string {
	base := uint64(len(charset))
	if base == 0 || length <= 0 {
		return ""
	}
	buf := make([]byte, length)
	for i := length - 1; i >= 0; i-- {
		buf[i] = charset[idx%base]
		idx /= base
	}
	return string(buf)
}

// PowU64 returns base^exp, panics only on caller misuse (base==0).
func PowU64(base uint64, exp int) uint64 {
	var r uint64 = 1
	for i := 0; i < exp; i++ {
		r *= base
	}
	return r
}
