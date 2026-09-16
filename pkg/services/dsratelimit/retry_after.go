package dsratelimit

import (
	"time"

	"golang.org/x/time/rate"
)

// computeRetryAfter returns how long the caller should wait before retrying,
// without mutating the limiter. It uses lim.TokensAt (rate.go:84-89, documented
// as non-mutating) instead of lim.Reserve() — the latter would consume a token
// on every call, forming a punitive spiral and breaking the
// attempted == allowed + denied invariant.
//
// rate.Inf is defined as Limit(math.MaxFloat64) in rate.go:22 — a finite
// float, not IEEE 754 infinity. math.IsInf(float64(rate.Inf), 1) is therefore
// false, and the guard must compare directly against rate.Inf.
func computeRetryAfter(lim *rate.Limiter, n int, now time.Time) time.Duration {
	if lim.Limit() == 0 || lim.Limit() == rate.Inf {
		return time.Second
	}
	deficit := float64(n) - lim.TokensAt(now)
	if deficit <= 0 {
		return time.Second
	}
	return time.Duration(deficit / float64(lim.Limit()) * float64(time.Second))
}
