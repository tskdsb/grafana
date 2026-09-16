package dsratelimit

import (
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// TestComputeRetryAfter_InfLimiter guards the Retry-After floor.
// rate.Inf == Limit(math.MaxFloat64), a finite float; if a future refactor makes
// ModeUnlimited construct a limiter with rate.Inf, dividing by it would return 0
// and produce a Retry-After of 0, inviting an immediate retry storm.
//
// The assertion is on observable behavior (>= 1s) rather than on the presence
// of any specific guard, so a test written with math.IsInf would not double the
// implementation's bug.
func TestComputeRetryAfter_InfLimiter(t *testing.T) {
	got := computeRetryAfter(rate.NewLimiter(rate.Inf, 0), 1, time.Now())
	if got < time.Second {
		t.Fatalf("rate.Inf limiter: want >= 1s, got %v", got)
	}
}

// TestComputeRetryAfter_ZeroLimiter locks the other guard branch (Limit == 0).
// A zero-limit limiter must not cause a divide-by-zero or return 0.
func TestComputeRetryAfter_ZeroLimiter(t *testing.T) {
	got := computeRetryAfter(rate.NewLimiter(0, 10), 1, time.Now())
	if got < time.Second {
		t.Fatalf("zero-limit limiter: want >= 1s, got %v", got)
	}
}

// TestComputeRetryAfter_Formula verifies the deficit / rate calculation.
// limit=30/s, burst=60, drain to 0 tokens, ask for 10 -> 10/30 s ≈ 333ms.
func TestComputeRetryAfter_Formula(t *testing.T) {
	now := time.Now()
	lim := rate.NewLimiter(30, 60)
	if !lim.AllowN(now, 60) {
		t.Fatalf("failed to drain initial burst")
	}
	got := computeRetryAfter(lim, 10, now)
	want := 333 * time.Millisecond
	if got < want-time.Millisecond || got > want+time.Millisecond {
		t.Fatalf("limit=30 n=10: want ~333ms, got %v", got)
	}
}

// TestComputeRetryAfter_NoMutation: computing Retry-After must not consume
// tokens.
// 100 calls to computeRetryAfter must not consume any tokens; if the
// implementation ever switched to lim.Reserve().Delay(), tokens would go
// negative and this test would fail immediately.
func TestComputeRetryAfter_NoMutation(t *testing.T) {
	now := time.Now()
	lim := rate.NewLimiter(30, 60)
	lim.AllowN(now, 60) // drain to 0
	before := lim.TokensAt(now)
	for i := 0; i < 100; i++ {
		_ = computeRetryAfter(lim, 5, now)
	}
	after := lim.TokensAt(now)
	if before != after {
		t.Fatalf("computeRetryAfter mutated limiter tokens: before=%v after=%v", before, after)
	}
}

// TestComputeRetryAfter_SurplusTokens: when the limiter already has enough
// tokens for n, we still return >= 1s (a lower bound the write429 layer
// already relies on to avoid retry storms; see write429 in middleware.go).
func TestComputeRetryAfter_SurplusTokens(t *testing.T) {
	now := time.Now()
	lim := rate.NewLimiter(30, 60) // starts with 60 tokens available
	got := computeRetryAfter(lim, 5, now)
	if got < time.Second {
		t.Fatalf("surplus tokens: want >= 1s (lower bound), got %v", got)
	}
}
