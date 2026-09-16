package dsratelimit

import (
	"fmt"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/user"
)

// TestConcurrentGetUserLimiter:
// under concurrent access, getUserLimiter for the same key must return
// the SAME *rate.Limiter instance (LoadOrStore contract), otherwise
// different goroutines would observe independent buckets and per-user
// enforcement would be broken.
func TestConcurrentGetUserLimiter(t *testing.T) {
	s := newTestService(defaultCfg())
	rule := s.resolveRule("user:1")

	const goroutines = 100
	var wg sync.WaitGroup
	seen := make(chan uintptr, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lim := s.getUserLimiter("user:1", rule)
			// Cast pointer to uintptr for uniqueness check.
			seen <- uintptrOfLimiter(lim)
		}()
	}
	wg.Wait()
	close(seen)

	unique := map[uintptr]struct{}{}
	for p := range seen {
		unique[p] = struct{}{}
	}
	require.Equal(t, 1, len(unique),
		"getUserLimiter must return the same *rate.Limiter across goroutines; saw %d distinct", len(unique))
	require.Equal(t, int64(1), s.userCount.Load(),
		"userCount must be exactly 1 after %d concurrent LoadOrStore of the same key", goroutines)
}

// TestKeyChurnLRUBound:
// creating far more keys than CacheMaxEntries followed by cleanup must
// leave the map bounded. Without this, a caller spraying random keys
// could grow the map unboundedly and evict real users.
func TestKeyChurnLRUBound(t *testing.T) {
	cfg := defaultCfg()
	cfg.CacheMaxEntries = 100
	s := newTestService(cfg)

	for i := 0; i < 500; i++ {
		u := &user.SignedInUser{UserID: int64(i)}
		c, _ := buildCtx("POST", "/api/datasources/proxy/1", nil, u)
		s.Middleware(c)
	}
	require.Equal(t, int64(500), s.userCount.Load(), "sanity: 500 keys inserted")

	s.cleanup()

	require.LessOrEqual(t, s.userCount.Load(), int64(100),
		"cleanup must bound userCount to CacheMaxEntries=100")
}

// TestFailOpen_EmptySnapshot locks the fail-open path.
// A Service with an empty rules snapshot (as would happen if the initial
// load failed) must still let requests pass rather than reject everything.
// Since default_user_burst=100, a single request under a fresh limiter
// clearly passes; the point is that the empty snapshot doesn't crash or
// return 429 spuriously.
func TestFailOpen_EmptySnapshot(t *testing.T) {
	s := newTestService(defaultCfg())
	// newTestService already installs an empty snapshot; simulate the
	// post-failed-initial-load state explicitly.
	s.rulesPtr.Store(&rulesSnapshot{
		byKey: map[string]*Rule{},
	})

	u := &user.SignedInUser{UserID: 42}
	c, rec := buildCtx("POST", "/api/datasources/proxy/1", nil, u)
	s.Middleware(c)

	require.NotEqual(t, 500, rec.Code,
		"empty snapshot must not cause 500; got %d", rec.Code)
	require.NotEqual(t, 429, rec.Code,
		"empty snapshot must not spuriously reject; got %d", rec.Code)
}

// uintptrOfLimiter returns a stable identity for a *rate.Limiter suitable
// for equality comparison via map keys.
func uintptrOfLimiter(lim any) uintptr {
	s := fmt.Sprintf("%p", lim)
	if len(s) < 3 {
		return 0
	}
	v, _ := strconv.ParseUint(s[2:], 16, 64)
	return uintptr(v)
}
