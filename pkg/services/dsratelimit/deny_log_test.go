package dsratelimit

import (
	"bytes"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/user"
)

// capturingLogger records Warn calls so tests can assert on what an operator
// would actually see. It embeds *ConcreteLogger to satisfy log.Logger without
// reimplementing the whole interface; only Warn is intercepted.
type capturingLogger struct {
	*log.ConcreteLogger
	mu    sync.Mutex
	warns []logLine
}

type logLine struct {
	msg string
	kv  map[string]any
}

func newCapturingLogger() *capturingLogger {
	return &capturingLogger{ConcreteLogger: log.NewNopLogger()}
}

func (l *capturingLogger) Warn(msg string, ctx ...any) {
	kv := map[string]any{}
	for i := 0; i+1 < len(ctx); i += 2 {
		kv[fmt.Sprint(ctx[i])] = ctx[i+1]
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warns = append(l.warns, logLine{msg: msg, kv: kv})
}

func (l *capturingLogger) lines() []logLine {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]logLine(nil), l.warns...)
}

// withCapturingLogger swaps in a capturing logger and returns it.
func withCapturingLogger(s *Service) *capturingLogger {
	cl := newCapturingLogger()
	s.logger = cl
	return cl
}

// TestDenyLogging_IdentifiesTheCaller is the point of the deny log: metrics
// carry only {datasource, kind, reason} (no per-identity label, on purpose, to keep
// cardinality bounded), so the log is the only place the operator can learn
// *which* caller is being throttled.
func TestDenyLogging_IdentifiesTheCaller(t *testing.T) {
	cfg := defaultCfg()
	cfg.DefaultUserRate = 1
	cfg.DefaultUserBurst = 1
	s := newTestService(cfg)
	cl := withCapturingLogger(s)

	u := &user.SignedInUser{UserID: 42, IsServiceAccount: true}
	// First request consumes the single token, second is denied.
	for i := 0; i < 2; i++ {
		c, _ := buildCtx("POST", "/api/ds/query", []byte(`{"queries":[{}]}`), u)
		s.Middleware(c)
	}

	lines := cl.lines()
	require.Len(t, lines, 1, "expected exactly one deny log line")

	got := lines[0]
	require.Equal(t, "datasource query rate limit exceeded", got.msg)
	require.Equal(t, "sa:42", got.kv["key"],
		"the log must name the caller — this is the only place identity appears")
	require.Equal(t, "user", got.kv["reason"])
	require.Equal(t, "/api/ds/query", got.kv["path"])
	require.Equal(t, 1, got.kv["tokens_this_request"])
	require.Equal(t, int64(1), got.kv["denied_since_last_log"])
}

// TestDenyLogging_EnforcedFlagDistinguishesShadow locks the field an operator
// needs during the shadow rollout: shadow denials must be visibly marked as
// "would have been denied" rather than "was denied".
func TestDenyLogging_EnforcedFlagDistinguishesShadow(t *testing.T) {
	for _, tc := range []struct {
		name         string
		shadow       bool
		wantEnforced bool
	}{
		{"shadow mode reports not enforced", true, false},
		{"live mode reports enforced", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := defaultCfg()
			cfg.ShadowMode = tc.shadow
			cfg.DefaultUserRate = 1
			cfg.DefaultUserBurst = 1
			s := newTestService(cfg)
			cl := withCapturingLogger(s)

			u := &user.SignedInUser{UserID: 7, IsServiceAccount: true}
			for i := 0; i < 2; i++ {
				c, _ := buildCtx("POST", "/api/ds/query", []byte(`{"queries":[{}]}`), u)
				s.Middleware(c)
			}

			lines := cl.lines()
			require.Len(t, lines, 1)
			require.Equal(t, tc.wantEnforced, lines[0].kv["enforced"])
		})
	}
}

// TestDenyLogging_ThrottledPerKey is the reason the throttle exists: a denied
// key is by definition being hit hard, so one line per denial would turn a
// rate-limit event into a log flood. The volume must still be recoverable
// from denied_since_last_log.
func TestDenyLogging_ThrottledPerKey(t *testing.T) {
	cfg := defaultCfg()
	cfg.DefaultUserRate = 1
	cfg.DefaultUserBurst = 1
	s := newTestService(cfg)
	cl := withCapturingLogger(s)

	u := &user.SignedInUser{UserID: 99, IsServiceAccount: true}
	const total = 200
	for i := 0; i < total; i++ {
		c, _ := buildCtx("POST", "/api/ds/query", []byte(`{"queries":[{}]}`), u)
		s.Middleware(c)
	}

	lines := cl.lines()
	require.Len(t, lines, 1,
		"%d denials must collapse into a single line within one interval", total-1)

	// The single line must not under-report: it carries the count accumulated
	// so far, and the remaining denials stay pending on the counter.
	logged := lines[0].kv["denied_since_last_log"].(int64)
	v, ok := s.userBuckets.Load("sa:99")
	require.True(t, ok)
	pending := v.(*userEntry).denyLog.deniedSinceLog.Load()

	require.Equal(t, int64(total-1), logged+pending,
		"every denial must be accounted for: logged=%d pending=%d", logged, pending)
}

// TestDenyLogging_LogsAgainAfterInterval proves the throttle is a throttle,
// not a one-shot: a key that keeps being denied must keep producing evidence.
func TestDenyLogging_LogsAgainAfterInterval(t *testing.T) {
	cfg := defaultCfg()
	cfg.DefaultUserRate = 1
	cfg.DefaultUserBurst = 1
	s := newTestService(cfg)
	cl := withCapturingLogger(s)

	u := &user.SignedInUser{UserID: 5, IsServiceAccount: true}
	for i := 0; i < 3; i++ {
		c, _ := buildCtx("POST", "/api/ds/query", []byte(`{"queries":[{}]}`), u)
		s.Middleware(c)
	}
	require.Len(t, cl.lines(), 1)

	// Backdate the last-log stamp instead of sleeping a minute.
	v, ok := s.userBuckets.Load("sa:5")
	require.True(t, ok)
	e := v.(*userEntry)
	e.denyLog.lastDenyLogUnixNano.Store(time.Now().Add(-2 * denyLogInterval).UnixNano())

	c, _ := buildCtx("POST", "/api/ds/query", []byte(`{"queries":[{}]}`), u)
	s.Middleware(c)

	require.Len(t, cl.lines(), 2,
		"a persistently throttled key must log again once the interval passes")
}

// TestDenyLogging_PerKeyIndependence guards against a global throttle: one
// noisy caller must not suppress evidence about a different caller.
func TestDenyLogging_PerKeyIndependence(t *testing.T) {
	cfg := defaultCfg()
	cfg.DefaultUserRate = 1
	cfg.DefaultUserBurst = 1
	s := newTestService(cfg)
	cl := withCapturingLogger(s)

	for _, uid := range []int64{1, 2, 3} {
		u := &user.SignedInUser{UserID: uid, IsServiceAccount: true}
		for i := 0; i < 5; i++ {
			c, _ := buildCtx("POST", "/api/ds/query", []byte(`{"queries":[{}]}`), u)
			s.Middleware(c)
		}
	}

	keys := map[string]bool{}
	for _, l := range cl.lines() {
		keys[fmt.Sprint(l.kv["key"])] = true
	}
	require.Equal(t, map[string]bool{"sa:1": true, "sa:2": true, "sa:3": true}, keys,
		"each denied key must be reported independently")
}

// TestDenyLogging_AllowedRequestsAreSilent keeps the happy path quiet — the
// hot path must not log on success.
func TestDenyLogging_AllowedRequestsAreSilent(t *testing.T) {
	s := newTestService(defaultCfg()) // generous defaults: 30/100
	cl := withCapturingLogger(s)

	u := &user.SignedInUser{UserID: 1, IsServiceAccount: true}
	for i := 0; i < 20; i++ {
		c, _ := buildCtx("POST", "/api/ds/query", []byte(`{"queries":[{}]}`), u)
		s.Middleware(c)
	}
	require.Empty(t, cl.lines(), "allowed requests must not log")
}

// TestDenyLogging_BlockedMode covers the fast path: it must report the denial
// with the caller identity, and must still not construct a rate.Limiter.
//
// This asserted three unthrottled lines for three requests until anonymous
// traffic became blocked by default; see
// TestDenyLog_BlockedModeIsThrottled for why that had to change.
func TestDenyLogging_BlockedMode(t *testing.T) {
	rule := &Rule{Kind: string(KindSA), Target: "77", Mode: string(ModeBlocked)}
	s := newTestService(defaultCfg(), rule)
	cl := withCapturingLogger(s)

	u := &user.SignedInUser{UserID: 77, IsServiceAccount: true}
	for i := 0; i < 3; i++ {
		c, _ := buildCtx("POST", "/api/ds/query", []byte(`{"queries":[{}]}`), u)
		s.Middleware(c)
	}

	lines := cl.lines()
	require.Len(t, lines, 1,
		"blocked-mode denials are throttled per key: 3 requests inside one "+
			"throttle interval must produce one line")
	require.Equal(t, "datasource query blocked by rule", lines[0].msg)
	require.Equal(t, "sa:77", lines[0].kv["key"])
	require.Equal(t, "blocked", lines[0].kv["reason"])

	// No denial may be lost to throttling: the emitted line plus what is still
	// pending must account for all 3 requests.
	v, ok := s.blockedLog.Load("sa:77")
	require.True(t, ok, "the blocked key must have a throttle entry")
	pending := v.(*denyLogThrottle).deniedSinceLog.Load()
	reported, _ := lines[0].kv["denied_since_last_log"].(int64)
	require.Equal(t, int64(3), reported+pending,
		"throttling must defer denials, not drop them")

	// The fast path must not have created a limiter (that is its purpose).
	_, ok = s.userBuckets.Load("sa:77")
	require.False(t, ok, "blocked mode must not construct a rate.Limiter")
}

// TestDenyLogging_NoRaceOnSharedKey runs the deny path concurrently for one
// key. Meaningful only under -race; asserts no lost denials.
func TestDenyLogging_NoRaceOnSharedKey(t *testing.T) {
	cfg := defaultCfg()
	cfg.DefaultUserRate = 1
	cfg.DefaultUserBurst = 1
	s := newTestService(cfg)
	cl := withCapturingLogger(s)

	u := &user.SignedInUser{UserID: 8, IsServiceAccount: true}
	const goroutines, each = 8, 50

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				c, _ := buildCtx("POST", "/api/ds/query", []byte(`{"queries":[{}]}`), u)
				s.Middleware(c)
			}
		}()
	}
	wg.Wait()

	var logged int64
	for _, l := range cl.lines() {
		logged += l.kv["denied_since_last_log"].(int64)
	}
	v, ok := s.userBuckets.Load("sa:8")
	require.True(t, ok)
	pending := v.(*userEntry).denyLog.deniedSinceLog.Load()

	// One request wins the only token; everything else is denied and must be
	// accounted for exactly once, whether logged or still pending.
	require.Equal(t, int64(goroutines*each-1), logged+pending,
		"denials must not be lost or double-counted under concurrency")
}

// TestDenyLog_DistinguishesPermanentFromTransient locks the one denial that is
// easy to misread as the limiter working correctly.
//
// A request costing more than burst is refused on every attempt (x/time/rate
// gates on `ok := n <= lim.burst`, rate.go:371 — there is no queueing), so the
// panel never loads and retrying does not help. A request that merely ran out
// of tokens succeeds a moment later. In aggregate both look like a modest
// stream of 429s, so without a distinct signal the permanent case reads as
// normal throttling.
//
// Both directions are asserted: the oversized request must be marked, and the
// transient one must NOT be, or the marker would fire on every denial and mean
// nothing.
func TestDenyLog_DistinguishesPermanentFromTransient(t *testing.T) {
	body := func(nq int) []byte {
		b := bytes.NewBufferString(`{"queries":[`)
		for i := 0; i < nq; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			// instant+range => 2 tokens per query
			b.WriteString(`{"instant":true,"range":true}`)
		}
		b.WriteString(`]}`)
		return b.Bytes()
	}

	for _, tc := range []struct {
		name          string
		queries       int
		wantPermanent bool
		wantReason    string
	}{
		// 21 queries * 2 = 42 tokens > burst 40: never admissible.
		{"oversized_is_permanent", 21, true, "user_oversized"},
		// 5 queries * 2 = 10 tokens <= burst: refills and succeeds later.
		{"transient_is_not_permanent", 5, false, "user"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := defaultCfg()
			cfg.DefaultUserRate = 20
			cfg.DefaultUserBurst = 40
			cfg.ShadowMode = false

			s := newTestService(cfg)
			cl := withCapturingLogger(s)
			u := &user.SignedInUser{UserID: 7}

			denied := 0
			for i := 0; i < 12; i++ {
				c, rec := buildCtx("POST", dsQueryPath, body(tc.queries), u)
				s.Middleware(c)
				if rec.Code == http.StatusTooManyRequests {
					denied++
				}
			}
			require.NotZero(t, denied, "test needs at least one denial to inspect")

			lines := cl.lines()
			require.NotEmpty(t, lines, "a denial must be logged")

			require.Equal(t, tc.wantPermanent, lines[0].kv["permanent"],
				"permanent flag wrong: an oversized request can never succeed, "+
					"a throttled one can; conflating them hides a panel that never loads")
			require.Equal(t, tc.wantReason, lines[0].kv["reason"],
				"reason must separate the permanent case so it is filterable in metrics")
		})
	}
}

// TestDenyLog_BlockedModeIsThrottled locks throttling on the mode=blocked path.
//
// This path logged every request until anonymous traffic became blocked by
// default. That default turned "anon:anon" into a shared key that ordinary
// unauthenticated requests land on, so a public dashboard or a scraper produced
// one line per request: measured at 500 anonymous requests, 500 lines, 1:1.
//
// The count must survive throttling, otherwise quieting the log would also
// destroy the evidence of how much traffic was blocked -- the thing an operator
// needs before turning enforcement on.
func TestDenyLog_BlockedModeIsThrottled(t *testing.T) {
	const N = 500

	cfg := defaultCfg()
	cfg.ShadowMode = true // the mode this ships in
	s := newTestService(cfg)
	cl := withCapturingLogger(s)

	for i := 0; i < N; i++ {
		c, _ := buildCtx("POST", dsQueryPath,
			[]byte(`{"queries":[{"instant":true}]}`), &user.SignedInUser{})
		c.IsAnonymous = true
		s.Middleware(c)
	}

	lines := cl.lines()
	require.NotEmpty(t, lines, "a blocked key must still be reported at least once")
	require.LessOrEqual(t, len(lines), 2,
		"blocked denials must be throttled per key: %d requests produced %d lines. "+
			"Anonymous traffic is blocked by default, so this is ordinary "+
			"unauthenticated traffic, not a hand-set rule", N, len(lines))
	require.Equal(t, "datasource query blocked by rule", lines[0].msg,
		"the blocked path must be the one under test")

	var reported int64
	for _, l := range lines {
		v, ok := l.kv["denied_since_last_log"].(int64)
		require.True(t, ok, "each blocked line must carry denied_since_last_log")
		reported += v
	}

	// Nothing may be dropped. A throttled line reports only what had piled up
	// when it was emitted, so within this one-minute window the rest is still
	// sitting in the counter waiting for the next line -- reported plus
	// residual must equal every blocked request. Asserting the residual (not
	// just the reported total) is what proves throttling defers denials instead
	// of discarding them.
	v, ok := s.blockedLog.Load("anon:anon")
	require.True(t, ok, "the blocked key must have a throttle entry")
	residual := v.(*denyLogThrottle).deniedSinceLog.Load()

	require.Equal(t, int64(N), reported+residual,
		"throttling must defer denials, not drop them: %d reported + %d pending "+
			"must equal %d blocked requests", reported, residual, N)
	require.NotZero(t, residual,
		"with %d requests inside one throttle interval most must still be "+
			"pending, or the throttle is not actually throttling", N)
}
