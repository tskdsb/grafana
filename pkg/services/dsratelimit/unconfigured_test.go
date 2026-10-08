package dsratelimit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"

	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// An unset limit must mean "no limit", on both layers.
//
// This is not a style preference. Before the change, an operator who set
// enabled=true but never filled in default_user_rate got a rule of
// mode=limited with rate=0, which x/time/rate reads as "refuse everything":
// twenty requests, twenty refusals, the whole query API down because a number
// was missing rather than wrong. The in-flight cap had the inverse problem --
// it could only be changed by restarting the process.
//
// Both now resolve the same way: identity rule, then default rule, then ini,
// and a non-positive result anywhere in that chain means the layer stays out
// of the way.

func i64(v int64) *int64 { return &v }

// waitEntered blocks until n requests have reached the handler, or fails the
// test if they do not.
//
// Written after a mutation run took 601 seconds instead of 1.5: with the
// per-identity override disabled, only one request was admitted and a bare
// `<-h.entered` loop waited for the other two until Go's own ten-minute
// timeout killed it. A test that detects a regression only by hanging is
// nearly useless in CI -- the timeout says "something is stuck", not which
// cap failed to apply.
func waitEntered(t *testing.T, h *blockingHandler, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-h.entered:
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d of %d requests reached the handler; "+
				"the rest were refused, so the cap in force is lower than expected", i, n)
		}
	}
}

func TestUnconfiguredQPSDefault_AdmitsRatherThanRefuses(t *testing.T) {
	cfg := defaultCfg()
	cfg.DefaultUserRate = 0 // never configured
	cfg.DefaultUserBurst = 0
	s := newTestService(cfg)

	rule := s.resolveRule("user:1")
	require.Equal(t, string(ModeUnlimited), rule.Mode,
		"an identity with no configured baseline must resolve to unlimited; "+
			"mode=limited with a zero rate is what took the query API down")

	// Driven through the middleware rather than the limiter directly. The
	// exemption lives in the middleware's unlimited branch -- reading the
	// limiter would assert how the exemption is implemented instead of that
	// requests get served, and would fail even when the behaviour is correct.
	u := &user.SignedInUser{UserID: 1, OrgID: 1}
	for i := 0; i < 20; i++ {
		c, rec := buildCtx("POST", "/api/ds/query", []byte(`{"queries":[{}]}`), u)
		s.Middleware(c)
		require.Equal(t, http.StatusOK, rec.Code,
			"request %d refused with no limit configured", i)
	}
}

func TestUnconfiguredQPSDefault_StillHonoursAnExplicitRule(t *testing.T) {
	// "Unconfigured means unlimited" must not become "unlimited wins": an
	// identity with its own rule is configured, and that rule still applies
	// even when the deployment-wide baseline is absent.
	cfg := defaultCfg()
	cfg.DefaultUserRate = 0
	cfg.DefaultUserBurst = 0
	s := newTestService(cfg, &Rule{
		Kind: string(KindUser), Target: "7",
		Mode: string(ModeLimited), Rate: i64(1), Burst: i64(1),
	})

	require.Equal(t, string(ModeLimited), s.resolveRule("user:7").Mode)

	u := &user.SignedInUser{UserID: 7, OrgID: 1}
	c1, rec1 := buildCtx("POST", "/api/ds/query", []byte(`{"queries":[{}]}`), u)
	s.Middleware(c1)
	require.Equal(t, http.StatusOK, rec1.Code, "burst=1 should admit the first request")

	c2, rec2 := buildCtx("POST", "/api/ds/query", []byte(`{"queries":[{}]}`), u)
	s.Middleware(c2)
	require.Equal(t, http.StatusTooManyRequests, rec2.Code,
		"the explicit limit was not applied")
}

func TestUnconfiguredConcurrency_DoesNotCap(t *testing.T) {
	cfg := concCfg(0) // no cap configured
	s := newTestService(cfg)

	require.Equal(t, int64(0), s.concurrencyLimit(s.rulesPtr.Load(), "user:1"),
		"a limit must not appear from nowhere")

	// Ten simultaneous requests, none of which may be refused.
	const n = 10
	h := newBlockingHandler(n)
	codes := make(chan int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- concRequest(s, "/api/ds/query", 1, h.ServeHTTP).Code
		}()
	}
	waitEntered(t, h, n)
	close(h.release)
	wg.Wait()
	close(codes)

	for c := range codes {
		require.NotEqual(t, http.StatusTooManyRequests, c,
			"a request was refused with no cap configured")
	}
}

func TestConcurrencyLimit_ResolvesIdentityThenDefaultThenIni(t *testing.T) {
	// The precedence an operator has to be able to predict. Asserted on the
	// resolver directly so a failure names which tier is wrong, rather than
	// surfacing as an unexplained 429 count.
	cases := []struct {
		name  string
		cfg   Config
		rules []*Rule
		key   string
		want  int64
	}{
		{
			name: "ini only",
			cfg:  concCfg(3),
			key:  "user:1",
			want: 3,
		},
		{
			name:  "default rule overrides ini",
			cfg:   concCfg(3),
			rules: []*Rule{{Kind: string(KindDefault), Target: DefaultTarget, Mode: string(ModeLimited), Concurrency: i64(5)}},
			key:   "user:1",
			want:  5,
		},
		{
			name: "identity rule overrides default rule",
			cfg:  concCfg(3),
			rules: []*Rule{
				{Kind: string(KindDefault), Target: DefaultTarget, Mode: string(ModeLimited), Concurrency: i64(5)},
				{Kind: string(KindUser), Target: "1", Mode: string(ModeLimited), Concurrency: i64(9)},
			},
			key:  "user:1",
			want: 9,
		},
		{
			name: "identity rule without a concurrency value falls through",
			cfg:  concCfg(3),
			rules: []*Rule{
				{Kind: string(KindUser), Target: "1", Mode: string(ModeLimited), Rate: i64(50), Burst: i64(50)},
			},
			key:  "user:1",
			want: 3,
		},
		{
			name: "zero in a rule means uncapped, not unset",
			cfg:  concCfg(3),
			rules: []*Rule{
				{Kind: string(KindUser), Target: "1", Mode: string(ModeLimited), Concurrency: i64(0)},
			},
			key:  "user:1",
			want: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestService(tc.cfg, tc.rules...)
			require.Equal(t, tc.want, s.concurrencyLimit(s.rulesPtr.Load(), tc.key))
		})
	}
}

func TestConcurrencyCap_PerIdentityOverrideIsEnforced(t *testing.T) {
	// The table above is resolution only. This drives real traffic: two
	// identities, different caps, both enforced independently.
	s := newTestService(concCfg(1),
		&Rule{Kind: string(KindUser), Target: "2", Mode: string(ModeLimited), Concurrency: i64(3)},
	)

	// user 1 has no override and gets the ini cap of 1.
	h1 := newBlockingHandler(1)
	var wg1 sync.WaitGroup
	wg1.Add(1)
	go func() {
		defer wg1.Done()
		concRequest(s, "/api/ds/query", 1, h1.ServeHTTP)
	}()
	waitEntered(t, h1, 1)

	w := concRequest(s, "/api/ds/query", 1, func(http.ResponseWriter, *http.Request) {})
	require.Equal(t, http.StatusTooManyRequests, w.Code,
		"user 1 should be refused at the ini cap of 1")
	close(h1.release)
	wg1.Wait()

	// user 2 is overridden to 3 and must get all three.
	const n = 3
	h2 := newBlockingHandler(n)
	codes := make(chan int, n)
	var wg2 sync.WaitGroup
	for i := 0; i < n; i++ {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			codes <- concRequest(s, "/api/ds/query", 2, h2.ServeHTTP).Code
		}()
	}
	waitEntered(t, h2, n)
	close(h2.release)
	wg2.Wait()
	close(codes)

	for c := range codes {
		require.NotEqual(t, http.StatusTooManyRequests, c,
			"user 2 was refused below its override of 3")
	}
}

func TestConcurrencyCap_ChangesWithoutRestart(t *testing.T) {
	// The whole point of moving the cap into the rule table. A reload replaces
	// the snapshot; the next request must see the new number with no process
	// restart and no cache eviction.
	s := newTestService(concCfg(1))
	require.Equal(t, int64(1), s.concurrencyLimit(s.rulesPtr.Load(), "user:1"))

	// What reloadRules publishes after an admin API write.
	old := s.rulesPtr.Load()
	s.rulesPtr.Store(&rulesSnapshot{
		byKey:              old.byKey,
		dsQuota:            old.dsQuota,
		defaultConcurrency: i64(4),
	})
	require.Equal(t, int64(4), s.concurrencyLimit(s.rulesPtr.Load(), "user:1"),
		"the runtime override did not take effect")

	// And it is the resolved value that governs traffic, not the ini one.
	const n = 4
	h := newBlockingHandler(n)
	codes := make(chan int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- concRequest(s, "/api/ds/query", 1, h.ServeHTTP).Code
		}()
	}
	waitEntered(t, h, n)
	close(h.release)
	wg.Wait()
	close(codes)

	for c := range codes {
		require.NotEqual(t, http.StatusTooManyRequests, c,
			"refused below the reloaded cap of 4")
	}
}

func TestStats_ReportsResolvedConcurrencyNotIni(t *testing.T) {
	// /stats is how an operator confirms a change landed. Reporting the ini
	// value would tell them their runtime override did not apply when it did.
	s := newTestService(concCfg(2))
	old := s.rulesPtr.Load()
	s.rulesPtr.Store(&rulesSnapshot{
		byKey:              old.byKey,
		dsQuota:            old.dsQuota,
		defaultConcurrency: i64(7),
	})

	rec := httptest.NewRecorder()
	c := &contextmodel.ReqContext{
		Context:      &web.Context{Resp: web.NewResponseWriter(http.MethodGet, rec)},
		SignedInUser: &user.SignedInUser{UserID: 1, OrgID: 1},
	}
	resp := s.AdminStats(c)
	require.Equal(t, http.StatusOK, resp.Status())
	resp.WriteTo(c)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	conc, ok := body["concurrency"].(map[string]any)
	require.True(t, ok, "no concurrency block in /stats")
	require.EqualValues(t, 7, conc["limit"],
		"stats must report the resolved limit, not the ini value")
	require.Equal(t, "db", conc["limit_source"])
}

func TestConcurrencyShadow_SwitchesWithoutRestart(t *testing.T) {
	// Going from observing to enforcing is the rollout step and going back is
	// the rollback step. The QPS layer got a runtime switch for exactly that
	// reason; the in-flight cap was left reading s.cfg, so both moves cost a
	// restart -- including the one made under pressure.
	cfg := concCfg(1)
	cfg.ConcurrencyShadowMode = true // observing
	s := newTestService(cfg)

	require.True(t, s.concurrencyShadowMode(s.rulesPtr.Load()))

	// Observing means the cap counts but never refuses, even past the limit.
	h := newBlockingHandler(2)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		concRequest(s, "/api/ds/query", 1, h.ServeHTTP)
	}()
	waitEntered(t, h, 1)
	w := concRequest(s, "/api/ds/query", 1, func(http.ResponseWriter, *http.Request) {})
	require.Equal(t, http.StatusOK, w.Code, "shadow mode must not reject")
	close(h.release)
	wg.Wait()

	// What reloadRules publishes for kind=concurrency_enforcement mode=limited.
	old := s.rulesPtr.Load()
	enforce := false
	s.rulesPtr.Store(&rulesSnapshot{
		byKey:             old.byKey,
		dsQuota:           old.dsQuota,
		concurrencyShadow: &enforce,
	})
	require.False(t, s.concurrencyShadowMode(s.rulesPtr.Load()),
		"the runtime switch did not take effect")

	// And now it refuses.
	h2 := newBlockingHandler(1)
	var wg2 sync.WaitGroup
	wg2.Add(1)
	go func() {
		defer wg2.Done()
		concRequest(s, "/api/ds/query", 1, h2.ServeHTTP)
	}()
	waitEntered(t, h2, 1)
	w2 := concRequest(s, "/api/ds/query", 1, func(http.ResponseWriter, *http.Request) {})
	require.Equal(t, http.StatusTooManyRequests, w2.Code,
		"enforcement was switched on but nothing was refused")
	close(h2.release)
	wg2.Wait()
}

func TestConcurrencyShadow_IsIndependentOfTheQPSSwitch(t *testing.T) {
	// The two layers must be separately switchable: production may already be
	// enforcing QPS while the in-flight cap is still being trialled, and a
	// shared switch would mean the trial can only run by standing QPS
	// enforcement down.
	cfg := concCfg(1)
	cfg.ShadowMode = false           // QPS enforcing
	cfg.ConcurrencyShadowMode = true // concurrency observing
	s := newTestService(cfg)

	snap := s.rulesPtr.Load()
	require.False(t, s.shadowMode(snap), "QPS should be enforcing")
	require.True(t, s.concurrencyShadowMode(snap), "concurrency should be observing")

	// Flipping the concurrency switch must leave the QPS one alone.
	observe := true
	s.rulesPtr.Store(&rulesSnapshot{
		byKey:             snap.byKey,
		dsQuota:           snap.dsQuota,
		concurrencyShadow: &observe,
	})
	require.False(t, s.shadowMode(s.rulesPtr.Load()),
		"changing the concurrency switch must not disturb QPS enforcement")
}

// TestBothLayers_AnswerConfigurationTheSameWay is the symmetry contract.
//
// The two layers were built months apart and drifted: QPS read an absent
// default as a limit of zero while concurrency read it as no limit; QPS could
// be switched between observing and enforcing at runtime while concurrency
// needed a restart; QPS supported per-identity overrides while concurrency
// had a single deploy-time number.
//
// Every one of those was found by asking "are these two the same?" rather
// than by a failing test, which is why this exists: a divergence an operator
// would have to discover in production should fail here instead.
func TestBothLayers_AnswerConfigurationTheSameWay(t *testing.T) {
	t.Run("an absent value limits nothing, on either layer", func(t *testing.T) {
		cfg := defaultCfg()
		cfg.DefaultUserRate, cfg.DefaultUserBurst = 0, 0
		cfg.ConcurrencyEnabled = true
		cfg.DefaultUserConcurrency = 0
		s := newTestService(cfg)

		require.Equal(t, string(ModeUnlimited), s.resolveRule("user:1").Mode,
			"QPS: an absent baseline must not limit")
		require.Zero(t, s.concurrencyLimit(s.rulesPtr.Load(), "user:1"),
			"concurrency: an absent baseline must not limit")
	})

	t.Run("an unusable value limits nothing, on either layer", func(t *testing.T) {
		// Reaching through loadConfigFromSetting, which is where an ini value
		// is judged -- the same path a real deployment takes.
		bad := setting.NewCfg()
		bad.DsRateLimit.DefaultUserRate = -5
		bad.DsRateLimit.DefaultUserBurst = -5
		bad.DsRateLimit.DefaultUserConcurrency = -5
		got := loadConfigFromSetting(bad)

		require.Zero(t, got.DefaultUserRate, "QPS rate")
		require.Zero(t, got.DefaultUserBurst, "QPS burst")
		// Concurrency reaches the resolver unsanitised, so the guard lives
		// there instead; either way a negative must not become a cap.
		s := newTestService(concCfg(-5))
		require.LessOrEqual(t, s.concurrencyLimit(s.rulesPtr.Load(), "user:1"), int64(0),
			"concurrency: a negative must not become a cap")
	})

	t.Run("both layers take a DB override for their baseline", func(t *testing.T) {
		s := newTestService(concCfg(1),
			&Rule{Kind: string(KindDefault), Target: DefaultTarget,
				Mode: string(ModeLimited), Rate: i64(50), Burst: i64(50),
				Concurrency: i64(6)},
		)
		snap := s.rulesPtr.Load()
		r, b := s.defaultParams(snap)
		require.EqualValues(t, 50, r, "QPS rate from DB")
		require.EqualValues(t, 50, b, "QPS burst from DB")
		require.EqualValues(t, 6, s.concurrencyLimit(snap, "user:1"),
			"concurrency from DB")
	})

	t.Run("both layers switch enforcement at runtime", func(t *testing.T) {
		cfg := concCfg(1)
		cfg.ShadowMode = true
		cfg.ConcurrencyShadowMode = true
		s := newTestService(cfg,
			&Rule{Kind: string(KindEnforcement), Target: DefaultTarget, Mode: string(ModeLimited)},
			&Rule{Kind: string(KindConcurrencyEnforcement), Target: DefaultTarget, Mode: string(ModeLimited)},
		)
		snap := s.rulesPtr.Load()
		require.False(t, s.shadowMode(snap), "QPS enforcement from DB")
		require.False(t, s.concurrencyShadowMode(snap), "concurrency enforcement from DB")
	})
}

// TestIniIsNotLaxerThanTheAdminAPI closes the gap where the same numbers were
// refused through the API and accepted from the file.
//
// Found by listing the checks each entry point performs and comparing them,
// not by a failure. Both gaps were then reproduced before being fixed: with
// rate=100 burst=2 from the ini, a five-token request was denied ten times
// out of ten, permanently, because x/time/rate refuses any cost above burst
// regardless of accumulated tokens.
func TestIniIsNotLaxerThanTheAdminAPI(t *testing.T) {
	t.Run("burst below rate disarms instead of denying forever", func(t *testing.T) {
		c := setting.NewCfg()
		c.DsRateLimit.Enabled = true
		c.DsRateLimit.ShadowMode = false
		c.DsRateLimit.DefaultUserRate = 100
		c.DsRateLimit.DefaultUserBurst = 2
		got := loadConfigFromSetting(c)

		require.Zero(t, got.DefaultUserRate,
			"a pair the admin API rejects must not be accepted from the ini")
		require.Zero(t, got.DefaultUserBurst)

		// The reason it matters: a request costing more than burst is refused
		// on every attempt, so this is an outage rather than throttling.
		s := newTestService(got)
		u := &user.SignedInUser{UserID: 1, OrgID: 1}
		body := []byte(`{"queries":[{},{},{},{},{}]}`) // five tokens
		for i := 0; i < 5; i++ {
			ctx, rec := buildCtx("POST", "/api/ds/query", body, u)
			s.Middleware(ctx)
			require.Equal(t, http.StatusOK, rec.Code,
				"request %d denied; the unusable pair should have disarmed the layer", i)
		}
	})

	t.Run("an absurd concurrency cap disarms", func(t *testing.T) {
		c := setting.NewCfg()
		c.DsRateLimit.ConcurrencyEnabled = true
		c.DsRateLimit.DefaultUserConcurrency = int(DefaultMaxRuleConcurrency) + 1
		got := loadConfigFromSetting(c)
		require.Zero(t, got.DefaultUserConcurrency,
			"a cap the admin API rejects must not be accepted from the ini")
	})

	t.Run("a negative concurrency cap is already harmless", func(t *testing.T) {
		// Not a defect, and worth pinning so nobody "fixes" it into one:
		// acquire() treats any non-positive limit as no cap, so -5 and 0
		// behave identically. Rejecting it would only add a code path.
		s := newTestService(concCfg(-5))
		require.LessOrEqual(t, s.concurrencyLimit(s.rulesPtr.Load(), "user:1"), int64(0))
	})

	t.Run("a usable pair still applies", func(t *testing.T) {
		c := setting.NewCfg()
		c.DsRateLimit.Enabled = true
		c.DsRateLimit.DefaultUserRate = 20
		c.DsRateLimit.DefaultUserBurst = 40
		got := loadConfigFromSetting(c)
		require.Equal(t, 20, got.DefaultUserRate)
		require.Equal(t, 40, got.DefaultUserBurst)
	})
}

// TestSaneSetting_SameRulesForBothLayers pins the judgement itself.
//
// The two layers share one function, so a table driving it with only the
// bound differing is the strongest available statement that they cannot
// drift again -- a divergence would require someone to stop calling the
// shared function, which review can see.
func TestSaneSetting_SameRulesForBothLayers(t *testing.T) {
	const ceiling = int64(1000)
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"zero means no limit", 0, 0},
		{"negative means no limit", -5, 0},
		{"a normal value applies", 50, 50},
		{"a large value under the ceiling applies as written", 999, 999},
		{"exactly at the ceiling applies", 1000, 1000},
		{"above the ceiling disarms", 1001, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, saneSetting(log.New("test"), "k", tc.got, ceiling))
		})
	}
}

// TestSaneSetting_BothLayersUseTheSameBoundaries walks the same inputs through
// each layer's real bound, so "the rules are identical" is asserted rather
// than assumed from the shared call site.
func TestSaneSetting_BothLayersUseTheSameBoundaries(t *testing.T) {
	for _, layer := range []struct {
		name    string
		ceiling int64
	}{
		{"qps", DefaultMaxRuleRate},
		{"concurrency", DefaultMaxRuleConcurrency},
	} {
		t.Run(layer.name, func(t *testing.T) {
			lg := log.New("test")
			require.Zero(t, saneSetting(lg, "k", 0, layer.ceiling), "zero")
			require.Zero(t, saneSetting(lg, "k", -1, layer.ceiling), "negative")
			require.Equal(t, 7, saneSetting(lg, "k", 7, layer.ceiling), "normal")
			require.Equal(t, int(layer.ceiling),
				saneSetting(lg, "k", int(layer.ceiling), layer.ceiling), "at ceiling")
			require.Zero(t, saneSetting(lg, "k", int(layer.ceiling)+1, layer.ceiling),
				"above ceiling")
		})
	}
}

// TestConcurrencyOnlyRule_DoesNotArmTheQPSLayer covers the defect this change
// set introduced while removing the same defect elsewhere.
//
// The admin API accepts a rule carrying only a concurrency value, so that
// tuning the in-flight cap does not force an operator to restate QPS numbers.
// resolveRuleIn returned that rule unchanged, and Mode=limited with Rate=nil
// sent getUserEntry to an unconfigured baseline: rate.NewLimiter(0, 0), which
// refuses everything.
//
// Measured before the fix: an identity given a concurrency cap of 5 was denied
// ten requests out of ten, while an identity with no rule at all was served.
// Asking for a limit on one layer disabled the other.
//
// Raised in review, and correctly: it reintroduced by a new path exactly the
// failure the surrounding commits exist to remove.
func TestConcurrencyOnlyRule_DoesNotArmTheQPSLayer(t *testing.T) {
	cfg := defaultCfg()
	cfg.Enabled = true
	cfg.ShadowMode = false
	cfg.DefaultUserRate = 0 // no QPS baseline configured
	cfg.DefaultUserBurst = 0
	cfg.ConcurrencyEnabled = true

	s := newTestService(cfg, &Rule{
		Kind: string(KindUser), Target: "7",
		Mode: string(ModeLimited), Concurrency: i64(5),
	})

	require.Equal(t, string(ModeUnlimited), s.resolveRule("user:7").Mode,
		"a rule that states no QPS limit must resolve to unlimited, "+
			"exactly as an identity with no rule does")

	u := &user.SignedInUser{UserID: 7, OrgID: 1}
	for i := 0; i < 10; i++ {
		c, rec := buildCtx("POST", "/api/ds/query", []byte(`{"queries":[{}]}`), u)
		s.Middleware(c)
		require.Equal(t, http.StatusOK, rec.Code,
			"request %d denied; setting a concurrency cap must not arm the QPS layer", i)
	}

	// The cap itself must still work -- the fix must not neutralise the
	// setting it was protecting.
	require.EqualValues(t, 5, s.concurrencyLimit(s.rulesPtr.Load(), "user:7"),
		"the concurrency override was lost")
}

func TestConcurrencyOnlyRule_StillDefersToAConfiguredBaseline(t *testing.T) {
	// The fallback is "resolve as if no rule existed", not "never limit".
	// With a baseline configured, a concurrency-only rule must inherit it.
	cfg := defaultCfg()
	cfg.Enabled = true
	cfg.ShadowMode = false
	cfg.DefaultUserRate = 1
	cfg.DefaultUserBurst = 1
	cfg.ConcurrencyEnabled = true

	s := newTestService(cfg, &Rule{
		Kind: string(KindUser), Target: "9",
		Mode: string(ModeLimited), Concurrency: i64(5),
	})

	rule := s.resolveRule("user:9")
	require.Equal(t, string(ModeLimited), rule.Mode)
	require.EqualValues(t, 1, *rule.Rate, "must inherit the configured baseline")

	u := &user.SignedInUser{UserID: 9, OrgID: 1}
	c1, rec1 := buildCtx("POST", "/api/ds/query", []byte(`{"queries":[{}]}`), u)
	s.Middleware(c1)
	require.Equal(t, http.StatusOK, rec1.Code, "burst=1 admits the first request")

	c2, rec2 := buildCtx("POST", "/api/ds/query", []byte(`{"queries":[{}]}`), u)
	s.Middleware(c2)
	require.Equal(t, http.StatusTooManyRequests, rec2.Code,
		"the inherited baseline must still apply")
}
