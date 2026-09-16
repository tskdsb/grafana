package dsratelimit

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/user"
)

// TestDatasourceTargets_Attribution locks how a request is attributed to
// datasources. Everything downstream (which quota is charged, how much, and
// whether anything is charged at all) follows from this, so it is table-driven
// over the addressing forms that actually occur.
//
// The four body forms are not hypothetical: pkg/services/query/query.go accepts
// datasource.uid (:317), the bare datasource string (:321), and legacy
// datasourceId (:347) — all three reach real backends today, and old dashboards
// still emit the last two.
func TestDatasourceTargets_Attribution(t *testing.T) {
	for _, tc := range []struct {
		name     string
		path     string
		body     string
		wantCost map[string]int
		wantN    int
	}{
		{
			name:     "modern uid form",
			path:     dsQueryPath,
			body:     `{"queries":[{"range":true,"datasource":{"uid":"PROM_MAIN"}}]}`,
			wantCost: map[string]int{"PROM_MAIN": 1},
			wantN:    1,
		},
		{
			name:     "bare datasource string (query.go:321)",
			path:     dsQueryPath,
			body:     `{"queries":[{"range":true,"datasource":"PROM_MAIN"}]}`,
			wantCost: map[string]int{"PROM_MAIN": 1},
			wantN:    1,
		},
		{
			// A datasourceId-only body draws on no datasource quota: the cost
			// is still charged to the caller's identity, but a numeric ID
			// cannot be resolved to a UID without a DB lookup in the request
			// path, and giving it its own bucket would hand the same backend a
			// second, unconfigured quota to hide behind.
			//
			// Unreachable from normal traffic anyway: the 9.5 frontend always
			// sends `datasource` next to `datasourceId`
			// (DataSourceWithBackend.ts:174, marked "deprecated!"), and the
			// both-fields case below confirms `datasource` wins.
			name:     "legacy numeric datasourceId alone attributes to no quota",
			path:     dsQueryPath,
			body:     `{"queries":[{"range":true,"datasourceId":7}]}`,
			wantCost: map[string]int{},
			wantN:    1,
		},
		{
			// The shape the 9.5 frontend actually sends. `datasource` must win,
			// otherwise every real dashboard query would land in the
			// no-attribution path above and no datasource quota would ever
			// apply.
			name: "both datasource and deprecated datasourceId: uid wins",
			path: dsQueryPath,
			body: `{"queries":[{"range":true,"datasource":{"uid":"PROM_MAIN",` +
				`"type":"prometheus"},"datasourceId":7}]}`,
			wantCost: map[string]int{"PROM_MAIN": 1},
			wantN:    1,
		},
		{
			name: "instant+range+exemplar all count on the same datasource",
			path: dsQueryPath,
			body: `{"queries":[{"instant":true,"range":true,"exemplar":true,` +
				`"datasource":{"uid":"PROM_MAIN"}}]}`,
			wantCost: map[string]int{"PROM_MAIN": 3},
			wantN:    3,
		},
		{
			name: "mixed datasources split the cost",
			path: dsQueryPath,
			body: `{"queries":[` +
				`{"range":true,"datasource":{"uid":"PROM_MAIN"}},` +
				`{"range":true,"instant":true,"datasource":{"uid":"PROM_MAIN"}},` +
				`{"range":true,"datasource":{"uid":"MYSQL_REPORTS"}}]}`,
			wantCost: map[string]int{"PROM_MAIN": 3, "MYSQL_REPORTS": 1},
			wantN:    4,
		},
		{
			// The expression engine evaluates server-side against results
			// already fetched; charging a backend for it would double-count the
			// queries it consumes. pkg/expr/service.go:17,21.
			name:     "expression pseudo-datasource is not a backend",
			path:     dsQueryPath,
			body:     `{"queries":[{"range":true,"datasource":{"uid":"__expr__"}}]}`,
			wantCost: map[string]int{},
			wantN:    1,
		},
		{
			// pkg/expr/service.go:31 — the pre-uid spelling of the same thing.
			name:     "legacy expression id -100 is not a backend",
			path:     dsQueryPath,
			body:     `{"queries":[{"range":true,"datasourceId":-100}]}`,
			wantCost: map[string]int{},
			wantN:    1,
		},
		{
			// pkg/tsdb/grafanads/grafana.go:33 — served in-process.
			name:     "built-in grafana datasource is not a backend",
			path:     dsQueryPath,
			body:     `{"queries":[{"range":true,"datasource":{"uid":"grafana"}}]}`,
			wantCost: map[string]int{},
			wantN:    1,
		},
		{
			name: "expression mixed with a real datasource charges only the real one",
			path: dsQueryPath,
			body: `{"queries":[` +
				`{"range":true,"datasource":{"uid":"PROM_MAIN"}},` +
				`{"range":true,"datasource":{"uid":"__expr__"}}]}`,
			wantCost: map[string]int{"PROM_MAIN": 1},
			wantN:    2,
		},
		{
			name:     "proxy route by uid",
			path:     "/api/datasources/proxy/uid/PROM_MAIN",
			wantCost: map[string]int{"PROM_MAIN": 1},
			wantN:    1,
		},
		{
			// Same rule for the deprecated numeric-ID proxy route
			// (api.go:438/440): charged to the identity, attributed to no
			// quota. This route is registered and callable, so before this it
			// was a live way to reach a rate-limited backend on a quota nobody
			// had configured.
			name:     "proxy route by legacy numeric id attributes to no quota",
			path:     "/api/datasources/proxy/42",
			wantCost: map[string]int{},
			wantN:    1,
		},
		{
			name:     "resources route by uid",
			path:     "/api/datasources/uid/PROM_MAIN/resources/api/v1/labels",
			wantCost: map[string]int{"PROM_MAIN": 1},
			wantN:    1,
		},
		{
			// No queries[] at all: still one backend request, but nothing to
			// attribute it to. Must not become zero-cost.
			name:     "unattributable request still costs one token",
			path:     dsQueryPath,
			body:     `{"queries":[]}`,
			wantCost: map[string]int{},
			wantN:    1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body []byte
			if tc.body != "" {
				body = []byte(tc.body)
			}
			c, _ := buildCtx("POST", tc.path, body, &user.SignedInUser{UserID: 1})

			var gotCost map[string]int
			var gotN int
			if isDsQueryRoute(c) {
				buf, countable := readCountableBody(c)
				require.True(t, countable, "body must be countable in this test")
				gotCost, gotN = datasourceTargets(c, buf)
			} else {
				gotCost, gotN = datasourceTargets(c, nil)
			}

			require.Equal(t, tc.wantN, gotN, "total token cost")
			require.Len(t, gotCost, len(tc.wantCost))
			for target, want := range tc.wantCost {
				require.Equal(t, want, gotCost[target],
					"cost attributed to %q", target)
			}
		})
	}
}

// TestDatasourceQuota_IsolatesBackends is the whole point of the refactor, as a
// single assertion: saturating one datasource must not affect another.
//
// The old global lane failed this both ways -- it could not defend one instance's
// quota (traffic had to exceed the shared limit first), and it let unrelated
// backends spend each other's capacity.
func TestDatasourceQuota_IsolatesBackends(t *testing.T) {
	cfg := defaultCfg()
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 10000, 10000 // identity out of the way
	s := newTestService(cfg,
		dsQuotaRule("PROM_MAIN", 5, 5),
		dsQuotaRule("MYSQL_REPORTS", 5, 5),
	)
	u := &user.SignedInUser{UserID: 4}

	promBody := []byte(`{"queries":[{"range":true,"datasource":{"uid":"PROM_MAIN"}}]}`)
	mysqlBody := []byte(`{"queries":[{"range":true,"datasource":{"uid":"MYSQL_REPORTS"}}]}`)

	// Drain Prometheus.
	denied := 0
	for i := 0; i < 20; i++ {
		c, rec := buildCtx("POST", dsQueryPath, promBody, u)
		s.Middleware(c)
		if rec.Code == http.StatusTooManyRequests {
			denied++
		}
	}
	require.Greater(t, denied, 0, "precondition: the Prometheus quota must saturate")

	// MySQL must be untouched.
	for i := 0; i < 5; i++ {
		c, rec := buildCtx("POST", dsQueryPath, mysqlBody, u)
		s.Middleware(c)
		require.Equal(t, http.StatusOK, rec.Code,
			"MySQL request %d denied while only Prometheus was saturated: "+
				"the buckets are not isolated", i)
	}
}

// TestChargeDatasources_RollsBackOnPartialDenial locks the cross-bucket
// atomicity.
//
// A panel mixing two datasources must not spend tokens on the one with capacity
// when the other is going to refuse the request: those tokens buy a query that
// never runs, and they are taken from whoever would have used them. This is the
// same class of bug as charging the datasource after the identity bucket already
// denied, one level up.
//
// x/time/rate offers no multi-bucket primitive, so this is a two-phase commit
// over Reservation.CancelAt. Measured directly: a bucket at 40 charged 5 and
// then cancelled returns to exactly 40.00.
func TestChargeDatasources_RollsBackOnPartialDenial(t *testing.T) {
	cfg := defaultCfg()
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 10000, 10000
	s := newTestService(cfg,
		dsQuotaRule("HAS_ROOM", 100, 100),
		dsQuotaRule("IS_FULL", 1, 1),
	)
	u := &user.SignedInUser{UserID: 5}

	// Drain IS_FULL with a request that touches only it.
	c, _ := buildCtx("POST", dsQueryPath,
		[]byte(`{"queries":[{"range":true,"datasource":{"uid":"IS_FULL"}}]}`), u)
	s.Middleware(c)

	roomLim := s.getDatasourceLimiter("HAS_ROOM")
	require.NotNil(t, roomLim)
	now := time.Now()
	before := roomLim.TokensAt(now)

	// Mixed request: HAS_ROOM can serve it, IS_FULL cannot. Must be denied,
	// and HAS_ROOM must not have paid for it.
	mixed := []byte(`{"queries":[` +
		`{"range":true,"datasource":{"uid":"HAS_ROOM"}},` +
		`{"range":true,"datasource":{"uid":"IS_FULL"}}]}`)
	c, rec := buildCtx("POST", dsQueryPath, mixed, u)
	s.Middleware(c)
	require.Equal(t, http.StatusTooManyRequests, rec.Code,
		"a request must be denied when any datasource it touches refuses it")

	after := roomLim.TokensAt(now)
	require.InDelta(t, before, after, 0.001,
		"the datasource that had room must be refunded when a sibling refuses "+
			"the request: before=%v after=%v (tokens spent on a query that never ran)",
		before, after)
}

// TestChargeDatasources_ChargesAllOnSuccess is the negative control for the
// rollback test: without it, a chargeDatasources that always rolled back (or
// never charged at all) would pass the test above.
func TestChargeDatasources_ChargesAllOnSuccess(t *testing.T) {
	cfg := defaultCfg()
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 10000, 10000
	s := newTestService(cfg,
		dsQuotaRule("DS_A", 100, 100),
		dsQuotaRule("DS_B", 100, 100),
	)
	u := &user.SignedInUser{UserID: 6}

	mixed := []byte(`{"queries":[` +
		`{"range":true,"instant":true,"datasource":{"uid":"DS_A"}},` +
		`{"range":true,"datasource":{"uid":"DS_B"}}]}`)
	c, rec := buildCtx("POST", dsQueryPath, mixed, u)
	s.Middleware(c)
	require.Equal(t, http.StatusOK, rec.Code)

	now := time.Now()
	a := s.getDatasourceLimiter("DS_A")
	b := s.getDatasourceLimiter("DS_B")
	require.NotNil(t, a)
	require.NotNil(t, b)

	// DS_A carried instant+range = 2 tokens, DS_B carried 1.
	require.InDelta(t, 98.0, a.TokensAt(now), 0.05,
		"DS_A must be charged its own share (2 of the request's 3 tokens)")
	require.InDelta(t, 99.0, b.TokensAt(now), 0.05,
		"DS_B must be charged its own share (1 of the request's 3 tokens)")
}

// TestDatasourceTargets_HostileUIDsAllocateNothing is the security property that
// makes it safe to read the target from the request at all.
//
// The UID is client-supplied free text -- verified: a 60-character hostile
// string passes through the query path untouched. If an unrecognised target
// created a bucket, any caller could allocate unbounded limiters and unbounded
// Prometheus label values by varying it. Buckets exist only for configured
// quotas, so the bucket count is bounded by the rule table, not by traffic.
func TestDatasourceTargets_HostileUIDsAllocateNothing(t *testing.T) {
	cfg := defaultCfg()
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 10000, 10000
	s := newTestService(cfg, dsQuotaRule("PROM_MAIN", 100, 100))
	u := &user.SignedInUser{UserID: 8}

	hostile := []string{
		strings.Repeat("A", 200),
		"' OR 1=1 --",
		"../../etc/passwd",
		`{"nested":"json"}`,
		"PROM_MAIN\x00suffix",
		"prom_main", // case differs -> a different target, not a match
	}
	for i, uid := range hostile {
		body := fmt.Appendf(nil, `{"queries":[{"range":true,"datasource":{"uid":%q}}]}`, uid)
		c, rec := buildCtx("POST", dsQueryPath, body, u)
		s.Middleware(c)
		require.Equal(t, http.StatusOK, rec.Code, "hostile uid %d must not be rejected here", i)
	}

	// Exactly one bucket: the configured one. Nothing the client sent created
	// another.
	count := 0
	s.dsBuckets.Range(func(k, _ any) bool {
		require.Equal(t, "PROM_MAIN", k.(string),
			"only configured quotas may have buckets; %q was created from client input", k)
		count++
		return true
	})
	require.LessOrEqual(t, count, 1,
		"client-supplied UIDs must not allocate buckets (found %d)", count)
}

// TestDatasourceQuota_UnconfiguredIsNotUnlimited pins the meaning of "no quota
// row": not quota-managed, but still bounded by the caller's identity limit.
//
// Getting this backwards in either direction is bad: a permissive bucket per
// observed UID is the memory problem above, while treating unconfigured as
// unlimited would mean adding a datasource silently opts it out of all limiting.
func TestDatasourceQuota_UnconfiguredIsNotUnlimited(t *testing.T) {
	cfg := defaultCfg()
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 3, 3
	s := newTestService(cfg) // no datasource quotas at all
	u := &user.SignedInUser{UserID: 9}

	body := []byte(`{"queries":[{"range":true,"datasource":{"uid":"NOT_CONFIGURED"}}]}`)
	denied := 0
	for i := 0; i < 20; i++ {
		c, rec := buildCtx("POST", dsQueryPath, body, u)
		s.Middleware(c)
		if rec.Code == http.StatusTooManyRequests {
			denied++
		}
	}
	require.Greater(t, denied, 0,
		"a datasource without a quota must still be bounded by the identity limit")
	require.Nil(t, s.getDatasourceLimiter("NOT_CONFIGURED"),
		"and must not have acquired a bucket of its own")
}

// TestUncountableBody_StillAttributesAndCharges closes the bypass in the
// oversized-body path.
//
// The handler executes every query in the body regardless of our counting cap,
// so a body padded past the cap would otherwise cost 1 token and escape the
// backend quota entirely -- padding as a way to buy queries. The prefix is
// decoded element by element to recover what targets it can.
func TestUncountableBody_StillAttributesAndCharges(t *testing.T) {
	// Real queries first, then padding that pushes the body past the cap.
	head := `{"queries":[` +
		`{"range":true,"datasource":{"uid":"PROM_MAIN"}},` +
		`{"range":true,"datasource":{"uid":"PROM_MAIN"}},`
	filler := strings.Repeat("x", int(maxCountedBodyBytes))
	raw := []byte(head + `{"range":true,"pad":"` + filler + `"}]}`)
	require.Greater(t, int64(len(raw)), maxCountedBodyBytes,
		"precondition: the body must exceed the counting cap")

	cfg := defaultCfg()
	cfg.DefaultUserBurst, cfg.DefaultUserRate = 4096, 4096
	s := newTestService(cfg, dsQuotaRule("PROM_MAIN", 100, 100))

	c, _ := buildCtx("POST", dsQueryPath, raw, &user.SignedInUser{UserID: 10})
	s.Middleware(c)

	lim := s.getDatasourceLimiter("PROM_MAIN")
	require.NotNil(t, lim,
		"the datasource named in the readable prefix must still be attributed")
	spent := 100.0 - lim.TokensAt(time.Now())
	require.Greater(t, spent, 1.0,
		"an uncountable body must be charged the ceiling, not one token: "+
			"otherwise padding a body is the cheapest way to buy queries (spent=%v)",
		spent)
}

// TestReloadRules_DropsRemovedQuota covers the bucket lifecycle across reloads.
//
// Re-pointing an existing bucket keeps its token state, which is correct for a
// changed quota. Removing the row must drop the bucket instead, so a later
// re-add starts from the configured burst rather than from whatever state the
// old bucket happened to be in.
func TestReloadRules_DropsRemovedQuota(t *testing.T) {
	cfg := defaultCfg()
	s := newTestService(cfg, dsQuotaRule("PROM_MAIN", 50, 60))

	require.NotNil(t, s.getDatasourceLimiter("PROM_MAIN"), "precondition")

	// Simulate a reload that no longer contains the row.
	s.rulesPtr.Store(&rulesSnapshot{
		byKey:   map[string]*Rule{},
		dsQuota: map[string]laneParams{},
	})
	s.dsBuckets.Range(func(k, _ any) bool {
		if _, ok := s.rulesPtr.Load().dsQuota[k.(string)]; !ok {
			s.dsBuckets.Delete(k)
		}
		return true
	})

	require.Nil(t, s.getDatasourceLimiter("PROM_MAIN"),
		"a removed quota must leave no bucket behind")
}

// TestUncountableBody_ClampsToDatasourceBurst locks a bug found while writing
// the test above.
//
// The ceiling for an uncountable body is derived from the CALLER's burst, which
// can be larger than a datasource's quota. Charged verbatim, that cost exceeds
// the datasource's burst -- and x/time/rate refuses any cost above burst on
// every attempt, forever, no matter how long the caller waits (rate.go:371).
// One oversized body would have made that datasource permanently unreachable
// through this route, showing up in metrics as an unremarkable trickle of 429s.
//
// This is the second time the same trap appeared (the first was a fixed
// ceiling constant of 1000 against a production burst of 420), which is why it
// gets an explicit test rather than a comment.
func TestUncountableBody_ClampsToDatasourceBurst(t *testing.T) {
	// The first element must be COMPLETE within the buffered prefix, or it
	// cannot be decoded and the datasource is never attributed at all -- in
	// which case this test would pass without exercising the clamp. That is
	// exactly how the first version of this test was silently useless: a
	// mutation removing the clamp still passed it.
	filler := strings.Repeat("x", int(maxCountedBodyBytes))
	raw := []byte(`{"queries":[` +
		`{"range":true,"datasource":{"uid":"SMALL_QUOTA"}},` +
		`{"range":true,"pad":"` + filler + `"}]}`)
	require.Greater(t, int64(len(raw)), maxCountedBodyBytes,
		"precondition: the body must exceed the counting cap")

	cfg := defaultCfg()
	// Caller burst deliberately far above the datasource quota.
	cfg.DefaultUserBurst, cfg.DefaultUserRate = 4096, 4096
	s := newTestService(cfg, dsQuotaRule("SMALL_QUOTA", 10, 12))

	u := &user.SignedInUser{UserID: 11}
	c, rec := buildCtx("POST", dsQueryPath, raw, u)
	s.Middleware(c)
	require.Equal(t, http.StatusOK, rec.Code,
		"the first oversized request must be admissible: its cost is clamped to "+
			"the datasource burst (12), not the caller's ceiling (%d)",
		maxCountedQueries(cfg.DefaultUserBurst))

	// And the datasource must recover: after refill it accepts traffic again.
	// An unclamped charge would deny every subsequent request forever.
	lim := s.getDatasourceLimiter("SMALL_QUOTA")
	require.NotNil(t, lim)
	require.True(t, lim.AllowN(time.Now().Add(2*time.Second), 10),
		"the datasource must recover after refill; an over-burst charge would "+
			"leave it permanently refusing every request")
}

// TestNonBackendUIDs_MatchUpstream keeps the three excluded UIDs in step with
// the upstream constants they mirror.
//
// They are duplicated deliberately: importing pkg/expr and pkg/tsdb/grafanads
// for three strings took this package from 532 to 1239 transitive dependencies
// (pkg/expr alone pulls 710) and would place the rate limiter downstream of the
// expression engine, inviting a future import cycle. The cost of duplication is
// exactly this drift risk, so it is asserted against the source instead.
func TestNonBackendUIDs_MatchUpstream(t *testing.T) {
	for _, tc := range []struct {
		local string
		file  string
		decl  string
	}{
		{uidExpr, "../../expr/service.go", `DatasourceType = "__expr__"`},
		{uidExprOld, "../../expr/service.go", `OldDatasourceUID = "-100"`},
		{uidGrafana, "../../tsdb/grafanads/grafana.go", `DatasourceUID = "grafana"`},
	} {
		t.Run(tc.local, func(t *testing.T) {
			src, err := os.ReadFile(tc.file)
			require.NoError(t, err, "reading %s", tc.file)
			require.Contains(t, string(src), tc.decl,
				"upstream declaration %q not found in %s: the local constant %q "+
					"mirrors it and may have drifted -- excluding the wrong UID "+
					"either charges a backend that does not exist or lets a real "+
					"one through unmetered",
				tc.decl, tc.file, tc.local)
			require.Contains(t, tc.decl, `"`+tc.local+`"`,
				"local constant %q does not match the upstream literal in %q",
				tc.local, tc.decl)
		})
	}
}

// TestIniQuotas_InForceBeforeFirstReload is the reason deploy-time quotas exist.
//
// The whole point of putting quotas in the ini is that a freshly deployed
// environment is protected without anyone remembering to call the admin API. If
// they only took effect after the first DB reload, there would be a window at
// every startup -- and an indefinite one whenever the DB is unreachable -- during
// which the backend has no quota at all. Startup is exactly when a restarted
// Grafana re-renders every open dashboard at once, so that window is the worst
// possible time to be unprotected.
func TestIniQuotas_InForceBeforeFirstReload(t *testing.T) {
	cfg := defaultCfg()
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 10000, 10000
	cfg.IniQuotas = map[string]laneParams{"PROM_MAIN": {rate: 3, burst: 3}}

	// A service built the way ProvideService builds it, with NO reload yet and
	// no store at all -- the state during startup, or with a dead DB.
	s := &Service{cfg: cfg, logger: log.New("dsratelimit.test")}
	s.rulesPtr.Store(&rulesSnapshot{
		byKey:    map[string]*Rule{},
		dsQuota:  baseQuotas(cfg.IniQuotas),
		dsFromDB: map[string]bool{},
	})

	require.NotNil(t, s.getDatasourceLimiter("PROM_MAIN"),
		"a deployed quota must be in force before the first DB reload")

	u := &user.SignedInUser{UserID: 12}
	body := []byte(`{"queries":[{"range":true,"datasource":{"uid":"PROM_MAIN"}}]}`)
	denied := 0
	for i := 0; i < 20; i++ {
		c, rec := buildCtx("POST", dsQueryPath, body, u)
		s.Middleware(c)
		if rec.Code == http.StatusTooManyRequests {
			denied++
		}
	}
	require.Greater(t, denied, 0,
		"the deployed quota must actually enforce before any reload has run: "+
			"otherwise every restart leaves the backend unprotected until the "+
			"first reload, which is precisely when all dashboards reconnect")
}

// TestNumericIDCannotBypassQuota is the regression test for the bypass.
//
// Before this, a numeric datasource ID got its own quota bucket keyed "id:7".
// Since quotas are configured by UID, that bucket was always unconfigured --
// so the same backend was reachable on two quotas, one of them effectively
// unlimited. Measured on the old code: three identical requests to PROM_MAIN
// gave [200 429 429] via the uid form and [200 200 200] via the numeric form.
//
// Not reachable from normal 9.5 dashboard traffic (the frontend always sends
// `datasource` too), but /api/datasources/proxy/:id is a registered, callable
// route, so a hand-written script or internal tool could take it.
func TestNumericIDCannotBypassQuota(t *testing.T) {
	u := &user.SignedInUser{UserID: 5}
	// A quota tight enough that a second request must be refused, and an
	// identity limit high enough that it cannot be what refuses anything.
	newSvc := func() *Service {
		cfg := defaultCfg()
		cfg.DefaultUserRate, cfg.DefaultUserBurst = 100000, 100000
		cfg.IniQuotas = map[string]laneParams{"PROM_MAIN": {rate: 1, burst: 1}}
		s := &Service{cfg: cfg, logger: log.New("dsratelimit.test")}
		s.rulesPtr.Store(&rulesSnapshot{
			byKey:    map[string]*Rule{},
			dsQuota:  baseQuotas(cfg.IniQuotas),
			dsFromDB: map[string]bool{},
		})
		return s
	}
	drive := func(s *Service, path string, body []byte) int {
		denied := 0
		for i := 0; i < 3; i++ {
			c, rec := buildCtx("POST", path, body, u)
			s.Middleware(c)
			if rec.Code == http.StatusTooManyRequests {
				denied++
			}
		}
		return denied
	}

	// The configured path still enforces -- otherwise this test proves nothing.
	uidBody := []byte(`{"queries":[{"range":true,"datasource":{"uid":"PROM_MAIN"}}]}`)
	require.NotZero(t, drive(newSvc(), dsQueryPath, uidBody),
		"the uid form must still be limited by the configured quota")

	// No unconfigured bucket is created for the numeric forms, so nothing
	// grants them capacity of their own.
	for _, tc := range []struct {
		name string
		path string
		body []byte
	}{
		{"body datasourceId", dsQueryPath,
			[]byte(`{"queries":[{"range":true,"datasourceId":7}]}`)},
		{"proxy by numeric id", "/api/datasources/proxy/7", nil},
		{"resources by numeric id", "/api/datasources/7/resources/api/v1/labels", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSvc()
			c, _ := buildCtx("POST", tc.path, tc.body, u)
			cost, _ := datasourceTargets(c, tc.body)
			require.Empty(t, cost,
				"a numeric ID must not be attributed to any datasource quota; "+
					"got %v. A bucket here is unconfigured by construction, "+
					"which is what made it a bypass", cost)

			// And no bucket was allocated as a side effect.
			s.Middleware(c)
			s.dsBuckets.Range(func(k, _ any) bool {
				t.Errorf("allocated a quota bucket %q for a numeric ID", k)
				return true
			})
		})
	}

	// The requests are not free: the identity limit still charges them, so
	// closing the quota bypass did not create an unlimited path.
	cfg := defaultCfg()
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 1, 1
	s := &Service{cfg: cfg, logger: log.New("dsratelimit.test")}
	s.rulesPtr.Store(&rulesSnapshot{
		byKey: map[string]*Rule{}, dsQuota: map[string]laneParams{},
		dsFromDB: map[string]bool{},
	})
	require.NotZero(t, drive(s, "/api/datasources/proxy/7", nil),
		"numeric-ID requests must still be charged to the caller's identity "+
			"limit: unattributed must not mean uncounted")
}
