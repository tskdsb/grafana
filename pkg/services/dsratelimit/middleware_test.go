package dsratelimit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/infra/log"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/web"
)

// newTestService builds a Service without a DB dependency. Rules are provided
// as a static snapshot so tests can exercise the middleware in isolation.
//
// The logger is set because ProvideService always sets one; leaving it nil
// would make the helper diverge from production and hide nil-logger panics
// on paths that log (e.g. the invalid-rule fallback in getUserLimiter).
func newTestService(cfg Config, rules ...*Rule) *Service {
	s := &Service{cfg: cfg, logger: log.New("dsratelimit.test")}
	snap := &rulesSnapshot{
		byKey:   make(map[string]*Rule, len(rules)),
		dsQuota: map[string]laneParams{},
	}
	for _, r := range rules {
		// Datasource rules become quotas, mirroring reloadRules, so tests
		// exercise the same resolution path production does.
		if r.Kind == string(KindDatasource) && r.Rate != nil && r.Burst != nil {
			if lp, ok := sanitizeParams(*r.Rate, *r.Burst, DefaultMaxRuleRate, DefaultMaxRuleBurst); ok {
				snap.dsQuota[r.Target] = lp
				continue
			}
		}
		// Same for the deployment-wide default: reloadRules puts it in
		// snap.defaults, not in byKey, and resolveRule only ever reads it from
		// there.
		if r.Kind == string(KindDefault) {
			// Mirrors reloadRules: the QPS pair and the in-flight cap are
			// applied independently, so a default row carrying only one of
			// them still takes effect.
			if r.Concurrency != nil && *r.Concurrency >= 0 {
				v := *r.Concurrency
				snap.defaultConcurrency = &v
			}
			if r.Rate != nil && r.Burst != nil {
				if lp, ok := sanitizeParams(*r.Rate, *r.Burst, DefaultMaxRuleRate, DefaultMaxRuleBurst); ok {
					snap.defaults = &lp
				}
			}
			continue
		}
		// Mirrors reloadRules: each layer's master switch is hot-reloadable.
		if r.Kind == string(KindActivation) || r.Kind == string(KindConcurrencyActivation) {
			var v bool
			switch Mode(r.Mode) {
			case ModeLimited:
				v = true
			case ModeUnlimited:
				v = false
			default:
				continue
			}
			if r.Kind == string(KindActivation) {
				snap.active = &v
			} else {
				snap.concurrencyActive = &v
			}
			continue
		}
		// Mirrors reloadRules: each layer has its own enforcement switch.
		if r.Kind == string(KindConcurrencyEnforcement) {
			switch Mode(r.Mode) {
			case ModeLimited:
				v := false
				snap.concurrencyShadow = &v
			case ModeUnlimited:
				v := true
				snap.concurrencyShadow = &v
			default:
			}
			continue
		}
		// Enforcement carries its decision in Mode, mirroring reloadRules.
		if r.Kind == string(KindEnforcement) {
			switch Mode(r.Mode) {
			case ModeLimited:
				v := false
				snap.shadow = &v
			case ModeUnlimited:
				v := true
				snap.shadow = &v
			default:
				// ModeBlocked, same as reloadRules: not a valid enforcement
				// decision, so the ini value stands.
			}
			continue
		}
		snap.byKey[r.Kind+":"+r.Target] = r
	}
	s.rulesPtr.Store(snap)
	return s
}

// dsQuotaRule is shorthand for a per-datasource quota in tests.
func dsQuotaRule(target string, rateVal, burstVal int64) *Rule {
	return &Rule{
		Kind: string(KindDatasource), Target: target,
		Mode: string(ModeLimited), Rate: &rateVal, Burst: &burstVal,
	}
}

func defaultCfg() Config {
	return Config{
		Enabled:          true,
		DefaultUserRate:  30,
		DefaultUserBurst: 100,
		// The ceilings the admin API validates against. Set here because
		// production resolves them in ProvideService, which tests bypass; a
		// zero bound would reject every rule and the failure would look like a
		// validation bug rather than an unset test fixture.
		MaxRuleRate:        DefaultMaxRuleRate,
		MaxRuleBurst:       DefaultMaxRuleBurst,
		MaxRuleConcurrency: DefaultMaxRuleConcurrency,
	}
}

func buildCtx(method, path string, body []byte, u *user.SignedInUser) (*contextmodel.ReqContext, *httptest.ResponseRecorder) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	// Populate the router params the real macaron router would have set before
	// this middleware runs. Verified on a running server: web.Params(c.Req)
	// returns ":uid" inside the middleware, which is how proxy and resources
	// requests are attributed to a datasource at all. Without this, every such
	// test would silently exercise the "no datasource identified" path and the
	// attribution would be untested.
	if params := routeParamsFor(path); len(params) > 0 {
		req = web.SetURLParams(req, params)
	}
	rec := httptest.NewRecorder()
	return &contextmodel.ReqContext{
		SignedInUser: u,
		Context: &web.Context{
			Req:  req,
			Resp: web.NewResponseWriter(req.Method, rec),
		},
	}, rec
}

// TestMiddleware_NilService locks the not-wired path. Some HTTPServer
// construction paths (SetupAPITestServer in pkg/api/common_test.go) leave
// DsRateLimit nil while still registering routes, so a nil receiver must
// behave as disabled rather than panic. Without the guard this reproduces
// the pkg/api failures in TestAPIEndpoint_Metrics_QueryMetricsV2 and
// TestAPIEndpoint_Metrics_PluginDecryptionFailure.
func TestMiddleware_NilService(t *testing.T) {
	var s *Service // not wired

	u := &user.SignedInUser{UserID: 1}
	c, rec := buildCtx("POST", "/api/ds/query", []byte(`{"queries":[{},{}]}`), u)

	require.NotPanics(t, func() { s.Middleware(c) },
		"nil *Service must not panic — it is reachable via SetupAPITestServer")

	// The request must pass through untouched: no 429, nothing written.
	require.Equal(t, http.StatusOK, rec.Code,
		"nil service must not write a status (got %d, body %q)", rec.Code, rec.Body.String())
	require.False(t, c.Resp.Written(),
		"nil service must leave the response unwritten so the handler still runs")

	// Admin handlers are reachable the same way and must degrade to 404.
	for name, fn := range map[string]func(*contextmodel.ReqContext) response.Response{
		"AdminList":   s.AdminList,
		"AdminGet":    s.AdminGet,
		"AdminPut":    s.AdminPut,
		"AdminDelete": s.AdminDelete,
		"AdminStats":  s.AdminStats,
	} {
		t.Run(name, func(t *testing.T) {
			var resp response.Response
			require.NotPanics(t, func() { resp = fn(c) }, "%s must not panic on nil receiver", name)
			require.NotNil(t, resp)
			require.Equal(t, http.StatusNotFound, resp.Status(),
				"%s should report 404 when the service is not wired", name)
		})
	}
}

// TestMiddleware_Unlimited locks the unlimited fast path.
// ModeUnlimited must let 1000 requests through and must NOT create a
// per-user *rate.Limiter (that's the whole point of the fast path — it
// dodges the Limit==0 trap in x/time/rate).
func TestMiddleware_Unlimited(t *testing.T) {
	rule := &Rule{
		Kind: string(KindSA), Target: "12", Mode: string(ModeUnlimited),
	}
	s := newTestService(defaultCfg(), rule)

	u := &user.SignedInUser{UserID: 12, IsServiceAccount: true}
	for i := 0; i < 1000; i++ {
		c, rec := buildCtx("POST", "/api/ds/query", []byte(`{"queries":[{}]}`), u)
		s.Middleware(c)
		require.Equal(t, http.StatusOK, rec.Code, "iteration %d unexpectedly non-200: %d", i, rec.Code)
	}

	// A bucket is now allocated for an unlimited key, but never charged. The
	// previous assertion here was "no limiter exists", which described how the
	// exemption happened to be implemented (an early return) rather than what
	// it has to guarantee -- and that early return was also skipping the
	// datasource quotas. Asserting the balance instead survives the fix and is
	// the stronger claim: not consulted, whatever the allocation.
	//
	// The bucket earns its keep: it carries the deny-log throttle used when a
	// datasource quota refuses an unlimited caller. One limiter per
	// rule-listed key is bounded by the rule table, not by traffic.
	v, exists := s.userBuckets.Load("sa:12")
	require.True(t, exists)
	lim := v.(*userEntry).limiter
	require.InDelta(t, float64(lim.Burst()), lim.TokensAt(time.Now()), 0.01,
		"1000 unlimited requests must leave the identity bucket untouched")
}

// TestMiddleware_UserDeniedDoesNotChargeDatasource locks the first-fail-wins
// order: identity first, datasource quota second. If identity denies, no
// datasource bucket may be touched.
//
// Otherwise a throttled caller would still consume the backend's quota on
// requests that never reach that backend -- capacity spent on queries that do
// not run, taken from whoever would have used it legitimately.
func TestMiddleware_UserDeniedDoesNotChargeDatasource(t *testing.T) {
	cfg := defaultCfg()
	cfg.DefaultUserBurst = 1
	cfg.DefaultUserRate = 1
	s := newTestService(cfg, dsQuotaRule("PROM_MAIN", 500, 600))

	u := &user.SignedInUser{UserID: 7}
	body := []byte(`{"queries":[{"range":true,"datasource":{"uid":"PROM_MAIN"}}]}`)

	// First request: identity allows, datasource is charged.
	c, _ := buildCtx("POST", dsQueryPath, body, u)
	s.Middleware(c)

	lim := s.getDatasourceLimiter("PROM_MAIN")
	require.NotNil(t, lim, "precondition: the quota must exist")
	before := lim.TokensAt(time.Now())

	// Next 50: identity denies every one. The datasource must not be charged.
	for i := 0; i < 50; i++ {
		c, _ = buildCtx("POST", dsQueryPath, body, u)
		s.Middleware(c)
	}

	after := lim.TokensAt(time.Now())
	require.GreaterOrEqual(t, after, before,
		"datasource tokens must not decrease while the identity bucket is "+
			"denying: before=%v after=%v", before, after)
}

// TestMiddleware_ShadowInvariant locks shadow-mode accounting.
// In shadow mode:
//   - blocked path must not write 429 (i.e., request would pass through).
//   - attempted == allowed + denied at token granularity for every kind.
func TestMiddleware_ShadowInvariant(t *testing.T) {
	cfg := defaultCfg()
	cfg.ShadowMode = true
	cfg.DefaultUserBurst = 1
	cfg.DefaultUserRate = 1

	blockedRule := &Rule{Kind: string(KindSA), Target: "99", Mode: string(ModeBlocked)}
	s := newTestService(cfg, blockedRule)

	// Blocked SA in shadow mode: no 429 should be written.
	u := &user.SignedInUser{UserID: 99, IsServiceAccount: true}
	c, rec := buildCtx("POST", "/api/datasources/proxy/1", nil, u)
	s.Middleware(c)
	require.Equal(t, http.StatusOK, rec.Code,
		"blocked+shadow must not write 429 (got status %d, body %q)", rec.Code, rec.Body.String())

	// Even after being denied, the request must not hold any custom body.
	require.Empty(t, rec.Header().Get("Retry-After"),
		"shadow mode must not set Retry-After")
}

// TestMiddleware_NLargerThanBurst locks the oversized-request case.
// AllowN with n > burst is unconditionally false. The design chose to
// size burst above any realistic dashboard so this never trips in
// practice; the test guarantees the observed behavior (429) rather
// than silently under-charging.
func TestMiddleware_NLargerThanBurst(t *testing.T) {
	cfg := defaultCfg()
	cfg.DefaultUserBurst = 5
	s := newTestService(cfg)

	// Build a body with 20 queries (n=20 > burst=5).
	body, _ := json.Marshal(map[string]any{
		"queries": []map[string]any{
			{}, {}, {}, {}, {}, {}, {}, {}, {}, {},
			{}, {}, {}, {}, {}, {}, {}, {}, {}, {},
		},
	})
	u := &user.SignedInUser{UserID: 1}
	c, rec := buildCtx("POST", "/api/ds/query", body, u)
	s.Middleware(c)

	require.Equal(t, http.StatusTooManyRequests, rec.Code,
		"n > burst must be denied; got %d body=%q", rec.Code, rec.Body.String())
}

// TestMiddleware_BodyReplay locks the body-restore contract.
// After countQueriesAndReplayBody, downstream handlers must still be
// able to read c.Req.Body via web.Bind (which does
// json.NewDecoder(req.Body).Decode).
func TestMiddleware_BodyReplay(t *testing.T) {
	cfg := defaultCfg()
	s := newTestService(cfg)

	body, _ := json.Marshal(map[string]any{
		"queries": []map[string]any{{"refId": "A"}, {"refId": "B"}},
	})
	u := &user.SignedInUser{UserID: 1}
	c, _ := buildCtx("POST", "/api/ds/query", body, u)

	s.Middleware(c)

	// Now simulate what web.Bind does: read Body via json.Decoder.
	var got struct {
		Queries []map[string]any `json:"queries"`
	}
	require.NoError(t, json.NewDecoder(c.Req.Body).Decode(&got),
		"downstream web.Bind must still be able to decode Body")
	require.Len(t, got.Queries, 2)
	require.Equal(t, "A", got.Queries[0]["refId"])
}

// TestMiddleware_DatasourceDenyAfterUserOK locks the other ordering branch:
// identity allows, the datasource quota refuses.
//
// The identity token is refunded in that case, symmetrically with the
// datasource rollback: the request reached no backend, so nobody spent
// anything.
//
// This test previously pinned the opposite, on the stated grounds that
// refunding "would need a second round of locking on the hot path for no
// correctness gain". Both halves turned out to be wrong. There is a
// correctness gain -- without the refund, a datasource saturated by other
// traffic drains every caller aimed at it, and denials start reporting
// reason=user, blaming a caller who is within their limit (measured: 60
// retries at a full quota split 39 datasource / 20 user). And the hot path
// does not pay: AllowN and ReserveN are the same single lock and measure the
// same (24.7ns vs 22.7ns); only the deny path adds a second lock for the
// cancel (44.8ns), which is already the path that writes a 429 and a log line.
func TestMiddleware_DatasourceDenyAfterUserOK(t *testing.T) {
	cfg := defaultCfg()
	s := newTestService(cfg, dsQuotaRule("PROM_MAIN", 1, 1))

	u := &user.SignedInUser{UserID: 3}

	// First request drains the datasource quota.
	c, _ := buildCtx("POST", "/api/datasources/proxy/uid/PROM_MAIN", nil, u)
	s.Middleware(c)

	userLim := s.getUserLimiter("user:3", s.resolveRule("user:3"))
	tokensBeforeSecond := userLim.TokensAt(time.Now())

	// Second request: the identity bucket still has plenty of tokens, but this
	// datasource's quota is empty. Must be the SAME datasource -- a different
	// one has its own bucket and would be allowed, which is the whole point of
	// the per-datasource split.
	c, rec := buildCtx("POST", "/api/datasources/proxy/uid/PROM_MAIN", nil, u)
	s.Middleware(c)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)

	tokensAfterSecond := userLim.TokensAt(time.Now())
	// The identity token was refunded: the request never reached a backend, so
	// charging the caller for it would let a saturated datasource consume the
	// budget of everyone pointed at it.
	require.GreaterOrEqual(t, tokensAfterSecond, tokensBeforeSecond-0.01,
		"identity token must be refunded when the datasource quota denies -- "+
			"otherwise a backend saturated by others silently drains this caller")

	// An unrelated datasource must be unaffected: this is the failure the whole
	// refactor exists to fix -- a MySQL report must not be refused because a
	// Prometheus instance is saturated.
	c, rec = buildCtx("POST", "/api/datasources/proxy/uid/MYSQL_REPORTS", nil, u)
	s.Middleware(c)
	require.Equal(t, http.StatusOK, rec.Code,
		"a saturated datasource must not deny traffic to a different datasource")
}

// failingBody yields some bytes and then fails, like a client connection that
// drops mid-upload.
type failingBody struct {
	reads int
	err   error
}

func (b *failingBody) Read(p []byte) (int, error) {
	switch b.reads {
	case 0:
		b.reads++
		return copy(p, []byte(`{"queries":[{"ins`)), nil
	case 1:
		b.reads++
		return 0, b.err
	default:
		// A spent body does not keep replaying its error: a real server body
		// returns http.ErrBodyReadAfterClose once closed, and most readers
		// return EOF. Modelling that is what makes this test able to fail --
		// a fake that replays b.err forever would pass with or without the
		// fix, since the handler would see the right error by accident.
		return 0, io.EOF
	}
}
func (b *failingBody) Close() error { return nil }

// TestCountQueries_BodyReadErrorStaysReadable covers the error path of the
// body-replay logic.
//
// The middleware must consume the body to count queries, so it always owes the
// handler a replacement: ReadAll drains it and Close closes it. On the success
// path that replacement is the bytes we read. On the error path there was no
// replacement at all, so the handler read from a spent body -- verified before
// the fix: downstream ReadAll returned 0 bytes.
//
// The replacement deliberately replays the original error rather than the
// partial bytes. Both make the request fail, but truncated JSON would blame the
// payload for what was actually a broken connection, sending whoever debugs it
// after the wrong party.
func TestCountQueries_BodyReadErrorStaysReadable(t *testing.T) {
	readErr := errors.New("connection reset by peer")

	cfg := defaultCfg()
	cfg.ShadowMode = false
	s := newTestService(cfg)

	req := httptest.NewRequest("POST", dsQueryPath, &failingBody{err: readErr})
	rec := httptest.NewRecorder()
	c := &contextmodel.ReqContext{
		Context:      &web.Context{Resp: web.NewResponseWriter("POST", rec), Req: req},
		SignedInUser: &user.SignedInUser{UserID: 11},
		IsSignedIn:   true,
	}

	s.Middleware(c)

	require.NotEqual(t, http.StatusTooManyRequests, rec.Code,
		"an unreadable body must not be charged as an oversized request")
	require.NotNil(t, c.Req.Body, "middleware must always leave a readable body behind")

	_, err := io.ReadAll(c.Req.Body)
	require.ErrorIs(t, err, readErr,
		"the handler must see the original transport error, not truncated JSON; "+
			"otherwise a dropped connection is misdiagnosed as a malformed payload")
}

// TestCountQueries_OversizedBodyIsBoundedNotRejected locks the two decisions in
// the bounded-read path.
//
// The handler decodes the body as a stream (web.Bind uses json.NewDecoder), so
// the ReadAll here is an extra full copy this middleware adds, and it happens
// before the limit decision -- a request about to be rejected pays for it too.
// Measured: ReadAll on a 64 MiB body grows the heap 135 MiB; a bounded prefix
// of the same body costs 4 MiB. Nothing upstream caps this path, and any user
// with datasource-query permission can reach it concurrently.
//
// Two things must hold, and they pull in opposite directions:
//
//  1. The request must NOT be rejected. This middleware decides cost, not
//     admissibility; a 413 here would let the limiter change the outcome of
//     requests even in shadow mode, which is precisely what shadow mode
//     promises it cannot do.
//  2. The handler must still receive the WHOLE body, byte for byte, or
//     bounding our read would corrupt requests we chose not to reject.
func TestCountQueries_OversizedBodyIsBoundedNotRejected(t *testing.T) {
	// A body far over the cap, valid JSON, with a payload we can verify
	// survived intact.
	filler := strings.Repeat("y", int(maxCountedBodyBytes)+4096)
	raw := []byte(`{"queries":[{"instant":true,"pad":"` + filler + `"}]}`)
	require.Greater(t, int64(len(raw)), maxCountedBodyBytes, "body must exceed the cap")

	cfg := defaultCfg()
	cfg.ShadowMode = false
	// Burst high enough that the ceiling charge alone does not deny, so a 429
	// here would mean the size path rejected the request. No datasource quota is
	// configured, so only the identity bucket is in play.
	cfg.DefaultUserBurst = 4096
	cfg.DefaultUserRate = 4096
	s := newTestService(cfg)

	c, rec := buildCtx("POST", dsQueryPath, raw, &user.SignedInUser{UserID: 21})
	s.Middleware(c)

	require.NotEqual(t, http.StatusRequestEntityTooLarge, rec.Code,
		"the limiter must not reject on body size: that would make it decide "+
			"admissibility, and would fire in shadow mode too")
	require.NotEqual(t, http.StatusTooManyRequests, rec.Code,
		"an oversized body is charged this user's burst, which by construction "+
			"fits in the bucket, so it must be admitted rather than refused")

	got, err := io.ReadAll(c.Req.Body)
	require.NoError(t, err, "the handler must still be able to read the body")
	require.Equal(t, raw, got,
		"the handler must see the original body byte-for-byte; bounding our own "+
			"read must not truncate what the handler decodes")
}

// TestCountQueries_OversizedBodyChargesCeiling pins the cost of a body we
// refused to count.
//
// Charging 1 token (the other "safe" default) would make an oversized body the
// cheapest possible request, turning the size cap into a way to buy queries.
// Charging the ceiling means declining to count is never advantageous.
func TestCountQueries_OversizedBodyChargesCeiling(t *testing.T) {
	filler := strings.Repeat("z", int(maxCountedBodyBytes)+1024)
	raw := []byte(`{"queries":[{"instant":true,"pad":"` + filler + `"}]}`)

	cfg := defaultCfg()
	cfg.ShadowMode = false
	// Burst below the ceiling charge: if the request were charged 1 token it
	// would be allowed, so the assertion below distinguishes the two policies.
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 20, 40
	s := newTestService(cfg)

	// Charged burst tokens, one such request drains the bucket exactly, so the
	// first is admitted and the second must be refused. Were it charged 1
	// token, dozens would sail through -- which is what distinguishes the two
	// policies here.
	c1, rec1 := buildCtx("POST", dsQueryPath, raw, &user.SignedInUser{UserID: 22})
	s.Middleware(c1)
	require.NotEqual(t, http.StatusTooManyRequests, rec1.Code,
		"the first burst-sized request fits in a full bucket")

	c2, rec2 := buildCtx("POST", dsQueryPath, raw, &user.SignedInUser{UserID: 22})
	s.Middleware(c2)
	require.Equal(t, http.StatusTooManyRequests, rec2.Code,
		"an uncountable body must cost the user's whole burst, not 1 token; "+
			"otherwise oversizing the payload is the cheapest way to buy queries")
}

// routeParamsFor mimics the macaron router's extraction of :uid / :id for the
// datasource routes, so buildCtx produces the same context shape production has.
func routeParamsFor(path string) map[string]string {
	// Strip any query string, then match the two addressing forms used by the
	// proxy and resources routes.
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	for _, prefix := range []string{
		"/api/datasources/proxy/uid/",
		"/api/datasources/uid/",
	} {
		if strings.HasPrefix(path, prefix) {
			rest := path[len(prefix):]
			uid, _, _ := strings.Cut(rest, "/")
			if uid != "" && uid != "resources" {
				return map[string]string{":uid": uid}
			}
		}
	}
	for _, prefix := range []string{
		"/api/datasources/proxy/",
		"/api/datasources/",
	} {
		if strings.HasPrefix(path, prefix) {
			rest := path[len(prefix):]
			id, _, _ := strings.Cut(rest, "/")
			if id == "" {
				continue
			}
			if _, err := strconv.Atoi(id); err == nil {
				return map[string]string{":id": id}
			}
		}
	}
	return nil
}

// TestUnlimited_StillPaysDatasourceQuota pins the boundary of the unlimited
// exemption: it waives the identity's own bucket, not the protection around a
// backend.
//
// The two limits exist for different reasons -- one bounds a caller's share,
// the other bounds what a backend can survive -- and the second is not the
// caller's to waive. The exemption is also granted precisely to high-volume
// accounts, so treating it as a blanket bypass excuses the one caller most
// able to flatten a datasource from the quota protecting it.
func TestUnlimited_StillPaysDatasourceQuota(t *testing.T) {
	newSvc := func() *Service {
		cfg := defaultCfg()
		cfg.Enabled, cfg.ShadowMode = true, false
		// Deliberately tiny, so a leak through the identity layer would be
		// visible as extra 200s rather than hidden by a roomy default.
		cfg.DefaultUserRate, cfg.DefaultUserBurst = 1, 1
		cfg.IniQuotas = map[string]laneParams{"PROM_MAIN": {rate: 1, burst: 1}}
		s := &Service{cfg: cfg, logger: log.New("dsratelimit.test")}
		s.rulesPtr.Store(&rulesSnapshot{
			byKey: map[string]*Rule{
				"user:77": {Kind: "user", Target: "77", Mode: string(ModeUnlimited)},
			},
			dsQuota: baseQuotas(cfg.IniQuotas), dsFromDB: map[string]bool{},
		})
		return s
	}
	quotaBody := []byte(`{"queries":[{"datasource":{"uid":"PROM_MAIN"}}]}`)

	codes := func(s *Service, uid int64, body []byte, n int) []int {
		out := make([]int, 0, n)
		for i := 0; i < n; i++ {
			c, rec := buildCtx("POST", dsQueryPath, body, &user.SignedInUser{UserID: uid})
			s.Middleware(c)
			out = append(out, rec.Code)
		}
		return out
	}

	t.Run("datasource quota still applies", func(t *testing.T) {
		s := newSvc()
		got := codes(s, 77, quotaBody, 3)
		require.Equal(t, []int{200, 429, 429}, got,
			"burst=1 admits the first request only; an unlimited identity must "+
				"not be able to spend a datasource's quota without limit")

		lim := s.getDatasourceLimiter("PROM_MAIN")
		require.NotNil(t, lim)
		require.LessOrEqual(t, lim.TokensAt(time.Now()), 0.01,
			"the quota bucket must actually be drained, not merely report 429")
	})

	t.Run("identity bucket is still waived", func(t *testing.T) {
		s := newSvc()
		// No quota for this datasource, so only the identity layer could
		// refuse -- and with burst=1 it certainly would if it were consulted.
		noQuota := []byte(`{"queries":[{"datasource":{"uid":"OTHER_DS"}}]}`)
		require.Equal(t, []int{200, 200, 200, 200}, codes(s, 77, noQuota, 4),
			"unlimited must still exempt the caller from its own bucket, "+
				"otherwise the mode means nothing")
	})

	t.Run("ordinary identity is unaffected", func(t *testing.T) {
		s := newSvc()
		require.Equal(t, []int{200, 429, 429}, codes(s, 88, quotaBody, 3),
			"control: a normal caller was already limited here")
	})
}
