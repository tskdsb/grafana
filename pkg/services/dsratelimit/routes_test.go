package dsratelimit

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/web"
)

// TestMiddleware_AllDatasourceRoutes locks the bypass surface: the middleware
// must fire on every one of the 9 datasource routes, and isDsQueryRoute must be
// true only for /api/ds/query (with or without a trailing slash).
//
// This is the behavior-side lock. TestRouteRegistrations below is the
// registration-side lock (source-level, catches "middleware forgotten on
// this route" without needing a running server).
func TestMiddleware_AllDatasourceRoutes(t *testing.T) {
	cases := []struct {
		name        string
		path        string
		wantDsQuery bool
	}{
		{"ds_query", "/api/ds/query", true},
		// macaron TrimSuffixes one trailing slash before matching
		// (pkg/web/tree.go:379), so this hits the same handler and must be
		// charged per query too. See TestIsDsQueryRoute_TrailingSlash.
		{"ds_query_trailing_slash", "/api/ds/query/", true},
		{"proxy_id", "/api/datasources/proxy/1", false},
		{"proxy_id_star", "/api/datasources/proxy/1/api/v1/query", false},
		{"proxy_uid", "/api/datasources/proxy/uid/abc", false},
		{"proxy_uid_star", "/api/datasources/proxy/uid/abc/api/v1/query", false},
		{"resources_id", "/api/datasources/1/resources", false},
		{"resources_uid", "/api/datasources/uid/abc/resources", false},
		{"resources_id_star", "/api/datasources/1/resources/api/v1/series", false},
		{"resources_uid_star", "/api/datasources/uid/abc/resources/api/v1/labels", false},
		// Save & Test in the datasource editor. CheckHealth reaches the backend
		// (datasources.go:833 pluginClient.CheckHealth), so it costs the
		// downstream a real request and is charged like the proxy routes.
		{"health_id", "/api/datasources/1/health", false},
		{"health_uid", "/api/datasources/uid/abc/health", false},
	}

	s := newTestService(defaultCfg())
	u := &user.SignedInUser{UserID: 1}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var body []byte
			if tc.wantDsQuery {
				body = []byte(`{"queries":[{},{},{}]}`)
			}
			c, rec := buildCtx("POST", tc.path, body, u)

			require.Equal(t, tc.wantDsQuery, isDsQueryRoute(c),
				"isDsQueryRoute mismatch for %s", tc.path)

			s.Middleware(c)

			require.Equal(t, http.StatusOK, rec.Code,
				"middleware unexpectedly denied %s: status=%d body=%q",
				tc.path, rec.Code, rec.Body.String())
		})
	}
}

// TestRouteRegistrations locks the same bypass surface at the
// source-registration layer.
// Reads pkg/api/api.go, finds each of the 9 datasource route literals,
// and asserts the same source line references hs.DsRateLimit.Middleware.
// Catches "someone added/refactored a datasource route and forgot to hang
// the middleware on it" — which is invisible to compile and to normal
// unit tests, but is exactly the bypass regression class that matters here.
func TestRouteRegistrations(t *testing.T) {
	apiPath := findAPIGoPath(t)
	// nolint:gosec
	// G304: the path is derived from runtime.Caller inside findAPIGoPath, i.e.
	// this repo's own source tree, not from any external input.
	src, err := os.ReadFile(apiPath)
	require.NoError(t, err, "read %s", apiPath)

	// Route literal -> whether we require the same line to mention
	// hs.DsRateLimit.Middleware.
	// (For /api/ds/query we match the substring `/ds/query`, and for
	// datasource routes we match distinguishing substrings.)
	needMiddleware := []string{
		`"/ds/query"`,
		`"/datasources/proxy/:id/*"`,
		`"/datasources/proxy/uid/:uid/*"`,
		`"/datasources/proxy/:id"`,
		`"/datasources/proxy/uid/:uid"`,
		`"/datasources/:id/resources"`,
		`"/datasources/uid/:uid/resources"`,
		`"/datasources/:id/resources/*"`,
		`"/datasources/uid/:uid/resources/*"`,
		`"/datasources/:id/health"`,
		`"/datasources/uid/:uid/health"`,
	}

	lines := strings.Split(string(src), "\n")
	// commentRe drops leading whitespace + "//" to skip commented-out routes.
	commentRe := regexp.MustCompile(`^\s*//`)

	for _, needle := range needMiddleware {
		t.Run(needle, func(t *testing.T) {
			var hit bool
			for _, ln := range lines {
				if commentRe.MatchString(ln) {
					continue
				}
				if !strings.Contains(ln, needle) {
					continue
				}
				// Only match a route registration (apiRoute.Any/Post/Get/... call).
				if !strings.Contains(ln, "apiRoute.") {
					continue
				}
				hit = true
				require.Contains(t, ln, "hs.DsRateLimit.Middleware",
					"route %s is registered without ds-rate-limit middleware:\n  %s",
					needle, strings.TrimSpace(ln))
			}
			require.True(t, hit, "route literal %s not found in %s (rename or removal?)", needle, apiPath)
		})
	}
}

// findAPIGoPath returns the absolute path of pkg/api/api.go, resolved
// relative to this test file — so `go test ./...` works regardless of
// where the module root is (matters for pkg-nested test execution).
func findAPIGoPath(t *testing.T) string {
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller failed")
	// thisFile = .../pkg/services/dsratelimit/routes_test.go
	// api.go   = .../pkg/api/api.go
	dir := filepath.Dir(thisFile)
	return filepath.Clean(filepath.Join(dir, "..", "..", "api", "api.go"))
}

// TestIsDsQueryRoute_TrailingSlash locks the cost-accounting bypass found
// while replying to MR review.
//
// macaron routes "/api/ds/query/" to the same handler as "/api/ds/query"
// (asserted below, so this is not an assumption). An exact string compare in
// isDsQueryRoute therefore let a caller charge an N-query request as a single
// token just by appending a slash — defeating the per-query accounting that
// makes lane_default_rate correspond to backend QPS.
//
// The pairing matters: the accounting predicate must agree with what macaron
// actually routes. Charging per-query on a path that never reaches the handler
// would over-charge requests that do not run at all.
func TestIsDsQueryRoute_TrailingSlash(t *testing.T) {
	m := web.New()
	var reached bool
	m.Post(dsQueryPath, func(c *web.Context) {
		reached = true
		c.Resp.WriteHeader(http.StatusOK)
	})

	body := []byte(`{"queries":[{"refId":"A"},{"refId":"B"},{"refId":"C"},{"refId":"D"},{"refId":"E"}]}`)

	for _, tc := range []struct {
		path        string
		wantRouted  bool
		wantCharged int
	}{
		{"/api/ds/query", true, 5},
		{"/api/ds/query/", true, 5},   // the bypass: must charge 5, not 1
		{"/api/ds/query//", false, 1}, // not routed -> must not charge per query
		{"/api/ds/query/x", false, 1},
		{"/api/datasources/proxy/1/foo", false, 1},
	} {
		t.Run(tc.path, func(t *testing.T) {
			// 1. What does macaron actually do with this path?
			reached = false
			probe := httptest.NewRequest(http.MethodPost, tc.path, nil)
			m.ServeHTTP(httptest.NewRecorder(), probe)
			require.Equal(t, tc.wantRouted, reached,
				"routing assumption for %s no longer holds; the accounting "+
					"predicate below must be re-derived from real routing", tc.path)

			// 2. Does our accounting agree with that?
			req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewReader(body))
			rec := httptest.NewRecorder()
			c := &contextmodel.ReqContext{Context: &web.Context{
				Req:  req,
				Resp: web.NewResponseWriter(http.MethodPost, rec),
			}}

			charged := 1
			if isDsQueryRoute(c) {
				charged = testChargedTokens(c, 40)
			}
			require.Equal(t, tc.wantCharged, charged,
				"%s must be charged %d token(s)", tc.path, tc.wantCharged)

			// Routed-and-charged must always coincide for the query route.
			require.Equal(t, tc.wantRouted, isDsQueryRoute(c),
				"isDsQueryRoute must match what macaron routes, for %s", tc.path)
		})
	}
}

// TestTokenCost_FanOut locks the cost model: one token per *backend request*,
// not per element of queries[].
//
// The Prometheus datasource runs instant / range / exemplar as three
// independent ifs (pkg/tsdb/prometheus/querydata/request.go:125,131,143), so
// one query can issue up to three backend calls. If the limiter charged
// len(queries) instead, lane_default_rate would admit ~1.2-1.5x the backend
// QPS it names, and the operator would have to maintain an empirical
// correction factor that drifts with traffic mix. Counting the flags keeps
// the lane limit derivable from the backend quota by plain subtraction.
//
// The legacy fallback case is the dangerous one: older dashboards send
// neither `range` nor `instant`, and models/query.go:103-105 treats that as a
// range query. A cost function that only counted explicit flags would charge
// those requests 0 tokens — exempting legacy dashboards from rate limiting.
func TestTokenCost_FanOut(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		// Legacy / flagless: neither instant nor range -> datasource runs it
		// as a range query. Must cost 1 per query, never 0.
		{"flagless_one", `{"queries":[{"refId":"A"}]}`, 1},
		{"flagless_three", `{"queries":[{},{},{}]}`, 3},

		// Explicit single-mode queries.
		{"instant_only", `{"queries":[{"instant":true}]}`, 1},
		{"range_only", `{"queries":[{"range":true}]}`, 1},
		{"both_false", `{"queries":[{"instant":false,"range":false}]}`, 1},

		// The fan-out cases the old len(queries) model under-charged.
		{"instant_and_range", `{"queries":[{"instant":true,"range":true}]}`, 2},
		{"all_three", `{"queries":[{"instant":true,"range":true,"exemplar":true}]}`, 3},
		{"exemplar_with_range", `{"queries":[{"range":true,"exemplar":true}]}`, 2},
		// exemplar alone still implies the legacy range fallback -> 1 + 1.
		{"exemplar_only", `{"queries":[{"exemplar":true}]}`, 2},

		// A realistic dashboard panel refresh: mixed modes in one body.
		{"mixed", `{"queries":[{"instant":true,"range":true},{"range":true},{}]}`, 4},

		// Degenerate bodies fall back to 1 rather than hard-failing.
		{"empty_queries", `{"queries":[]}`, 1},
		{"no_queries_key", `{"foo":1}`, 1},
		{"malformed_json", `{"queries":[`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, dsQueryPath,
				bytes.NewReader([]byte(tc.body)))
			c := &contextmodel.ReqContext{Context: &web.Context{
				Req:  req,
				Resp: web.NewResponseWriter(http.MethodPost, httptest.NewRecorder()),
			}}

			got := testChargedTokens(c, 40)
			require.Equal(t, tc.want, got, "token cost for %s", tc.body)

			// Body must still be readable by the downstream handler.
			replayed, err := io.ReadAll(c.Req.Body)
			require.NoError(t, err)
			require.Equal(t, tc.body, string(replayed),
				"body must be replayed verbatim for web.Bind")
		})
	}
}

// TestTokenCost_NeverZero is the invariant that matters most: no body shape
// may ever cost 0 tokens, or that shape becomes a free bypass.
func TestTokenCost_NeverZero(t *testing.T) {
	for _, body := range []string{
		`{"queries":[{}]}`,
		`{"queries":[{"instant":false}]}`,
		`{"queries":[{"range":false}]}`,
		`{"queries":[{"instant":false,"range":false,"exemplar":false}]}`,
		`{"queries":[{"instant":null,"range":null}]}`,
		`{}`,
		``,
	} {
		req := httptest.NewRequest(http.MethodPost, dsQueryPath, bytes.NewReader([]byte(body)))
		c := &contextmodel.ReqContext{Context: &web.Context{
			Req:  req,
			Resp: web.NewResponseWriter(http.MethodPost, httptest.NewRecorder()),
		}}
		require.GreaterOrEqual(t, testChargedTokens(c, 40), 1,
			"cost must never be 0 for body %q", body)
	}
}

// TestBurstFloor_OversizedRequestIsDeniedForever documents *why* burst has a
// hard floor, so the constant in pkg/setting's test is not just an unexplained
// number.
//
// x/time/rate has no queueing: reserveN computes `ok := n <= lim.burst`
// (rate.go:371), so AllowN(n) with n > burst returns false on every call, no
// matter how long the caller waits or how many tokens accumulated. A dashboard
// panel whose token cost exceeds burst therefore never loads — and because it
// shows up as a steady trickle of 429s rather than an outage, it is easy to
// misread as normal throttling.
//
// Measured worst single panel on this deployment costs 29 tokens, which is why
// default_user_burst is 40 rather than something tighter.
func TestBurstFloor_OversizedRequestIsDeniedForever(t *testing.T) {
	cfg := defaultCfg()
	cfg.ShadowMode = false // we want the real 429
	cfg.DefaultUserRate = 20
	cfg.DefaultUserBurst = 10 // deliberately below the request cost

	s := newTestService(cfg)
	u := &user.SignedInUser{UserID: 1}

	// 12 flagless queries -> 12 tokens, above the burst of 10.
	body := []byte(`{"queries":[{},{},{},{},{},{},{},{},{},{},{},{}]}`)

	// Waiting does not help: the bucket is full (limiter starts full) and
	// refills at 20/s, yet every attempt is refused because 12 > burst=10.
	for attempt := 1; attempt <= 3; attempt++ {
		c, rec := buildCtx("POST", dsQueryPath, body, u)
		s.Middleware(c)
		require.Equal(t, http.StatusTooManyRequests, rec.Code,
			"attempt %d: n=12 > burst=10 must be denied; x/time/rate never admits it", attempt)
	}

	// Raising burst above the request cost fixes it immediately — proving the
	// denial was structural (n > burst), not exhausted tokens.
	cfg.DefaultUserBurst = 40
	s2 := newTestService(cfg)
	c, rec := buildCtx("POST", dsQueryPath, body, u)
	s2.Middleware(c)
	require.Equal(t, http.StatusOK, rec.Code,
		"with burst=40 the same 12-token request must pass (body %q)", rec.Body.String())
}

// TestRateLimitKey_MatchesAdminKeyShape locks the invariant that makes admin
// rules reachable at all.
//
// reloadRules stores every rule under Kind+":"+Target (ratelimit.go). If
// rateLimitKey returns a key in any other shape for some identity type, an
// admin rule for that type is accepted by the API, shows up in AdminList, and
// then silently never matches — the limit looks configured but does nothing.
// That is strictly worse than rejecting the rule, because nothing surfaces the
// mismatch.
//
// This regressed once already: anonymous requests keyed as "anon" (no colon)
// while rules were stored as "anon:<target>".
func TestRateLimitKey_MatchesAdminKeyShape(t *testing.T) {
	for _, tc := range []struct {
		name     string
		u        *user.SignedInUser
		apiKeyID int64
		anon     bool
		sa       bool
		wantKind string
	}{
		{name: "user", u: &user.SignedInUser{UserID: 7}, wantKind: string(KindUser)},
		{name: "service_account", u: &user.SignedInUser{UserID: 42}, sa: true, wantKind: string(KindSA)},
		{name: "apikey", u: &user.SignedInUser{UserID: 0}, apiKeyID: 3, wantKind: string(KindApiKey)},
		{name: "anonymous", u: &user.SignedInUser{UserID: 0}, anon: true, wantKind: string(KindAnon)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := buildCtx("POST", dsQueryPath, nil, tc.u)
			c.IsServiceAccount = tc.sa
			c.IsAnonymous = tc.anon
			c.ApiKeyID = tc.apiKeyID

			key := rateLimitKey(c)

			// Shape: exactly "<kind>:<id>" with a non-empty id.
			parts := strings.SplitN(key, ":", 2)
			require.Len(t, parts, 2,
				"key %q for %s has no colon; an admin rule (stored as kind:target) "+
					"could never match it", key, tc.name)
			require.NotEmpty(t, parts[1], "key %q has an empty target", key)
			require.Equal(t, tc.wantKind, parts[0], "kind prefix of %q", key)

			// keyKind (used for metric labels) must agree, and must be a kind
			// the admin API accepts — otherwise the metric label names a kind
			// no rule can be written for.
			require.Equal(t, tc.wantKind, keyKind(key))
			require.True(t, ValidKind(keyKind(key)),
				"kind %q is not in validKinds, so no admin rule can target it", keyKind(key))

			// End to end: a rule stored the way the admin API stores it must be
			// the rule the middleware resolves for this identity.
			rate1, burst1 := int64(1), int64(1)
			rule := &Rule{
				Kind: parts[0], Target: parts[1],
				Mode: string(ModeLimited), Rate: &rate1, Burst: &burst1,
			}
			s := newTestService(defaultCfg(), rule)
			require.Same(t, rule, s.resolveRule(key),
				"admin rule for %s/%s did not resolve for runtime key %q",
				parts[0], parts[1], key)
		})
	}
}

// TestAnonymous_BlockedByDefault locks the audit requirement: a datasource
// query with no identity cannot be attributed to anyone, so it is refused
// unless an operator explicitly opts in.
//
// Only reachable when [auth.anonymous] enabled=true (defaults to false).
func TestAnonymous_BlockedByDefault(t *testing.T) {
	cfg := defaultCfg()
	cfg.ShadowMode = false

	t.Run("denied_with_no_rule", func(t *testing.T) {
		s := newTestService(cfg)
		c, rec := buildCtx("POST", dsQueryPath, []byte(`{"queries":[{}]}`), &user.SignedInUser{UserID: 0})
		c.IsAnonymous = true
		s.Middleware(c)
		require.Equal(t, http.StatusTooManyRequests, rec.Code,
			"anonymous datasource queries must be refused by default (body %q)", rec.Body.String())
	})

	t.Run("signed_in_user_unaffected", func(t *testing.T) {
		s := newTestService(cfg)
		c, rec := buildCtx("POST", dsQueryPath, []byte(`{"queries":[{}]}`), &user.SignedInUser{UserID: 7})
		s.Middleware(c)
		require.Equal(t, http.StatusOK, rec.Code,
			"a signed-in user must not be caught by the anonymous default")
	})

	t.Run("operator_can_opt_in", func(t *testing.T) {
		r, b := int64(5), int64(5)
		rule := &Rule{
			Kind: string(KindAnon), Target: "anon",
			Mode: string(ModeLimited), Rate: &r, Burst: &b,
		}
		s := newTestService(cfg, rule)
		c, rec := buildCtx("POST", dsQueryPath, []byte(`{"queries":[{}]}`), &user.SignedInUser{UserID: 0})
		c.IsAnonymous = true
		s.Middleware(c)
		require.Equal(t, http.StatusOK, rec.Code,
			"an explicit anon rule must override the blocked default (body %q)", rec.Body.String())
	})
}

// TestKnownBypasses_PublicDashboardStaysGated turns the public-dashboard
// finding into an alarm rather than a comment.
//
// /api/public/dashboards/:accessToken/panels/:panelId/query is registered in
// pkg/services/publicdashboards/api/api.go, so it never passes through the
// middleware wired in pkg/api/api.go, and its service calls QueryData directly
// with an anonymous user. That is a genuine bypass; it is currently harmless
// only because the entire registration sits behind the publicDashboards
// feature toggle, which is alpha and off by default.
//
// "Off by default" is the whole safety argument, and it is one line in another
// package that nobody editing this limiter would think to check. If that gate
// is removed or defaulted on, enforcement silently stops covering a route that
// serves unauthenticated traffic. This test fails at that moment.
func TestKnownBypasses_PublicDashboardStaysGated(t *testing.T) {
	src, err := os.ReadFile("../publicdashboards/api/api.go")
	require.NoError(t, err, "public dashboard api.go must be readable")

	body := string(src)
	idx := strings.Index(body, "api.RegisterAPIEndpoints()")
	require.NotEqual(t, -1, idx,
		"RegisterAPIEndpoints call not found; if public dashboard routes are now "+
			"registered elsewhere, re-check whether the query route bypasses the "+
			"rate limiter and update this test")

	// The gate must be the toggle check immediately preceding registration.
	before := body[:idx]
	lastIf := strings.LastIndex(before, "if features.IsEnabled(featuremgmt.FlagPublicDashboards)")
	require.NotEqual(t, -1, lastIf,
		"public dashboard API registration is no longer gated on the "+
			"publicDashboards feature toggle. That gate is the only reason "+
			"/api/public/dashboards/:accessToken/panels/:panelId/query may skip "+
			"the datasource rate limiter: the route is registered outside "+
			"pkg/api/api.go and calls QueryData directly with an anonymous user. "+
			"Cover that route before relying on enforcement, and update "+
			"conf/defaults.ini [datasource_ratelimit] scope notes")

	// Nothing but whitespace/braces between the gate and the registration, so
	// the check really guards this call rather than sitting further up.
	between := before[lastIf:]
	require.Less(t, len(between), 200,
		"the toggle check is no longer adjacent to RegisterAPIEndpoints; verify "+
			"it still guards route registration")
}

// testChargedTokens is the cost half of the middleware's accounting, isolated
// for the tests that assert on token counts. It mirrors the middleware's own
// sequence exactly -- read the body, then either count it or fall back to the
// ceiling -- so a divergence between them shows up as a test failure rather
// than as a wrong charge in production.
func testChargedTokens(c *contextmodel.ReqContext, burst int) int {
	body, countable := readCountableBody(c)
	if !countable {
		_, n := newTestService(defaultCfg()).uncountableCost(c, body, burst)
		return n
	}
	_, n := datasourceTargets(c, body)
	return n
}
