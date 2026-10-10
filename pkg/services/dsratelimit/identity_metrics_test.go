package dsratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/contexthandler/ctxkey"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/user"
)

func freshIdentityMetrics(t *testing.T) {
	t.Helper()
	savedTokens := metricIdentityTokens
	savedInflight := metricIdentityInflight
	savedRate := metricIdentityRateLimit
	savedConcurrency := metricIdentityConcurrencyLimit
	metricIdentityTokens = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_identity_tokens_total"}, []string{"kind", "identity", "login", "result", "enforced"})
	metricIdentityInflight = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_identity_inflight"}, []string{"kind", "identity", "login"})
	metricIdentityRateLimit = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_identity_rate_limit"}, []string{"kind", "identity", "login"})
	metricIdentityConcurrencyLimit = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_identity_concurrency_limit"}, []string{"kind", "identity", "login"})
	t.Cleanup(func() {
		metricIdentityTokens = savedTokens
		metricIdentityInflight = savedInflight
		metricIdentityRateLimit = savedRate
		metricIdentityConcurrencyLimit = savedConcurrency
	})
}

func identityGaugeValue(t *testing.T, vec *prometheus.GaugeVec, labels ...string) float64 {
	t.Helper()
	g, err := vec.GetMetricWithLabelValues(labels...)
	require.NoError(t, err)
	return gaugeValue(t, g)
}

func TestIdentityMetrics_QPSDemandAndLimitedSemantics(t *testing.T) {
	freshIdentityMetrics(t)
	cfg := defaultCfg()
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 1, 1
	cfg.ShadowMode = true
	s := newTestService(cfg)
	u := &user.SignedInUser{UserID: 42, Login: "alice"}

	for i := 0; i < 3; i++ {
		c, rec := buildCtx(http.MethodPost, "/api/datasources/proxy/uid/PROM", nil, u)
		s.Middleware(c)
		require.NotEqual(t, http.StatusTooManyRequests, rec.Code)
	}
	s.sampleUserRates()

	require.Equal(t, float64(3), counterValue(t, metricIdentityTokens, "user", "42", "alice", "demand", "false"))
	require.Equal(t, float64(2), counterValue(t, metricIdentityTokens, "user", "42", "alice", "limited", "false"))
	require.Equal(t, float64(0), counterValue(t, metricIdentityTokens, "user", "42", "alice", "limited", "true"))
	require.Equal(t, float64(1), identityGaugeValue(t, metricIdentityRateLimit, "user", "42", "alice"))
}

func TestIdentityMetrics_QPSEnforcedLimited(t *testing.T) {
	freshIdentityMetrics(t)
	cfg := defaultCfg()
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 1, 1
	cfg.ShadowMode = false
	s := newTestService(cfg)
	u := &user.SignedInUser{UserID: 42, Login: "alice"}

	for i := 0; i < 2; i++ {
		c, _ := buildCtx(http.MethodPost, "/api/datasources/proxy/uid/PROM", nil, u)
		s.Middleware(c)
	}
	require.Equal(t, float64(1), counterValue(t, metricIdentityTokens, "user", "42", "alice", "limited", "true"))
	require.Equal(t, float64(0), counterValue(t, metricIdentityTokens, "user", "42", "alice", "limited", "false"))
}

func TestIdentityMetrics_ExcludeAPIKeyAndAnonymous(t *testing.T) {
	freshIdentityMetrics(t)
	s := newTestService(defaultCfg())

	for _, u := range []*user.SignedInUser{
		{ApiKeyID: 9},
		{IsAnonymous: true},
	} {
		c, _ := buildCtx(http.MethodPost, "/api/datasources/proxy/uid/PROM", nil, u)
		s.Middleware(c)
	}
	s.sampleUserRates()

	for _, key := range []string{"apikey:9", "anon:anon"} {
		v, ok := s.userBuckets.Load(key)
		if ok {
			v.(*userEntry).metricMu.Lock()
			require.Nil(t, v.(*userEntry).labels)
			v.(*userEntry).metricMu.Unlock()
		}
	}
}

func TestIdentityMetrics_LimitsShowUnlimitedWhenLayerInactive(t *testing.T) {
	freshIdentityMetrics(t)
	cfg := defaultCfg()
	cfg.Enabled, cfg.ConcurrencyEnabled = false, false
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 20, 40
	cfg.DefaultUserConcurrency = 5
	s := newTestService(cfg)
	entry := s.getUserEntry(s.rulesPtr.Load(), "user:8", s.resolveRuleIn(s.rulesPtr.Load(), "user:8"))
	s.withIdentityLabels(entry, "user:8", "bob", func(labels *identityMetricLabels) {
		metricIdentityRateLimit.WithLabelValues(labels.values()...).Set(s.effectiveIdentityRateLimit(s.rulesPtr.Load(), s.resolveRuleIn(s.rulesPtr.Load(), "user:8"), entry.limiter))
		metricIdentityConcurrencyLimit.WithLabelValues(labels.values()...).Set(s.effectiveIdentityConcurrencyLimit(s.rulesPtr.Load(), "user:8"))
	})

	require.Equal(t, float64(0), identityGaugeValue(t, metricIdentityRateLimit, "user", "8", "bob"))
	require.Equal(t, float64(0), identityGaugeValue(t, metricIdentityConcurrencyLimit, "user", "8", "bob"))
}

func TestIdentityMetrics_CleanupRemovesAllLocalSeries(t *testing.T) {
	freshIdentityMetrics(t)
	cfg := defaultCfg()
	cfg.CacheMaxEntries = 1
	s := newTestService(cfg)
	first := s.getUserEntry(s.rulesPtr.Load(), "user:1", s.resolveRuleIn(s.rulesPtr.Load(), "user:1"))
	first.lastUsedUnixNano.Store(1)
	s.withIdentityLabels(first, "user:1", "old", func(labels *identityMetricLabels) {
		metricIdentityInflight.WithLabelValues(labels.values()...).Set(0)
		metricIdentityTokens.WithLabelValues(labels.kind, labels.identity, labels.login, "demand", "false").Add(3)
	})
	// Make the second entry newer, so cleanup evicts user:1.
	second := s.getUserEntry(s.rulesPtr.Load(), "user:2", s.resolveRuleIn(s.rulesPtr.Load(), "user:2"))
	s.withIdentityLabels(second, "user:2", "new", func(labels *identityMetricLabels) {})
	s.cleanup()

	require.False(t, metricHasIdentity(t, metricIdentityInflight, "1", "old"),
		"evicted identity must not remain as a current gauge series")
	require.False(t, counterHasIdentity(t, metricIdentityTokens, "1", "old"),
		"evicted identity must not leave a CounterVec child in process memory")
}

func metricHasIdentity(t *testing.T, collector prometheus.Collector, identity, login string) bool {
	t.Helper()
	var gathered dto.Metric
	ch := make(chan prometheus.Metric, 8)
	go func() {
		collector.Collect(ch)
		close(ch)
	}()
	for metric := range ch {
		require.NoError(t, metric.Write(&gathered))
		labels := map[string]string{}
		for _, pair := range gathered.GetLabel() {
			labels[pair.GetName()] = pair.GetValue()
		}
		if labels["identity"] == identity && labels["login"] == login {
			return true
		}
		gathered.Reset()
	}
	return false
}

func counterHasIdentity(t *testing.T, vec *prometheus.CounterVec, identity, login string) bool {
	return metricHasIdentity(t, vec, identity, login)
}

func TestIdentityMetrics_ConcurrencyTracksHeldAndRelease(t *testing.T) {
	freshIdentityMetrics(t)
	s := newTestService(concCfg(5))
	h := newBlockingHandler(1)
	u := &user.SignedInUser{UserID: 7, Login: "robot", IsServiceAccount: true}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		r := concRequestForUser(s, "/api/ds/query", u, h.ServeHTTP)
		require.Equal(t, http.StatusOK, r.Code)
	}()
	<-h.entered

	require.Equal(t, float64(1), identityGaugeValue(t, metricIdentityInflight, "sa", "7", "robot"))
	require.Equal(t, float64(5), identityGaugeValue(t, metricIdentityConcurrencyLimit, "sa", "7", "robot"))
	close(h.release)
	wg.Wait()
	require.Equal(t, float64(0), identityGaugeValue(t, metricIdentityInflight, "sa", "7", "robot"))
}

func concRequestForUser(s *Service, path string, u *user.SignedInUser, handler http.HandlerFunc) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, nil)
	reqCtx := &contextmodel.ReqContext{SignedInUser: u}
	r = r.WithContext(context.WithValue(r.Context(), ctxkey.Key{}, reqCtx))
	w := httptest.NewRecorder()
	s.ConcurrencyMiddleware(handler).ServeHTTP(w, r)
	return w
}

// TestReloadGaugeRefreshNoTraffic pins the no-traffic hot-reload observability
// fix: identity_rate_limit / identity_concurrency_limit are otherwise only
// written on the request path, so an admin PUT leaves them stale until the next
// query. After reloadRules republishes them from the new snapshot, idle gauges
// must refresh across default, per-identity override, invalid-fallback and
// null-concurrency-fallback cases. No limiter decision is touched.
func TestReloadGaugeRefreshNoTraffic(t *testing.T) {
	freshIdentityMetrics(t)
	cfg := defaultCfg()
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 20, 40
	cfg.ConcurrencyEnabled = true
	cfg.DefaultUserConcurrency = 5
	s := newTestService(cfg)

	e := s.getUserEntry(s.rulesPtr.Load(), "user:42", s.resolveRuleIn(s.rulesPtr.Load(), "user:42"))
	s.withIdentityLabels(e, "user:42", "alice", func(l *identityMetricLabels) {
		metricIdentityRateLimit.WithLabelValues(l.values()...).Set(s.effectiveIdentityRateLimit(s.rulesPtr.Load(), s.resolveRuleIn(s.rulesPtr.Load(), "user:42"), e.limiter))
		metricIdentityConcurrencyLimit.WithLabelValues(l.values()...).Set(s.effectiveIdentityConcurrencyLimit(s.rulesPtr.Load(), "user:42"))
	})
	require.Equal(t, float64(20), identityGaugeValue(t, metricIdentityRateLimit, "user", "42", "alice"))

	rate7, burst10, conc3 := int64(7), int64(10), int64(3)
	badRate := int64(cfg.MaxRuleRate + 1)
	cases := []struct {
		name     string
		snap     *rulesSnapshot
		wantQPS float64
		wantConc float64
	}{
		{"override", &rulesSnapshot{byKey: map[string]*Rule{"user:42": {Kind: "user", Target: "42", Mode: "limited", Rate: &rate7, Burst: &burst10, Concurrency: &conc3}}}, 7, 3},
		{"invalid-rate-fallback", &rulesSnapshot{byKey: map[string]*Rule{"user:42": {Kind: "user", Target: "42", Mode: "limited", Rate: &badRate}}}, 20, 5},
		{"no-override-default", &rulesSnapshot{byKey: map[string]*Rule{}}, 20, 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s.rulesPtr.Store(tc.snap)
			s.republishIdentityGauges(tc.snap)
			require.Equal(t, tc.wantQPS, identityGaugeValue(t, metricIdentityRateLimit, "user", "42", "alice"))
			require.Equal(t, tc.wantConc, identityGaugeValue(t, metricIdentityConcurrencyLimit, "user", "42", "alice"))
		})
	}
}

// TestEvictionPreservesNewOwnerSeries pins the R1 eviction ownership fix: when
// cleanup removes a stale entry but a fresh request has already re-created the
// key, the stale entry must not DeleteLabelValues the new owner's live series.
// The interleaving is driven deterministically through identityMetricMu (no
// sleeps): the eviction goroutine blocks on the global lock while the test
// inserts+emits the new owner's counter and inflight gauge.
func TestEvictionPreservesNewOwnerSeries(t *testing.T) {
	freshIdentityMetrics(t)
	s := newTestService(defaultCfg())

	a := s.getUserEntry(s.rulesPtr.Load(), "user:7", s.resolveRuleIn(s.rulesPtr.Load(), "user:7"))
	s.withIdentityLabels(a, "user:7", "alice", func(l *identityMetricLabels) {
		metricIdentityTokens.WithLabelValues(l.kind, l.identity, l.login, "demand", "false").Add(100)
	})

	s.identityMetricMu.Lock()
	s.userBuckets.Delete("user:7")
	done := make(chan struct{})
	go func() { s.removeIdentitySeries(a, "user:7"); close(done) }()
	b := s.getUserEntry(s.rulesPtr.Load(), "user:7", s.resolveRuleIn(s.rulesPtr.Load(), "user:7"))
	b.metricMu.Lock()
	b.labels = &identityMetricLabels{kind: "user", identity: "7", login: "alice"}
	metricIdentityTokens.WithLabelValues("user", "7", "alice", "demand", "false").Add(3)
	metricIdentityInflight.WithLabelValues("user", "7", "alice").Set(4)
	b.metricMu.Unlock()
	s.identityMetricMu.Unlock()
	<-done

	require.True(t, a.removed)
	require.Equal(t, float64(103), counterValue(t, metricIdentityTokens, "user", "7", "alice", "demand", "false"),
		"new owner counter survives (no reset/wipe)")
	require.Equal(t, float64(4), identityGaugeValue(t, metricIdentityInflight, "user", "7", "alice"),
		"new owner inflight gauge survives")
}

// TestConcurrency_PanicDownstreamReleasesSlotThenAdmitsNext pins the concurrency
// defer-release: a downstream panic unwinds through the middleware, so the
// deferred release must still return the slot (inflight back to 0) and the very
// next request must be admitted. The middleware does not itself recover -- the
// panic propagates to Grafana's HTTP recovery layer -- so the test recovers.
func TestConcurrency_PanicDownstreamReleasesSlotThenAdmitsNext(t *testing.T) {
	freshIdentityMetrics(t)
	s := newTestService(concCfg(1))
	u := &user.SignedInUser{UserID: 8, Login: "panicuser"}

	panicking := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic("boom") })
	require.Panics(t, func() { concRequestForUser(s, "/api/ds/query", u, panicking) })
	require.Equal(t, float64(0), identityGaugeValue(t, metricIdentityInflight, "user", "8", "panicuser"),
		"deferred release must run despite the downstream panic")

	// Slot freed: a normal request is admitted and runs to completion.
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	r := concRequestForUser(s, "/api/ds/query", u, ok)
	require.Equal(t, http.StatusOK, r.Code)
	require.Equal(t, float64(0), identityGaugeValue(t, metricIdentityInflight, "user", "8", "panicuser"))
}
