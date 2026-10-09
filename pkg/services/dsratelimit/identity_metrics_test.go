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
	entry.withIdentityLabels("user:8", "bob", func(labels *identityMetricLabels) {
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
	first.withIdentityLabels("user:1", "old", func(labels *identityMetricLabels) {
		metricIdentityInflight.WithLabelValues(labels.values()...).Set(0)
		metricIdentityTokens.WithLabelValues(labels.kind, labels.identity, labels.login, "demand", "false").Add(3)
	})
	// Make the second entry newer, so cleanup evicts user:1.
	second := s.getUserEntry(s.rulesPtr.Load(), "user:2", s.resolveRuleIn(s.rulesPtr.Load(), "user:2"))
	second.withIdentityLabels("user:2", "new", func(labels *identityMetricLabels) {})
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
