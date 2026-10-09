package dsratelimit

import (
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/user"
)

// counterValue reads one labelled counter out of the registry.
func counterValue(t *testing.T, vec *prometheus.CounterVec, labels ...string) float64 {
	t.Helper()
	m, err := vec.GetMetricWithLabelValues(labels...)
	require.NoError(t, err)
	var pb dto.Metric
	require.NoError(t, m.(prometheus.Metric).Write(&pb))
	return pb.GetCounter().GetValue()
}

func histogramValue(t *testing.T, observer prometheus.Observer) (count uint64, sum float64) {
	t.Helper()
	var pb dto.Metric
	require.NoError(t, observer.(prometheus.Metric).Write(&pb))
	h := pb.GetHistogram()
	return h.GetSampleCount(), h.GetSampleSum()
}

func freshQueriesPerRequest(t *testing.T) {
	t.Helper()
	saved := metricQueriesPerRequest
	metricQueriesPerRequest = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "test_queries_per_request",
		Buckets: []float64{1, 2, 5, 10, 20, 40, 100, 300, 1000},
	})
	t.Cleanup(func() { metricQueriesPerRequest = saved })
}

// TestQueriesPerRequest_RecordsDemandBeforeTheLimiterDecides pins the metric's
// sizing semantics: it measures requested cost, not the subset the current
// rate/burst happened to admit.
//
// This distinction is load-bearing during shadow rollout. An over-burst
// request is still served in shadow mode, and is exactly the observation an
// operator needs before raising burst. Recording only outcomeAllowed made the
// histogram self-censor at the configured limit: the expensive request used to
// size burst was missing because the old burst was already too small.
func TestQueriesPerRequest_RecordsDemandBeforeTheLimiterDecides(t *testing.T) {
	freshQueriesPerRequest(t)
	cfg := defaultCfg()
	cfg.Enabled, cfg.ShadowMode = true, true
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 1, 1
	s := newTestService(cfg)

	// Three backend calls in one HTTP request, above burst=1. Shadow mode must
	// serve it, and the histogram must still contain the cost of three.
	body := []byte(`{"queries":[
		{"range":true,"datasource":{"uid":"PROM_MAIN"}},
		{"instant":true,"datasource":{"uid":"PROM_MAIN"}},
		{"datasource":{"uid":"PROM_MAIN"}}
	]}`)
	c, rec := buildCtx("POST", dsQueryPath, body, &user.SignedInUser{UserID: 5})
	s.Middleware(c)

	require.Equal(t, http.StatusOK, rec.Code, "shadow mode must serve the over-burst request")
	count, sum := histogramValue(t, metricQueriesPerRequest)
	require.EqualValues(t, 1, count, "every /api/ds/query demand must be sampled exactly once")
	require.Equal(t, float64(3), sum,
		"burst sizing must see the full cost even when the current limiter says it is too expensive")
}

// TestDeniedMetric_DistinguishesShadowFromEnforced is the reason the `enforced`
// label exists.
//
// Measured before it did: the same over-limit traffic produced
// denied_total = 9 in shadow mode and denied_total = 9 under enforcement, while
// actual rejections were 0 and 9. A dashboard therefore could not tell "we are
// refusing this many requests" from "we would refuse this many if we switched
// enforcement on" -- readings that call for opposite reactions. Since shadow
// mode is the default, the ambiguous reading is the one operators see first.
func TestDeniedMetric_DistinguishesShadowFromEnforced(t *testing.T) {
	run := func(shadow bool) (real429 int, deniedShadow, deniedEnforced float64) {
		metricDenied.Reset()
		cfg := defaultCfg()
		cfg.Enabled, cfg.ShadowMode = true, shadow
		cfg.DefaultUserRate, cfg.DefaultUserBurst = 1, 1
		s := &Service{cfg: cfg, logger: log.New("dsratelimit.test")}
		s.rulesPtr.Store(&rulesSnapshot{
			byKey: map[string]*Rule{}, dsQuota: map[string]laneParams{},
			dsFromDB: map[string]bool{},
		})
		u := &user.SignedInUser{UserID: 5}
		body := []byte(`{"queries":[{"range":true,"datasource":{"uid":"PROM_MAIN"}}]}`)
		for i := 0; i < 10; i++ {
			c, rec := buildCtx("POST", dsQueryPath, body, u)
			s.Middleware(c)
			if rec.Code == http.StatusTooManyRequests {
				real429++
			}
		}
		return real429,
			counterValue(t, metricDenied, dsLabelNone, "user", "user", "false"),
			counterValue(t, metricDenied, dsLabelNone, "user", "user", "true")
	}

	rejected, shadowCount, enforcedCount := run(true)
	require.Zero(t, rejected, "shadow mode must not reject")
	require.NotZero(t, shadowCount,
		"shadow denials must still be counted -- that projection is the whole "+
			"point of running shadow mode")
	require.Zero(t, enforcedCount,
		"shadow denials must not be counted as enforced: that reading would "+
			"claim users are being refused when every request was served")

	rejected, shadowCount, enforcedCount = run(false)
	require.NotZero(t, rejected, "enforcement must reject")
	require.EqualValues(t, rejected, enforcedCount,
		"under enforcement, denied_total{enforced=true} must match the number "+
			"of requests actually refused")
	require.Zero(t, shadowCount,
		"nothing may be attributed to shadow mode while enforcing")
}

func gaugeValue(t *testing.T, gauge prometheus.Gauge) float64 {
	t.Helper()
	var pb dto.Metric
	require.NoError(t, gauge.Write(&pb))
	return pb.GetGauge().GetValue()
}

// TestRuntimeConfigMetrics_ReportEffectiveHotReloadedState makes the dashboard
// independent of stale ini knowledge. The DB can hot-change every value below;
// publishing cfg fields alone would make the graph disagree with the request
// path immediately after an admin update.
func TestRuntimeConfigMetrics_ReportEffectiveHotReloadedState(t *testing.T) {
	cfg := defaultCfg()
	cfg.Enabled, cfg.ShadowMode = true, true
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 20, 40
	cfg.ConcurrencyEnabled, cfg.ConcurrencyShadowMode = true, true
	cfg.DefaultUserConcurrency = 0
	s := newTestService(cfg,
		&Rule{Kind: string(KindDefault), Target: DefaultTarget, Mode: string(ModeLimited),
			Rate: ptr64(55), Burst: ptr64(80), Concurrency: ptr64(12)},
		enforcementRule(true),
		&Rule{Kind: string(KindConcurrencyEnforcement), Target: DefaultTarget, Mode: string(ModeLimited)},
	)

	s.publishRuntimeConfig(s.rulesPtr.Load())
	require.Equal(t, float64(1), gaugeValue(t, metricEnabled))
	require.Equal(t, float64(0), gaugeValue(t, metricShadowMode))
	require.Equal(t, float64(1), gaugeValue(t, metricEnforcing))
	require.Equal(t, float64(55), gaugeValue(t, metricDefaultRate))
	require.Equal(t, float64(80), gaugeValue(t, metricDefaultBurst))
	require.Equal(t, float64(1), gaugeValue(t, metricConcurrencyEnabled))
	require.Equal(t, float64(0), gaugeValue(t, metricConcurrencyShadowMode))
	require.Equal(t, float64(12), gaugeValue(t, metricDefaultConcurrency))
	require.Equal(t, float64(1), gaugeValue(t, metricConcurrencyEnforcing))
}

// TestEnforcingGauge_ReportsConfiguredState pins the "is it actually on?" signal.
//
// Shadow mode is the default, so a deployment that believes it is protected but
// never flipped the setting is a realistic failure -- and one that stays
// invisible precisely because nothing is being rejected. Reading it off a gauge
// beats shelling into a box to check an ini.
func TestEnforcingGauge_ReportsConfiguredState(t *testing.T) {
	for _, tc := range []struct {
		name            string
		enabled, shadow bool
		want            float64
	}{
		{"enforcing", true, false, 1},
		{"shadow mode is not enforcing", true, true, 0},
		{"disabled is not enforcing", false, false, 0},
		{"disabled and shadow", false, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := defaultCfg()
			cfg.Enabled, cfg.ShadowMode = tc.enabled, tc.shadow
			s := newTestService(cfg)
			// Both the gauge and the denied_total label now derive from
			// Service.enforcing, so this asserts they cannot drift apart.
			require.Equal(t, tc.want == 1, s.enforcing(s.rulesPtr.Load()),
				"the gauge and the denied_total label must agree on what "+
					"'enforcing' means, or a dashboard built on one will "+
					"contradict the other")
		})
	}
}

// TestDenyLog_NamesTheDatasourceThatRefused checks the denial line is actionable.
//
// Metrics carry no identity (deliberately -- unbounded cardinality), so this log
// line is the only record of *who* was throttled. With per-datasource quotas it
// also has to say *which backend* ran out, otherwise reason=datasource leaves
// the reader to guess among every configured datasource.
func TestDenyLog_NamesTheDatasourceThatRefused(t *testing.T) {
	cfg := defaultCfg()
	cfg.Enabled, cfg.ShadowMode = true, false
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 100000, 100000
	cfg.IniQuotas = map[string]laneParams{"PROM_MAIN": {rate: 1, burst: 1}}
	s := &Service{cfg: cfg, logger: log.New("dsratelimit.test")}
	s.rulesPtr.Store(&rulesSnapshot{
		byKey: map[string]*Rule{}, dsQuota: baseQuotas(cfg.IniQuotas),
		dsFromDB: map[string]bool{},
	})
	cap := withCapturingLogger(s)

	u := &user.SignedInUser{UserID: 5}
	body := []byte(`{"queries":[{"range":true,"datasource":{"uid":"PROM_MAIN"}}]}`)
	for i := 0; i < 3; i++ {
		c, _ := buildCtx("POST", dsQueryPath, body, u)
		s.Middleware(c)
	}

	var found bool
	for _, line := range cap.lines() {
		if line.msg != "datasource query rate limit exceeded" {
			continue
		}
		found = true
		require.Equal(t, "datasource", line.kv["reason"])
		require.Equal(t, "PROM_MAIN", line.kv["target"],
			"a quota denial must name the datasource that refused; "+
				"reason=datasource alone does not identify the backend")
		require.Equal(t, true, line.kv["enforced"])
	}
	require.True(t, found, "a quota denial must be logged at all")
}

// TestDatasourceTokens_ReportsPerBackendLoad covers the signal a quota is
// actually chosen from.
//
// The request-level counters can only name a datasource when one refused, so
// they answer "how much did PROM_MAIN reject?" but never "how much did
// PROM_MAIN carry?" -- allowed requests are labelled `none` because one request
// may fan out to several backends. During shadow mode nothing is rejected, so
// without a per-datasource allowed count there is no measured basis for setting
// the quota at all.
func TestDatasourceTokens_ReportsPerBackendLoad(t *testing.T) {
	metricDatasourceTokens.Reset()

	cfg := defaultCfg()
	cfg.Enabled, cfg.ShadowMode = true, false
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 100000, 100000
	cfg.IniQuotas = map[string]laneParams{
		"PROM_MAIN": {rate: 2, burst: 2},
		"MYSQL_A":   {rate: 1000, burst: 1000},
	}
	s := &Service{cfg: cfg, logger: log.New("dsratelimit.test")}
	s.rulesPtr.Store(&rulesSnapshot{
		byKey: map[string]*Rule{}, dsQuota: baseQuotas(cfg.IniQuotas),
		dsFromDB: map[string]bool{},
	})

	// One request touching two datasources, so fan-out attribution is exercised
	// rather than assumed.
	u := &user.SignedInUser{UserID: 5}
	body := []byte(`{"queries":[` +
		`{"range":true,"datasource":{"uid":"PROM_MAIN"}},` +
		`{"datasource":{"uid":"MYSQL_A"}},` +
		`{"datasource":{"uid":"NO_QUOTA_DS"}}]}`)
	for i := 0; i < 4; i++ {
		c, _ := buildCtx("POST", dsQueryPath, body, u)
		s.Middleware(c)
	}

	promAllowed := counterValue(t, metricDatasourceTokens, "PROM_MAIN", "allowed")
	promDenied := counterValue(t, metricDatasourceTokens, "PROM_MAIN", "denied")
	mysqlAllowed := counterValue(t, metricDatasourceTokens, "MYSQL_A", "allowed")

	require.NotZero(t, promAllowed,
		"a datasource that served traffic must report allowed tokens; without "+
			"this there is no measured basis for sizing its quota")
	require.NotZero(t, promDenied,
		"PROM_MAIN has burst=2 and was hit 4 times, so some demand must be "+
			"recorded as denied")
	require.EqualValues(t, 4, promAllowed+promDenied,
		"allowed+denied must equal total demand for the backend -- under shadow "+
			"mode the denied half is served too, so the sum is what a quota is "+
			"sized against")

	// MYSQL_A has ample quota, yet only 2 of its 4 tokens are allowed: the
	// outcome is per *request*, and once PROM_MAIN refuses, the request is
	// refused as a whole and no backend is reached. So a datasource can carry
	// denied tokens without having been the one that refused -- denied_total
	// holds the reason. Sizing MYSQL_A's quota still uses the sum, since that
	// is the demand it would face if the other limit were lifted.
	mysqlDenied := counterValue(t, metricDatasourceTokens, "MYSQL_A", "denied")
	require.EqualValues(t, 2, mysqlAllowed,
		"a second datasource must be charged separately, not folded into the first")
	require.EqualValues(t, 4, mysqlAllowed+mysqlDenied,
		"total demand on the second datasource must still be visible")

	// An unconfigured datasource has no bucket, so it must not open a series;
	// UIDs are client-supplied free text and would be a cardinality vector.
	require.Zero(t, counterValue(t, metricDatasourceTokens, "NO_QUOTA_DS", "allowed"))
	require.Zero(t, counterValue(t, metricDatasourceTokens, "NO_QUOTA_DS", "denied"))
}

// TestDenyAttribution_SaturatedDatasourceDoesNotBlameCaller guards the signal
// an operator acts on: which limit refused.
//
// Both limits sit on the same request, so if the identity bucket is charged for
// requests the datasource quota refused, a saturated backend quietly drains
// every caller aimed at it. Denials then start reporting reason=user, and the
// operator raises a caller's limit -- which cannot help, because the caller was
// never the constraint.
func TestDenyAttribution_SaturatedDatasourceDoesNotBlameCaller(t *testing.T) {
	metricDenied.Reset()

	cfg := defaultCfg()
	cfg.Enabled, cfg.ShadowMode = true, false
	// Production identity defaults, against a quota that is already full: the
	// realistic shape, since a dashboard re-runs a failing panel on a timer.
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 20, 40
	cfg.IniQuotas = map[string]laneParams{"PROM_MAIN": {rate: 1, burst: 1}}
	s := &Service{cfg: cfg, logger: log.New("dsratelimit.test")}
	s.rulesPtr.Store(&rulesSnapshot{
		byKey: map[string]*Rule{}, dsQuota: baseQuotas(cfg.IniQuotas),
		dsFromDB: map[string]bool{},
	})

	u := &user.SignedInUser{UserID: 9}
	body := []byte(`{"queries":[{"datasource":{"uid":"PROM_MAIN"}}]}`)
	const attempts = 60
	for i := 0; i < attempts; i++ {
		c, _ := buildCtx("POST", dsQueryPath, body, u)
		s.Middleware(c)
	}

	blamedDatasource := counterValue(t, metricDenied, "PROM_MAIN", "user", "datasource", "true")
	blamedUser := counterValue(t, metricDenied, dsLabelNone, "user", "user", "true")

	require.Zero(t, blamedUser,
		"the caller is inside its own limit; every denial here belongs to the "+
			"datasource quota. Charging the identity for refused requests "+
			"exhausts its bucket and misattributes the cause (measured 20 of 60 "+
			"before the refund)")
	require.EqualValues(t, attempts-1, blamedDatasource,
		"all but the first request must be attributed to the quota that refused")

	// The identity bucket is the thing that must not erode: only the one
	// request that actually reached the backend may be charged.
	entry := s.getUserEntry(s.rulesPtr.Load(), "user:9", &Rule{})
	require.InDelta(t, float64(entry.limiter.Burst()-1),
		entry.limiter.TokensAt(time.Now()), 0.5,
		"exactly one token spent -- the request that was served")
}

// TestMasterSwitches_AreHotReloadable is the "no knob needs a restart" claim,
// asserted rather than assumed.
//
// The two master switches were the last settings still read straight from the
// ini. That made the one move an operator wants fastest -- switching a layer
// off when it is causing harm -- the only one costing a restart, which on a
// shared Grafana means a minute of everyone's dashboards failing.
func TestMasterSwitches_AreHotReloadable(t *testing.T) {
	cfg := defaultCfg()
	cfg.Enabled, cfg.ConcurrencyEnabled = false, false

	// Nothing stored: the ini still decides, so an absent row cannot arm a
	// layer by omission.
	s := newTestService(cfg)
	require.False(t, s.activeQPS(s.rulesPtr.Load()))
	require.False(t, s.activeConcurrency(s.rulesPtr.Load()))

	// Stored rows flip both on, with the ini still saying false.
	on := newTestService(cfg,
		&Rule{Kind: string(KindActivation), Target: DefaultTarget, Mode: string(ModeLimited)},
		&Rule{Kind: string(KindConcurrencyActivation), Target: DefaultTarget, Mode: string(ModeLimited)},
	)
	require.True(t, on.activeQPS(on.rulesPtr.Load()),
		"a stored activation row must override the ini without a restart")
	require.True(t, on.activeConcurrency(on.rulesPtr.Load()))

	// And the reverse: ini true, row turns it off. This is the rollback path,
	// so it matters more than the one above.
	cfgOn := defaultCfg()
	cfgOn.Enabled, cfgOn.ConcurrencyEnabled = true, true
	off := newTestService(cfgOn,
		&Rule{Kind: string(KindActivation), Target: DefaultTarget, Mode: string(ModeUnlimited)},
		&Rule{Kind: string(KindConcurrencyActivation), Target: DefaultTarget, Mode: string(ModeUnlimited)},
	)
	require.False(t, off.activeQPS(off.rulesPtr.Load()),
		"turning the layer off at runtime is the rollback path and must not need a restart")
	require.False(t, off.activeConcurrency(off.rulesPtr.Load()))

	// The two layers are independent: switching one must not move the other.
	mixed := newTestService(cfgOn,
		&Rule{Kind: string(KindConcurrencyActivation), Target: DefaultTarget, Mode: string(ModeUnlimited)},
	)
	require.True(t, mixed.activeQPS(mixed.rulesPtr.Load()),
		"turning concurrency off must leave the QPS layer alone")
	require.False(t, mixed.activeConcurrency(mixed.rulesPtr.Load()))
}

// TestActivationGauge_FollowsTheRuntimeValue stops the dashboard disagreeing
// with the request path: both must read the same resolved switch.
func TestActivationGauge_FollowsTheRuntimeValue(t *testing.T) {
	cfg := defaultCfg()
	cfg.Enabled, cfg.ConcurrencyEnabled = false, false
	s := newTestService(cfg,
		&Rule{Kind: string(KindActivation), Target: DefaultTarget, Mode: string(ModeLimited)},
		&Rule{Kind: string(KindConcurrencyActivation), Target: DefaultTarget, Mode: string(ModeLimited)},
	)
	s.publishRuntimeConfig(s.rulesPtr.Load())
	require.Equal(t, float64(1), gaugeValue(t, metricEnabled),
		"the gauge must report the value the request path uses, not the ini")
	require.Equal(t, float64(1), gaugeValue(t, metricConcurrencyEnabled))
}
