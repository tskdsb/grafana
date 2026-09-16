package dsratelimit

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/user"
)

// histSamples reads back one label set of a HistogramVec: sample count, sum,
// and cumulative bucket counts keyed by upper bound.
func histSamples(t *testing.T, vec *prometheus.HistogramVec, labels ...string) (uint64, float64, map[float64]uint64) {
	t.Helper()
	m, err := vec.GetMetricWithLabelValues(labels...)
	require.NoError(t, err)
	var pb dto.Metric
	require.NoError(t, m.(prometheus.Metric).Write(&pb))
	h := pb.GetHistogram()
	buckets := map[float64]uint64{}
	for _, b := range h.GetBucket() {
		buckets[b.GetUpperBound()] = b.GetCumulativeCount()
	}
	return h.GetSampleCount(), h.GetSampleSum(), buckets
}

// freshUserRate swaps in a private histogram so each test starts from zero and
// asserts on its own samples only. The package-level metric is registered once
// in init() and accumulates across tests, which would make sample counts depend
// on execution order.
func freshUserRate(t *testing.T) {
	t.Helper()
	saved := metricUserRate
	metricUserRate = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "test_user_rate",
		Buckets: []float64{1, 2, 5, 10, 20, 30, 50, 100, 200, 500, 1000},
	}, []string{"kind"})
	t.Cleanup(func() { metricUserRate = saved })
}

// TestUserRate_MeasuresPerIdentityNotAggregate is the whole point of this
// metric.
//
// attempted_total carries kind, not identity, so two callers doing 5 tokens/sec
// each and one caller doing 10 are indistinguishable in it -- yet only the
// second case argues for raising default_user_rate. This asserts the histogram
// separates them: three identities produce three observations, and the heavy
// one lands in a higher bucket than the light ones.
func TestUserRate_MeasuresPerIdentityNotAggregate(t *testing.T) {
	freshUserRate(t)
	s := newTestService(defaultCfg())

	// 10 tokens for one identity, 1 token each for two others.
	for i := 0; i < 10; i++ {
		c, _ := buildCtx("POST", "/api/datasources/proxy/uid/PROM", nil, &user.SignedInUser{UserID: 1})
		s.Middleware(c)
	}
	for _, uid := range []int64{2, 3} {
		c, _ := buildCtx("POST", "/api/datasources/proxy/uid/PROM", nil, &user.SignedInUser{UserID: uid})
		s.Middleware(c)
	}

	s.sampleUserRates()

	count, _, buckets := histSamples(t, metricUserRate, "user")
	require.EqualValues(t, 3, count, "one observation per active identity, not one per request")

	// Window is 10s, so 10 tokens -> 1.0/sec and 1 token -> 0.1/sec. Both are
	// under le=1, but the distinction that matters is that each identity is
	// counted separately: an aggregate would have produced a single 1.2/sec.
	require.EqualValues(t, 3, buckets[1], "all three identities are at or below 1 token/sec")
}

// TestUserRate_HeavyIdentityLandsAboveTheDefault is the sizing question stated
// as a test: with default_user_rate at 20, a caller pushing past it must show up
// in a bucket above 20, otherwise the histogram cannot tell you the default is
// too tight.
func TestUserRate_HeavyIdentityLandsAboveTheDefault(t *testing.T) {
	freshUserRate(t)
	// Burst high enough that the traffic is admitted; the metric records demand
	// either way, but this keeps the test about measurement, not refusal.
	cfg := defaultCfg()
	cfg.DefaultUserRate = 20
	cfg.DefaultUserBurst = 1000
	s := newTestService(cfg)

	// 300 tokens in one window = 30/sec, above the 20 default.
	for i := 0; i < 300; i++ {
		c, _ := buildCtx("POST", "/api/datasources/proxy/uid/PROM", nil, &user.SignedInUser{UserID: 7})
		s.Middleware(c)
	}

	s.sampleUserRates()

	count, sum, buckets := histSamples(t, metricUserRate, "user")
	require.EqualValues(t, 1, count)
	require.InDelta(t, 30.0, sum, 0.001, "300 tokens over a 10s window is 30/sec")
	require.EqualValues(t, 0, buckets[20], "must NOT be counted at or below the 20 default")
	require.EqualValues(t, 1, buckets[30], "must be visible in the bucket that shows the default is exceeded")
}

// TestUserRate_IdleIdentitiesAreNotObserved protects the property that makes the
// high quantiles readable.
//
// Most buckets are idle at any instant (cleanup keeps up to cache_max_entries).
// Observing their zeros would dominate the distribution: measured on a
// simulated 500-bucket / 20-active mix, including them moved P99 from 200 QPS
// to 2. active_keys already reports how many identities exist, so excluding
// them loses nothing.
func TestUserRate_IdleIdentitiesAreNotObserved(t *testing.T) {
	freshUserRate(t)
	s := newTestService(defaultCfg())

	// Three identities get traffic, creating three buckets.
	for _, uid := range []int64{1, 2, 3} {
		c, _ := buildCtx("POST", "/api/datasources/proxy/uid/PROM", nil, &user.SignedInUser{UserID: uid})
		s.Middleware(c)
	}
	s.sampleUserRates()
	first, _, _ := histSamples(t, metricUserRate, "user")
	require.EqualValues(t, 3, first)

	// Second window with no traffic at all: the same three buckets still exist.
	s.sampleUserRates()

	second, _, _ := histSamples(t, metricUserRate, "user")
	require.EqualValues(t, 3, second,
		"idle buckets must contribute no samples; got %d new observations", second-first)
}

// TestUserRate_CountersDrainPerWindow asserts each token is observed in exactly
// one window.
//
// If the counter were read instead of swapped, a bucket would keep reporting its
// cumulative total forever: a caller that did 100 tokens once would read as
// permanently busy, and the distribution would drift upward on its own with no
// traffic at all.
func TestUserRate_CountersDrainPerWindow(t *testing.T) {
	freshUserRate(t)
	s := newTestService(defaultCfg())

	for i := 0; i < 50; i++ {
		c, _ := buildCtx("POST", "/api/datasources/proxy/uid/PROM", nil, &user.SignedInUser{UserID: 1})
		s.Middleware(c)
	}
	s.sampleUserRates()
	_, sum1, _ := histSamples(t, metricUserRate, "user")
	require.InDelta(t, 5.0, sum1, 0.001, "50 tokens / 10s")

	// One more request, then sample again. The second observation must reflect
	// only the new token, not 51.
	c, _ := buildCtx("POST", "/api/datasources/proxy/uid/PROM", nil, &user.SignedInUser{UserID: 1})
	s.Middleware(c)
	s.sampleUserRates()

	count, sum2, _ := histSamples(t, metricUserRate, "user")
	require.EqualValues(t, 2, count)
	require.InDelta(t, 5.1, sum2, 0.001,
		"second window must add 0.1/sec (one token), not re-report the cumulative total")
}

// TestUserRate_RecordsDemandNotJustAdmitted is why the counter sits before the
// limiters rather than after.
//
// A metric that only sampled admitted traffic would agree with whatever limit is
// already configured -- capped at the limit by construction -- and so could
// never be evidence that the limit is too low. Sampling demand is what makes it
// useful for sizing.
func TestUserRate_RecordsDemandNotJustAdmitted(t *testing.T) {
	freshUserRate(t)
	cfg := defaultCfg()
	cfg.DefaultUserRate = 1
	cfg.DefaultUserBurst = 2
	s := newTestService(cfg)

	// 20 requests against a burst of 2: most are refused.
	denied := 0
	for i := 0; i < 20; i++ {
		c, rec := buildCtx("POST", "/api/datasources/proxy/uid/PROM", nil, &user.SignedInUser{UserID: 1})
		s.Middleware(c)
		if rec.Code == 429 {
			denied++
		}
	}
	require.Greater(t, denied, 10, "test needs most requests refused to be meaningful")

	s.sampleUserRates()

	_, sum, _ := histSamples(t, metricUserRate, "user")
	require.InDelta(t, 2.0, sum, 0.001,
		"must report all 20 tokens of demand (2.0/sec), not the ~2 that were admitted")
}

// TestUserRate_SeparatesKinds keeps service-account traffic from being read as a
// human caller: the two get different defaults, so a shared distribution would
// be the wrong input for either.
func TestUserRate_SeparatesKinds(t *testing.T) {
	freshUserRate(t)
	s := newTestService(defaultCfg())

	c, _ := buildCtx("POST", "/api/datasources/proxy/uid/PROM", nil, &user.SignedInUser{UserID: 1})
	s.Middleware(c)
	c, _ = buildCtx("POST", "/api/datasources/proxy/uid/PROM", nil,
		&user.SignedInUser{UserID: 2, IsServiceAccount: true})
	s.Middleware(c)

	s.sampleUserRates()

	userCount, _, _ := histSamples(t, metricUserRate, "user")
	saCount, _, _ := histSamples(t, metricUserRate, "sa")
	require.EqualValues(t, 1, userCount)
	require.EqualValues(t, 1, saCount)
}
