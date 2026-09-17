package dsratelimit

import "github.com/prometheus/client_golang/prometheus"

// Metrics for the datasource rate limiter. Registered with Grafana's default
// prometheus registry, exposed on /metrics. Counter units are tokens (not
// requests). The invariant attempted == allowed + denied holds at token
// granularity, so shadow-mode and live-mode observations are comparable.
var (
	metricAttempted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "grafana",
		Subsystem: "datasource_ratelimit",
		Name:      "attempted_total",
		Help:      "Tokens attempted through the limiter (allowed + denied). Unit: tokens.",
	}, []string{"datasource", "kind"})

	metricAllowed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "grafana",
		Subsystem: "datasource_ratelimit",
		Name:      "allowed_total",
		Help:      "Tokens permitted to reach the backend. Unit: tokens.",
	}, []string{"datasource", "kind", "mode"})

	metricDenied = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "grafana",
		Subsystem: "datasource_ratelimit",
		Name:      "denied_total",
		Help: "Tokens the limiter refused. Unit: tokens. enforced=\"false\" means " +
			"shadow mode: the token was counted as denied but the request was " +
			"still served, so this is the projection of what enforcement would " +
			"reject, not traffic that was actually rejected.",
	}, []string{"datasource", "kind", "reason", "enforced"})

	metricFailOpen = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "grafana",
		Subsystem: "datasource_ratelimit",
		Name:      "fail_open_total",
		Help:      "Occurrences of the limiter failing open (rule load error, DB unreachable, etc.). Should be zero.",
	})

	metricQueriesPerRequest = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "grafana",
		Subsystem: "datasource_ratelimit",
		Name:      "queries_per_request",
		Help:      "Token cost of each /api/ds/query request, i.e. the number of backend calls it fans out to (instant/range/exemplar counted separately), not len(queries).",
		// Buckets straddle the burst defaults (per-user 40, lane 420) so the
		// histogram answers the question that matters: how close are real
		// requests to the ceiling above which they are refused permanently?
		// Counting backend calls rather than queries raised the top end by up
		// to 3x (instant/range/exemplar each count), so the range extends past
		// 100 -- otherwise the expensive tail all lands in +Inf and the
		// distribution that decides burst sizing is invisible.
		Buckets: []float64{1, 2, 5, 10, 20, 40, 100, 300, 1000},
	})

	metricInvalidRule = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "grafana",
		Subsystem: "datasource_ratelimit",
		Name:      "invalid_rule_total",
		Help:      "Rules whose stored rate/burst was rejected and replaced by the configured defaults. Should be zero; a non-zero value means a bad row exists in datasource_rate_limit.",
	})

	metricActiveKeys = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "grafana",
		Subsystem: "datasource_ratelimit",
		Name:      "active_keys",
		Help:      "Current number of user limiter entries in the LRU map.",
	})

	// Per-datasource token flow, the signal a quota is actually chosen from.
	//
	// The counters above are per-request and can only name a datasource when
	// one refused, so they answer "how much did PROM_MAIN reject?" but not
	// "how much did PROM_MAIN carry?" -- and during shadow mode the second one
	// is the whole question, since the quota number has to be set against real
	// observed load. Charged per target, so one request fanning out to two
	// datasources increments both.
	//
	// Cardinality is bounded by the number of configured quotas: a datasource
	// with no quota has no bucket and is never charged, so client-supplied UIDs
	// cannot create series.
	metricDatasourceTokens = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "grafana",
		Subsystem: "datasource_ratelimit",
		Name:      "datasource_tokens_total",
		Help: "Tokens charged against each datasource quota, by outcome. Unit: " +
			"tokens. outcome=\"allowed\" is the load that reached the backend, " +
			"which is what a quota should be sized against.",
	}, []string{"datasource", "outcome"})

	// Config state, so a dashboard or an alert can answer "is this thing
	// actually enforcing right now?" without shelling into a box to read the
	// ini. Shadow mode is the default, which makes "we thought it was on" a
	// realistic way to discover a backend was never protected.
	metricEnforcing = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "grafana",
		Subsystem: "datasource_ratelimit",
		Name:      "enforcing",
		Help: "1 when the limiter rejects over-limit requests; 0 when disabled " +
			"or in shadow mode (counted but served).",
	})

	// Freshness of the rule snapshot. fail_open_total counts reload failures,
	// but a counter cannot answer "how stale is the config in memory?" -- after
	// the first failure the service keeps serving the previous snapshot
	// indefinitely, so an admin API change can appear to have no effect. Alert
	// on time() - this exceeding a few reload intervals.
	metricLastReload = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "grafana",
		Subsystem: "datasource_ratelimit",
		Name:      "last_successful_reload_timestamp_seconds",
		Help:      "Unix timestamp of the last successful rule reload.",
	})

	// Requests whose body exceeded maxCountedBodyBytes, so the token cost was
	// charged at the ceiling instead of counted. Should be zero: 1 MiB holds
	// far more queries than any real dashboard sends.
	metricOversizedBody = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "grafana",
		Subsystem: "datasource_ratelimit",
		Name:      "oversized_body_total",
		Help:      "Requests whose body exceeded the size buffered for query counting; charged at the ceiling. Should be zero.",
	})

	// metricUserRate is what default_user_rate is sized against.
	//
	// The other counters carry kind (user/sa/apikey/anon), not identity, so they
	// answer "how much traffic in total" but never "how hard does the heaviest
	// single caller push" -- and the latter is what a per-identity limit caps. A
	// gauge of the max would be no better: one runaway script sets it forever
	// and it says nothing about how many callers are near the ceiling.
	//
	// So each active identity contributes one observation per sample window, and
	// the distribution answers the sizing question directly: read the high
	// quantiles to see the heavy tail, and the buckets around 20 to see how many
	// callers the current default would start refusing.
	//
	// Idle buckets are deliberately not observed. Measured on a simulated 500
	// buckets / 20 active mix, feeding the idle zeros in moved P99 from 200 QPS
	// down to 2 -- it buries exactly the tail this metric exists to show.
	metricUserRate = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "grafana",
		Subsystem: "datasource_ratelimit",
		Name:      "user_rate",
		Help:      "Per-identity backend-request rate (tokens/sec), sampled every userRateSampleInterval over identities with traffic in that window. Sized for reading default_user_rate off the high quantiles; idle identities are not observed.",
		// Straddles default_user_rate (20) so the buckets on either side show
		// how many callers that default would refuse, and extends to 1000
		// because a runaway dashboard or script is the case worth seeing rather
		// than collapsing into +Inf.
		Buckets: []float64{1, 2, 5, 10, 20, 30, 50, 100, 200, 500, 1000},
	}, []string{"kind"})

	// metricConcurrencyDenied counts requests the in-flight cap turned away.
	//
	// Separate from denied_total rather than another label on it: that counter
	// is denominated in tokens and a concurrency rejection spends none, so
	// folding them together would corrupt the token arithmetic that
	// default_user_rate is sized against.
	metricConcurrencyDenied = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "grafana",
		Subsystem: "datasource_ratelimit",
		Name:      "concurrency_denied_total",
		Help: "Requests refused by the per-identity in-flight cap. Unit: requests. " +
			"enforced=\"false\" means shadow mode: counted as denied but served anyway.",
	}, []string{"kind", "enforced"})

	// metricConcurrencyInflight records how many requests one identity had in
	// flight, observed on admission.
	//
	// A histogram rather than a gauge. A gauge labelled only by kind would be
	// overwritten by whichever identity was admitted last, so the peak that
	// matters -- one caller holding many slow queries -- would be erased by the
	// next ordinary request. The histogram keeps the distribution, which is the
	// input for choosing default_user_concurrency.
	metricConcurrencyInflight = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "grafana",
		Subsystem: "datasource_ratelimit",
		Name:      "concurrency_inflight",
		Help: "Per-identity in-flight datasource queries, observed when a request is admitted. " +
			"Read the high quantiles to size default_user_concurrency.",
		// Starts at 1 because admission always observes at least the request
		// being admitted, and reaches 500 so a runaway caller shows as its own
		// bucket instead of vanishing into +Inf.
		Buckets: []float64{1, 2, 3, 5, 8, 12, 20, 30, 50, 100, 200, 500},
	}, []string{"kind"})

	// metricConcurrencyHeld is the live count of in-flight requests the cap is
	// tracking, across all identities. Unlike the histogram this answers "is
	// anything happening right now", which is what an operator checks first
	// when deciding whether the cap is doing something.
	// metricConcurrencyFailOpen counts requests the cap let through without
	// counting them, because it could not obtain a live entry. Should stay at
	// zero; a non-zero value means the eviction protocol is not self-healing
	// and the cap is quietly leaking capacity.
	metricConcurrencyFailOpen = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "grafana",
		Subsystem: "datasource_ratelimit",
		Name:      "concurrency_fail_open_total",
		Help:      "Requests admitted uncounted because no live in-flight entry could be obtained. Expected to stay at zero.",
	})

	metricConcurrencyHeld = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "grafana",
		Subsystem: "datasource_ratelimit",
		Name:      "concurrency_held",
		Help:      "Datasource query slots currently held across all identities.",
	})
)

func init() {
	prometheus.MustRegister(
		metricAttempted,
		metricAllowed,
		metricDenied,
		metricFailOpen,
		metricInvalidRule,
		metricQueriesPerRequest,
		metricActiveKeys,
		metricDatasourceTokens,
		metricEnforcing,
		metricLastReload,
		metricOversizedBody,
		metricUserRate,
		metricConcurrencyDenied,
		metricConcurrencyInflight,
		metricConcurrencyHeld,
		metricConcurrencyFailOpen,
	)
}
