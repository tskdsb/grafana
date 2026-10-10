package dsratelimit

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/time/rate"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/setting"
)

// rulesSnapshot is an atomically-swappable view of the rules table.
// Middleware reads it lock-free via Service.rulesPtr.Load(). Never mutate
// a published snapshot; construct a new one and Store() to replace.
type rulesSnapshot struct {
	byKey map[string]*Rule

	// dsQuota holds the configured quota per datasource target (UID, or
	// "id:<n>" for legacy numeric addressing). A datasource with no entry here
	// gets NO datasource-level bucket at all -- it is limited only by its
	// caller's identity bucket.
	//
	// That absence is the design, not a gap. Targets come from unverified
	// client input (a caller can put any string in datasource.uid), so
	// creating a bucket per observed target would let anyone allocate unbounded
	// limiters and unbounded metric label values. Keying off configured quotas
	// instead bounds both by the size of the rule table.
	dsQuota map[string]laneParams

	// dsFromDB marks the targets whose quota came from a DB rule rather than
	// from the ini baseline. Reported by /stats: with two sources for the same
	// number, "is my runtime override actually in force?" is otherwise
	// unanswerable without reading the log.
	dsFromDB map[string]bool

	// defaults, when non-nil, replaces the ini default_user_rate /
	// default_user_burst for identities without a rule of their own. Held here
	// rather than in byKey because there is no key to match on: it is the
	// fallback, so resolveRule reaches it only after byKey misses.
	//
	// nil means "no DB override" and the ini value applies -- deleting the row
	// restores the deployed baseline, same as for a datasource quota.
	defaults *laneParams

	// defaultConcurrency, when non-nil, overrides the ini
	// default_user_concurrency. Separate from defaults because the two can be
	// set independently: an operator tuning the in-flight cap during the
	// observation window should not have to restate the QPS pair to do it.
	//
	// nil means the ini value applies. Zero or negative, from either source,
	// means no cap -- the same "unconfigured is unlimited" rule the QPS layer
	// follows, so neither layer can be armed by omission.
	defaultConcurrency *int64

	// shadow, when non-nil, overrides the ini shadow_mode. Going from observing
	// to enforcing (and back, if enforcement turns out to hurt) is the single
	// most time-critical switch this package has, and requiring a restart for it
	// meant the rollout step and the rollback step both cost a restart.
	//
	// nil means the ini value applies, same convention as defaults.
	shadow *bool

	// concurrencyShadow, when non-nil, overrides the ini
	// concurrency_shadow_mode. Separate from shadow for the same reason the
	// two ini keys are separate: the QPS layer may already be enforcing while
	// the in-flight cap is still observing, and a single switch would make a
	// concurrency trial require standing QPS enforcement down.
	//
	// nil means the ini value applies, same convention as the others.
	concurrencyShadow *bool

	// active / concurrencyActive, when non-nil, override the ini enabled and
	// concurrency_enabled master switches. Same nil-means-ini convention as
	// every other field here.
	//
	// These exist so that no knob in this package requires a restart. The
	// master switches were the last two holdouts, and they were the worst ones
	// to leave behind: turning a layer off is what an operator reaches for when
	// something is going wrong, and that is the moment a restart is least
	// affordable -- on a shared Grafana it fails everyone's dashboards for a
	// minute.
	active            *bool
	concurrencyActive *bool
}

type laneParams struct {
	rate  int
	burst int
}

// userEntry lives in Service.userBuckets. LastUsedUnixNano is written by
// the middleware on every hit and read by the cleanup goroutine.
//
// deniedSinceLog / lastDenyLogUnixNano implement per-key log throttling: a
// key being denied is by definition being hit hard (hundreds of times per
// second), so logging every denial would turn one problem into two. We log
// at most once per denyLogInterval per key and report how many denials that
// line represents. Both are atomics because the middleware runs concurrently
// for the same key.
type userEntry struct {
	limiter          *rate.Limiter
	lastUsedUnixNano atomic.Int64

	// labels exists only for user and service-account entries. It binds the
	// stable ID to the current login for identity-level Prometheus series.
	metricMu sync.Mutex
	labels   *identityMetricLabels
	removed  bool

	// Tokens charged to this identity since the last sample, drained by
	// sampleUserRates. Feeds the per-identity QPS histogram, which is what
	// default_user_rate is sized against: the aggregate counters carry only
	// kind (user/sa/apikey/anon), so they show the total but never how hard the
	// heaviest single caller pushes -- and that is the number the limit caps.
	sinceSample atomic.Int64

	// conc is this identity's in-flight counter. It lives on the same entry as
	// the token bucket so both layers resolve one identity through one lookup,
	// and so the concurrency layer inherits the identity parsing, the LRU and
	// the cleanup that already exist rather than duplicating them.
	//
	// Note that cleanup must not evict an entry while this is non-zero; see
	// the comment there.
	conc inflight

	denyLog denyLogThrottle
}

// denyLogThrottle rate-limits deny log lines for one key while preserving the
// true denial count. Split out from userEntry because the ModeBlocked path
// needs the same throttling without a rate.Limiter: it is a deliberate fast
// path that never allocates a limiter.
type denyLogThrottle struct {
	deniedSinceLog      atomic.Int64
	lastDenyLogUnixNano atomic.Int64
}

// denyLogInterval is the per-key floor between two deny log lines. Chosen so
// that a steadily-throttled key produces a readable trickle (one line per
// key per minute) rather than a flood, while still surfacing within a minute
// of the first denial.
const denyLogInterval = time.Minute

// shouldLogDeny records a denial of n tokens and reports whether this call
// should emit a log line. When it returns true it also returns how many
// denials (in tokens) have accumulated since the previous line, and resets
// the counter.
//
// Concurrency: two goroutines can both pass the interval check for the same
// key and emit two lines. That is accepted — the alternative is a mutex on
// the hot path, and a duplicate line is harmless. The counter uses Swap so
// no denial is double-reported.
func (e *denyLogThrottle) shouldLogDeny(n int, now time.Time) (int64, bool) {
	e.deniedSinceLog.Add(int64(n))

	nowNano := now.UnixNano()
	last := e.lastDenyLogUnixNano.Load()
	if last != 0 && nowNano-last < int64(denyLogInterval) {
		return 0, false
	}
	if !e.lastDenyLogUnixNano.CompareAndSwap(last, nowNano) {
		// Another goroutine just logged; let it own this line.
		return 0, false
	}
	return e.deniedSinceLog.Swap(0), true
}

// Service is the datasource rate limiter. Constructed via ProvideService,
// implements registry.BackgroundService (Run) for reload + cleanup loops.
type Service struct {
	cfg    Config
	store  *store
	logger log.Logger

	rulesPtr atomic.Pointer[rulesSnapshot]

	// dsBuckets: sync.Map[string]*rate.Limiter, one per datasource that has a
	// configured quota. Created on first request touching that datasource and
	// updated in place on reload (SetLimit/SetBurst are internally atomic).
	//
	// Never evicted: the set is bounded by the rule table, not by traffic, and
	// evicting would hand back a full bucket to a backend that is being
	// hammered -- the opposite of what a quota guard should do.
	dsBuckets sync.Map

	// userBuckets: sync.Map[string]*userEntry. Hot-path uses LoadOrStore;
	// cleanup uses Range + Delete.
	userBuckets sync.Map
	userCount   atomic.Int64

	// blockedLog: sync.Map[string]*denyLogThrottle, throttling deny log lines
	// for keys resolved to mode=blocked. Separate from userBuckets because the
	// blocked path deliberately allocates no limiter.
	//
	// Unbounded growth is not a concern here the way it is for userBuckets:
	// keys land here only if a rule maps them to blocked, so the set is bounded
	// by the rule table (plus the single shared "anon:anon" key), not by
	// traffic. It therefore needs no TTL eviction.
	blockedLog sync.Map

	// identityMetricMu serialises the lifecycle of the per-identity metric
	// series: a request path publishing (or re-publishing) a series under
	// e.metricMu, and an eviction deleting series under e.metricMu, can briefly
	// own the same (kind,identity,login). Deletion is by label value, so the
	// ownership check + delete must be atomic against the concurrent owner's
	// first publish. There is deliberately a single lock (no per-key sharding):
	// the path already serialises on e.metricMu, correctness first, shard only
	// with perf evidence. Lock order is always identityMetricMu -> e.metricMu.
	identityMetricMu sync.Mutex
}

// ProvideService is the wire provider. Fail-open at startup: if the initial
// rule load errors (DB unreachable, migration not yet run), we log, bump
// fail_open_total, and continue with an empty snapshot; the reload goroutine
// will retry every 30s. The alternative — refusing to start — would take
// every dashboard down alongside a transient DB blip.
func ProvideService(cfg *setting.Cfg, dbConn db.DB) *Service {
	s := &Service{
		cfg:    loadConfigFromSetting(cfg),
		store:  newStore(dbConn),
		logger: log.New("dsratelimit"),
	}
	// Seed from the ini so the deployed quotas are in force from the first
	// request, before the first DB reload has run (and even if the DB is
	// unreachable). rulesPtr must also never be nil for Load(). Publish the
	// complete ini-derived runtime state at the same point: if the initial DB
	// load fails, the gauges still describe the baseline the request path uses.
	s.publishRuntimeConfig(nil)

	s.rulesPtr.Store(&rulesSnapshot{
		byKey:    map[string]*Rule{},
		dsQuota:  baseQuotas(s.cfg.IniQuotas),
		dsFromDB: map[string]bool{},
	})
	if err := s.reloadRules(context.Background()); err != nil {
		s.logger.Error("initial rule load failed; running fail-open until next reload", "err", err)
		metricFailOpen.Inc()
	}
	return s
}

// loadConfigFromSetting copies the ini-derived settings into the service's own
// Config, sanitising the four rate/burst numbers on the way through.
//
// setting.MustInt only supplies a fallback when a key is absent or unparseable;
// an explicit `default_user_rate = -5` is passed through verbatim. Reaching
// rate.NewLimiter, such a value produces a limiter whose tokens never recover
// (x/time/rate v0.2.0 has no panic path — see sanitizeParams), so a single
// mistyped line silently rejects every datasource query in the deployment.
//
// This is the one place all four values cross into the service, so guarding it
// covers both per-datasource quota configuration and the per-user
// defaults. Note the per-user path was already protected: resolveRule wraps the
// config values in a Rule, which getUserEntry runs through sanitizeParams. The
// datasource quota path had no equivalent, which is exactly the asymmetry fixed here.
//
// Invalid or incomplete values disarm that layer instead of inventing a limit
// nobody chose. Each ignored value is logged and counted in invalid_rule_total,
// so the fail-open decision remains visible.
func loadConfigFromSetting(cfg *setting.Cfg) Config {
	logger := log.New("dsratelimit")
	// An unusable configured value disarms the layer instead of substituting a
	// number nobody chose.
	//
	// This used to fall back to the built-in 20/40. That turned a typo into a
	// limit: an operator who wrote default_user_rate = 2O (letter O) got a
	// working limiter at someone else's number, with only a log line to say
	// so. And the reverse case was worse -- a zero reached x/time/rate, which
	// has no "unlimited" value and reads zero as refuse-everything, so a
	// missing number took the query API down entirely.
	//
	// Both failures came from treating an absent or broken value as if it
	// expressed an intention. It does not. Returning 0 here means the layer
	// stays out of the way until someone states a real number, through the ini
	// or through the admin API.
	// Bounds first: everything validated below is judged against them, so they
	// have to be resolved before any value is checked. A non-positive or absent
	// setting falls back to the built-in default rather than disabling the
	// check -- a ceiling that omission can switch off is not a ceiling.
	maxRate := ceilingSetting(logger, "max_rule_rate", cfg.DsRateLimit.MaxRuleRate, DefaultMaxRuleRate)
	maxBurst := ceilingSetting(logger, "max_rule_burst", cfg.DsRateLimit.MaxRuleBurst, DefaultMaxRuleBurst)
	maxConc := ceilingSetting(logger, "max_rule_concurrency", cfg.DsRateLimit.MaxRuleConcurrency, DefaultMaxRuleConcurrency)

	// Deploy-time quotas get the same treatment as the rest of the ini: a bad
	// value is dropped with a reason, never applied. Dropping rather than
	// falling back to some default is the only honest option here -- there is no
	// sensible default for "how much capacity does this backend have", and
	// inventing one would silently limit a datasource to a number nobody chose.
	iniQuotas := map[string]laneParams{}
	for uid, q := range cfg.DsRateLimit.Quotas {
		if uid == "" {
			continue
		}
		lp, ok := sanitizeParams(int64(q.Rate), int64(q.Burst), maxRate, maxBurst)
		// burst >= rate is required here for the same reason AdminPut requires
		// it: the two paths configure the same thing, and a value the API
		// rejects must not be silently accepted just because it arrived via the
		// ini. (x/time/rate does tolerate burst < rate -- measured -- but it
		// then permanently refuses any cost between burst and rate, so the
		// per-second limit is not actually reachable.)
		if ok && lp.burst < lp.rate {
			ok = false
		}
		if !ok {
			logger.Warn("ignoring invalid [datasource_ratelimit.quota] section",
				// "target", not "uid": every other line in this package calls
				// this field target, and a field that changes name between log
				// lines cannot be grepped or aggregated as one.
				"target", uid, "rate", q.Rate, "burst", q.Burst,
				"why", "rate and burst must both be > 0, burst >= rate, and within "+
					"the rule bounds; an out-of-range value makes x/time/rate "+
					"refuse every query to this datasource without recovering")
			metricInvalidRule.Inc()
			continue
		}
		iniQuotas[uid] = lp
	}

	// rate and burst are judged as a pair, not one at a time.
	//
	// AdminPut rejects burst < rate; the ini path did not, so the same numbers
	// were refused through the API and accepted from the file. Measured with
	// rate=100 burst=2: a five-token request was denied ten times out of ten
	// and would never succeed, because x/time/rate refuses any cost above
	// burst outright (rate.go:371) no matter how many tokens have accumulated.
	//
	// One entry point may not be stricter than another about the same setting.
	// Disarming is the honest outcome here, as everywhere else in this
	// function: the pair as written cannot serve traffic, so enforcing it
	// would only convert a typo into an outage.
	iniRate := saneSetting(logger, "default_user_rate", cfg.DsRateLimit.DefaultUserRate, maxRate)
	iniBurst := saneSetting(logger, "default_user_burst", cfg.DsRateLimit.DefaultUserBurst, maxBurst)
	if iniRate > 0 && iniBurst > 0 && iniBurst < iniRate {
		logger.Warn("default_user_burst is below default_user_rate; this layer will "+
			"not limit until the pair is fixed",
			"default_user_rate", iniRate, "default_user_burst", iniBurst,
			"why", "x/time/rate refuses any single request costing more than burst, "+
				"permanently and regardless of accumulated tokens, so the configured "+
				"rate is not actually reachable. The admin API rejects this pair; "+
				"accepting it here would make the file the laxer of the two")
		metricInvalidRule.Inc()
		iniRate, iniBurst = 0, 0
	}

	return Config{
		Enabled:          cfg.DsRateLimit.Enabled,
		ShadowMode:       cfg.DsRateLimit.ShadowMode,
		DefaultUserRate:  iniRate,
		DefaultUserBurst: iniBurst,
		IniQuotas:        iniQuotas,
		CacheMaxEntries:  cfg.DsRateLimit.CacheMaxEntries,

		ConcurrencyEnabled: cfg.DsRateLimit.ConcurrencyEnabled,
		// Not run through sane(), which is built around the rate/burst pair.
		// Zero or negative already means "no cap" to acquire(), so the only
		// value worth rejecting is one too large to be a real policy -- and
		// AdminPut rejects those, so the ini must too.
		DefaultUserConcurrency: saneSetting(logger, "default_user_concurrency",
			cfg.DsRateLimit.DefaultUserConcurrency, maxConc),
		ConcurrencyShadowMode: cfg.DsRateLimit.ConcurrencyShadowMode,
		MaxRuleRate:           maxRate,
		MaxRuleBurst:          maxBurst,
		MaxRuleConcurrency:    maxConc,
	}
}

// saneSetting judges one configured limit, for either layer.
//
// One function rather than one per layer, because the two used to answer the
// same question differently and nobody noticed until they were listed side by
// side. Sharing the implementation makes that drift impossible; the layers
// differ only in the bounds they pass.
//
//	<= 0       no limit. Zero means "not configured", negative can only be a
//	           typo, and both describe an operator who has not stated a limit.
//	           Silent: the shipped default is zero and an observation window
//	           runs in exactly this state.
//	> ceiling  no limit, with a warning. The value cannot be applied safely --
//	           for QPS it would reach x/time/rate, which has no "unlimited"
//	           and would refuse everything.
//
// Anything in between is applied as written. A separate "looks like a typo"
// tier was built here and removed: measured, a value just under the ceiling
// and a value just over it both admitted all fifty probe requests, because a
// limit of 999999 never binds either. Warning about a number that changes
// nothing is noise, and the tier cost an ini key, a metric and a second
// threshold to say what the ceiling already said.
func saneSetting(logger log.Logger, key string, got int, ceiling int64) int {
	v := int64(got)
	if v <= 0 {
		return 0
	}
	if v > ceiling {
		logger.Warn("datasource_ratelimit setting is out of range; this layer will not "+
			"limit until a usable value is set",
			"key", key, "configured", got, "max", ceiling,
			"why", "a value this large cannot be applied safely, and substituting a "+
				"built-in number would enforce a limit nobody chose")
		metricInvalidRule.Inc()
		return 0
	}
	return got
}

// ceilingSetting resolves one configured bound, falling back to the built-in
// default when the ini omits it or states something unusable.
//
// Falling back rather than accepting is the point: a ceiling exists to catch a
// typo, so letting a typo in the ceiling itself disable the check would remove
// the guard exactly when the config is already known to be wrong.
func ceilingSetting(logger log.Logger, key string, got int, fallback int64) int64 {
	if got <= 0 {
		return fallback
	}
	v := int64(got)
	if v > maxSafeInt {
		logger.Warn("datasource_ratelimit ceiling is out of range; using the built-in default",
			"key", key, "configured", got, "default", fallback)
		metricInvalidRule.Inc()
		return fallback
	}
	return v
}

// maxSafeInt is the largest int64 that survives conversion to int on a 32-bit
// build, where x/time/rate's int-typed burst would otherwise wrap negative.
const maxSafeInt = int64(^uint32(0) >> 1)

// Run implements registry.BackgroundService: reload + cleanup goroutines.
// Blocks until ctx is cancelled.
func (s *Service) Run(ctx context.Context) error {
	// Deliberately NOT gated on the master switch. The reload loop is what
	// makes the switch hot: parking here when the ini ships enabled=false
	// would mean the DB override could never be read, so turning the layer on
	// at runtime would silently do nothing and the only way back would be the
	// restart this design exists to avoid. The loop is one query every 30s.
	reloadTick := time.NewTicker(30 * time.Second)
	cleanupTick := time.NewTicker(5 * time.Minute)
	sampleTick := time.NewTicker(userRateSampleInterval)
	defer reloadTick.Stop()
	defer cleanupTick.Stop()
	defer sampleTick.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-reloadTick.C:
			if err := s.reloadRules(ctx); err != nil {
				s.logger.Error("periodic rule reload failed; keeping previous snapshot", "err", err)
				metricFailOpen.Inc()
			}
		case <-cleanupTick.C:
			s.cleanup()
		case <-sampleTick.C:
			s.sampleUserRates()
		}
	}
}

// userRateSampleInterval is the window over which per-identity demand is
// averaged into metricUserRate.
//
// A window this size trades peak fidelity for a readable distribution: 10s
// smooths a dashboard's burst of panels into one number, which is the right
// unit for sizing a rate (burst is what absorbs the spike, and
// queries_per_request already measures that). Shorter windows would multiply
// observations without adding information, since Prometheus scrapes far less
// often than that anyway.
const userRateSampleInterval = 10 * time.Second

// sampleUserRates converts each active identity's accumulated demand into a
// rate and observes it.
//
// Only identities with traffic in the window are observed. Feeding the idle
// buckets in as zeros would swamp the distribution: measured on a simulated
// 500-bucket / 20-active mix, it moved P99 from 200 QPS to 2 -- burying the
// heavy tail this metric exists to expose. The count of identities is already
// carried by active_keys, so nothing is lost by leaving them out.
func (s *Service) sampleUserRates() {
	secs := userRateSampleInterval.Seconds()
	s.userBuckets.Range(func(k, v any) bool {
		e := v.(*userEntry)
		// Swap, so each token is observed in exactly one window, and a bucket
		// that goes quiet contributes nothing rather than repeating its last
		// value forever.
		charged := e.sinceSample.Swap(0)
		if charged <= 0 {
			return true
		}
		metricUserRate.WithLabelValues(keyKind(k.(string))).Observe(float64(charged) / secs)
		return true
	})
}

// reloadRules pulls all rules from DB and swaps in a fresh snapshot.
// Existing datasource quota buckets are refreshed below (SetLimit/SetBurst).
func (s *Service) reloadRules(ctx context.Context) error {
	rules, err := s.store.list(ctx)
	if err != nil {
		return err
	}
	// Start from the deployed baseline; DB rows layered on top override it per
	// UID. Rebuilding from the ini each time (rather than mutating the previous
	// snapshot) is what makes deleting a DB row restore the deployed value
	// instead of leaving the last override in place forever.
	snap := &rulesSnapshot{
		byKey:    make(map[string]*Rule, len(rules)),
		dsQuota:  baseQuotas(s.cfg.IniQuotas),
		dsFromDB: map[string]bool{},
	}
	for i := range rules {
		r := &rules[i]

		if r.Kind == string(KindLane) {
			// Accepted and ignored: the global lane no longer exists (see
			// LaneDefault). Existing rows must not break a reload, but they
			// also must not silently look effective, hence the warning.
			s.logger.Warn("ignoring kind=lane rule: the global lane was removed; "+
				"configure a per-datasource quota with kind=datasource instead",
				"target", r.Target)
			continue
		}

		if r.Kind == string(KindDatasource) {
			if r.Mode != string(ModeLimited) || r.Rate == nil || r.Burst == nil {
				// Only a quota makes sense for a datasource. blocked/unlimited
				// would need a meaning ("no one may query this backend") that
				// nothing implements, and accepting them would repeat the lane
				// bug where a write succeeded and then did nothing.
				s.logger.Warn("ignoring datasource rule without a rate/burst quota",
					"target", r.Target, "mode", r.Mode)
				continue
			}
			lp, ok := sanitizeParams(*r.Rate, *r.Burst, s.cfg.MaxRuleRate, s.cfg.MaxRuleBurst)
			if !ok {
				// Ignore the row rather than apply it. A bad row can predate
				// admin-API validation or come from a direct DB edit; applying
				// it would silently deny every request to this datasource
				// forever (x/time/rate does not panic on negatives, it just
				// never refills).
				metricInvalidRule.Inc()
				s.logger.Warn("ignoring invalid datasource quota",
					"target", r.Target, "rate", *r.Rate, "burst", *r.Burst)
				continue
			}
			snap.dsQuota[r.Target] = lp
			snap.dsFromDB[r.Target] = true
			continue
		}

		if r.Kind == string(KindDefault) {
			// A default row may carry the QPS pair, the in-flight cap, or
			// both. They are applied independently: setting one must not
			// require restating the other, and an invalid half must not
			// discard the valid half.
			if r.Concurrency != nil {
				switch {
				case *r.Concurrency < 0:
					metricInvalidRule.Inc()
					s.logger.Warn("ignoring negative default concurrency; keeping the configured baseline",
						"concurrency", *r.Concurrency,
						"baseline", s.cfg.DefaultUserConcurrency)
				default:
					// Zero is kept, not rejected: it is how an operator turns
					// the cap off at runtime without a restart, and it reads
					// the same as an unset ini value.
					v := *r.Concurrency
					snap.defaultConcurrency = &v
				}
			}

			// Same shape as a datasource quota: only a rate/burst pair means
			// anything. blocked/unlimited as a global default would let one
			// write disable limiting (or lock everyone out) for the whole
			// deployment, which is what the master switch is for.
			if r.Mode != string(ModeLimited) || r.Rate == nil || r.Burst == nil {
				// Not a warning when the row exists only to carry a
				// concurrency value -- that is a supported shape, not a
				// malformed rule.
				if r.Concurrency == nil {
					s.logger.Warn("ignoring default rule without a rate/burst pair",
						"mode", r.Mode)
				}
				continue
			}
			lp, ok := sanitizeParams(*r.Rate, *r.Burst, s.cfg.MaxRuleRate, s.cfg.MaxRuleBurst)
			if !ok {
				// Ignoring it leaves the ini baseline in force. Applying it
				// would deny every request from every identity that has no
				// rule of its own -- the widest possible blast radius in this
				// package.
				metricInvalidRule.Inc()
				s.logger.Warn("ignoring invalid default rule; keeping the configured baseline",
					"rate", *r.Rate, "burst", *r.Burst,
					"baseline_rate", s.cfg.DefaultUserRate,
					"baseline_burst", s.cfg.DefaultUserBurst)
				continue
			}
			snap.defaults = &lp
			continue
		}

		if r.Kind == string(KindConcurrencyEnforcement) {
			// Same decoding as KindEnforcement below, against the in-flight
			// cap's own switch.
			switch Mode(r.Mode) {
			case ModeLimited:
				v := false
				snap.concurrencyShadow = &v
			case ModeUnlimited:
				v := true
				snap.concurrencyShadow = &v
			default:
				s.logger.Warn("ignoring concurrency enforcement rule with an unusable "+
					"mode; keeping the configured concurrency_shadow_mode",
					"mode", r.Mode, "concurrency_shadow_mode", s.cfg.ConcurrencyShadowMode)
			}
			continue
		}

		if r.Kind == string(KindActivation) || r.Kind == string(KindConcurrencyActivation) {
			// ModeLimited = the layer runs, ModeUnlimited = bypassed. Same
			// encoding as the enforcement kinds, so there is one convention to
			// learn rather than two.
			var v bool
			switch Mode(r.Mode) {
			case ModeLimited:
				v = true
			case ModeUnlimited:
				v = false
			default:
				s.logger.Warn("ignoring activation rule with an unusable mode; "+
					"keeping the configured value",
					"kind", r.Kind, "mode", r.Mode)
				continue
			}
			if r.Kind == string(KindActivation) {
				snap.active = &v
			} else {
				snap.concurrencyActive = &v
			}
			continue
		}

		if r.Kind == string(KindEnforcement) {
			// Mode carries the decision: limited = enforce, unlimited = observe.
			// Anything else is ambiguous, and guessing would be the worst kind of
			// mistake here -- it decides whether real traffic gets rejected.
			switch Mode(r.Mode) {
			case ModeLimited:
				v := false
				snap.shadow = &v
			case ModeUnlimited:
				v := true
				snap.shadow = &v
			default:
				s.logger.Warn("ignoring enforcement rule with an unusable mode; "+
					"keeping the configured shadow_mode",
					"mode", r.Mode, "shadow_mode", s.cfg.ShadowMode)
			}
			continue
		}

		snap.byKey[r.Kind+":"+r.Target] = r
	}
	s.rulesPtr.Store(snap)
	// Defaults and switches can change without a restart. Republish the
	// resolved values after every atomic snapshot swap so the dashboard reads
	// the same generation the request path does.
	s.publishRuntimeConfig(snap)
	s.republishIdentityGauges(snap)
	// Snapshot freshness. fail_open_total counts reload failures, but a counter
	// cannot say how stale the in-memory config is: after a failure the service
	// keeps serving the previous snapshot indefinitely, so an admin API change
	// looks like it simply had no effect.
	metricLastReload.SetToCurrentTime()

	// Re-point existing buckets at the new quota, and drop buckets whose quota
	// was removed so a later re-add starts from the configured burst rather
	// than from stale token state.
	s.dsBuckets.Range(func(k, v any) bool {
		target := k.(string)
		lp, ok := snap.dsQuota[target]
		if !ok {
			s.dsBuckets.Delete(target)
			return true
		}
		lim := v.(*rate.Limiter)
		lim.SetLimit(rate.Limit(lp.rate))
		lim.SetBurst(lp.burst)
		return true
	})
	return nil
}

// resolveRule returns the rule matching the given key, or a synthesized
// default (mode=limited with cfg defaults).
//
// Anonymous traffic defaults to ModeBlocked instead: a datasource query with no
// identity cannot be attributed to anyone, so it cannot be audited, and this
// deployment requires every action to be traceable to a caller. Note this is
// only reachable when [auth.anonymous] enabled is true (it defaults to false),
// so for most deployments the branch never fires.
//
// It is a *default*, not a hard block: an operator who genuinely wants
// anonymous dashboards can override it with
// PUT /api/admin/datasource-rate-limits/anon/anon {"mode":"limited",...}.
// Denials are recorded with the key either way, so the audit trail shows that
// anonymous traffic was attempted and refused.
func (s *Service) resolveRule(key string) *Rule {
	return s.resolveRuleIn(s.rulesPtr.Load(), key)
}

// resolveRuleIn is resolveRule against a caller-supplied snapshot, for the
// middleware: one request must see one generation of config throughout. Reading
// rulesPtr separately for the rule, the default and the enforcement flag would
// let a reload landing mid-request produce a combination that was never
// configured -- e.g. the new limit judged with the old enforcement setting.
func (s *Service) resolveRuleIn(snap *rulesSnapshot, key string) *Rule {
	if r, ok := snap.byKey[key]; ok {
		// A stored rule may carry only a concurrency value: the admin API
		// accepts that deliberately, so tuning the in-flight cap does not
		// force an operator to restate QPS numbers.
		//
		// Such a rule says nothing about QPS, so QPS must fall back exactly as
		// it does for an identity with no rule at all. Returning it unchanged
		// left Mode=limited with Rate=nil, which getUserEntry then filled from
		// an unconfigured baseline -- rate.NewLimiter(0, 0), which refuses
		// everything. Measured: an identity given a concurrency cap of 5 was
		// denied ten requests out of ten while an identity with no rule was
		// served. Adding a limit on one layer disabled the other.
		//
		// That is the same defect this change set exists to remove, reached
		// through a path added by the same change set -- which is why the
		// fallback is now one function called from both places rather than a
		// branch here and a matching branch there.
		if Mode(r.Mode) == ModeLimited && r.Rate == nil && r.Burst == nil {
			return s.baselineRule(snap)
		}
		return r
	}
	if keyKind(key) == string(KindAnon) {
		return &Rule{Mode: string(ModeBlocked)}
	}
	return s.baselineRule(snap)
}

// baselineRule is the QPS rule for an identity that has not been given one.
//
// Reached from two places -- an identity with no stored rule, and one whose
// stored rule sets only a concurrency cap. Both mean "nobody has stated a QPS
// limit for this identity", so both must resolve identically; keeping the
// logic here rather than at each call site is what makes that true by
// construction.
//
// No configured baseline means no limit, not a limit of zero. This used to
// return ModeLimited with rate=0, which x/time/rate reads as "refuse
// everything": an operator who set enabled=true but never filled in
// default_user_rate took the whole query API down. Measured before the change
// -- twenty requests against an unconfigured default, twenty refusals.
//
// An absent number is an operator who has not decided yet, and the only safe
// reading of "not decided" is to stay out of the way. The same rule governs
// the in-flight cap, so neither layer can be armed by omission.
func (s *Service) baselineRule(snap *rulesSnapshot) *Rule {
	r, b := s.defaultParams(snap)
	if r <= 0 || b <= 0 {
		return &Rule{Mode: string(ModeUnlimited)}
	}
	return &Rule{Mode: string(ModeLimited), Rate: &r, Burst: &b}
}

// defaultParams returns the baseline rate/burst for an identity with no rule of
// its own: the DB override when one is set, otherwise the ini value.
//
// Takes the snapshot as an argument rather than re-reading rulesPtr so that a
// caller which already resolved a rule sees the same generation for both -- a
// reload landing in between would otherwise mix a rule from one snapshot with
// a default from the next.
func (s *Service) defaultParams(snap *rulesSnapshot) (rate int64, burst int64) {
	if snap != nil && snap.defaults != nil {
		return int64(snap.defaults.rate), int64(snap.defaults.burst)
	}
	return int64(s.cfg.DefaultUserRate), int64(s.cfg.DefaultUserBurst)
}

// shadowMode reports whether the limiter is observing rather than enforcing,
// preferring a DB override over the ini value.
//
// Every decision that depends on shadow mode must go through here rather than
// reading s.cfg directly: a request that consults the snapshot for its limit and
// s.cfg for whether to enforce it can observe a state that was never configured
// (new limit, old enforcement) for up to one reload interval.
func (s *Service) shadowMode(snap *rulesSnapshot) bool {
	if snap != nil && snap.shadow != nil {
		return *snap.shadow
	}
	return s.cfg.ShadowMode
}

// concurrencyShadowMode is shadowMode for the in-flight cap: DB override
// first, ini second.
//
// Every decision that depends on it must come through here rather than
// reading s.cfg, for the same reason shadowMode exists -- a request that
// takes its limit from the snapshot and its enforcement flag from the config
// can observe a combination that was never configured.
func (s *Service) concurrencyShadowMode(snap *rulesSnapshot) bool {
	if snap != nil && snap.concurrencyShadow != nil {
		return *snap.concurrencyShadow
	}
	return s.cfg.ConcurrencyShadowMode
}

// enforcing is the positive form, for the metric and for /stats. Kept as its own
// method so that "enabled but shadowed" cannot be spelled two different ways in
// two places.
func (s *Service) enforcing(snap *rulesSnapshot) bool {
	return s.activeQPS(snap) && !s.shadowMode(snap)
}

// concurrencyEnforcing is enforcing() for the in-flight layer, and
// deliberately does NOT gate on activeQPS. The two layers are independently
// switchable: gating concurrency on the QPS switch meant turning the QPS layer
// off silently disabled concurrency counting and rejection, so the two
// "independent" rollouts were secretly coupled. Whether concurrency runs is
// decided solely by its own activation + shadow + a positive cap.
func (s *Service) concurrencyEnforcing(snap *rulesSnapshot, cap int64) bool {
	return s.activeConcurrency(snap) && !s.concurrencyShadowMode(snap) && cap > 0
}

// activeQPS reports whether the QPS layer runs at all: DB override first, ini
// second -- the precedence every other setting in this package follows.
//
// Every read of the master switch goes through here rather than touching
// s.cfg.Enabled directly. A request that took its limit from the snapshot and
// its on/off state from the ini could observe a combination that was never
// configured, which is the same failure shadowMode exists to prevent.
func (s *Service) activeQPS(snap *rulesSnapshot) bool {
	if snap != nil && snap.active != nil {
		return *snap.active
	}
	return s.cfg.Enabled
}

// activeConcurrency is activeQPS for the in-flight layer.
//
// It governs accounting, not rejection: with this on and no cap configured the
// layer only records the per-identity in-flight distribution, which is exactly
// the observation needed before choosing a cap. Whether an over-limit request
// is actually refused remains a question for concurrencyShadowMode.
func (s *Service) activeConcurrency(snap *rulesSnapshot) bool {
	if snap != nil && snap.concurrencyActive != nil {
		return *snap.concurrencyActive
	}
	return s.cfg.ConcurrencyEnabled
}

// publishRuntimeConfig mirrors resolved runtime state into gauges. Every value
// is derived through the same helper as the request path and /stats, so a DB
// hot-update cannot leave the dashboard showing the superseded ini baseline.
func (s *Service) publishRuntimeConfig(snap *rulesSnapshot) {
	boolGauge := func(g prometheus.Gauge, value bool) {
		if value {
			g.Set(1)
		} else {
			g.Set(0)
		}
	}

	rate, burst := s.defaultParams(snap)
	concurrency := s.concurrencyLimit(snap, "")
	shadow := s.shadowMode(snap)
	concurrencyShadow := s.concurrencyShadowMode(snap)

	boolGauge(metricEnabled, s.activeQPS(snap))
	boolGauge(metricShadowMode, shadow)
	boolGauge(metricEnforcing, s.enforcing(snap))
	metricDefaultRate.Set(float64(rate))
	metricDefaultBurst.Set(float64(burst))
	boolGauge(metricConcurrencyEnabled, s.activeConcurrency(snap))
	boolGauge(metricConcurrencyShadowMode, concurrencyShadow)
	metricDefaultConcurrency.Set(float64(concurrency))
	boolGauge(metricConcurrencyEnforcing, s.concurrencyEnforcing(snap, concurrency))
}

// sanitizeParams converts an admin-supplied (rate, burst) pair to the int
// form x/time/rate needs, rejecting values that would produce a limiter
// that denies every request forever.
//
// x/time/rate v0.2.0 does NOT panic on negative or zero values — there is no
// panic path in rate.go at all. It silently yields a limiter whose token
// count never recovers (tokens stay at -1 indefinitely), which is much harder
// to diagnose than a crash. The upper bound also covers int64->int truncation
// on 32-bit builds (linux/arm, linux/386), where a value above MaxInt32 would
// wrap to a negative int.
func sanitizeParams(rateVal, burstVal, maxRate, maxBurst int64) (laneParams, bool) {
	const maxInt = int64(^uint(0) >> 1) // 32-bit safe
	if rateVal <= 0 || burstVal <= 0 {
		return laneParams{}, false
	}
	if rateVal > maxRate || burstVal > maxBurst {
		return laneParams{}, false
	}
	if rateVal > maxInt || burstVal > maxInt {
		return laneParams{}, false
	}
	return laneParams{rate: int(rateVal), burst: int(burstVal)}, true
}

// getUserLimiter returns (creating if needed) the per-key *rate.Limiter.
// Thin wrapper over getUserEntry for callers that do not need the entry.
func (s *Service) getUserLimiter(key string, rule *Rule) *rate.Limiter {
	return s.getUserEntry(s.rulesPtr.Load(), key, rule).limiter
}

// getUserEntry returns (creating if needed) the per-key cache entry.
// The rule's rate/burst is applied on every call so that admin-API updates
// take effect on the next request without waiting for cache eviction.
// The caller supplies the snapshot used to resolve rule so one request never
// mixes a rule from one generation with defaults from another.
//
// Invalid stored values fall back to the configured defaults and are logged
// rather than applied: see sanitizeParams for why applying them would be
// worse than ignoring them.
func (s *Service) getUserEntry(snap *rulesSnapshot, key string, rule *Rule) *userEntry {
	baseRate, baseBurst := s.defaultParams(snap)
	desiredRate := rate.Limit(baseRate)
	desiredBurst := int(baseBurst)
	if rule.Rate != nil && rule.Burst != nil {
		if lp, ok := sanitizeParams(*rule.Rate, *rule.Burst, s.cfg.MaxRuleRate, s.cfg.MaxRuleBurst); ok {
			desiredRate = rate.Limit(lp.rate)
			desiredBurst = lp.burst
		} else {
			metricInvalidRule.Inc()
			s.logger.Warn("rule has invalid rate/burst; falling back to configured defaults",
				"key", key, "rate", *rule.Rate, "burst", *rule.Burst,
				"fallback_rate", baseRate, "fallback_burst", baseBurst)
		}
	}

	nowNano := time.Now().UnixNano()

	if v, ok := s.userBuckets.Load(key); ok {
		e := v.(*userEntry)
		e.lastUsedUnixNano.Store(nowNano)
		if e.limiter.Limit() != desiredRate {
			e.limiter.SetLimit(desiredRate)
		}
		if e.limiter.Burst() != desiredBurst {
			e.limiter.SetBurst(desiredBurst)
		}
		return e
	}
	entry := &userEntry{limiter: rate.NewLimiter(desiredRate, desiredBurst)}
	entry.lastUsedUnixNano.Store(nowNano)
	actual, loaded := s.userBuckets.LoadOrStore(key, entry)
	if !loaded {
		metricActiveKeys.Set(float64(s.userCount.Add(1)))
	}
	return actual.(*userEntry)
}

// getDatasourceLimiter returns the quota bucket for a datasource target, or
// nil when that target has no configured quota.
//
// nil means "not quota-managed", not "unlimited": such a request is still
// subject to its caller's identity limit. Returning nil rather than a permissive
// bucket is what keeps unverified client-supplied UIDs from allocating memory.
func (s *Service) getDatasourceLimiter(target string) *rate.Limiter {
	// A quota removed concurrently with this call can leave one bucket behind:
	// the snapshot read above still has the target, and if reloadRules finishes
	// its sweep before the LoadOrStore below, nothing deletes what we just put
	// there. The next reload's sweep does (the target is no longer in dsQuota),
	// so the window is bounded by one reload interval and the bucket is not
	// consulted in the meantime -- chargeDatasources only asks for targets the
	// current snapshot still has a quota for.
	lp, ok := s.rulesPtr.Load().dsQuota[target]
	if !ok {
		return nil
	}
	if v, ok := s.dsBuckets.Load(target); ok {
		return v.(*rate.Limiter)
	}
	actual, _ := s.dsBuckets.LoadOrStore(target,
		rate.NewLimiter(rate.Limit(lp.rate), lp.burst))
	return actual.(*rate.Limiter)
}

// cleanup bounds the per-identity limiter map: once it exceeds
// cfg.CacheMaxEntries, the least recently used entries are dropped.
//
// There is deliberately no idle-TTL pass. It would be a second mechanism for
// the job this one already does: the cap is the memory ceiling either way
// (measured 253 bytes per entry, so 10000 entries is 2.5 MB), and evicting
// early frees nothing that was not already bounded. Nor does it affect
// correctness -- dropping an entry hands its key a fresh full bucket, but a
// bucket at rate=20/burst=40 refills in 2 seconds, so any entry idle long
// enough to qualify was already full. It only added a knob to reason about.
func (s *Service) cleanup() {
	max := int64(s.cfg.CacheMaxEntries)
	if max <= 0 {
		max = 10000
	}
	excess := s.userCount.Load() - max
	if excess > 0 {
		type kv struct {
			key      any
			lastUsed int64
		}
		entries := make([]kv, 0, s.userCount.Load())
		s.userBuckets.Range(func(k, v any) bool {
			// A cheap pre-filter only. tryEvict below is what actually decides,
			// because anything read here can change before the delete.
			if v.(*userEntry).conc.load() > 0 {
				return true
			}
			entries = append(entries, kv{k, v.(*userEntry).lastUsedUnixNano.Load()})
			return true
		})
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].lastUsed < entries[j].lastUsed
		})
		for i := int64(0); i < excess && int(i) < len(entries); i++ {
			// Never evict an identity that still has requests in flight.
			//
			// Eviction resets the in-flight counter, so the identity would get
			// a full fresh allowance on top of the requests it is already
			// running. Measured at a limit of 2: two held, a third correctly
			// rejected, then eviction let two more straight through. The QPS
			// layer has no such window -- a token is spent at admission and
			// never owed back, so evicting a bucket can only cost an identity
			// capacity, never grant it.
			//
			// Checking the counter and then deleting are two steps, and a
			// request arriving between them would take a slot on an entry about
			// to vanish. tryEvict closes that: it marks the entry dead under a
			// CAS on the counter, so a concurrent acquire either got there
			// first (and the entry stays) or sees the flag and retries against
			// the live entry. Measured before this: 399 of 400 attempts slipped
			// past a full cap while cleanup ran alongside live traffic.
			//
			// claimRemoval, then re-check identity before deleting: between the
			// load and the delete the key may already have been removed and
			// refilled by a new request, and deleting by key alone would
			// discard that new entry along with what it is tracking.
			//
			// sync.Map.CompareAndDelete would express this directly but arrived
			// in Go 1.20, and go.mod declares 1.19.
			v, ok := s.userBuckets.Load(entries[i].key)
			if !ok {
				continue
			}
			ue, ok := v.(*userEntry)
			if !ok || !ue.conc.tryEvict() {
				continue
			}
			if !ue.conc.claimRemoval() {
				// A request already took ownership of removing this entry.
				continue
			}
			if cur, present := s.userBuckets.Load(entries[i].key); present && cur == v {
				s.userBuckets.Delete(entries[i].key)
				s.removeIdentitySeries(ue, entries[i].key.(string))
				s.userCount.Add(-1)
			}
			// No else branch. The entry is committed to removal at this point,
			// and if the key now holds something else then this object is
			// already unreachable -- nothing to delete, and nothing that could
			// reach it to be revived. Reviving here would also be a lie: the
			// state says removed, which is exactly what it is.
		}
	}
	metricActiveKeys.Set(float64(s.userCount.Load()))
}

// blockedLogThrottle returns the deny-log throttle for a blocked key,
// creating it on first use.
func (s *Service) blockedLogThrottle(key string) *denyLogThrottle {
	if v, ok := s.blockedLog.Load(key); ok {
		return v.(*denyLogThrottle)
	}
	actual, _ := s.blockedLog.LoadOrStore(key, &denyLogThrottle{})
	return actual.(*denyLogThrottle)
}

// baseQuotas copies the deploy-time quotas into a fresh map.
//
// The copy matters: a snapshot's dsQuota is mutated as DB rows are layered on,
// and sharing the config's map would let one reload's overrides leak into the
// baseline used by the next -- a deleted DB row would then never fall back to
// the deployed value.
func baseQuotas(ini map[string]laneParams) map[string]laneParams {
	out := make(map[string]laneParams, len(ini))
	for uid, lp := range ini {
		out[uid] = lp
	}
	return out
}
