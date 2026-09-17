package dsratelimit

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"time"

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

	// shadow, when non-nil, overrides the ini shadow_mode. Going from observing
	// to enforcing (and back, if enforcement turns out to hurt) is the single
	// most time-critical switch this package has, and requiring a restart for it
	// meant the rollout step and the rollback step both cost a restart.
	//
	// nil means the ini value applies, same convention as defaults.
	shadow *bool
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
	// unreachable). rulesPtr must also never be nil for Load().
	// Config is the only source until the first DB reload lands, so this
	// publishes the ini state; reloadRules re-publishes it whenever a DB
	// override changes it. It answers "is the limiter actually enforcing right
	// now?" from a dashboard, which matters because shadow mode is the default
	// -- "we thought it was on" is a realistic way to find out a backend was
	// never protected.
	s.publishEnforcing(nil)

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
// an explicit `lane_default_rate = -5` is passed through verbatim. Reaching
// rate.NewLimiter, such a value produces a limiter whose tokens never recover
// (x/time/rate v0.2.0 has no panic path — see sanitizeParams), so a single
// mistyped line silently rejects every datasource query in the deployment.
//
// This is the one place all four values cross into the service, so guarding it
// covers both the lane bucket built in ProvideService and the per-user
// defaults. Note the per-user path was already protected: resolveRule wraps the
// config values in a Rule, which getUserEntry runs through sanitizeParams. The
// lane bucket had no equivalent, which is exactly the asymmetry fixed here.
//
// Invalid values fall back to the built-in defaults rather than disabling the
// limiter: a typo should not silently remove the protection either. Each
// fallback is logged with the offending key and value, and counted in
// invalid_rule_total, so it cannot pass unnoticed.
func loadConfigFromSetting(cfg *setting.Cfg) Config {
	logger := log.New("dsratelimit")
	sane := func(key string, got, fallback int) int {
		if got > 0 && int64(got) <= MaxRuleRate {
			return got
		}
		logger.Warn("invalid datasource_ratelimit setting; falling back to built-in default",
			"key", key, "configured", got, "using", fallback,
			"why", "rate/burst must be > 0 and <= MaxRuleRate; other values make "+
				"x/time/rate reject every request without recovering")
		metricInvalidRule.Inc()
		return fallback
	}
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
		lp, ok := sanitizeParams(int64(q.Rate), int64(q.Burst))
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

	return Config{
		Enabled:          cfg.DsRateLimit.Enabled,
		ShadowMode:       cfg.DsRateLimit.ShadowMode,
		DefaultUserRate:  sane("default_user_rate", cfg.DsRateLimit.DefaultUserRate, defaultUserRateFallback),
		DefaultUserBurst: sane("default_user_burst", cfg.DsRateLimit.DefaultUserBurst, defaultUserBurstFallback),
		IniQuotas:        iniQuotas,
		CacheMaxEntries:  cfg.DsRateLimit.CacheMaxEntries,

		ConcurrencyEnabled: cfg.DsRateLimit.ConcurrencyEnabled,
		// Not run through sane(): unlike rate and burst, where zero would
		// silently deny every request, zero here is the meaningful default of
		// "no cap". Substituting a fallback would turn an explicit
		// default_user_concurrency = 0 into a limit nobody asked for.
		DefaultUserConcurrency: cfg.DsRateLimit.DefaultUserConcurrency,
		ConcurrencyShadowMode:  cfg.DsRateLimit.ConcurrencyShadowMode,
	}
}

// Run implements registry.BackgroundService: reload + cleanup goroutines.
// Blocks until ctx is cancelled.
func (s *Service) Run(ctx context.Context) error {
	if !s.cfg.Enabled {
		<-ctx.Done()
		return nil
	}
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
		// Swap, so each token is observed in exactly one window, and a bucket
		// that goes quiet contributes nothing rather than repeating its last
		// value forever.
		charged := v.(*userEntry).sinceSample.Swap(0)
		if charged <= 0 {
			return true
		}
		metricUserRate.WithLabelValues(keyKind(k.(string))).Observe(float64(charged) / secs)
		return true
	})
}

// reloadRules pulls all rules from DB and swaps in a fresh snapshot.
// The default lane bucket is also refreshed here (SetLimit/SetBurst).
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
			lp, ok := sanitizeParams(*r.Rate, *r.Burst)
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
			// Same shape as a datasource quota: only a rate/burst pair means
			// anything. blocked/unlimited as a global default would let one
			// write disable limiting (or lock everyone out) for the whole
			// deployment, which is what the master switch is for.
			if r.Mode != string(ModeLimited) || r.Rate == nil || r.Burst == nil {
				s.logger.Warn("ignoring default rule without a rate/burst pair",
					"mode", r.Mode)
				continue
			}
			lp, ok := sanitizeParams(*r.Rate, *r.Burst)
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
	// Enforcement can now change without a restart, so the gauge has to be
	// re-published on every reload rather than set once at startup. A dashboard
	// that says "shadow" while the limiter is rejecting traffic is worse than no
	// gauge at all.
	s.publishEnforcing(snap)
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
		return r
	}
	if keyKind(key) == string(KindAnon) {
		return &Rule{Mode: string(ModeBlocked)}
	}
	r, b := s.defaultParams(snap)
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

// enforcing is the positive form, for the metric and for /stats. Kept as its own
// method so that "enabled but shadowed" cannot be spelled two different ways in
// two places.
func (s *Service) enforcing(snap *rulesSnapshot) bool {
	return s.cfg.Enabled && !s.shadowMode(snap)
}

// publishEnforcing mirrors the current enforcement state into the gauge.
func (s *Service) publishEnforcing(snap *rulesSnapshot) {
	if s.enforcing(snap) {
		metricEnforcing.Set(1)
	} else {
		metricEnforcing.Set(0)
	}
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
func sanitizeParams(rateVal, burstVal int64) (laneParams, bool) {
	const maxInt = int64(^uint(0) >> 1) // 32-bit safe
	if rateVal <= 0 || burstVal <= 0 {
		return laneParams{}, false
	}
	if rateVal > MaxRuleRate || burstVal > MaxRuleBurst {
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
	return s.getUserEntry(key, rule).limiter
}

// getUserEntry returns (creating if needed) the per-key cache entry.
// The rule's rate/burst is applied on every call so that admin-API updates
// take effect on the next request without waiting for cache eviction.
//
// Invalid stored values fall back to the configured defaults and are logged
// rather than applied: see sanitizeParams for why applying them would be
// worse than ignoring them.
func (s *Service) getUserEntry(key string, rule *Rule) *userEntry {
	baseRate, baseBurst := s.defaultParams(s.rulesPtr.Load())
	desiredRate := rate.Limit(baseRate)
	desiredBurst := int(baseBurst)
	if rule.Rate != nil && rule.Burst != nil {
		if lp, ok := sanitizeParams(*rule.Rate, *rule.Burst); ok {
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
