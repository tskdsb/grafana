package dsratelimit

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/grafana/grafana/pkg/services/contexthandler"
)

// Concurrency limiting: a cap on how many datasource queries one identity may
// have in flight at once.
//
// Why this exists alongside the QPS limiter. QPS answers "how often", not "how
// much at once", and the two come apart exactly where it hurts. An identity
// issuing 15 queries a second that each return in 50ms occupies almost nothing;
// an identity issuing 15 a second that each take 20 seconds accumulates 300
// simultaneous queries against the backend. Both sit at the same QPS and only
// the second one starves everyone else. A token bucket cannot see the
// difference, because a token is spent at admission and never reclaimed -- the
// bucket has already forgotten the request by the time it becomes expensive.
//
// Per identity only, deliberately. The failure mode above is one caller holding
// resources, so the cap belongs on the caller. Datasource-level protection is
// already covered by the QPS layer's per-datasource quotas, and adding a second
// datasource-level gate would make "why was I rejected" answerable only by
// reading both layers at once.
//
// Rejection rather than queueing. Queueing would keep the request, and with it
// the goroutine, the connection and the memory, which is the resource pressure
// this is supposed to relieve; a queue deep enough to matter is just the
// original problem with extra latency. Rejecting sheds the load immediately and
// tells the caller something true.

// managedPathRe matches the datasource query routes that carry an :id or :uid
// path parameter.
//
// The QPS middleware never needs this: it is mounted per route, so the router
// has already decided the request is in scope. Concurrency is mounted globally
// -- the only place where a request's completion is observable -- and therefore
// has to recognise its own traffic from the raw path.
//
// Kept deliberately strict rather than a prefix test on /api/datasources/.
// That prefix also covers /datasources/new, /datasources/edit/*, and
// /datasources/correlations, none of which query a backend; limiting them would
// make the settings UI fail under load for no benefit. The alternative signal,
// RouteOperationName, is populated by a route-level handler and so is still
// empty this early in the chain.
var managedPathRe = regexp.MustCompile(
	`^/api/datasources/(` +
		`proxy/(uid/[^/]+|[^/]+)(/.*)?` + // proxy, by id or uid, with or without a suffix
		`|(uid/[^/]+|[^/]+)/(resources(/.*)?|health)` + // resources and health, by id or uid
		`)$`)

// isManagedPath reports whether a path is one of the datasource query routes
// the QPS middleware guards, and so should also be subject to the in-flight cap.
//
// The trailing slash is trimmed first for the same reason the QPS layer does it:
// pkg/web/tree.go strips it before matching, so /api/ds/query/ reaches the same
// handler as /api/ds/query. Treating them differently here would leave a free
// bypass open for anyone who appends a slash.
func isManagedPath(p string) bool {
	if p != "/" {
		p = strings.TrimSuffix(p, "/")
	}
	if p == dsQueryPath {
		return true
	}
	// Prefix test before the regexp. This middleware wraps every request in
	// the server, and the overwhelming majority are not datasource routes at
	// all; a string compare rejects them without entering the matcher.
	if !strings.HasPrefix(p, "/api/datasources/") {
		return false
	}
	return managedPathRe.MatchString(p)
}

// inflight is one identity's concurrency counter.
//
// Compare-and-swap rather than Add-then-check. Add-then-check does not actually
// over-admit -- each caller's returned value is unique, so the (limit+1)-th
// caller always loses -- but it publishes a count that momentarily includes
// callers who are about to be rejected. Measured with 16 racing callers against
// a limit of 3, the counter reached 16 while nothing was in flight. That figure
// is what the gauge reports and what the next caller is compared against, so
// the inflated window both corrupts the metric and rejects requests that should
// have been admitted. CAS never publishes a value above the limit.
//
// evicted marks an entry that cleanup has removed from the map. A holder that
// arrives after eviction would otherwise keep counting against an object no
// future request can see, and the identity would be tracked by two counters at
// once -- which is the eviction bug this type exists to prevent, one level
// down. acquire refuses on an evicted entry so the caller retries against the
// live one.
type inflight struct {
	cur atomic.Int64
	// state is one of the stateX constants below. One field rather than two
	// booleans: with a separate "evicted" and "removing" flag there is a window
	// where the first is set and the second is not, and a reader that sampled
	// the first would act on a decision the writer went on to undo. Merging
	// them makes every observable value a state the protocol actually defines.
	state atomic.Int32
}

// The entry's lifecycle. Transitions are one-way apart from the retreat from
// stateDying, and each is a CAS, so a reader never sees an intermediate value.
//
//	stateLive  --tryEvict, idle--> stateDying --> (remover deletes it)
//	stateLive  --tryEvict, busy--> stateLive   (no transition; nothing observed)
//	stateDying --claimRemoval--->  stateRemoved
const (
	// stateLive accepts traffic.
	stateLive int32 = iota
	// stateDying is claimed for removal and refuses new holders. Only reached
	// from an idle entry, and only by a caller that will either remove it or
	// hand it back to stateLive.
	stateDying
	// stateRemoved has had its key deleted. Terminal; the next lookup for that
	// key builds a fresh entry.
	stateRemoved
)

// acquire takes a slot, and reports whether the caller is within the limit.
//
// A slot is taken either way. limit <= 0 is observation mode -- the counter
// still moves, so the histogram sees real concurrency, and the caller is always
// admitted. Returning early without counting would make the observation period
// produce nothing at all, which is the state this rollout depends on: the limit
// can only be chosen by reading what the histogram recorded while unlimited.
//
// The counter is therefore "slots held", not "slots granted". Those differ only
// while unlimited, where nothing is refused and every holder is counted.
//
// ok is false when the entry has been evicted between lookup and acquisition;
// the caller must fetch the entry again rather than use this one.
func (f *inflight) acquire(limit int64) (admitted, ok bool) {
	if f.state.Load() != stateLive {
		return false, false
	}
	if limit <= 0 {
		f.cur.Add(1)
		// Re-check after incrementing. A racing tryEvict can only move a live
		// entry to stateDying while the count reads zero, so an entry that is
		// dying here never saw this increment and must not be counted on.
		if f.state.Load() != stateLive {
			f.cur.Add(-1)
			return false, false
		}
		return true, true
	}
	for {
		c := f.cur.Load()
		if c >= limit {
			return false, true
		}
		if f.cur.CompareAndSwap(c, c+1) {
			if f.state.Load() != stateLive {
				f.cur.Add(-1)
				return false, false
			}
			return true, true
		}
	}
}

// tryEvict marks the entry dead if and only if nothing is in flight.
//
// The flag is what closes the window cleanup would otherwise have: checking
// "is it idle" and deleting from the map are two steps, and a request arriving
// between them would acquire a slot on an entry about to disappear. Setting the
// flag first, under CAS on the counter, means any such request loses the race
// and is sent to the live entry instead.
func (f *inflight) tryEvict() bool {
	if f.cur.Load() != 0 {
		// Busy. Also release a claim left over from an earlier attempt: that
		// claim was taken while the entry looked idle, and leaving it in place
		// would have every acquire report a miss forever, locking the identity
		// out of datasource queries entirely. CAS so this cannot resurrect an
		// entry that has already been removed.
		f.state.CompareAndSwap(stateDying, stateLive)
		return false
	}
	if !f.state.CompareAndSwap(stateLive, stateDying) {
		// Already dying or removed: someone else owns this entry's removal.
		return false
	}
	// A holder may have incremented between the read above and the CAS. It
	// will see stateDying and back out, but if it got in first the count is
	// non-zero and the entry has to go back to live.
	//
	// Putting it back is safe precisely because stateDying is exclusive: no
	// other remover can be holding it, so nobody is mid-decision on a value
	// this is about to change.
	if f.cur.Load() != 0 {
		f.state.CompareAndSwap(stateDying, stateLive)
		return false
	}
	return true
}

// release returns a slot.
//
// Clamped at zero. A release without a matching acquire should be impossible --
// every caller releases via defer on the path that acquired -- but an unclamped
// counter that goes negative would silently grant extra capacity forever, which
// is a worse failure than the accounting being briefly wrong.
func (f *inflight) release() {
	for {
		c := f.cur.Load()
		if c <= 0 {
			return
		}
		if f.cur.CompareAndSwap(c, c-1) {
			return
		}
	}
}

// claimRemoval hands exactly one caller the right to take this entry out of
// the map and decrement the count. Whoever wins removes it; everyone else
// leaves it alone.
//
// This is what sync.Map.CompareAndDelete would give for free, but that arrived
// in Go 1.20 and go.mod declares 1.19. The flag reaches the same guarantee --
// exactly one remover per entry -- without depending on the map API, and has
// the same shape as the rest of this type.
// claimRemoval commits a dying entry to removal, and hands exactly one caller
// the right to delete the key and decrement the count.
//
// It refuses anything that is not currently dying. That is the fix for a real
// race: a caller can observe stateDying, have tryEvict retreat to stateLive
// behind it because a holder got in, and then go on to delete an entry that is
// alive and counting. Measured with the interleaving spelled out in review --
// an entry with a request in flight passed both the claim and the pointer
// check. Re-reading the state at the moment of commit closes it, because the
// retreat is itself a state change this CAS cannot miss.
func (f *inflight) claimRemoval() bool {
	return f.state.CompareAndSwap(stateDying, stateRemoved)
}

func (f *inflight) load() int64 { return f.cur.Load() }

// ConcurrencyMiddleware caps simultaneous in-flight datasource queries per
// identity.
//
// Mounted globally rather than per route, which is forced rather than chosen:
// pkg/web's Context has no Next(), so a route-level handler cannot observe when
// the request finishes, and without that there is nothing to release. A
// wrapping middleware gets the completion for free -- next.ServeHTTP returning
// is the end of the request.
//
// Must be installed after ContextHandler. The identity is read off ReqContext,
// which ContextHandler is what populates.
func (s *Service) ConcurrencyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A nil service means the feature was never wired; a disabled one means
		// it was wired and turned off. Both must pass traffic through
		// untouched.
		if s == nil {
			next.ServeHTTP(w, r)
			return
		}
		// Both master switches come from the snapshot, so either layer can be
		// turned on or off at runtime. Reading s.cfg here instead would have
		// made the one operation worth doing fast -- switching a layer off
		// when it misbehaves -- the only one needing a restart.
		//
		// Only the concurrency switch gates this layer; it must not also read
		// the QPS switch. The two layers roll out independently, so turning the
		// QPS layer off (or leaving it disabled at first launch) must not
		// silently stop concurrency counting and rejection.
		snapActive := s.rulesPtr.Load()
		if !s.activeConcurrency(snapActive) {
			next.ServeHTTP(w, r)
			return
		}
		if !isManagedPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		c := contexthandler.FromContext(r.Context())
		if c == nil || c.SignedInUser == nil {
			// No identity to charge. Only reachable if this middleware is
			// mounted before ContextHandler, which is a wiring mistake rather
			// than a request the limiter should reject.
			next.ServeHTTP(w, r)
			return
		}

		// Unauthenticated requests are not counted.
		//
		// This middleware wraps the whole chain, so unlike the QPS layer -- which
		// sits behind authorize() on each route -- it also sees requests that are
		// about to be rejected with 401 or 403. Those carry UserID 0 and are not
		// anonymous, so rateLimitKey maps every one of them to the single key
		// "user:0": a shared pool where unrelated failed logins would evict each
		// other, and where a burst of them could exhaust the slots while
		// consuming no datasource capacity at all, since none of them reach a
		// backend.
		//
		// Anonymous traffic is a different case and stays counted: it is a real
		// identity with a deliberate policy attached, and it does reach backends
		// when an operator allows it.
		if c.UserID <= 0 && !c.IsAnonymous && c.ApiKeyID == 0 {
			next.ServeHTTP(w, r)
			return
		}

		snap := s.rulesPtr.Load()
		key := rateLimitKey(c)
		limit := s.concurrencyLimit(snap, key)
		// The in-flight cap's own switch, not shadowMode(snap). That one governs
		// the QPS layer, which may already be enforcing in production; reusing
		// it would mean a concurrency trial can only run by standing the QPS
		// layer down.
		shadow := s.concurrencyShadowMode(snap)

		// Three states, not two. Disabled was handled above; what remains is
		// observing (limit <= 0) and enforcing (limit > 0). Both count, so the
		// histogram is populated in either -- returning early while unlimited
		// would leave the observation period with no data, and the limit can
		// only be chosen from that data.
		//
		// In shadow mode the effective limit is zero: the request is going to
		// be served regardless, so it genuinely will be in flight, and the
		// counter has to say so. Passing the trial limit here instead would cap
		// the recorded value at that limit and hide the demand above it, which
		// is precisely the demand the operator is trying to measure.
		effective := limit
		if shadow {
			effective = 0
		}

		// Cooperative eviction. acquire returns a miss when it lands on an entry
		// cleanup has marked dead but not yet removed from the map, and the
		// request clears that itself rather than waiting.
		//
		// Waiting does not work: cleanup runs on a single ticker goroutine, so
		// between the mark and the delete there is no other goroutine to finish
		// the job. getUserEntry returns whatever is in the map, dead or not, so
		// retrying alone just hands back the same corpse -- measured as the
		// request reaching the handler with the counter still at zero, an
		// uncounted request straight through the cap.
		//
		// CompareAndDelete by pointer so this and cleanup cannot both decrement
		// userCount for the same entry: exactly one CAS wins. Losing is fine and
		// needs no retry of its own -- the winner has already removed it, so the
		// next getUserEntry creates a live one.
		var entry *userEntry
		var admitted bool
		for attempt := 0; attempt < 3; attempt++ {
			rule := s.resolveRuleIn(snap, key)
			e := s.getUserEntry(snap, key, rule)
			e.withIdentityLabels(key, c.Login, func(labels *identityMetricLabels) {
				metricIdentityRateLimit.WithLabelValues(labels.values()...).Set(s.effectiveIdentityRateLimit(snap, rule, e.limiter))
				metricIdentityConcurrencyLimit.WithLabelValues(labels.values()...).Set(s.effectiveIdentityConcurrencyLimit(snap, key))
			})
			got, ok := e.conc.acquire(effective)
			if ok {
				entry, admitted = e, got
				break
			}
			// Clear the corpse so the next attempt builds a live entry.
			//
			// claimRemoval only succeeds on an entry that is still dying, which
			// is what makes this safe: a miss can also be observed on an entry
			// that tryEvict subsequently returned to service, and deleting that
			// one would drop a live counter with requests on it. The CAS inside
			// claimRemoval sees that retreat and refuses.
			//
			// The pointer check guards a different case: the key may already
			// have been removed and refilled, and deleting by key alone would
			// discard the replacement.
			if e.conc.claimRemoval() {
				if cur, ok := s.userBuckets.Load(key); ok && cur == any(e) {
					s.userBuckets.Delete(key)
					e.removeIdentitySeries()
					s.userCount.Add(-1)
				}
			}
		}
		if entry == nil {
			// Three rounds of "found a corpse, cleared it, found another" is not
			// a state this cache reaches; the loop bound exists so a bug here
			// cannot spin forever. Fail open rather than refuse real traffic.
			metricConcurrencyFailOpen.Inc()
			next.ServeHTTP(w, r)
			return
		}

		// Refused requests never took a slot, so they must not return one.
		// Releasing unconditionally decrements the counter for a slot that was
		// never held, which quietly frees capacity for someone else -- measured
		// as the counter dropping from 2 to 1 on the very request that was
		// correctly rejected, after which the cap stopped holding at all.
		if !admitted {
			metricConcurrencyDenied.WithLabelValues(keyKind(key), enforcedLabel(!shadow)).Inc()
			s.writeConcurrencyDenial(w, key, limit)
			return
		}

		defer func() {
			entry.conc.release()
			entry.publishIdentityInflight()
			metricConcurrencyHeld.Dec()
		}()
		metricConcurrencyHeld.Inc()

		// Observed after the slot is taken, so the value includes this request:
		// the reading an operator compares against a candidate limit.
		held := entry.conc.load()
		entry.publishIdentityInflight()
		metricConcurrencyInflight.WithLabelValues(keyKind(key)).Observe(float64(held))

		// Shadow mode admits everything, so the refusal it would have made has
		// to be inferred from the count rather than from `admitted`.
		if shadow && limit > 0 && held > limit {
			metricConcurrencyDenied.WithLabelValues(keyKind(key), enforcedLabel(false)).Inc()
		}
		next.ServeHTTP(w, r)
	})
}

// concurrencyLimit resolves the in-flight cap for one identity.
//
// Three sources, most specific first: a rule for this exact identity, the
// default rule, then the ini baseline. Same table and same precedence the QPS
// layer uses, so an operator learns one model rather than two.
//
// Takes the snapshot rather than re-reading rulesPtr so that one request sees
// one generation of config throughout -- a reload landing mid-request must not
// produce a combination that was never configured.
//
// A non-positive result means no cap. That covers both "never configured" and
// "explicitly turned off at runtime", which are the same thing as far as a
// request is concerned: nothing was decided, so nothing is enforced.
func (s *Service) concurrencyLimit(snap *rulesSnapshot, key string) int64 {
	if snap != nil {
		if r, ok := snap.byKey[key]; ok && r.Concurrency != nil {
			if *r.Concurrency < 0 {
				// Negative can only arrive from a direct DB edit; the admin
				// API rejects it. Falling through to the default is the same
				// choice reloadRules makes for a malformed rate/burst.
				s.logger.Warn("ignoring negative concurrency override",
					"key", key, "concurrency", *r.Concurrency)
			} else {
				return *r.Concurrency
			}
		}
		if snap.defaultConcurrency != nil {
			return *snap.defaultConcurrency
		}
	}
	return int64(s.cfg.DefaultUserConcurrency)
}

// writeConcurrencyDenial sends the 429 for an in-flight rejection.
//
// Wording comes from the shared builder in deny_message.go, which already had a
// denyKindConcurrent branch. Going through it keeps both layers phrased the same
// way; the one thing that differs -- concurrency cannot be waited out -- lives
// in that branch rather than in a second copy of the sentence here.
//
// No Retry-After header. The slot frees when one of the caller's own requests
// finishes, which is not a duration this layer knows, and clients honour an
// invented number literally.
func (s *Service) writeConcurrencyDenial(w http.ResponseWriter, key string, limit int64) {
	in := denyMessageInput{
		Kind:  denyKindConcurrent,
		Scope: scopePersonal,
		Limit: int(limit),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-RateLimit-Scope", in.scopeLabel())
	w.WriteHeader(http.StatusTooManyRequests)

	// Same fields the QPS layer sends, so one client parser handles both. No
	// retry_after_ms and no Retry-After: a slot frees when one of the caller's
	// own requests ends, which is not a duration this layer knows, and an
	// invented one would be honoured literally. The absence is the signal --
	// kind=concurrent says why waiting is not the remedy.
	//
	// No traceID either. An earlier version sent one, always empty, which the
	// QPS layer does not send at all; a field that is always blank is worse
	// than no field, because a client may render it.
	body := map[string]any{
		"message": in.String(),
		"scope":   in.scopeLabel(),
		"kind":    in.kindLabel(),
	}
	if limit > 0 {
		body["limit"] = limit
	}
	_ = json.NewEncoder(w).Encode(body)
}
