package dsratelimit

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"

	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/web"
)

// Middleware is the pre-hook handler mounted on the 9 datasource routes.
// The metrics emitted here are declared in metrics.go; rule resolution and
// bucket lifecycle live in ratelimit.go.
//
// Invariants that this function guarantees (and unit tests lock down):
//  1. Single accounting exit — attempted == allowed + denied at token
//     granularity, in both live and shadow modes.
//  2. "First-fail-wins" short-circuit — if the per-user bucket denies,
//     datasource quota buckets are never touched (no charging of shared capacity).
//  3. Non-mutating Retry-After — computeRetryAfter uses TokensAt, not
//     Reserve, so repeated denials don't compound the wait time.
func (s *Service) Middleware(c *contextmodel.ReqContext) {
	// Not wired: some HTTPServer construction paths (notably
	// SetupAPITestServer in pkg/api/common_test.go) leave DsRateLimit nil
	// while still calling registerRoutes(). Behave as disabled instead of
	// panicking on the nil receiver. Guarding here rather than at the 9
	// route registrations keeps them single-form, which TestRouteRegistrations
	// relies on to detect a route that forgot the middleware.
	if s == nil {
		return
	}
	// One snapshot for the whole request. Everything below -- the rule, the
	// baseline it falls back to, and whether a denial is enforced or only
	// recorded -- must come from the same generation, or a reload landing
	// mid-request yields a decision that matches no configuration that ever
	// existed.
	snap := s.rulesPtr.Load()
	// Read off the same snapshot as everything else, so the master switch can
	// be flipped at runtime without a restart and without a request ever
	// seeing a half-applied generation.
	if !s.activeQPS(snap) {
		return
	}
	shadow := s.shadowMode(snap)
	key := rateLimitKey(c)
	rule := s.resolveRuleIn(snap, key)
	kind := keyKind(key)
	dsLabel := dsLabelNone

	// unlimited exempts the identity from its own bucket -- and nothing else.
	//
	// It used to return here, which also skipped the datasource quotas. That
	// made an identity-level allowance silently disable a resource-level
	// protection: measured against a datasource with rate=1/burst=1, an
	// unlimited caller got 200 on all 5 requests and the bucket never lost a
	// token, while an ordinary caller got 200 then four 429s.
	//
	// The two levels answer different questions -- "is this caller taking more
	// than its share" versus "can this backend survive the load" -- and the
	// second is not the caller's to waive. Worse, the exemption is granted
	// exactly to high-volume accounts, so the one caller able to flatten a
	// backend was the one excused from the quota protecting it.
	//
	// The bucket is still allocated: it costs one limiter per rule-listed key
	// and keeps the deny-log throttle available, which is what reports an
	// unlimited caller running a datasource out of quota.
	unlimitedIdentity := Mode(rule.Mode) == ModeUnlimited
	modeLabel := "limited"
	if unlimitedIdentity {
		modeLabel = "unlimited"
	}

	// Fast path: blocked never constructs a rate.Limiter. The mode enum exists
	// precisely to keep it out of x/time/rate's Limit==0 trap (rate.go:345-356
	// would permanently drain burst).
	switch Mode(rule.Mode) {
	case ModeBlocked:
		metricAttempted.WithLabelValues(dsLabel, kind).Add(1)
		metricDenied.WithLabelValues(dsLabel, kind, "blocked", enforcedLabel(s.enforcing(snap))).Add(1)
		// Throttled per key, exactly like the limited path.
		//
		// This used to log every request, on the reasoning that mode=blocked is
		// set by hand for one identity so any traffic here is noteworthy. That
		// reasoning expired when anonymous traffic became blocked by default:
		// "anon:anon" is now a shared key that ordinary unauthenticated
		// requests land on, and a public dashboard or a scraper turns it into
		// one log line per request. Measured at 500 anonymous requests: 500
		// lines, 1:1 -- the log volume was itself the incident.
		//
		// denied_since_last_log keeps the true count, so throttling costs no
		// information. The throttle lives in its own map because this path
		// allocates no limiter, which is what makes it a fast path.
		if denied, ok := s.blockedLogThrottle(key).shouldLogDeny(1, time.Now()); ok {
			s.logger.Warn("datasource query blocked by rule",
				"key", key,
				"reason", "blocked",
				"enforced", !shadow,
				"denied_since_last_log", denied,
				"path", c.Req.URL.Path,
			)
		}
		if shadow {
			// Shadow: fall through to the handler like the "limited" path
			// does — otherwise we'd depend on downstream handlers writing
			// a response, which is a subtle contract to maintain.
			return
		}
		s.write429(c, dsLabel, time.Minute, denyMessageInput{
			Scope: scopeBlocked,
			Kind:  denyKindQPS,
		})
		return
	default:
		// ModeLimited and ModeUnlimited both continue below: limited uses the
		// rule's rate, unlimited still pays the datasource quota. Only blocked
		// short-circuits, so there is nothing to do here.
	}

	entry := s.getUserEntry(key, rule)
	userLim := entry.limiter
	now := time.Now()

	// Cost accounting: one token per backend request. A /api/ds/query body
	// carries a queries[] array and each element becomes at least one backend
	// call, so charging by request would let one HTTP call cost dozens of
	// backend calls for free. Also yields the per-datasource split below.
	//
	// Resolved after the limiter so an uncountable body can be charged this
	// user's burst -- the most expensive request that is still admissible.
	var n int
	var dsCost map[string]int
	if isDsQueryRoute(c) {
		body, countable := readCountableBody(c)
		if countable {
			dsCost, n = datasourceTargets(c, body)
		} else {
			dsCost, n = s.uncountableCost(c, body, userLim.Burst())
		}
	} else {
		// Proxy and resources routes: one backend call, datasource named in
		// the path.
		dsCost, n = datasourceTargets(c, nil)
	}
	if n < 1 {
		n = 1
	}

	// Demand, recorded before either limiter rules on it. What sizes a limit is
	// how much a caller asks for, not how much it was let through: sampling the
	// allowed half would make the metric agree with whatever limit is already
	// configured and stop being evidence about it.
	entry.sinceSample.Add(int64(n))
	if isDsQueryRoute(c) {
		// Same demand semantics for burst sizing. In shadow mode an over-burst
		// request is served, and it is exactly the sample the operator needs in
		// order to raise burst. Recording only outcomeAllowed made the histogram
		// self-censor at the old burst and systematically hide the expensive tail.
		metricQueriesPerRequest.Observe(float64(n))
	}

	outcome := outcomeAllowed
	denyReason := ""
	denyTarget := ""
	var deniedLim *rate.Limiter

	// Two levels, and a request must satisfy both: its caller's identity
	// bucket, and the quota bucket of every datasource it touches.
	//
	// Identity first. If it denies, no datasource bucket is touched -- the v1
	// bug was a throttled heavy user still draining shared capacity on requests
	// that never reached a backend.
	//
	// The symmetric case also has to hold: when a datasource quota refuses, the
	// identity is refunded. Reserve-then-cancel rather than AllowN, because
	// AllowN commits the tokens with no way back.
	//
	// Without the refund a caller pays for requests that reached no backend, so
	// a datasource saturated by *other* traffic silently drains every caller
	// aimed at it. Measured, 60 retries at a full quota with the production
	// 20/40 identity default: 39 denials reported reason=datasource and then 20
	// flipped to reason=user. The operator reads "this user is over their
	// limit" while the actual cause is "this backend is out of quota" -- the
	// wrong party, and the wrong fix.
	var userRes *rate.Reservation
	if !unlimitedIdentity {
		userRes = userLim.ReserveN(now, n)
		if !userRes.OK() || userRes.DelayFrom(now) > 0 {
			userRes.CancelAt(now)
			userRes = nil
			outcome, denyReason, deniedLim = outcomeDenied, "user", userLim
		}
	}
	if outcome != outcomeDenied {
		if target, lim, ok := s.chargeDatasources(dsCost, now); !ok {
			outcome, denyReason, denyTarget, deniedLim = outcomeDenied, "datasource", target, lim
			if userRes != nil {
				userRes.CancelAt(now)
			}
		}
	}
	if outcome == outcomeDenied && denyReason == "user" {
		dsLabel = dsLabelNone
	} else if denyTarget != "" {
		dsLabel = denyTarget
	}

	// Separate "will succeed once tokens refill" from "can never succeed".
	//
	// x/time/rate has no queueing: reserveN gates on `ok := n <= lim.burst`
	// (rate.go:371), so a request costing more than burst is refused on every
	// attempt no matter how long the caller waits. The panel never loads and
	// retrying does not help.
	//
	// Without this distinction both cases report reason="user" and are
	// indistinguishable in metrics and logs -- the permanent one looks like a
	// small steady trickle of 429s, i.e. like the limiter working normally.
	// That is the failure mode most likely to be misread, so it gets its own
	// reason rather than a different threshold.
	//
	// Compare the cost charged to whoever refused, not the request total. On a
	// datasource denial those differ: a panel hitting a small datasource for 1
	// token and a large one for 30 has n=31, and judging the small bucket
	// (burst=2) by 31 declares a permanently impossible request when the truth
	// is "wait about a second". The user is then told to split the dashboard,
	// which fixes nothing, and reason/permanent/Retry-After all agree on the
	// wrong answer.
	deniedCost := n
	if denyTarget != "" {
		deniedCost = dsCost[denyTarget]
	}
	if outcome == outcomeDenied && deniedCost > deniedLim.Burst() {
		denyReason = denyReason + "_oversized"
	}

	// Per-datasource demand, recorded before the request-level counters below.
	// Those can only name a datasource when one refused, which answers "how
	// much did PROM_MAIN reject?" but never "how much did PROM_MAIN carry?" --
	// and the second is the question a quota is sized from.
	s.recordDatasourceTokens(dsCost, outcome)

	// Single accounting exit — see invariant 1 above.
	metricAttempted.WithLabelValues(dsLabel, kind).Add(float64(n))
	if outcome == outcomeAllowed {
		metricAllowed.WithLabelValues(dsLabel, kind, modeLabel).Add(float64(n))
		return
	}
	metricDenied.WithLabelValues(dsLabel, kind, denyReason, enforcedLabel(s.enforcing(snap))).Add(float64(n))

	// Log the denial. Metrics carry only {datasource, kind, reason} — deliberately
	// no per-identity label, to avoid unbounded cardinality — so this line is
	// the only place the *identity* of a throttled caller is recorded.
	//
	// It matters most during shadow_mode, where nothing is rejected and the
	// operator otherwise has no way to answer "who would this have blocked?"
	// before turning enforcement on.
	//
	// Throttled per key (see denyLogThrottle.shouldLogDeny): a denied key is being
	// hit hard by definition, so one line per denial would be a second
	// incident. denied_since_last_log preserves the true volume.
	if denied, ok := entry.denyLog.shouldLogDeny(n, now); ok {
		s.logger.Warn("datasource query rate limit exceeded",
			"key", key,
			"reason", denyReason,
			// Which datasource refused, empty when the identity limit did.
			// reason=datasource alone does not say which backend ran out of
			// quota, and with per-datasource quotas that is the first thing
			// anyone reading this line needs.
			"target", denyTarget,
			"enforced", !shadow,
			"tokens_this_request", n,
			// True when this request costs more than the bucket's burst, so it
			// can never succeed: not throttling, a request that will never be
			// admitted until burst is raised or the request is made smaller.
			"permanent", deniedCost > deniedLim.Burst(),
			"denied_since_last_log", denied,
			"limit_rate", float64(userLim.Limit()),
			"limit_burst", userLim.Burst(),
			"path", c.Req.URL.Path,
		)
	}

	if shadow {
		return
	}
	retryAfter := computeRetryAfter(deniedLim, deniedCost, now)
	// Report the limit that actually refused, not the identity one: on a
	// datasource denial those are different numbers, and quoting the caller's
	// own limit would point them at the wrong thing to fix.
	//
	// Keyed off denyTarget rather than matching denyReason against "datasource".
	// denyReason is a free-form metrics label that already grows a suffix
	// (_oversized) at line 201, so a string comparison would have to be kept in
	// step with every future variant, and getting it wrong fails silently --
	// scope quietly reverts to personal and the message blames the wrong party.
	// denyTarget is assigned only in the datasource branch, so it answers the
	// question structurally.
	scope := scopePersonal
	if denyTarget != "" {
		scope = scopeDatasource
	}
	s.write429(c, dsLabel, retryAfter, denyMessageInput{
		Scope:      scope,
		Kind:       denyKindQPS,
		Limit:      int(deniedLim.Limit()),
		Target:     denyTarget,
		RetryAfter: retryAfter,
		Permanent:  deniedCost > deniedLim.Burst(),
		Cost:       deniedCost,
		Burst:      deniedLim.Burst(),
	})
}

// rateLimitKey picks the identity dimension for this request.
// GrafanaAdmin is intentionally NOT auto-whitelisted (admins run scripts too);
// operators can whitelist via admin API.
//
// Every returned key is "<kind>:<id>". That shape is load-bearing: reloadRules
// stores admin rules under Kind+":"+Target (ratelimit.go), so a key produced
// here that lacks the colon can never match a stored rule -- the rule would be
// accepted by the admin API, appear in AdminList, and silently do nothing.
// TestRateLimitKey_MatchesAdminKeyShape locks this.
func rateLimitKey(c *contextmodel.ReqContext) string {
	switch {
	case c.IsServiceAccount:
		return "sa:" + strconv.FormatInt(c.UserID, 10)
	case c.ApiKeyID != 0 && c.UserID == 0:
		return "apikey:" + strconv.FormatInt(c.ApiKeyID, 10)
	case c.IsAnonymous:
		// One shared bucket for all anonymous traffic, and by policy it is
		// blocked outright (see the ModeBlocked short-circuit in Middleware):
		// an anonymous datasource query cannot be attributed to anyone, so it
		// cannot be audited. RemoteAddr would not help -- it honors
		// X-Forwarded-For / X-Real-IP with no trusted-proxy list, so per-IP
		// buckets are both trivially spoofed and a way to churn the LRU and
		// evict real users.
		//
		// The ":anon" suffix keeps the "<kind>:<id>" shape so an operator who
		// deliberately wants to allow anonymous traffic can override this with
		// PUT /api/admin/datasource-rate-limits/anon/anon. Without the colon
		// that rule would be accepted and then never match.
		return "anon:anon"
	default:
		return "user:" + strconv.FormatInt(c.UserID, 10)
	}
}

// keyKind returns the prefix before the first ':', for metric labels.
func keyKind(key string) string {
	for i := 0; i < len(key); i++ {
		if key[i] == ':' {
			return key[:i]
		}
	}
	return key
}

// dsQueryPath is the one route whose cost is charged per query in the body
// rather than a flat 1 token.
const dsQueryPath = "/api/ds/query"

// Values of the `mode` label on metricAllowed and of the internal outcome
// variable. Constants because a typo in either would not fail any build or
// test -- it would silently split one time series into two, and the mistake
// would only surface when someone reads a dashboard and the numbers no longer
// add up.
const (
	outcomeAllowed = "allowed"
	outcomeDenied  = "denied"
)

// isDsQueryRoute is true only for POST /api/ds/query. Proxy and resources
// routes charge a flat 1 token.
//
// The trailing slash must be tolerated. macaron's router normalises the path
// with strings.TrimSuffix(url, "/") before matching (pkg/web/tree.go:379), so
// "/api/ds/query/" reaches the very same handler. An exact string compare
// here would therefore let a caller charge an N-query request as 1 token just
// by appending "/" -- the cost-accounting bypass this function prevents.
//
// The TrimSuffix below deliberately mirrors that line: it strips exactly one
// slash, so this predicate admits precisely the set macaron routes.
// "/api/ds/query//" does NOT reach the handler, and charging per query for a
// request that never executes would over-count just as badly as under-count.
func isDsQueryRoute(c *contextmodel.ReqContext) bool {
	if c.Req == nil || c.Req.URL == nil {
		return false
	}
	return strings.TrimSuffix(c.Req.URL.Path, "/") == dsQueryPath
}

// countQueriesAndReplayBody reads /api/ds/query's body once, computes the
// token cost, and restores req.Body so the downstream handler's web.Bind can
// still decode it. On any parse error, returns 1 (safe default — we prefer to
// under-count than to hard-fail a real request).
//
// Note: web.Bind (pkg/web/binding.go:14-30) calls Close() on Body and then
// json.NewDecoder(req.Body).Decode(v). Close() on io.NopCloser is a no-op,
// and Decode re-reads from the underlying bytes.Reader; safe.
//
// COST MODEL: one token per *backend request*, not per element of queries[].
// A single query fans out to 1-3 backend calls because the Prometheus
// datasource runs instant / range / exemplar as three independent ifs
// (pkg/tsdb/prometheus/querydata/request.go:125,131,143 — not else-if, they
// can all fire for one query). Charging len(queries) would therefore
// under-count by the average fan-out (measured ~1.2x on this deployment,
// drifting to ~1.5x as dashboard traffic share rises), which is exactly the
// factor that decouples a configured quota from real backend QPS. Counting the
// flags here keeps `1 token == 1 backend request`, so each datasource limit can
// be derived from its backend quota by plain subtraction and needs no empirical
// correction factor.
//
// The flag semantics mirror pkg/tsdb/prometheus/models/query.go:98-106
// exactly, including the legacy fallback: older dashboards set neither
// `range` nor `instant`, and the datasource treats that as a range query.
// Omitting that branch would charge such requests 0 tokens — i.e. exempt
// legacy dashboards from rate limiting entirely.
//
// Non-Prometheus datasources do not read these flags, so for them the cost
// degenerates to 1 token per query (no flags set -> legacy fallback). That is
// correct: those datasources issue one backend call per query.
// Bounds on what the token count may cost us to compute.
//
// maxCountedBodyBytes caps the prefix we buffer to count queries. 1 MiB holds
// a few thousand queries -- far more than any real dashboard -- so no genuine
// request is affected. Above it we stop counting rather than stop the request.
//
// maxCountedQueries is what an over-cap body is charged. It is deliberately
// expensive rather than 1: an uncountable body must not be cheaper than a
// countable one, or oversizing the payload becomes a way to buy queries.
//
// It is capped at the per-user burst instead of some large round number. A
// value above a datasource burst would exceed that quota bucket and
// be refused on every attempt -- permanently, since x/time/rate does not queue
// -- which would turn this cost decision back into a rejection, exactly what
// the LimitReader path is written to avoid. Charging the burst makes such a
// request as expensive as a request can be while still being admissible.
const maxCountedBodyBytes int64 = 1 << 20

func maxCountedQueries(burst int) int {
	if burst < 1 {
		return 1
	}
	return burst
}

// readCountableBody buffers a bounded prefix of the request body for cost
// accounting and hands the handler back an equivalent body.
//
// Returns countable=false when the body cannot be counted (too large to buffer,
// or a read error). Callers must then charge the ceiling rather than 1 token.
func readCountableBody(c *contextmodel.ReqContext) (body []byte, countable bool) {
	if c.Req == nil || c.Req.Body == nil {
		return nil, false
	}
	// Bound what we buffer. The handler decodes the body as a stream
	// (web.Bind uses json.NewDecoder), so this ReadAll is an extra full copy
	// that we add -- and we add it BEFORE the limit decision, so even a
	// request we are about to reject pays for it. Measured: ReadAll on a
	// 64 MiB body grows the heap by 135 MiB (it doubles while growing), which
	// any user holding datasource-query permission could trigger concurrently.
	// Nothing upstream caps this path.
	//
	// Reading a bounded prefix costs 4 MiB for the same body, and
	// io.MultiReader hands the handler the original stream intact --
	// verified byte-for-byte on 64 MiB.
	limited := io.LimitReader(c.Req.Body, maxCountedBodyBytes+1)
	buf, err := io.ReadAll(limited)
	if int64(len(buf)) > maxCountedBodyBytes {
		// Deliberately NOT a 413. This middleware decides how much a request
		// costs, not whether it is acceptable; rejecting here would let the
		// limiter change the outcome of requests even in shadow mode, which is
		// the one thing shadow mode promises it cannot do. Body size is the
		// handler's business.
		metricOversizedBody.Inc()
		c.Req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), c.Req.Body))
		return buf, false
	}
	_ = c.Req.Body.Close()
	if err != nil {
		// Hand the handler a body that fails the same way ours did, rather
		// than the partial bytes we managed to read. Replaying a truncated
		// body would turn "the client's connection broke" into "invalid
		// JSON": the request fails either way, but the second diagnosis
		// points at the wrong party. errorReader replays err on first read.
		//
		// Leaving c.Req.Body as-is is not an option -- ReadAll drained and
		// Close closed it, so the handler would read from a spent body.
		c.Req.Body = io.NopCloser(&errorReader{err: err})
		return nil, false
	}
	c.Req.Body = io.NopCloser(bytes.NewReader(buf))
	return buf, true
}

// uncountableCost is what a request whose body could not be counted is charged:
// the ceiling, on both the identity bucket and every datasource it can still be
// shown to touch.
//
// Charging 1 token instead would make an oversized body the cheapest possible
// request -- a way to buy queries by padding the payload. Note the handler still
// receives the complete body and still executes every query in it (the
// truncation is only in our counting), so under-charging here is a real bypass,
// not a theoretical one.
//
// The datasource side matters just as much as the identity side: without it,
// padding a body past the cap would escape the backend quota entirely. Targets
// are recovered by decoding the prefix element by element and stopping at the
// truncation, which reaches far more queries than any real dashboard contains.
// Anything past the cap stays unattributed, and the identity ceiling is the
// backstop for it.
func (s *Service) uncountableCost(c *contextmodel.ReqContext, prefix []byte, burst int) (map[string]int, int) {
	ceiling := maxCountedQueries(burst)
	targets := map[string]int{}
	for _, uid := range partialTargets(c, prefix) {
		// Clamp to the datasource's own burst. The ceiling is derived from the
		// caller's burst, which can exceed a datasource's quota -- and a cost
		// above burst is refused on every attempt no matter how long the caller
		// waits (rate.go:371), so charging it verbatim would turn "this body is
		// too big to count" into "this datasource is permanently unavailable to
		// this route". That denial never recovers and reads in metrics like the
		// limiter working normally, which is the worst way to fail.
		//
		// Charging the bucket's burst instead keeps the intent -- the most
		// expensive request that is still admissible -- at whichever level is
		// tighter.
		cost := ceiling
		if lim := s.getDatasourceLimiter(uid); lim != nil && lim.Burst() < cost {
			cost = lim.Burst()
		}
		targets[uid] = cost
	}
	if len(targets) == 0 {
		return nil, ceiling
	}
	return targets, ceiling
}

// partialTargets recovers datasource UIDs from a possibly truncated body by
// streaming the queries array and stopping at the first element that will not
// decode. Returns nil when nothing can be recovered.
func partialTargets(c *contextmodel.ReqContext, prefix []byte) []string {
	if p := web.Params(c.Req); p != nil {
		if uid := p[":uid"]; uid != "" {
			return []string{uid}
		}
		if p[":id"] != "" {
			return nil // see datasourceTargets
		}
	}
	if len(prefix) == 0 {
		return nil
	}

	dec := json.NewDecoder(bytes.NewReader(prefix))
	// Walk to the value of "queries", then into its array.
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil
		}
		if key, ok := tok.(string); ok && key == "queries" {
			break
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
		return nil
	}

	seen := map[string]bool{}
	var out []string
	for dec.More() {
		var q struct {
			Datasource   json.RawMessage `json:"datasource"`
			DatasourceID *int64          `json:"datasourceId"`
		}
		if err := dec.Decode(&q); err != nil {
			break // truncated here; keep what we already have
		}
		uid := queryDatasourceUID(q.Datasource, q.DatasourceID)
		if uid == "" || isNonBackendUID(uid) || seen[uid] {
			continue
		}
		seen[uid] = true
		out = append(out, uid)
	}
	return out
}

// write429 emits a rate-limit response. The internal key is NOT included —
// user IDs and IPs are considered internal (they appear only in stats /
// server logs). Retry-After uses ceil with a 1s floor to prevent retry
// storms on sub-second delays.
//
// The message is built by denyMessageInput (deny_message.go) and is the only
// explanation the user gets: the frontend renders err.data.message verbatim
// (backend_srv.ts:321). It replaced a fixed "datasource rate limit exceeded",
// which named neither which limit fired, nor its value, nor what to do -- the
// three things the reader needs, and badly so on a deployment that had no
// throttling until now.
//
// The machine-readable fields stay alongside it: `scope` and `kind` let a
// caller branch without parsing prose, and keep the wording free to change.
//
// `X-RateLimit-Scope` replaced `X-RateLimit-Lane`. The old header was doubly
// wrong: it named the global lane, which no longer exists (see LaneDefault),
// and its value was the datasource UID -- unvalidated client text, since
// validateTarget bounds a UID's length but not its charset. Nothing consumed
// it. Net/http rewrites CR/LF in header values (verified on the wire: the
// bytes arrive as spaces), so this was never header injection, but shipping
// arbitrary caller-controlled text in a header nobody reads is cost without
// benefit. Scope is a closed set of three words, so the new header cannot
// carry anything unexpected. The UID still appears in the body, where it is
// JSON-escaped and actually useful.
func (s *Service) write429(c *contextmodel.ReqContext, datasource string, retryAfter time.Duration, in denyMessageInput) {
	seconds := int(math.Ceil(retryAfter.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	c.Resp.Header().Set("Retry-After", strconv.Itoa(seconds))
	c.Resp.Header().Set("X-RateLimit-Scope", in.scopeLabel())
	body := map[string]any{
		"message":        in.String(),
		"retry_after_ms": retryAfter.Milliseconds(),
		"scope":          in.scopeLabel(),
		"kind":           in.kindLabel(),
	}
	// Named `datasource`, not `lane`: the value has always been a datasource
	// UID, and the lane it was named after was deleted along with the global
	// bucket. Keeping the old name would leave the wire format describing an
	// architecture this MR does not have. Renaming is free only until this
	// merges, because after that some client may be reading it.
	//
	// Omitted, not empty, when the denial is not attributable to a datasource
	// (a personal-bucket or blocked denial): an empty string invites a client
	// to render "datasource: ".
	if datasource != "" && datasource != dsLabelNone {
		body["datasource"] = datasource
	}
	// Only meaningful when a limit is actually known; omitted rather than sent
	// as 0, which a client would reasonably read as "your limit is zero".
	if in.Limit > 0 {
		body["limit"] = in.Limit
	}
	c.JSON(http.StatusTooManyRequests, body)
}

// errorReader replays a read error, so a body we failed to read stays failed
// for whoever reads it next instead of appearing empty or truncated.
type errorReader struct{ err error }

func (r *errorReader) Read([]byte) (int, error) { return 0, r.err }

// datasourceTargets returns the datasource UIDs a request will hit, with the
// token cost attributed to each, plus the total cost n.
//
// Identity is taken from data the router and the request body already carry --
// no DB or cache lookup. That is deliberate: the datasource cache misses on
// first use and falls through to SQL (datasources/service/cache.go:91), and the
// moment this limiter matters most is a traffic surge, which is exactly when a
// flood of unknown UIDs would have it adding load to the DB it is meant to
// protect.
//
// The consequence is that UIDs here are unverified client input, so they are
// only ever used to look up a configured quota -- never to create a bucket or a
// metric label on their own. See getDatasourceLimiter.
//
// Four body forms exist in the wild and all are handled:
//   - {"datasource":{"uid":"P1"}}  modern
//   - {"datasource":"P1"}          pre-8.3 string form (query.go:321)
//   - {"datasourceId":42}          legacy numeric (query.go:347)
//   - absent                       nothing attributable
//
// Expression and built-in nodes are skipped: they hit no backend, so charging
// a quota for them would reserve capacity that is never consumed.
func datasourceTargets(c *contextmodel.ReqContext, body []byte) (map[string]int, int) {
	// Proxy and resources routes name the datasource in the path, not the
	// body. Verified that URL params are already bound at pre-handler time.
	if p := web.Params(c.Req); p != nil {
		if uid := p[":uid"]; uid != "" {
			return map[string]int{uid: 1}, 1
		}
		if p[":id"] != "" {
			// Numeric-ID routes (deprecated, api.go:438/440/443/446) are NOT
			// given a quota bucket. Resolving the ID to a UID would mean a
			// datasource lookup here, and a cache miss goes to SQL
			// (datasources/service/cache.go:91) -- so during the exact traffic
			// surge this limiter exists to contain, it would add load to the
			// DB. Bucketing by the raw ID instead was worse: the same backend
			// then holds two independent quotas, and the numeric one is not the
			// one anybody configures, so it acts as a bypass.
			//
			// Cost is still returned, so the request is charged to the caller's
			// identity limit. It just cannot draw on -- or escape -- a
			// datasource quota.
			return nil, 1
		}
	}

	var doc struct {
		Queries []struct {
			Datasource   json.RawMessage `json:"datasource"`
			DatasourceID *int64          `json:"datasourceId"`
			Instant      *bool           `json:"instant"`
			Range        *bool           `json:"range"`
			Exemplar     *bool           `json:"exemplar"`
		} `json:"queries"`
	}
	if len(body) == 0 || json.Unmarshal(body, &doc) != nil || len(doc.Queries) == 0 {
		return nil, 1
	}

	targets := map[string]int{}
	total := 0
	for _, q := range doc.Queries {
		cost := queryCost(q.Instant, q.Range, q.Exemplar)
		total += cost

		uid := queryDatasourceUID(q.Datasource, q.DatasourceID)
		if uid == "" || isNonBackendUID(uid) {
			continue
		}
		targets[uid] += cost
	}
	if total < 1 {
		total = 1
	}
	return targets, total
}

// queryCost is the per-query token cost: one token per backend request.
//
// The Prometheus datasource runs instant, range and exemplar as three
// independent ifs (tsdb/prometheus/querydata/request.go:125,131,143), so one
// query element can become up to three backend calls. Datasources without
// these flags cost exactly 1, which is correct for them -- verified by
// measurement across mysql, elasticsearch and stackdriver bodies.
func queryCost(instant, rng, exemplar *bool) int {
	i := instant != nil && *instant
	r := rng != nil && *rng
	// models/query.go:103-105 — "In older dashboards, we were not setting
	// range query param and !range && !instant was run as range query".
	if !i && !r {
		r = true
	}
	n := 0
	if i {
		n++
	}
	if r {
		n++
	}
	if exemplar != nil && *exemplar {
		n++
	}
	if n < 1 {
		n = 1
	}
	return n
}

// queryDatasourceUID pulls the datasource identity out of one query element,
// tolerating every form listed on datasourceTargets.
func queryDatasourceUID(raw json.RawMessage, legacyID *int64) string {
	if len(raw) > 0 {
		var obj struct {
			UID string `json:"uid"`
		}
		if json.Unmarshal(raw, &obj) == nil && obj.UID != "" {
			return obj.UID
		}
		var str string
		if json.Unmarshal(raw, &str) == nil && str != "" {
			return str
		}
	}
	// A body carrying only datasourceId yields no target, for the reasons in
	// datasourceTargets. Note the 9.5 frontend always sends `datasource`
	// alongside `datasourceId` (DataSourceWithBackend.ts:174, marked
	// "deprecated!"), and DashboardMigrator rewrites older panels to the uid
	// form, so this branch is not reached by normal dashboard traffic --
	// verified: a body with both fields resolves via `datasource`.
	return ""
}

// UIDs that denote something which never reaches a datasource backend:
// server-side expressions and the built-in Grafana datasource. Charging a
// backend quota for these would reserve capacity nobody consumes.
//
// Copied rather than imported. Importing pkg/expr for three string constants
// pulls 710 packages into this one (measured: 1239 deps vs 532 without), and it
// would put a rate limiter downstream of the expression engine -- the wrong
// direction, and a latent import cycle the day expr wants to rate-limit
// anything. TestNonBackendUIDs_MatchUpstream reads the upstream sources and
// fails if these drift.
const (
	uidExpr    = "__expr__" // expr.DatasourceUID / expr.DatasourceType
	uidExprOld = "-100"     // expr.OldDatasourceUID
	uidGrafana = "grafana"  // grafanads.DatasourceUID
)

// isNonBackendUID reports whether a UID hits no datasource backend.
func isNonBackendUID(uid string) bool {
	switch uid {
	case uidExpr, uidExprOld, uidGrafana:
		return true
	}
	return false
}

// chargeDatasources charges each datasource its share of the request, all or
// nothing. On success every quota bucket has been debited; on failure none has.
//
// The atomicity is the point. A dashboard panel mixing two datasources must not
// consume quota from the one with capacity when the other is going to refuse the
// request anyway -- those tokens would be spent on a query that never runs,
// which is the same "white-charging" bug that ordering identity before
// datasource fixes at the other level.
//
// x/time/rate has no multi-bucket primitive, so this is a two-phase commit over
// Reservation: reserve on each, and cancel every reservation if any of them
// cannot be served immediately. CancelAt restores the tokens exactly (measured:
// a bucket at 40 charged 5 and cancelled returns to 40.00), provided no later
// reservation on the same bucket has consumed them -- which is why the check
// runs before any of the cancels.
//
// Returns the offending target and its limiter when refused, so the caller can
// name it in metrics, logs and the oversized check.
func (s *Service) chargeDatasources(cost map[string]int, now time.Time) (string, *rate.Limiter, bool) {
	if len(cost) == 0 {
		return "", nil, true
	}

	type held struct {
		res *rate.Reservation
		lim *rate.Limiter
	}
	var holds []held
	denied := ""
	var deniedLim *rate.Limiter

	for target, tokens := range cost {
		lim := s.getDatasourceLimiter(target)
		if lim == nil {
			continue // no quota configured for this datasource
		}
		if tokens < 1 {
			tokens = 1
		}
		res := lim.ReserveN(now, tokens)
		holds = append(holds, held{res: res, lim: lim})
		// OK()==false means the cost exceeds burst and can never be served;
		// a non-zero delay means it could be served later but not now. Both
		// are refusals here: this limiter rejects, it does not queue.
		if !res.OK() || res.DelayFrom(now) > 0 {
			denied, deniedLim = target, lim
			break
		}
	}

	if denied == "" {
		return "", nil, true
	}
	for _, h := range holds {
		h.res.CancelAt(now)
	}
	return denied, deniedLim, false
}

// enforcedLabel reports whether a denial actually rejected the request.
//
// Without it denied_total is ambiguous in the one situation it matters most:
// during shadow mode the counter rises exactly as it would under enforcement,
// so a dashboard cannot distinguish "this many requests were refused" from
// "this many would have been refused if we turned it on" -- measured identical,
// 9 and 9, before this label existed. Those two readings call for opposite
// reactions.
//
// A two-value label, so cardinality is unaffected in practice.
//
// Takes the resolved flag rather than Config so it cannot disagree with the
// decision the request actually made: the label and the branch that rejected
// (or spared) the request now derive from the same value.
func enforcedLabel(enforced bool) string {
	if enforced {
		return "true"
	}
	return "false"
}

// recordDatasourceTokens attributes a request's cost to each datasource it
// touched, so per-backend load can be read directly instead of inferred.
//
// outcome="denied" means the tokens never reached this datasource, whichever
// limit refused them -- denied_total carries the reason. Keeping both under one
// datasource makes allowed+denied the total demand for that backend, which is
// the number to size a quota against: under shadow mode nothing is actually
// rejected, so the denied half is served too and belongs in the total.
//
// Only datasources with a configured quota are recorded. Unconfigured ones have
// no bucket, so a client-supplied UID cannot open a new series here.
func (s *Service) recordDatasourceTokens(cost map[string]int, outcome string) {
	for target, tokens := range cost {
		if s.getDatasourceLimiter(target) == nil {
			continue
		}
		if tokens < 1 {
			tokens = 1 // mirrors the floor chargeDatasources applies
		}
		metricDatasourceTokens.WithLabelValues(target, outcome).Add(float64(tokens))
	}
}
