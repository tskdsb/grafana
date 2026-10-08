package dsratelimit

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/grafana/grafana/pkg/api/response"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/web"
)

// UpsertBody is the request body for PUT /api/admin/datasource-rate-limits/:kind/:target.
// UpsertBody is a partial update: a field carries a new value, clears the
// stored one when explicitly null, or is absent and leaves it alone.
//
// json.RawMessage rather than *int64 because a pointer cannot tell an absent
// field from an explicit null -- both unmarshal to nil, and those two mean
// opposite things here.
//
// This replaces whole-row replacement, which forced every write to restate
// every field. That made the common edit -- change a rate, leave the in-flight
// cap alone -- silently clear the cap, so it needed a guard that refused any
// write dropping a stored value. The guard could not tell a slip from a
// deliberate clear, so clearing one field meant deleting the row and writing it
// back, leaving the identity unlimited in between. Partial update removes the
// whole chain: omitting a field is a no-op, so there is nothing to slip on and
// nothing to guard.
type UpsertBody struct {
	Mode        string          `json:"mode"`
	Rate        json.RawMessage `json:"rate,omitempty"`
	Burst       json.RawMessage `json:"burst,omitempty"`
	Concurrency json.RawMessage `json:"concurrency,omitempty"`
}

// fieldUpdate is one field's requested change: absent, cleared, or set.
type fieldUpdate struct {
	present bool  // the key appeared in the body
	clear   bool  // it appeared as null
	value   int64 // meaningful only when present && !clear
}

func (f fieldUpdate) apply(stored *int64) *int64 {
	switch {
	case !f.present:
		return stored
	case f.clear:
		return nil
	default:
		v := f.value
		return &v
	}
}

// parseField reads one field into the three states, rejecting anything that is
// neither null nor an integer rather than silently treating it as absent.
func parseField(raw json.RawMessage, name string) (fieldUpdate, error) {
	if raw == nil {
		return fieldUpdate{}, nil
	}
	if string(raw) == "null" {
		return fieldUpdate{present: true, clear: true}, nil
	}
	var v int64
	if err := json.Unmarshal(raw, &v); err != nil {
		return fieldUpdate{}, fmt.Errorf("%s must be an integer or null", name)
	}
	return fieldUpdate{present: true, value: v}, nil
}

// notWired reports whether the service is absent (nil receiver), which
// happens on HTTPServer construction paths that skip wire injection (e.g.
// SetupAPITestServer). Admin endpoints then behave as if the feature does
// not exist instead of panicking. Returns nil when the service is usable.
func (s *Service) notWired() response.Response {
	if s == nil {
		return response.Error(http.StatusNotFound, "datasource rate limiting is not enabled", nil)
	}
	return nil
}

// AdminList handles GET /api/admin/datasource-rate-limits.
// Returns every rule plus the resolved defaults, switches, and datasource quotas.
func (s *Service) AdminList(c *contextmodel.ReqContext) response.Response {
	if r := s.notWired(); r != nil {
		return r
	}
	rules, err := s.store.list(c.Req.Context())
	if err != nil {
		return response.Error(http.StatusInternalServerError, "failed to list rate-limit rules", err)
	}
	return response.JSON(http.StatusOK, map[string]any{
		"rules":       rules,
		"datasources": s.datasourceStatusSnapshot(time.Now()),
	})
}

// AdminGet handles GET /api/admin/datasource-rate-limits/:kind/:target.
func (s *Service) AdminGet(c *contextmodel.ReqContext) response.Response {
	if r := s.notWired(); r != nil {
		return r
	}
	kind := web.Params(c.Req)[":kind"]
	target := web.Params(c.Req)[":target"]
	if kind == "" || target == "" {
		return response.Error(http.StatusBadRequest, "kind and target are required", nil)
	}
	r, err := s.store.get(c.Req.Context(), kind, target)
	if err != nil {
		return response.Error(http.StatusInternalServerError, "failed to get rule", err)
	}
	if r == nil {
		return response.Error(http.StatusNotFound, "rule not found", nil)
	}
	return response.JSON(http.StatusOK, r)
}

// validateMergedRule checks a merged rule and returns an operator-facing reason
// when it must not be stored, or "" when it may.
//
// Pure, and called twice: once in the handler so a bad request is refused
// before any lock is taken and with a clear message, and again inside
// upsertPartial after the merge against the locked row. The second call is the
// one that decides. The first is a courtesy.
//
// Both are needed because they answer different questions. The handler knows
// what the caller asked for; only the transaction knows what the rule will
// actually become. A reviewer found the gap between them: two requests each
// changing one half of the QPS pair both validate against the row as it was,
// then merge in sequence into rate=80 burst=20 -- a pair neither request asked
// for and neither would have passed. Measured before the fix: 19 of 20
// concurrent rounds produced an invalid pair, both requests returning 200.
//
// That mattered because nothing downstream re-checks it: sanitizeParams
// verifies positivity and ceilings but not burst >= rate, so the pair reaches
// rate.NewLimiter(80, 20) and every request costing more than 20 is refused
// forever.
// bounds is the set of ceilings a submitted rule is judged against, read from
// Config so a deployment can move them without a rebuild. Passed explicitly
// rather than reached through the Service so the validator stays a pure
// function of its inputs and is testable at any bound.
type bounds struct {
	rate        int64
	burst       int64
	concurrency int64
}

func (s *Service) bounds() bounds {
	return bounds{
		rate:        s.cfg.MaxRuleRate,
		burst:       s.cfg.MaxRuleBurst,
		concurrency: s.cfg.MaxRuleConcurrency,
	}
}

// isSwitchKind reports whether a kind is one of the deployment-wide switches,
// whose only meaningful field is Mode.
//
// Kept as one predicate rather than repeated kind comparisons: the list has
// grown twice, and both times a site that enumerated the kinds inline was
// missed. validateTarget and this check must agree on what a switch is.
func isSwitchKind(k Kind) bool {
	switch k {
	case KindEnforcement, KindConcurrencyEnforcement, KindActivation, KindConcurrencyActivation:
		return true
	}
	return false
}

func validateMergedRule(kind Kind, mode Mode, rate, burst, conc *int64, b bounds) string {
	// The switch kinds carry a decision, not a number: their whole payload is
	// the mode. Requiring rate/burst from them would make "turn this layer on"
	// unexpressible -- which is what happened to the activation kinds until a
	// real PUT was tried against a running server.
	if mode == ModeLimited && !isSwitchKind(kind) {
		hasQPS := rate != nil || burst != nil
		if !hasQPS && conc == nil {
			return "mode=limited needs rate and burst, a concurrency cap, or both"
		}
		if hasQPS && (rate == nil || burst == nil) {
			return "rate and burst must both be set: sending one alone would leave a " +
				"rule reloadRules skips. Send both, or null both to clear them"
		}
		if rate != nil && burst != nil {
			// x/time/rate does NOT panic on these (v0.2.0 has no panic path) --
			// it silently denies forever, which is far harder to diagnose.
			if *rate <= 0 || *burst <= 0 {
				return "rate and burst must be positive when mode=limited"
			}
			if *rate > b.rate || *burst > b.burst {
				return fmt.Sprintf("rate must be <= %d and burst must be <= %d",
					b.rate, b.burst)
			}
			if *burst < *rate {
				return fmt.Sprintf("burst must be >= rate, otherwise a single burst of "+
					"traffic can never be admitted (merged result: rate=%d burst=%d)",
					*rate, *burst)
			}
		}
	}
	if conc != nil {
		if *conc < 0 {
			return "concurrency must be >= 0 (0 means no in-flight cap)"
		}
		if *conc > b.concurrency {
			return fmt.Sprintf("concurrency must be <= %d", b.concurrency)
		}
		if kind == KindEnforcement || kind == KindDatasource ||
			kind == KindConcurrencyEnforcement {
			// Enforcement carries a decision, not a number. A datasource cap
			// would need a shared counter across identities, which the
			// in-flight layer does not implement.
			return "concurrency applies to identity kinds (user, sa, apikey, anon) " +
				"and to kind=default; it is not supported for " + string(kind)
		}
	}
	return ""
}

// AdminPut handles PUT /api/admin/datasource-rate-limits/:kind/:target.
// Validates kind, mode, and (mode=limited) the rate/burst numeric range.
// Logs an audit line with actor + before/after digest, then triggers an
// immediate reload so the change is live on the next request.
func (s *Service) AdminPut(c *contextmodel.ReqContext) response.Response {
	if r := s.notWired(); r != nil {
		return r
	}
	kind := web.Params(c.Req)[":kind"]
	target := web.Params(c.Req)[":target"]
	if kind == "" || target == "" {
		return response.Error(http.StatusBadRequest, "kind and target are required", nil)
	}
	// Reject unknown kinds. Without this a typo (e.g. "lain/default")
	// silently writes a row that resolveRule/reloadRules will never match,
	// so the operator believes a limit is in effect when it is not.
	if !ValidKind(kind) {
		return response.Error(http.StatusBadRequest,
			"kind must be one of: "+strings.Join(ValidKinds(), ", "), nil)
	}
	if Kind(kind) == KindLane {
		// The global lane is gone (see LaneDefault). Reject rather than accept
		// a row that reloadRules now ignores -- the same "writes fine, does
		// nothing" failure this endpoint already guards against below.
		return response.Error(http.StatusBadRequest,
			"kind=lane is no longer supported: the global lane was replaced by "+
				"per-datasource quotas. Use kind=datasource with the datasource "+
				"UID as target", nil)
	}
	if msg := validateTarget(Kind(kind), target); msg != "" {
		return response.Error(http.StatusBadRequest, msg, nil)
	}
	var body UpsertBody
	if err := web.Bind(c.Req, &body); err != nil {
		return response.Error(http.StatusBadRequest, "invalid body", err)
	}
	switch Mode(body.Mode) {
	case ModeLimited, ModeUnlimited, ModeBlocked:
	default:
		return response.Error(http.StatusBadRequest,
			"mode must be one of: limited, unlimited, blocked", nil)
	}
	rateUpd, err := parseField(body.Rate, "rate")
	if err != nil {
		return response.Error(http.StatusBadRequest, err.Error(), nil)
	}
	burstUpd, err := parseField(body.Burst, "burst")
	if err != nil {
		return response.Error(http.StatusBadRequest, err.Error(), nil)
	}
	concUpd, err := parseField(body.Concurrency, "concurrency")
	if err != nil {
		return response.Error(http.StatusBadRequest, err.Error(), nil)
	}

	// The stored row is read before validation, not after, because a partial
	// body is only meaningful against it: "rate=30" alone is valid when a burst
	// is already stored and invalid when it is not. Validating the body in
	// isolation would accept the second case and store a rule that
	// reloadRules silently skips.
	//
	// A read error stops the write. Continuing as if the row were absent would
	// turn every omitted field into a clear -- the exact data loss this design
	// exists to prevent.
	before, err := s.store.get(c.Req.Context(), kind, target)
	if err != nil {
		return response.Error(http.StatusInternalServerError,
			"failed to read the existing rule", err)
	}
	var storedRate, storedBurst, storedConc *int64
	if before != nil {
		storedRate, storedBurst, storedConc = before.Rate, before.Burst, before.Concurrency
	}
	finalRate := rateUpd.apply(storedRate)
	finalBurst := burstUpd.apply(storedBurst)
	finalConc := concUpd.apply(storedConc)
	// A datasource quota accepts rate/burst only. reloadRules skips any
	// datasource row without both values, so accepting blocked/unlimited here
	// would return 200 and list the rule back while the quota stayed as it was
	// -- the operator believes a backend is protected (or released) when
	// nothing changed. That exact bug shipped once on the lane path; it is not
	// getting a second outing.
	//
	// blocked/unlimited would also need a meaning nothing implements: "no one
	// may query this backend" is an availability decision, not a rate limit.
	// Use enabled/shadow_mode to turn enforcement off globally.
	if Kind(kind) == KindDatasource && Mode(body.Mode) != ModeLimited {
		return response.Error(http.StatusBadRequest,
			"datasource rules support mode=limited only; blocked/unlimited would "+
				"be accepted but never applied. Use the enabled or shadow_mode "+
				"setting to turn enforcement off globally", nil)
	}
	// Same restriction for the deployment-wide default, for a sharper reason:
	// mode=blocked here would lock out every identity without a rule of its
	// own, and mode=unlimited would silently disable per-identity limiting for
	// all of them. Both are enforcement switches, and there are already two.
	if Kind(kind) == KindDefault && Mode(body.Mode) != ModeLimited {
		return response.Error(http.StatusBadRequest,
			"default rules support mode=limited only; blocked would lock out every "+
				"identity without its own rule, and unlimited would disable "+
				"per-identity limiting for all of them. Use the enabled or "+
				"shadow_mode setting to turn enforcement off globally", nil)
	}
	// All four switches carry their decision in Mode alone. The enforcement
	// kinds already rejected rate/burst, but the two activation kinds accepted
	// and persisted rate/burst/concurrency that reloadRules then ignores: the
	// PUT returned 200 and the operator believed a limit was set when only the
	// switch moved. A switch that takes numbers has to reject them all.
	if isSwitchKind(Kind(kind)) {
		if rateUpd.present || burstUpd.present || concUpd.present {
			return response.Error(http.StatusBadRequest,
				"switch rules take mode only (limited/unlimited), not rate/burst/concurrency; "+
					"set those on kind=default or on a specific identity", nil)
		}
		switch Mode(body.Mode) {
		case ModeLimited, ModeUnlimited:
		default:
			return response.Error(http.StatusBadRequest,
				"switch rules accept mode=limited or mode=unlimited only", nil)
		}
	}

	// Advisory check: refuses an obviously bad request before any lock is taken.
	// The authoritative one runs inside upsertPartial, against the row it locks
	// -- this one cannot see what a concurrent write is about to do.
	if msg := validateMergedRule(Kind(kind), Mode(body.Mode),
		finalRate, finalBurst, finalConc, s.bounds()); msg != "" {
		return response.Error(http.StatusBadRequest, msg, nil)
	}

	actorID := c.UserID

	// The merge above was for validation. What gets written is merged again
	// inside upsertPartial, against the row it locks -- otherwise two writers
	// each changing a different field would both succeed and the later one
	// would silently revert the earlier.
	written, err := s.store.upsertPartial(c.Req.Context(), kind, target, body.Mode,
		&actorID, rateUpd, burstUpd, concUpd,
		func(rate, burst, conc *int64) string {
			return validateMergedRule(Kind(kind), Mode(body.Mode), rate, burst, conc, s.bounds())
		})
	if err != nil {
		// A merge that validated on its own but not against the row as locked.
		// The caller asked for something reasonable, so this is a 400 with the
		// reason rather than a 500: reissuing the request usually succeeds,
		// since it will then merge against the row the other write left.
		var invalid *ErrInvalidMergedRule
		if errors.As(err, &invalid) {
			return response.Error(http.StatusBadRequest, invalid.Reason, nil)
		}
		return response.Error(http.StatusInternalServerError, "failed to upsert rule", err)
	}

	s.logger.Info("dsratelimit rule upserted",
		"actor", c.Login, "actor_id", actorID,
		"kind", kind, "target", target,
		"before", ruleDigest(before), "after", ruleDigest(written))

	if err := s.reloadRules(c.Req.Context()); err != nil {
		s.logger.Error("post-upsert reload failed; next 30s tick will retry", "err", err)
	}
	return response.JSON(http.StatusOK, written)
}

// AdminDelete handles DELETE /api/admin/datasource-rate-limits/:kind/:target.
func (s *Service) AdminDelete(c *contextmodel.ReqContext) response.Response {
	if r := s.notWired(); r != nil {
		return r
	}
	kind := web.Params(c.Req)[":kind"]
	target := web.Params(c.Req)[":target"]
	if kind == "" || target == "" {
		return response.Error(http.StatusBadRequest, "kind and target are required", nil)
	}
	// Do not delete a rule when its audit pre-image could not be read.
	before, err := s.store.get(c.Req.Context(), kind, target)
	if err != nil {
		return response.Error(http.StatusInternalServerError, "failed to read the existing rule", err)
	}
	if err := s.store.delete(c.Req.Context(), kind, target); err != nil {
		return response.Error(http.StatusInternalServerError, "failed to delete rule", err)
	}
	s.logger.Info("dsratelimit rule deleted",
		"actor", c.Login, "actor_id", c.UserID,
		"kind", kind, "target", target,
		"before", ruleDigest(before))
	if err := s.reloadRules(c.Req.Context()); err != nil {
		s.logger.Error("post-delete reload failed; next 30s tick will retry", "err", err)
	}
	return response.JSON(http.StatusOK, map[string]any{"deleted": true})
}

// AdminStats handles GET /api/admin/datasource-rate-limits/stats.
// Returns live datasource quota levels plus active-key count. Prometheus counters
// (attempted/allowed/denied) are exposed on /metrics; this endpoint is for
// quick human introspection during triage.
func (s *Service) AdminStats(c *contextmodel.ReqContext) response.Response {
	if r := s.notWired(); r != nil {
		return r
	}
	now := time.Now()
	snap := s.rulesPtr.Load()
	defRate, defBurst := s.defaultParams(snap)
	defSource := "ini"
	if snap != nil && snap.defaults != nil {
		defSource = "db"
	}
	shadowSource := "ini"
	if snap != nil && snap.shadow != nil {
		shadowSource = "db"
	}
	// The baseline in-flight cap and where it came from. Resolved through the
	// same function the middleware uses, with a key that matches no rule, so
	// what is reported is what an identity without its own override receives.
	concLimit := s.concurrencyLimit(snap, "")
	concSource := "ini"
	if snap != nil && snap.defaultConcurrency != nil {
		concSource = "db"
	}
	concShadow := s.concurrencyShadowMode(snap)
	concShadowSource := "ini"
	if snap != nil && snap.concurrencyShadow != nil {
		concShadowSource = "db"
	}
	return response.JSON(http.StatusOK, map[string]any{
		"datasources": s.datasourceStatusSnapshot(now),
		"active_keys": s.userCount.Load(),
		"shadow_mode": s.shadowMode(snap),
		"enabled":     s.activeQPS(snap),
		// Whether requests are actually being rejected right now. shadow_mode
		// alone does not answer that -- enabled=false also means "not
		// enforcing" -- and with both now readable from two sources, an
		// operator needs one field that is simply the truth.
		"enforcing": s.enforcing(snap),
		// The in-flight cap, reported separately because it is a separate
		// rollout: it can be observing while the QPS layer enforces, and
		// "enforcing" above answers only for QPS.
		//
		// concurrency_enforcing is the field that matters operationally. The
		// cap can be silently doing nothing for three different reasons --
		// the service is off, the cap is off, or no limit has been set -- and
		// an operator who has just switched something on needs one field that
		// says whether requests are being rejected, not three they have to
		// combine correctly.
		"concurrency": map[string]any{
			"enabled":            s.activeConcurrency(snap),
			"shadow_mode":        concShadow,
			"shadow_mode_source": concShadowSource,
			// The limit actually in force for an identity with no rule of its
			// own, and which source won. Reporting s.cfg here would have been
			// wrong from the moment the DB override landed: an operator who
			// raises the default at runtime would still see the ini number and
			// conclude the change did not apply.
			"limit":        concLimit,
			"limit_source": concSource,
			"enforcing":    s.concurrencyEnforcing(snap, concLimit),
			// Counting is what the observation week depends on, and it needs
			// less than enforcing does: a limit of zero still records.
			"recording": s.activeConcurrency(snap),
		},
		"sources": map[string]any{
			"shadow_mode": shadowSource,
		},
		// What an identity without its own rule actually gets right now, and
		// which of the two sources won. Without this an operator who raises the
		// default has no way to tell the change landed short of provoking a
		// rejection.
		"defaults": map[string]any{
			"rate":   defRate,
			"burst":  defBurst,
			"source": defSource,
		},
	})
}

// datasourceStatusSnapshot reports the live state of every configured
// datasource quota: its limit and how much of it is left right now.
//
// Includes quotas that have no bucket yet (nothing has queried that datasource
// since the last reload) so a freshly configured quota is visible immediately
// rather than looking unapplied. Those report full burst, which is true.
func (s *Service) datasourceStatusSnapshot(now time.Time) map[string]any {
	out := map[string]any{}
	snap := s.rulesPtr.Load()
	for target, lp := range snap.dsQuota {
		source := "ini"
		if snap.dsFromDB[target] {
			source = "db"
		}
		// float64 for rate/tokens in both branches: the live branch below reads
		// them off the limiter as floats, and a field whose Go type depends on
		// whether a bucket happens to exist yet is a trap for any consumer that
		// type-asserts.
		entry := map[string]any{
			"rate":   float64(lp.rate),
			"burst":  lp.burst,
			"tokens": float64(lp.burst),
			"source": source,
		}
		if v, ok := s.dsBuckets.Load(target); ok {
			lim := v.(*rate.Limiter)
			entry["rate"] = float64(lim.Limit())
			entry["burst"] = lim.Burst()
			entry["tokens"] = lim.TokensAt(now)
		}
		out[target] = entry
	}
	return out
}

// ruleDigest formats a Rule for audit logs. Returns "<none>" for nil.
func ruleDigest(r *Rule) string {
	if r == nil {
		return "<none>"
	}
	rt := "-"
	if r.Rate != nil {
		rt = strconv.FormatInt(*r.Rate, 10)
	}
	b := "-"
	if r.Burst != nil {
		b = strconv.FormatInt(*r.Burst, 10)
	}
	return fmt.Sprintf("%s{rate=%s,burst=%s}", r.Mode, rt, b)
}

// validateTarget rejects a target that could never match a live request,
// returning "" when the target is acceptable.
//
// Identity rules are looked up by the key rateLimitKey builds, which is always
// "<kind>:<numeric id>" -- so a rule written for user/john.doe is stored
// happily, listed back happily, and never matches anything. That is the worst
// possible failure for this endpoint: the operator walks away believing an
// exemption or a block is in place. This is the same class of bug the kind
// check above already guards, and target is the field far more likely to be
// typed by hand.
//
// Only the shape is checked. Whether user 77 exists is deliberately not
// verified: that would need a DB lookup on an admin path for no real benefit,
// and pre-creating a rule for a user who has not logged in yet is legitimate.
func validateTarget(kind Kind, target string) string {
	switch kind {
	case KindUser, KindSA, KindApiKey:
		// Must be byte-identical to what rateLimitKey emits, which is
		// strconv.FormatInt. Parsing alone is too lax: ParseInt accepts "+77"
		// and "077", neither of which FormatInt ever produces, so both would be
		// stored and then never match. Round-tripping is the only check that
		// says exactly what is meant -- "this is the canonical form".
		id, err := strconv.ParseInt(target, 10, 64)
		if err != nil || id <= 0 || strconv.FormatInt(id, 10) != target {
			return fmt.Sprintf(
				"target for kind=%s must be the numeric ID (e.g. %s/77), not a "+
					"login or name: rules are matched against %q, so %q would "+
					"be saved but never take effect",
				kind, kind, string(kind)+":<id>", target)
		}
	case KindAnon:
		// All anonymous traffic shares the single key "anon:anon".
		if target != string(KindAnon) {
			return fmt.Sprintf(
				"target for kind=anon must be %q (all anonymous traffic shares "+
					"one bucket); %q would be saved but never take effect",
				string(KindAnon), target)
		}
	case KindDatasource:
		// A UID is opaque client-supplied text, so only length is bounded --
		// the column is VARCHAR(64) and a longer value would be truncated on
		// write, silently producing a rule for a different UID than requested.
		if len(target) > maxTargetLen {
			return fmt.Sprintf(
				"target must be at most %d characters (datasource UIDs are at "+
					"most 40); got %d", maxTargetLen, len(target))
		}
	case KindDefault:
		// One row means "the deployment-wide default". Any other target would
		// be stored and then never consulted, which is the same class of bug
		// as the old kind=lane rows.
		if target != DefaultTarget {
			return fmt.Sprintf(
				"target for kind=default must be %q (there is one deployment-wide "+
					"default); %q would be saved but never take effect",
				DefaultTarget, target)
		}
	case KindEnforcement, KindConcurrencyEnforcement, KindActivation, KindConcurrencyActivation:
		// All four are deployment-wide switches, same as the ini keys they
		// override, so exactly one row of each may exist.
		//
		// The activation kinds need this as much as the enforcement ones, and
		// for a sharper reason: reloadRules keys these off r.Kind and ignores
		// r.Target, so a row stored under a mistyped target is not inert -- it
		// is applied deployment-wide. Two rows disagreeing would then resolve
		// by whichever store.list happened to return last, since it does no
		// ordering. Rejecting the write is what keeps "one switch" true.
		if target != DefaultTarget {
			return fmt.Sprintf(
				"target for kind=%s must be %q (this switch is deployment-wide); "+
					"%q would be stored as a second, conflicting switch row",
				kind, DefaultTarget, target)
		}
	default:
		// KindLane only. It is still in validKinds so an old caller gets a 400
		// naming the replacement (AdminPut rejects it before reaching here)
		// rather than a silent accept; there is no target shape to check.
	}
	return ""
}
