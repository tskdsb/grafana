package dsratelimit

import (
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
type UpsertBody struct {
	Mode  string `json:"mode"`
	Rate  *int64 `json:"rate,omitempty"`
	Burst *int64 `json:"burst,omitempty"`
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
// Returns every rule plus a snapshot of each lane's current config.
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
	// Enforcement carries its decision in Mode alone: limited = enforce,
	// unlimited = observe. It takes no rate/burst, so it must be handled before
	// the mode=limited branch below, which requires them.
	if Kind(kind) == KindEnforcement {
		switch Mode(body.Mode) {
		case ModeLimited, ModeUnlimited:
		default:
			return response.Error(http.StatusBadRequest,
				"enforcement rules accept mode=limited (enforce) or "+
					"mode=unlimited (observe only)", nil)
		}
		if body.Rate != nil || body.Burst != nil {
			return response.Error(http.StatusBadRequest,
				"enforcement rules take no rate/burst; they switch enforcement on "+
					"or off. Use kind=default to change the baseline limit", nil)
		}
	} else if Mode(body.Mode) == ModeLimited {
		if body.Rate == nil || body.Burst == nil {
			return response.Error(http.StatusBadRequest,
				"rate and burst are required when mode=limited", nil)
		}
		// Non-positive or oversized values are rejected at the only write
		// entry point. x/time/rate does NOT panic on them (v0.2.0 has no
		// panic path) — it silently denies forever, which is far harder to
		// diagnose. See sanitizeParams in ratelimit.go.
		if *body.Rate <= 0 || *body.Burst <= 0 {
			return response.Error(http.StatusBadRequest,
				"rate and burst must be positive when mode=limited", nil)
		}
		if *body.Rate > MaxRuleRate || *body.Burst > MaxRuleBurst {
			return response.Error(http.StatusBadRequest, fmt.Sprintf(
				"rate must be <= %d and burst must be <= %d", MaxRuleRate, MaxRuleBurst), nil)
		}
		if *body.Burst < *body.Rate {
			return response.Error(http.StatusBadRequest,
				"burst must be >= rate, otherwise a single burst of traffic can never be admitted", nil)
		}
	}

	before, _ := s.store.get(c.Req.Context(), kind, target)
	actorID := c.UserID

	r := &Rule{
		Kind:      kind,
		Target:    target,
		Mode:      body.Mode,
		Rate:      body.Rate,
		Burst:     body.Burst,
		UpdatedBy: &actorID,
	}
	if err := s.store.upsert(c.Req.Context(), r); err != nil {
		return response.Error(http.StatusInternalServerError, "failed to upsert rule", err)
	}

	s.logger.Info("dsratelimit rule upserted",
		"actor", c.Login, "actor_id", actorID,
		"kind", kind, "target", target,
		"before", ruleDigest(before), "after", ruleDigest(r))

	if err := s.reloadRules(c.Req.Context()); err != nil {
		s.logger.Error("post-upsert reload failed; next 30s tick will retry", "err", err)
	}
	return response.JSON(http.StatusOK, r)
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
	before, _ := s.store.get(c.Req.Context(), kind, target)
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
// Returns live lane token levels plus active-key count. Prometheus counters
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
	return response.JSON(http.StatusOK, map[string]any{
		"datasources": s.datasourceStatusSnapshot(now),
		"active_keys": s.userCount.Load(),
		"shadow_mode": s.shadowMode(snap),
		"enabled":     s.cfg.Enabled,
		// Whether requests are actually being rejected right now. shadow_mode
		// alone does not answer that -- enabled=false also means "not
		// enforcing" -- and with both now readable from two sources, an
		// operator needs one field that is simply the truth.
		"enforcing": s.enforcing(snap),
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
	case KindEnforcement:
		// Enforcement is deployment-wide, same as the shadow_mode setting it
		// overrides.
		if target != DefaultTarget {
			return fmt.Sprintf(
				"target for kind=enforcement must be %q (enforcement is "+
					"deployment-wide); %q would be saved but never take effect",
				DefaultTarget, target)
		}
	default:
		// KindLane only. It is still in validKinds so an old caller gets a 400
		// naming the replacement (AdminPut rejects it before reaching here)
		// rather than a silent accept; there is no target shape to check.
	}
	return ""
}
