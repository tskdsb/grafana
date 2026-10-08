// Package dsratelimit provides per-user QPS rate limiting for Grafana's
// datasource query endpoints. See middleware.go for the request path
// document (motivation, layered token bucket, admin API, calibration plan).
package dsratelimit

import "time"

// Mode describes the semantics of a rule. It replaces v1's magic values
// (rate=0 for unlimited, rate=-1 for blocked) which collided with the
// x/time/rate.Limiter zero-limit trap (rate.go:345-356 permanently drains burst).
type Mode string

const (
	// ModeLimited charges the identity bucket. The default.
	ModeLimited Mode = "limited"
	// ModeUnlimited exempts an identity from ITS OWN bucket only. Datasource
	// quotas still apply: those bound what a backend can survive, which is not
	// the caller's to waive, and the exemption is handed to exactly the
	// high-volume accounts most able to flatten one.
	ModeUnlimited Mode = "unlimited"
	// ModeBlocked refuses outright. Also the default for anonymous traffic
	// (see resolveRule), not only a hand-configured setting.
	ModeBlocked Mode = "blocked"
)

// Kind is the class of a rate-limit rule.
//
// Two families, and the distinction is the whole design:
//
//   - IDENTITY kinds (user, sa, apikey, anon) answer "who is calling" and are
//     exactly the prefixes rateLimitKey() can produce. There is deliberately
//     no "org" kind: rateLimitKey never emits one, so a rule with kind=org
//     could never match anything.
//
//   - RESOURCE kind (datasource) answers "what is being called" and protects a
//     backend's own quota. target is the datasource UID.
//
// A request is charged against both: its caller's bucket and the bucket of
// every datasource it touches. The identity limit stops one user from
// monopolising Grafana; the datasource limit stops all users together from
// exceeding what a specific backend will tolerate. Neither substitutes for the
// other.
//
// kind=lane is accepted for backward compatibility only and no longer has any
// effect -- see LaneDefault.
type Kind string

const (
	KindUser       Kind = "user"
	KindSA         Kind = "sa"
	KindApiKey     Kind = "apikey"
	KindAnon       Kind = "anon"
	KindLane       Kind = "lane"
	KindDatasource Kind = "datasource"

	// KindDefault overrides default_user_rate / default_user_burst for every
	// identity that has no rule of its own. It exists so that raising the
	// baseline does not require an ini edit and a restart: restarting is the
	// one action an operator is least willing to take during the incident this
	// feature exists for.
	//
	// Its target is fixed at DefaultTarget. Unlike the other kinds this is not
	// a key rateLimitKey() can emit, so it is resolved separately (see
	// rulesSnapshot.defaults) rather than through byKey.
	KindDefault Kind = "default"

	// KindEnforcement overrides the ini shadow_mode. Going from observing to
	// enforcing is the rollout step, and going back is the rollback step;
	// requiring a restart for both meant the two moves an operator most wants to
	// make quickly were the two slowest.
	//
	// Uses Mode rather than a rate/burst pair: ModeLimited means enforce,
	// ModeUnlimited means observe only. Target is fixed at DefaultTarget --
	// enforcement is deployment-wide, like shadow_mode itself.
	KindEnforcement Kind = "enforcement"

	// KindConcurrencyEnforcement is KindEnforcement for the in-flight cap.
	//
	// A separate kind rather than a shared one because the two layers are
	// deliberately independent: the QPS layer may already be enforcing in
	// production while the in-flight cap is still being trialled, and one row
	// governing both would mean a concurrency trial can only run by standing
	// QPS enforcement down. Same reason concurrency_shadow_mode is its own ini
	// key.
	//
	// Same shape as KindEnforcement: ModeLimited enforces, ModeUnlimited
	// observes, target fixed at DefaultTarget.
	KindConcurrencyEnforcement Kind = "concurrency_enforcement"

	// KindActivation overrides the ini enabled flag -- the master switch that
	// decides whether the QPS layer runs at all.
	//
	// It is here for the same reason KindEnforcement is: every other knob in
	// this package became hot-reloadable, and leaving the two master switches
	// behind meant the one move that recovers from a bad rollout -- turning the
	// layer off outright -- was also the only one that cost a restart. On a
	// shared Grafana a restart is a minute of everyone's dashboards failing,
	// which is a poor price for an operation whose whole point is damage
	// control.
	//
	// ModeLimited means the layer runs, ModeUnlimited means it is bypassed
	// entirely (no accounting, no metrics, no rejection). Target is fixed at
	// DefaultTarget: activation is deployment-wide, like the ini key it
	// overrides.
	KindActivation Kind = "activation"

	// KindConcurrencyActivation is KindActivation for the in-flight layer.
	//
	// Separate for the reason the two enforcement kinds are separate: the two
	// layers are independently rolled out. Turning concurrency accounting on to
	// collect the per-identity distribution must not require touching the QPS
	// layer, and vice versa.
	//
	// ModeLimited means in-flight accounting runs, ModeUnlimited means it is
	// bypassed. Note that accounting running is not the same as rejecting:
	// whether an over-limit request is refused is still decided by
	// KindConcurrencyEnforcement and the configured cap.
	KindConcurrencyActivation Kind = "concurrency_activation"
)

// DefaultTarget is the only accepted target for KindDefault. A single row means
// "the deployment-wide default", so allowing arbitrary targets would create
// rows that silently never apply.
const DefaultTarget = "default"

// validKinds is the write-side whitelist for the admin API. Keep it in sync
// with rateLimitKey() in middleware.go — a kind that cannot be produced there
// can never be matched by resolveRule, so accepting it would only create
// rows that look effective but are not. KindDefault is the documented
// exception: it is matched by resolveRule's fallback path, not by byKey.
var validKinds = []Kind{KindUser, KindSA, KindApiKey, KindAnon, KindLane, KindDatasource, KindDefault, KindEnforcement, KindConcurrencyEnforcement, KindActivation, KindConcurrencyActivation}

// ValidKind reports whether k is an accepted rule kind.
func ValidKind(k string) bool {
	for _, v := range validKinds {
		if Kind(k) == v {
			return true
		}
	}
	return false
}

// ValidKinds returns the accepted kinds as strings, for error messages.
func ValidKinds() []string {
	out := make([]string, 0, len(validKinds))
	for _, v := range validKinds {
		out = append(out, string(v))
	}
	return out
}

// Fallback bounds for admin-supplied rate/burst/concurrency, used when the ini
// does not state one. The ceiling exists to keep a typo -- an extra digit, or a
// value that overflows int on 32-bit builds -- from turning into an effectively
// unlimited rule; use mode=unlimited for that intent instead.
//
// These are defaults, not the values in force: the effective bounds come from
// Config (see conf/defaults.ini), so a deployment can raise or lower them
// without a rebuild. They are sized to sit clear of any legitimate value rather
// than to be reachable -- the busiest identity observed runs two orders of
// magnitude below the rate bound, and an in-flight cap is a single- or
// double-digit number in practice.
const (
	DefaultMaxRuleRate  int64 = 1_000
	DefaultMaxRuleBurst int64 = 1_000

	// DefaultMaxRuleConcurrency is far lower than the QPS ceilings because it
	// counts requests held open simultaneously: anything near this bound is a
	// typo rather than a policy.
	DefaultMaxRuleConcurrency int64 = 100
)

// maxTargetLen matches the target column width in
// sqlstore/migrations/ds_ratelimit_mig.go. A longer value would be truncated on
// write, silently producing a rule for a different target than the one asked
// for. Datasource UIDs are at most 40 (datasource_mig.go:119), so this only
// bites on hand-written input.
const maxTargetLen = 64

// LaneDefault is the historical global-lane target.
//
// The global lane is GONE. It was a single bucket shared by every datasource,
// sized from one specific Prometheus instance's 500 QPS quota -- which made it
// wrong in both directions: it could not protect that instance (traffic had to
// exceed the global limit before the per-instance quota was defended at all),
// and it let unrelated backends starve each other, since a MySQL report refresh
// consumed the same tokens as a Prometheus query. Quotas are granted per
// datasource instance, so the bucket has to be per datasource instance.
//
// The name and the DB column survive only so existing rows and admin calls do
// not error out; kind=lane rules are accepted and ignored. Use
// kind=datasource with the UID instead.
const (
	LaneDefault = "default"

	// dsLabelNone fills the `datasource` label on request-level metrics when a
	// decision is not attributable to one backend -- an identity denial, or any
	// allowed request, which may have touched several. Per-datasource load is
	// reported separately by datasource_tokens_total.
	dsLabelNone = "none"
)

// Rule is one row in the datasource_rate_limit table.
// Rate/Burst are only meaningful when Mode == ModeLimited;
// Unlimited and Blocked take the fast path in the middleware without
// ever constructing a rate.Limiter.
type Rule struct {
	Id     int64
	Kind   string
	Target string
	Mode   string
	Rate   *int64
	Burst  *int64
	// Concurrency is the in-flight cap for this identity. Nil means no
	// override: the caller falls back to the default rule, then to the ini
	// value, then to no cap at all.
	//
	// Separate from Rate/Burst rather than folded into them because the two
	// layers answer different questions -- how often may this identity ask,
	// versus how many may be open at once -- and an operator setting one
	// should not be forced to restate the other.
	Concurrency *int64
	UpdatedBy   *int64
	Created     time.Time
	Updated     time.Time
}

// TableName tells xorm the table for this struct.
func (Rule) TableName() string { return "datasource_rate_limit" }
