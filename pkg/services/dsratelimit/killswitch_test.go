package dsratelimit

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/user"
)

// The two settings in this file are the safety valves for the whole feature:
// `enabled` decides whether the limiter runs at all, and `shadow_mode` decides
// whether it may reject real traffic. Everything else here is about limiting
// correctly; these two are about being able to NOT limit.
//
// They were previously unprotected. Verified by mutation: deleting the
// `!s.cfg.Enabled` early return, and deleting the `s.cfg.ShadowMode` early
// return so shadow mode rejects for real, both left dsratelimit + pkg/api +
// pkg/setting fully green. Either mistake reaches production silently, and the
// second one starts serving 429 to real users during what was supposed to be a
// measurement-only rollout.
//
// The assertions below are deliberately about the ONE observable that matters
// to a user -- whether the request was rejected -- rather than about internals,
// because that is the property the valve promises.

// overLimitService returns a service whose limits are low enough that traffic is
// guaranteed to exceed them, so "not rejected" can only mean a valve held.
func overLimitService(t *testing.T, enabled, shadow bool) *Service {
	t.Helper()
	cfg := defaultCfg()
	cfg.Enabled = enabled
	cfg.ShadowMode = shadow
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 1, 1
	s := &Service{cfg: cfg, logger: log.New("dsratelimit.test")}
	s.rulesPtr.Store(&rulesSnapshot{
		byKey:    map[string]*Rule{},
		dsQuota:  map[string]laneParams{},
		dsFromDB: map[string]bool{},
	})
	return s
}

// countRejections drives clearly over-limit traffic through the middleware and
// reports how much of it was rejected.
func countRejections(t *testing.T, s *Service, requests int) int {
	t.Helper()
	u := &user.SignedInUser{UserID: 7}
	body := []byte(`{"queries":[{"range":true,"datasource":{"uid":"PROM_MAIN"}},` +
		`{"instant":true,"datasource":{"uid":"PROM_MAIN"}}]}`)
	rejected := 0
	for i := 0; i < requests; i++ {
		c, rec := buildCtx("POST", dsQueryPath, body, u)
		s.Middleware(c)
		if rec.Code == http.StatusTooManyRequests {
			rejected++
		}
	}
	return rejected
}

// TestKillSwitch_DisabledRejectsNothing pins the global off switch.
//
// This is the setting an operator reaches for when the limiter itself is
// suspected of causing an incident. If it ever stops working, the escape hatch
// is gone at precisely the moment it is needed, and the only remaining option is
// a rollback.
func TestKillSwitch_DisabledRejectsNothing(t *testing.T) {
	// enabled=false, and shadow_mode=false too: `enabled` must stand on its own
	// rather than leaning on shadow mode to suppress rejections.
	s := overLimitService(t, false, false)

	require.Zero(t, countRejections(t, s, 50),
		"enabled=false must reject nothing even when traffic is far over the "+
			"limit: this is the switch used to disable the limiter during an "+
			"incident, so it cannot depend on shadow_mode also being set")

	// Nothing rejected is necessary but not sufficient. The switch is the only
	// way out during an incident, so what matters is that the main path did not
	// run at all -- a version that evaluated every rule and then declined to act
	// would pass the assertion above while still spending locks, allocations and
	// map growth on traffic it must not touch.
	//
	// Bucket count is the observable that separates those two: buckets are
	// allocated on the hot path, so zero buckets after 50 over-limit requests
	// means execution really did stop at the guard.
	buckets := 0
	s.userBuckets.Range(func(_, _ any) bool { buckets++; return true })
	require.Zero(t, buckets,
		"enabled=false allocated %d buckets, so the main path ran anyway; the "+
			"switch must return before doing any work, not merely suppress the "+
			"rejection at the end", buckets)
}

// TestKillSwitch_ShadowModeRejectsNothing pins the measure-but-do-not-enforce
// promise.
//
// The whole rollout plan rests on it: ship with shadow_mode=true, watch the
// metrics, and only then enforce. If shadow mode rejects, the "safe" first step
// is actually the risky one -- users get 429s during a window when nobody is
// expecting any behaviour change, and the signal being collected to justify
// enforcement is itself the outage.
func TestKillSwitch_ShadowModeRejectsNothing(t *testing.T) {
	s := overLimitService(t, true, true)

	rejected := countRejections(t, s, 50)
	require.Zero(t, rejected,
		"shadow_mode=true must account and log but never reject; got %d/50 "+
			"rejections. Shadow mode is the first rollout step, so a rejection "+
			"here is an outage during a window nobody is watching for one",
		rejected)
}

// TestKillSwitch_EnforcingActuallyRejects is the counterweight to the two tests
// above.
//
// Without it, both valve tests could be satisfied by a limiter that never
// rejects anything at all -- which would make them worse than no tests, since
// they would report safety while the feature quietly did nothing. This asserts
// the same traffic IS rejected once both valves are open, so the zeros above are
// attributable to the valves rather than to a broken limiter.
func TestKillSwitch_EnforcingActuallyRejects(t *testing.T) {
	s := overLimitService(t, true, false)

	rejected := countRejections(t, s, 50)
	require.NotZero(t, rejected,
		"with enabled=true and shadow_mode=false the same over-limit traffic "+
			"must be rejected; otherwise the two zero-rejection tests above "+
			"prove nothing about the valves")
	require.Greater(t, rejected, 40,
		"rate=1 burst=1 against 50 requests should reject nearly all of them, "+
			"got %d: a much lower number means the traffic was not actually "+
			"over the limit and the valve tests are vacuous", rejected)
}
