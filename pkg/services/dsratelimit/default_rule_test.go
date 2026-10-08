package dsratelimit

import (
	"context"
	"net/http"
	"testing"

	"github.com/grafana/grafana/pkg/services/user"
	"github.com/stretchr/testify/require"
)

// defaultRule is shorthand for the deployment-wide default override.
func defaultRule(rateVal, burstVal int64) *Rule {
	return &Rule{
		Kind: string(KindDefault), Target: DefaultTarget,
		Mode: string(ModeLimited), Rate: &rateVal, Burst: &burstVal,
	}
}

// The point of kind=default is that raising the baseline does not need an ini
// edit and a restart. If the DB row did not win over cfg, the whole feature
// would be decoration.
func TestDefaultRule_OverridesIniBaseline(t *testing.T) {
	cfg := defaultCfg() // rate 30, burst 100
	s := newTestService(cfg, defaultRule(7, 21))

	r := s.resolveRule("user:1")
	require.NotNil(t, r.Rate)
	require.NotNil(t, r.Burst)
	require.EqualValues(t, 7, *r.Rate, "DB default must win over ini default_user_rate")
	require.EqualValues(t, 21, *r.Burst, "DB default must win over ini default_user_burst")
}

// Deleting the row has to restore the deployed value. Anything else would make
// a temporary bump permanent, which is how the old lane rules went wrong.
func TestDefaultRule_AbsenceFallsBackToIni(t *testing.T) {
	cfg := defaultCfg()
	s := newTestService(cfg) // no rules at all

	r := s.resolveRule("user:1")
	require.EqualValues(t, cfg.DefaultUserRate, *r.Rate)
	require.EqualValues(t, cfg.DefaultUserBurst, *r.Burst)
}

// A per-identity rule is more specific than the deployment default, so it must
// still win. Otherwise raising the default would silently flatten every
// individual exception an operator had configured.
func TestDefaultRule_PerIdentityRuleStillWins(t *testing.T) {
	var idRate, idBurst int64 = 3, 9
	idRule := &Rule{
		Kind: string(KindUser), Target: "1",
		Mode: string(ModeLimited), Rate: &idRate, Burst: &idBurst,
	}
	s := newTestService(defaultCfg(), defaultRule(7, 21), idRule)

	own := s.resolveRule("user:1")
	require.EqualValues(t, 3, *own.Rate, "identity rule must beat the default rule")
	require.EqualValues(t, 9, *own.Burst)

	other := s.resolveRule("user:2")
	require.EqualValues(t, 7, *other.Rate, "an identity without its own rule gets the default rule")
}

// Anonymous traffic is blocked by default and that decision is independent of
// the baseline numbers. A default rule must not accidentally un-block it.
func TestDefaultRule_DoesNotUnblockAnonymous(t *testing.T) {
	s := newTestService(defaultCfg(), defaultRule(7, 21))

	r := s.resolveRule("anon:anon")
	require.Equal(t, string(ModeBlocked), r.Mode,
		"a default rate/burst must not turn anonymous traffic into limited traffic")
}

// Buckets already in memory must pick up the new baseline. getUserEntry
// re-applies the rule on every call, so this asserts that the value it
// re-applies comes from the snapshot and not from a captured cfg.
func TestDefaultRule_ExistingBucketFollowsTheChange(t *testing.T) {
	cfg := defaultCfg()
	s := newTestService(cfg)

	// Create the bucket under the ini baseline.
	e := s.getUserEntry("user:1", s.resolveRule("user:1"))
	require.EqualValues(t, cfg.DefaultUserRate, int(e.limiter.Limit()))

	// Land a new snapshot carrying a DB default, as a reload would.
	snap := s.rulesPtr.Load()
	lp, ok := sanitizeParams(7, 21, DefaultMaxRuleRate, DefaultMaxRuleBurst)
	require.True(t, ok)
	newSnap := &rulesSnapshot{
		byKey:    snap.byKey,
		dsQuota:  snap.dsQuota,
		dsFromDB: snap.dsFromDB,
		defaults: &lp,
	}
	s.rulesPtr.Store(newSnap)

	e2 := s.getUserEntry("user:1", s.resolveRule("user:1"))
	require.Same(t, e, e2, "same key must reuse the same entry")
	require.EqualValues(t, 7, int(e2.limiter.Limit()),
		"an existing bucket must follow the new default without waiting for eviction")
	require.EqualValues(t, 21, e2.limiter.Burst())
}

// An unusable row must leave the ini baseline in force. Applying rate<=0 would
// deny every request from every identity without its own rule -- the widest
// blast radius in this package, and silent because x/time/rate never refills
// rather than panicking.
//
// Goes through the real reloadRules rather than newTestService: the guard being
// asserted lives there, so a shortcut that pre-builds the snapshot would test
// nothing.
func TestIntegrationDefaultRule_InvalidRowKeepsBaseline(t *testing.T) {
	s := newAdminTestService(t)
	cfg := s.cfg

	// Write directly through the store; AdminPut would (correctly) reject this.
	require.NoError(t, s.store.upsert(context.Background(), &Rule{
		Kind: string(KindDefault), Target: DefaultTarget,
		Mode: string(ModeLimited), Rate: ptr64(0), Burst: ptr64(10),
	}))
	require.NoError(t, s.reloadRules(context.Background()))

	r := s.resolveRule("user:1")
	require.EqualValues(t, cfg.DefaultUserRate, *r.Rate,
		"rate=0 must be ignored, not applied")
	require.EqualValues(t, cfg.DefaultUserBurst, *r.Burst)
}

// A row with no rate/burst pair is equally unusable: there is nothing to apply.
func TestIntegrationDefaultRule_ModeWithoutParamsKeepsBaseline(t *testing.T) {
	s := newAdminTestService(t)
	cfg := s.cfg

	require.NoError(t, s.store.upsert(context.Background(), &Rule{
		Kind: string(KindDefault), Target: DefaultTarget,
		Mode: string(ModeBlocked),
	}))
	require.NoError(t, s.reloadRules(context.Background()))

	r := s.resolveRule("user:1")
	require.EqualValues(t, cfg.DefaultUserRate, *r.Rate)
	require.Equal(t, string(ModeLimited), r.Mode,
		"a blocked default row must not be honoured; it would lock out everyone")
}

// The write side must reject a target other than "default": one row means the
// deployment-wide baseline, so any other target would be stored and then never
// consulted.
func TestDefaultRule_RejectsOtherTargets(t *testing.T) {
	require.Empty(t, validateTarget(KindDefault, DefaultTarget),
		"target=default must be accepted")

	for _, bad := range []string{"1", "all", "user", ""} {
		require.NotEmpty(t, validateTarget(KindDefault, bad),
			"target %q must be rejected for kind=default", bad)
	}
}

func ptr64(v int64) *int64 { return &v }

// enforcementRule is shorthand for the deployment-wide enforcement switch.
// mode=limited means enforce, mode=unlimited means observe only.
func enforcementRule(enforce bool) *Rule {
	m := ModeUnlimited
	if enforce {
		m = ModeLimited
	}
	return &Rule{
		Kind: string(KindEnforcement), Target: DefaultTarget, Mode: string(m),
	}
}

// The rollout step: ini ships shadow_mode=true, and a DB row must be able to
// turn enforcement on without a restart.
func TestEnforcementRule_TurnsEnforcementOn(t *testing.T) {
	cfg := defaultCfg()
	cfg.ShadowMode = true
	s := newTestService(cfg, enforcementRule(true))

	require.False(t, s.shadowMode(s.rulesPtr.Load()),
		"a DB enforcement row must override ini shadow_mode=true")
	require.True(t, s.enforcing(s.rulesPtr.Load()))
}

// The rollback step, which matters more: if enforcement turns out to hurt, going
// back must not need a restart either.
func TestEnforcementRule_TurnsEnforcementOff(t *testing.T) {
	cfg := defaultCfg()
	cfg.ShadowMode = false // deployed as enforcing
	s := newTestService(cfg, enforcementRule(false))

	require.True(t, s.shadowMode(s.rulesPtr.Load()),
		"a DB row must be able to put an enforcing deployment back into observation")
	require.False(t, s.enforcing(s.rulesPtr.Load()))
}

// Deleting the row restores whatever was deployed, in both directions.
func TestEnforcementRule_AbsenceFallsBackToIni(t *testing.T) {
	for _, iniShadow := range []bool{true, false} {
		cfg := defaultCfg()
		cfg.ShadowMode = iniShadow
		s := newTestService(cfg)
		require.Equal(t, iniShadow, s.shadowMode(s.rulesPtr.Load()))
	}
}

// enabled=false is a bigger hammer than shadow mode and is deliberately NOT
// overridable: Run() returns early when disabled, so there is no reload loop to
// notice a DB row. Enforcement must never appear to be on in that state.
func TestEnforcementRule_CannotOverrideDisabled(t *testing.T) {
	cfg := defaultCfg()
	cfg.Enabled = false
	s := newTestService(cfg, enforcementRule(true))

	require.False(t, s.enforcing(s.rulesPtr.Load()),
		"enabled=false must win over any enforcement row; with no reload loop "+
			"running, a row that looked effective would be a lie")
}

// A row whose mode means neither "enforce" nor "observe" must be ignored, not
// guessed at: this flag decides whether real traffic gets rejected.
func TestIntegrationEnforcementRule_UnusableModeKeepsIni(t *testing.T) {
	s := newAdminTestService(t)
	s.cfg.ShadowMode = true

	require.NoError(t, s.store.upsert(context.Background(), &Rule{
		Kind: string(KindEnforcement), Target: DefaultTarget,
		Mode: string(ModeBlocked),
	}))
	require.NoError(t, s.reloadRules(context.Background()))

	require.True(t, s.shadowMode(s.rulesPtr.Load()),
		"mode=blocked is not a valid enforcement decision; the ini value must stand")
}

// Both directions must survive a real reload, not just a hand-built snapshot.
func TestIntegrationEnforcementRule_RoundTripsThroughReload(t *testing.T) {
	s := newAdminTestService(t)
	s.cfg.ShadowMode = true
	ctx := context.Background()

	require.NoError(t, s.store.upsert(ctx, enforcementRule(true)))
	require.NoError(t, s.reloadRules(ctx))
	require.False(t, s.shadowMode(s.rulesPtr.Load()), "enforcement should be on")

	require.NoError(t, s.store.delete(ctx, string(KindEnforcement), DefaultTarget))
	require.NoError(t, s.reloadRules(ctx))
	require.True(t, s.shadowMode(s.rulesPtr.Load()),
		"deleting the row must restore the deployed shadow_mode")
}

// The write side must reject a target other than "default", same reason as
// kind=default: enforcement is deployment-wide.
func TestEnforcementRule_RejectsOtherTargets(t *testing.T) {
	require.Empty(t, validateTarget(KindEnforcement, DefaultTarget))
	for _, bad := range []string{"1", "all", ""} {
		require.NotEmpty(t, validateTarget(KindEnforcement, bad),
			"target %q must be rejected for kind=enforcement", bad)
	}
}

// End to end through Middleware, not just resolveRule: the value being
// resolved is only useful if it changes what a real request gets.
func TestEndToEnd_DefaultRuleAffectsRealRequests(t *testing.T) {
	cfg := defaultCfg()
	cfg.ShadowMode = false // 真拦截
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 2, 2

	// 无 DB 覆盖：第 3 个请求该被拒
	s := newTestService(cfg)
	u := &user.SignedInUser{UserID: 1}
	body := []byte(`{"queries":[{}]}`)
	codes := []int{}
	for i := 0; i < 4; i++ {
		c, rec := buildCtx("POST", "/api/ds/query", body, u)
		s.Middleware(c)
		codes = append(codes, rec.Code)
	}
	require.Equal(t, []int{200, 200, 429, 429}, codes,
		"ini baseline rate=2 burst=2 should admit 2 then reject")

	// 有 DB 覆盖 rate=10 burst=10：4 个请求全过
	s2 := newTestService(cfg, defaultRule(10, 10))
	codes2 := []int{}
	for i := 0; i < 4; i++ {
		c, rec := buildCtx("POST", "/api/ds/query", body, u)
		s2.Middleware(c)
		codes2 = append(codes2, rec.Code)
	}
	require.Equal(t, []int{200, 200, 200, 200}, codes2,
		"DB default rate=10 must actually admit requests the ini value would reject")
}

// The rollout switch, end to end: shadow mode must never reject, and a DB
// enforcement row must make the same traffic get 429.
func TestEndToEnd_EnforcementRuleAffectsRealRequests(t *testing.T) {
	cfg := defaultCfg()
	cfg.ShadowMode = true // ini 是影子模式
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 1, 1

	u := &user.SignedInUser{UserID: 1}
	body := []byte(`{"queries":[{}]}`)

	// 影子：超限也放行
	s := newTestService(cfg)
	for i := 0; i < 3; i++ {
		c, rec := buildCtx("POST", "/api/ds/query", body, u)
		s.Middleware(c)
		require.Equal(t, http.StatusOK, rec.Code, "shadow mode must never reject")
	}

	// DB 开启拦截：超限真拒
	s2 := newTestService(cfg, enforcementRule(true))
	c1, rec1 := buildCtx("POST", "/api/ds/query", body, u)
	s2.Middleware(c1)
	require.Equal(t, http.StatusOK, rec1.Code, "first request within burst")
	c2, rec2 := buildCtx("POST", "/api/ds/query", body, u)
	s2.Middleware(c2)
	require.Equal(t, http.StatusTooManyRequests, rec2.Code,
		"a DB enforcement row must make the limiter actually reject")
}
