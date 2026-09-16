package dsratelimit

import (
	"context"
	"strings"
	"testing"

	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/services/user"

	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/setting"
)

// TestSanitizeParams covers the write- and read-side numeric guard.
//
// Motivation: x/time/rate v0.2.0 has NO panic path (grep "panic" in rate.go
// returns nothing). A negative or zero burst yields a limiter that denies
// every request forever — tokens sit at -1 and never refill — so the failure
// mode is a silent permanent 429, not a crash. These cases lock the guard
// that keeps such values from ever reaching rate.NewLimiter.
func TestSanitizeParams(t *testing.T) {
	cases := []struct {
		name      string
		rate      int64
		burst     int64
		wantOK    bool
		wantRate  int
		wantBurst int
	}{
		{"typical", 30, 100, true, 30, 100},
		{"rate equals burst", 50, 50, true, 50, 50},
		{"at the ceiling", MaxRuleRate, MaxRuleBurst, true, int(MaxRuleRate), int(MaxRuleBurst)},
		{"zero rate", 0, 100, false, 0, 0},
		{"zero burst", 30, 0, false, 0, 0},
		{"both zero", 0, 0, false, 0, 0},
		{"negative rate", -5, 100, false, 0, 0},
		{"negative burst", 30, -1, false, 0, 0},
		{"both negative", -5, -1, false, 0, 0},
		{"rate above ceiling", MaxRuleRate + 1, 100, false, 0, 0},
		{"burst above ceiling", 30, MaxRuleBurst + 1, false, 0, 0},
		{"int64 max", 1 << 62, 1 << 62, false, 0, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := sanitizeParams(tc.rate, tc.burst)
			require.Equal(t, tc.wantOK, ok,
				"sanitizeParams(%d, %d) ok mismatch", tc.rate, tc.burst)
			if !tc.wantOK {
				return
			}
			require.Equal(t, tc.wantRate, got.rate)
			require.Equal(t, tc.wantBurst, got.burst)
		})
	}
}

// TestSanitizeParams_RejectedValuesWouldDenyForever documents *why* the
// rejected values must be rejected, by showing what a limiter built from
// them actually does. This is the observable behavior the guard prevents;
// asserting it here means a future relaxation of sanitizeParams cannot
// quietly reintroduce the permanent-deny bug.
func TestSanitizeParams_RejectedValuesWouldDenyForever(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rate  rate.Limit
		burst int
	}{
		{"negative burst", 30, -1},
		{"zero burst", 30, 0},
		{"negative rate", -5, 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lim := rate.NewLimiter(tc.rate, tc.burst)
			// No panic (that is the trap: it looks fine at construction).
			require.False(t, lim.Allow(),
				"expected the very first request to be denied")
			// And it never recovers, so the key is bricked until restart.
			require.False(t, lim.Allow(), "still denied on retry")

			_, ok := sanitizeParams(int64(tc.rate), int64(tc.burst))
			require.False(t, ok, "sanitizeParams must reject this pair")
		})
	}
}

// TestGetUserLimiter_InvalidRuleFallsBackToDefaults locks the read-side
// behavior: a bad row already in the DB (predating admin validation, or
// written by a direct SQL edit) must not brick the key. It should fall back
// to the configured defaults and be observable via a log + metric.
func TestGetUserLimiter_InvalidRuleFallsBackToDefaults(t *testing.T) {
	cfg := defaultCfg()
	s := newTestService(cfg)

	for _, tc := range []struct {
		name        string
		rate, burst int64
	}{
		{"negative burst", 30, -1},
		{"zero rate", 0, 100},
		{"negative both", -1, -1},
		{"above ceiling", MaxRuleRate + 1, MaxRuleBurst + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, b := tc.rate, tc.burst
			rule := &Rule{
				Kind: string(KindSA), Target: "7",
				Mode: string(ModeLimited), Rate: &r, Burst: &b,
			}
			lim := s.getUserLimiter("sa:7:"+tc.name, rule)

			require.Equal(t, rate.Limit(cfg.DefaultUserRate), lim.Limit(),
				"invalid rate must fall back to the configured default")
			require.Equal(t, cfg.DefaultUserBurst, lim.Burst(),
				"invalid burst must fall back to the configured default")
			// The key must still be usable — this is the whole point.
			require.True(t, lim.Allow(),
				"a key with a corrupt rule must still serve traffic, not be bricked")
		})
	}
}

// TestGetUserLimiter_ValidRuleIsApplied is the negative control for the test
// above: the fallback must not swallow legitimate values.
func TestGetUserLimiter_ValidRuleIsApplied(t *testing.T) {
	s := newTestService(defaultCfg())
	r, b := int64(7), int64(9)
	rule := &Rule{
		Kind: string(KindSA), Target: "8",
		Mode: string(ModeLimited), Rate: &r, Burst: &b,
	}
	lim := s.getUserLimiter("sa:8", rule)
	require.Equal(t, rate.Limit(7), lim.Limit())
	require.Equal(t, 9, lim.Burst())
}

// TestValidKind locks the admin-API kind whitelist against rateLimitKey's
// actual output. A kind that rateLimitKey can never emit would produce a
// row that resolveRule never matches — an "effective-looking" no-op.
func TestValidKind(t *testing.T) {
	// Every kind rateLimitKey can produce must be writable.
	for _, k := range []string{"user", "sa", "apikey", "anon"} {
		require.True(t, ValidKind(k), "%q is produced by rateLimitKey and must be accepted", k)
	}
	// Plus the lane override row.
	require.True(t, ValidKind("lane"))

	// Rejected: typos, the removed "org" kind, and empty.
	for _, k := range []string{"org", "lain", "Lane", "SA", "", "user ", "lane/default"} {
		require.False(t, ValidKind(k), "%q must be rejected", k)
	}
}

// TestValidKinds_MatchesWhitelist keeps the error-message helper in sync with
// the whitelist it describes.
func TestValidKinds_MatchesWhitelist(t *testing.T) {
	got := ValidKinds()
	require.Len(t, got, len(validKinds))
	for i, k := range validKinds {
		require.Equal(t, string(k), got[i])
	}
}

// TestConfigFallbacks_GuardBadIniValues covers the gap between setting.MustInt
// and rate.NewLimiter.
//
// MustInt only substitutes a fallback when a key is missing or unparseable, so
// an explicit `default_user_rate = -5` reaches the service verbatim. Verified
// against pkg/setting: rate=0 / burst=0 / rate=-5 / burst=-1 all survive
// readDsRateLimitSettings unchanged, and x/time/rate does not reject them
// either -- it accepts them and then denies every request forever without
// recovering (v0.2.0 has no panic path).
func TestConfigFallbacks_GuardBadIniValues(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		userRate, userBurst         int
		wantUserRate, wantUserBurst int
	}{
		{"sane values pass through untouched", 20, 40, 20, 40},
		{"zero is replaced", 0, 0,
			defaultUserRateFallback, defaultUserBurstFallback},
		{"negative is replaced", -1, -5,
			defaultUserRateFallback, defaultUserBurstFallback},
		{"above the ceiling is replaced",
			int(MaxRuleRate) + 1, int(MaxRuleBurst) + 1,
			defaultUserRateFallback, defaultUserBurstFallback},
		{"one bad value does not disturb the other", -5, 40,
			defaultUserRateFallback, 40},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := setting.NewCfg()
			cfg.DsRateLimit.DefaultUserRate = tc.userRate
			cfg.DsRateLimit.DefaultUserBurst = tc.userBurst

			got := loadConfigFromSetting(cfg)

			require.Equal(t, tc.wantUserRate, got.DefaultUserRate, "default_user_rate")
			require.Equal(t, tc.wantUserBurst, got.DefaultUserBurst, "default_user_burst")

			// The point of the fallback: whatever the ini said, the resulting
			// limiter must admit traffic rather than refuse everything.
			userLim := rate.NewLimiter(rate.Limit(got.DefaultUserRate), got.DefaultUserBurst)
			require.True(t, userLim.Allow(),
				"per-user limiter built from sanitised config must admit the first request; "+
					"rate=%d burst=%d", got.DefaultUserRate, got.DefaultUserBurst)
		})
	}

	// Datasource quotas come from the rule table, not the ini, and go through
	// sanitizeParams in reloadRules. Same class of protection, different entry
	// point -- covered by TestIntegrationReloadRules_IgnoresInvalidDatasourceQuota.
}

// TestConfigFallbacks_MatchSettingDefaults keeps the fallbacks in this package
// equal to the MustInt fallbacks in pkg/setting. They are separate constants by
// necessity -- this package must not import pkg/setting's private defaults --
// but if they drift, the value used when the ini is malformed stops matching the
// value used when the key is simply absent, for no visible reason.
func TestConfigFallbacks_MatchSettingDefaults(t *testing.T) {
	cfg := setting.NewCfg()
	cfg.Raw = ini.Empty()
	// With no [datasource_ratelimit] section at all, every MustInt fallback
	// applies -- that is the set this package must mirror.
	require.NoError(t, cfg.Load(setting.CommandLineArgs{HomePath: "../../../"}))

	require.Equal(t, cfg.DsRateLimit.DefaultUserRate, defaultUserRateFallback,
		"defaultUserRateFallback drifted from conf/defaults.ini")
	require.Equal(t, cfg.DsRateLimit.DefaultUserBurst, defaultUserBurstFallback,
		"defaultUserBurstFallback drifted from conf/defaults.ini")
}

// TestIniQuotas_RejectInvalidSections locks validation of the deploy-time quota
// sections.
//
// ini values reach the service verbatim -- MustInt only substitutes on a missing
// or unparseable key, so `rate = -5` arrives as -5. x/time/rate accepts it
// without complaint and then refuses every query to that datasource forever
// (v0.2.0 has no panic path), which for a deploy-time value means a datasource
// that is dead from startup with nothing in the request path to explain it.
//
// Invalid sections are dropped rather than defaulted: there is no sensible
// default for "how much capacity does this backend have", and inventing one
// would throttle a datasource to a number nobody chose.
func TestIniQuotas_RejectInvalidSections(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rate      int
		burst     int
		wantQuota bool
		wantRate  int
		wantBurst int
	}{
		{name: "valid quota is kept", rate: 350, burst: 420,
			wantQuota: true, wantRate: 350, wantBurst: 420},
		{name: "missing burst is dropped", rate: 350, burst: 0},
		{name: "missing rate is dropped", rate: 0, burst: 420},
		{name: "negative rate is dropped", rate: -5, burst: 420},
		{name: "negative burst is dropped", rate: 350, burst: -1},
		{name: "burst below rate is dropped", rate: 420, burst: 350},
		{name: "rate above the ceiling is dropped",
			rate: int(MaxRuleRate) + 1, burst: int(MaxRuleBurst) + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := setting.NewCfg()
			cfg.DsRateLimit.Quotas = map[string]setting.DsRateLimitQuota{
				"PROM_MAIN": {Rate: tc.rate, Burst: tc.burst},
			}

			got := loadConfigFromSetting(cfg)

			lp, ok := got.IniQuotas["PROM_MAIN"]
			require.Equal(t, tc.wantQuota, ok,
				"rate=%d burst=%d: an out-of-range quota must be dropped, since "+
					"applying it would refuse every query to this datasource "+
					"without recovering", tc.rate, tc.burst)
			if tc.wantQuota {
				require.Equal(t, tc.wantRate, lp.rate)
				require.Equal(t, tc.wantBurst, lp.burst)

				// The surviving value must produce a usable limiter -- that is
				// the entire point of validating it here.
				lim := rate.NewLimiter(rate.Limit(lp.rate), lp.burst)
				require.True(t, lim.Allow(),
					"a kept quota must admit the first request")
			}
		})
	}

	// An empty UID cannot be addressed by any request, so keeping it would put
	// an unreachable bucket in /stats for an operator to puzzle over.
	t.Run("empty uid section is dropped", func(t *testing.T) {
		cfg := setting.NewCfg()
		cfg.DsRateLimit.Quotas = map[string]setting.DsRateLimitQuota{
			"": {Rate: 350, Burst: 420},
		}
		require.Empty(t, loadConfigFromSetting(cfg).IniQuotas)
	})
}

// TestAdminPut_RejectsUnmatchableTarget covers the target shapes that would be
// stored successfully and then never match a request.
//
// Rules are looked up by the key rateLimitKey builds, which is always
// "<kind>:<numeric id>". A rule written as user/john.doe therefore saves, lists
// back, and does nothing. This is the worst failure mode this endpoint has: no
// error, no log, and an operator who believes an exemption or a block is now in
// place. The kind field was already guarded for exactly this reason; target is
// the field more likely to be typed by hand.
func TestAdminPut_RejectsUnmatchableTarget(t *testing.T) {
	for _, tc := range []struct {
		name       string
		kind       string
		target     string
		wantStatus int
	}{
		// The forms an operator would plausibly reach for.
		{"user by login", "user", "john.doe", 400},
		{"user by email", "user", "john@example.com", 400},
		{"service account by name", "sa", "sa-alerting", 400},
		{"api key by name", "apikey", "grafana-agent", 400},
		{"user id zero", "user", "0", 400},
		{"negative user id", "user", "-1", 400},
		{"user id not a number", "user", "77abc", 400},
		// ParseInt accepts these; strconv.FormatInt never emits them, so they
		// would be stored and never match. A raw-space target is not covered:
		// httptest.NewRequest cannot build such a URL, and neither can a real
		// client.
		{"user id with plus sign", "user", "+77", 400},
		{"user id with leading zero", "user", "077", 400},
		// anon has exactly one bucket; any other target is unreachable.
		{"anon with wrong target", "anon", "1.2.3.4", 400},

		// Shapes that must keep working.
		{"user by numeric id", "user", "77", 200},
		{"service account by numeric id", "sa", "9", 200},
		{"api key by numeric id", "apikey", "3", 200},
		{"anon with its only valid target", "anon", "anon", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newAdminTestService(t)
			r, b := int64(10), int64(20)
			c := adminPutCtx(tc.kind, tc.target, UpsertBody{
				Mode: string(ModeLimited), Rate: &r, Burst: &b,
			})
			got := s.AdminPut(c).(*response.NormalResponse).Status()
			require.Equal(t, tc.wantStatus, got,
				"PUT %s/%s: a target that cannot match a live request must be "+
					"rejected at write time, not accepted and silently ignored",
				tc.kind, tc.target)
		})
	}
}

// TestAdminPut_AcceptedTargetActuallyMatches closes the loop.
//
// Rejecting bad shapes is only half the guarantee -- the accepted shape has to
// be the one that actually takes effect. Without this, the validation above
// could be self-consistently wrong (rejecting the form that works and accepting
// one that does not) and every test would still pass.
func TestAdminPut_AcceptedTargetActuallyMatches(t *testing.T) {
	s := newAdminTestService(t)
	c := adminPutCtx("user", "77", UpsertBody{Mode: string(ModeUnlimited)})
	require.Equal(t, 200, s.AdminPut(c).(*response.NormalResponse).Status())
	require.NoError(t, s.reloadRules(context.Background()))

	// The key a real request from user 77 produces.
	reqCtx, _ := buildCtx("POST", dsQueryPath, []byte(`{"queries":[]}`),
		&user.SignedInUser{UserID: 77})
	key := rateLimitKey(reqCtx)
	require.Equal(t, "user:77", key,
		"the key shape validateTarget assumes must be the one rateLimitKey emits")

	require.Equal(t, string(ModeUnlimited), s.resolveRule(key).Mode,
		"a rule accepted for user/77 must be the rule a request from user 77 "+
			"resolves to; if these two ever diverge the endpoint is lying")
}

// TestAdminPut_TargetLengthBounded guards against silent truncation.
//
// The target column is VARCHAR(64). A longer value is truncated on write, so
// the stored rule would apply to a different target than the one requested --
// and the response would report success for the value that was not saved.
func TestAdminPut_TargetLengthBounded(t *testing.T) {
	s := newAdminTestService(t)
	r, b := int64(10), int64(20)

	long := strings.Repeat("u", maxTargetLen+1)
	c := adminPutCtx(string(KindDatasource), long, UpsertBody{
		Mode: string(ModeLimited), Rate: &r, Burst: &b,
	})
	require.Equal(t, 400, s.AdminPut(c).(*response.NormalResponse).Status(),
		"a target longer than the column must be rejected rather than truncated "+
			"into a rule for some other datasource")

	atLimit := strings.Repeat("u", maxTargetLen)
	c2 := adminPutCtx(string(KindDatasource), atLimit, UpsertBody{
		Mode: string(ModeLimited), Rate: &r, Burst: &b,
	})
	require.Equal(t, 200, s.AdminPut(c2).(*response.NormalResponse).Status(),
		"a target exactly at the column width must still be accepted")
}
