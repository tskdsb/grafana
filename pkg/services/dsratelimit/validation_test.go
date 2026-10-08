package dsratelimit

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/infra/log"
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
		{"at the ceiling", DefaultMaxRuleRate, DefaultMaxRuleBurst, true, int(DefaultMaxRuleRate), int(DefaultMaxRuleBurst)},
		{"zero rate", 0, 100, false, 0, 0},
		{"zero burst", 30, 0, false, 0, 0},
		{"both zero", 0, 0, false, 0, 0},
		{"negative rate", -5, 100, false, 0, 0},
		{"negative burst", 30, -1, false, 0, 0},
		{"both negative", -5, -1, false, 0, 0},
		{"rate above ceiling", DefaultMaxRuleRate + 1, 100, false, 0, 0},
		{"burst above ceiling", 30, DefaultMaxRuleBurst + 1, false, 0, 0},
		{"int64 max", 1 << 62, 1 << 62, false, 0, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := sanitizeParams(tc.rate, tc.burst, DefaultMaxRuleRate, DefaultMaxRuleBurst)
			require.Equal(t, tc.wantOK, ok,
				"sanitizeParams(%d, %d, DefaultMaxRuleRate, DefaultMaxRuleBurst) ok mismatch", tc.rate, tc.burst)
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

			_, ok := sanitizeParams(int64(tc.rate), int64(tc.burst), DefaultMaxRuleRate, DefaultMaxRuleBurst)
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
		{"above ceiling", DefaultMaxRuleRate + 1, DefaultMaxRuleBurst + 1},
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
//
// What the guard does with such a value changed: it returns 0, meaning this
// layer does not limit, rather than falling back to 20/40. Both failure modes
// that motivated the change were silent -- a zero reached x/time/rate and
// refused everything, and a typo got a working limiter at a number nobody
// picked. An unusable value expresses no intention, so the only honest
// reading is to stay out of the way until a real one arrives.
func TestConfigFallbacks_GuardBadIniValues(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		userRate, userBurst         int
		wantUserRate, wantUserBurst int
	}{
		{"sane values pass through untouched", 20, 40, 20, 40},
		// Every unusable value now disarms the layer instead of borrowing
		// 20/40. Substituting a built-in number enforced a limit the
		// deployment never chose, and told the operator only through a log
		// line they had no reason to read.
		{"zero means no limit", 0, 0, 0, 0},
		{"negative disarms rather than substitutes", -1, -5, 0, 0},
		{"above the ceiling disarms", int(DefaultMaxRuleRate) + 1, int(DefaultMaxRuleBurst) + 1, 0, 0},
		{"one bad value does not disturb the other", -5, 40, 0, 40},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := setting.NewCfg()
			cfg.DsRateLimit.DefaultUserRate = tc.userRate
			cfg.DsRateLimit.DefaultUserBurst = tc.userBurst

			got := loadConfigFromSetting(cfg)

			require.Equal(t, tc.wantUserRate, got.DefaultUserRate, "default_user_rate")
			require.Equal(t, tc.wantUserBurst, got.DefaultUserBurst, "default_user_burst")

			// Whatever the ini said, traffic must be admitted rather than
			// refused. Asserted through the middleware, not by building a
			// limiter from the sanitised numbers: rate.NewLimiter(0, 0)
			// refuses everything, which is exactly why zero now means
			// "unlimited" one level up instead of reaching x/time/rate at
			// all. Constructing the limiter here would test a path
			// production never takes and fail on correct behaviour.
			s := newTestService(got)
			u := &user.SignedInUser{UserID: 1, OrgID: 1}
			c, rec := buildCtx("POST", "/api/ds/query", []byte(`{"queries":[{}]}`), u)
			s.Middleware(c)
			require.Equal(t, http.StatusOK, rec.Code,
				"a request must be admitted after config sanitisation; rate=%d burst=%d",
				got.DefaultUserRate, got.DefaultUserBurst)
		})
	}

	// Datasource quotas come from the rule table, not the ini, and go through
	// sanitizeParams in reloadRules. Same class of protection, different entry
	// point -- covered by TestIntegrationReloadRules_IgnoresInvalidDatasourceQuota.
}

func TestConfigFallbacks_UseIndependentRateAndBurstCeilings(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		maxRate, maxBurst           int
		userRate, userBurst         int
		wantUserRate, wantUserBurst int
	}{
		{
			name:          "burst below its own higher ceiling is kept",
			maxRate:       100,
			maxBurst:      1000,
			userRate:      50,
			userBurst:     500,
			wantUserRate:  50,
			wantUserBurst: 500,
		},
		{
			name:          "burst above its own lower ceiling is rejected",
			maxRate:       1000,
			maxBurst:      100,
			userRate:      50,
			userBurst:     500,
			wantUserRate:  50,
			wantUserBurst: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := setting.NewCfg()
			cfg.DsRateLimit.MaxRuleRate = tc.maxRate
			cfg.DsRateLimit.MaxRuleBurst = tc.maxBurst
			cfg.DsRateLimit.DefaultUserRate = tc.userRate
			cfg.DsRateLimit.DefaultUserBurst = tc.userBurst

			got := loadConfigFromSetting(cfg)
			require.Equal(t, tc.wantUserRate, got.DefaultUserRate)
			require.Equal(t, tc.wantUserBurst, got.DefaultUserBurst)
		})
	}
}

// TestAbsentConfig_DoesNotLimit pins the startup contract across both layers:
// a deployment that never states a limit does not get one.
//
// This replaces a test that asserted the opposite -- that this package's
// fallback constants stayed equal to pkg/setting's MustInt fallbacks, so a
// malformed value and an absent one both landed on 20/40. Keeping two
// invented numbers in sync was the wrong goal; neither should have been
// invented. Both layers now answer an absent value the same way, with no
// number at all.
//
// Note this reads conf/defaults.ini from the repo, so it also catches the
// case where the shipped file is edited to omit these keys.
func TestAbsentConfig_DoesNotLimit(t *testing.T) {
	cfg := setting.NewCfg()
	cfg.Raw = ini.Empty()
	// An empty ini means every MustInt fallback applies -- the state this
	// contract is about.
	require.NoError(t, cfg.Load(setting.CommandLineArgs{HomePath: "../../../"}))

	// conf/defaults.ini ships real numbers, so a normal install is limited.
	// The contract is about what happens without them, which is what the
	// section below constructs.
	require.Positive(t, cfg.DsRateLimit.DefaultUserRate,
		"conf/defaults.ini should still ship a usable default_user_rate")

	bare := setting.NewCfg()
	got := loadConfigFromSetting(bare)
	require.Zero(t, got.DefaultUserRate,
		"an unstated QPS rate must not become a limit")
	require.Zero(t, got.DefaultUserBurst,
		"an unstated QPS burst must not become a limit")
	require.Zero(t, got.DefaultUserConcurrency,
		"an unstated in-flight cap must not become a limit")
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
			rate: int(DefaultMaxRuleRate) + 1, burst: int(DefaultMaxRuleBurst) + 1},
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
			c := adminPutCtx(tc.kind, tc.target, UpsertBody{
				Mode: string(ModeLimited), Rate: rawInt(10), Burst: rawInt(20),
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
	long := strings.Repeat("u", maxTargetLen+1)
	c := adminPutCtx(string(KindDatasource), long, UpsertBody{
		Mode: string(ModeLimited), Rate: rawInt(10), Burst: rawInt(20),
	})
	require.Equal(t, 400, s.AdminPut(c).(*response.NormalResponse).Status(),
		"a target longer than the column must be rejected rather than truncated "+
			"into a rule for some other datasource")

	atLimit := strings.Repeat("u", maxTargetLen)
	c2 := adminPutCtx(string(KindDatasource), atLimit, UpsertBody{
		Mode: string(ModeLimited), Rate: rawInt(10), Burst: rawInt(20),
	})
	require.Equal(t, 200, s.AdminPut(c2).(*response.NormalResponse).Status(),
		"a target exactly at the column width must still be accepted")
}

// TestCeilings_ComeFromConfig pins that the bounds are deployment settings
// rather than compile-time constants.
//
// They were constants, which meant moving a guard rail -- a rare but real
// operational need -- cost a rebuild and an image roll. They are still not
// hot-reloadable, and that is deliberate: a ceiling the admin API can raise is
// not a ceiling, so changing one stays a deploy-time act.
func TestCeilings_ComeFromConfig(t *testing.T) {
	// A rule that the shipped default refuses.
	overDefault := ptr64(DefaultMaxRuleRate + 1)
	burst := ptr64(DefaultMaxRuleRate + 1)

	shipped := bounds{DefaultMaxRuleRate, DefaultMaxRuleBurst, DefaultMaxRuleConcurrency}
	require.NotEmpty(t,
		validateMergedRule(KindUser, ModeLimited, overDefault, burst, nil, shipped),
		"a value above the configured ceiling must be refused")

	// Same rule, a deployment that raised the bound: now accepted, with no
	// rebuild involved.
	raised := bounds{DefaultMaxRuleRate * 10, DefaultMaxRuleBurst * 10, DefaultMaxRuleConcurrency}
	require.Empty(t,
		validateMergedRule(KindUser, ModeLimited, overDefault, burst, nil, raised),
		"raising the ceiling in config must let the same rule through")

	// And the concurrency bound moves independently of the QPS ones.
	conc := ptr64(DefaultMaxRuleConcurrency + 1)
	require.NotEmpty(t,
		validateMergedRule(KindUser, ModeLimited, nil, nil, conc, shipped))
	require.Empty(t,
		validateMergedRule(KindUser, ModeLimited, nil, nil, conc,
			bounds{DefaultMaxRuleRate, DefaultMaxRuleBurst, DefaultMaxRuleConcurrency * 2}))
}

// TestCeilingSetting_FallsBackRatherThanDisabling covers the case where the
// ceiling itself is misconfigured.
//
// Accepting a bad bound would remove the guard at exactly the moment the config
// is known to be wrong, so an absent or unusable value falls back to the
// built-in default instead.
func TestCeilingSetting_FallsBackRatherThanDisabling(t *testing.T) {
	lg := log.New("test")
	require.EqualValues(t, DefaultMaxRuleRate, ceilingSetting(lg, "max_rule_rate", 0, DefaultMaxRuleRate),
		"an absent ceiling must fall back, not become unlimited")
	require.EqualValues(t, DefaultMaxRuleRate, ceilingSetting(lg, "max_rule_rate", -5, DefaultMaxRuleRate),
		"a negative ceiling must fall back")
	require.EqualValues(t, 2000, ceilingSetting(lg, "max_rule_rate", 2000, DefaultMaxRuleRate),
		"a usable ceiling must be honoured verbatim")
}
