package setting

import (
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"
)

// TestDsRateLimitDefaults_MatchDefaultsIni locks the two copies of every
// default against each other.
//
// There are deliberately two: conf/defaults.ini is what ships and what an
// operator reads, while the MustXxx fallbacks in readDsRateLimitSettings apply
// when a key is absent entirely (a trimmed custom.ini, an older packaged
// defaults.ini, or a unit test building Cfg from an empty ini). If the two
// drift, the effective limit depends on which file the deployment happens to
// have — the worst possible failure mode for a limiter, because it is silent
// and only shows up as unexplained 429s or as no protection at all.
//
// The values themselves are derived in the defaults.ini comment block from
// measured traffic; this test only asserts the two sources agree.
func TestDsRateLimitDefaults_MatchDefaultsIni(t *testing.T) {
	iniPath := findDefaultsIni(t)

	// Parse the [datasource_ratelimit] section as shipped.
	section := extractSection(t, iniPath, "datasource_ratelimit")

	// Build a Cfg whose Raw has NO datasource_ratelimit section at all, so
	// every value comes from the MustXxx fallback.
	cfg := NewCfg()
	cfg.readDsRateLimitSettings()

	for _, tc := range []struct {
		key  string
		got  int
		what string
	}{
		{"default_user_rate", cfg.DsRateLimit.DefaultUserRate, "per-user rate"},
		{"default_user_burst", cfg.DsRateLimit.DefaultUserBurst, "per-user burst"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			want, ok := section[tc.key]
			require.True(t, ok, "%s missing from [datasource_ratelimit] in %s", tc.key, iniPath)
			n, err := strconv.Atoi(want)
			require.NoError(t, err, "%s = %q is not an integer", tc.key, want)
			require.Equal(t, n, tc.got,
				"%s (%s) disagrees: defaults.ini says %d, readDsRateLimitSettings falls back to %d",
				tc.key, tc.what, n, tc.got)
		})
	}

	// shadow_mode must ship as true: upgrading must never start rejecting
	// traffic before an operator has sized the limits.
	require.Equal(t, "true", section["shadow_mode"],
		"shadow_mode must default to true in defaults.ini")
	require.True(t, cfg.DsRateLimit.ShadowMode,
		"shadow_mode fallback must be true")

	// Burst must be >= rate, or the very first request of a quiet period is
	// denied (x/time/rate starts full but cannot exceed burst).
	require.GreaterOrEqual(t, cfg.DsRateLimit.DefaultUserBurst, cfg.DsRateLimit.DefaultUserRate,
		"per-user burst must be >= rate")

	// The same invariant for datasource quotas is enforced at the write path
	// (AdminPut requires burst >= rate), since those live in the rule table
	// rather than in this file.

	// Burst must clear the largest single-request token cost, or requests that
	// big are denied *permanently* rather than throttled.
	//
	// x/time/rate: reserveN does `ok := n <= lim.burst` (rate.go:371). There is
	// no queueing and no eventual success -- AllowN(n) with n > burst returns
	// false on every call regardless of accumulated tokens, so the panel simply
	// never loads and retrying does not help. This is the one limit whose
	// misconfiguration is invisible in aggregate metrics (it looks like a small
	// constant denial rate) but total for the affected panel.
	//
	// maxObservedRequestCost is measured, not guessed: across 2169 panels of
	// the five largest dashboards on this deployment, the worst single panel
	// costs 29 tokens. Raise this only alongside a fresh measurement.
	const maxObservedRequestCost = 29
	require.GreaterOrEqual(t, cfg.DsRateLimit.DefaultUserBurst, maxObservedRequestCost,
		"per-user burst (%d) must be >= the largest observed single-request cost (%d), "+
			"otherwise x/time/rate denies those requests forever (rate.go:371)",
		cfg.DsRateLimit.DefaultUserBurst, maxObservedRequestCost)
	// The equivalent floor for datasource quotas cannot be asserted here:
	// quotas live in the datasource_rate_limit table, not in this file. It is
	// enforced at the write path instead (AdminPut requires burst >= rate) and
	// documented in the [datasource_ratelimit] derivation.
}

// extractSection returns the key=value pairs of one ini section.
// Uses the same ini library the real config loader uses, so this test cannot
// disagree with production parsing over comments, quoting or continuations.
func extractSection(t *testing.T, path, name string) map[string]string {
	t.Helper()
	f, err := ini.Load(path)
	require.NoError(t, err, "ini.Load(%s)", path)
	sec, err := f.GetSection(name)
	require.NoError(t, err, "section [%s] missing from %s", name, path)

	out := map[string]string{}
	for _, k := range sec.Keys() {
		out[k.Name()] = k.String()
	}
	require.NotEmpty(t, out, "section [%s] is empty", name)
	return out
}

func findDefaultsIni(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller failed")
	// thisFile = .../pkg/setting/setting_ds_ratelimit_test.go
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", "conf", "defaults.ini"))
}

// TestDsRateLimitQuotaSections_ParseFromIni covers the deploy-time quota
// sections end-to-end, through the same ini library production uses.
//
// Worth asserting rather than assuming: these are dynamically-named sections, so
// nothing in the struct definition would catch a prefix typo or a case mismatch
// -- the quota would simply be absent, and a datasource everyone believed was
// protected would not be.
func TestDsRateLimitQuotaSections_ParseFromIni(t *testing.T) {
	raw := []byte(`
[datasource_ratelimit]
enabled = true

[datasource_ratelimit.quota.PROM_MAIN]
rate = 350
burst = 420

[datasource_ratelimit.quota.MYSQL_REPORTS]
rate = 50
burst = 60

[datasource_ratelimit.quota.PARTIAL]
rate = 30

[unrelated_section]
rate = 999
`)
	f, err := ini.Load(raw)
	require.NoError(t, err)

	got := extractDsRateLimitQuotas(f.Sections())

	require.Equal(t, DsRateLimitQuota{Rate: 350, Burst: 420}, got["PROM_MAIN"])
	require.Equal(t, DsRateLimitQuota{Rate: 50, Burst: 60}, got["MYSQL_REPORTS"])

	// A partial section is returned as-is; the service rejects it (burst=0
	// would refuse every request) rather than this layer guessing a burst.
	require.Equal(t, DsRateLimitQuota{Rate: 30, Burst: 0}, got["PARTIAL"],
		"an incomplete section must be surfaced, not silently completed here")

	require.Len(t, got, 3,
		"only [datasource_ratelimit.quota.*] sections may be collected; got %v", got)
	require.NotContains(t, got, "",
		"the bare prefix must not produce an empty-UID quota")
}

// TestDsRateLimitQuotaSections_NoneByDefault pins that shipping no quotas is the
// default.
//
// A default quota would be worse than none: the right number depends entirely on
// the backend a given deployment points at, so any value shipped here would
// silently throttle someone's datasource to a limit nobody chose.
func TestDsRateLimitQuotaSections_NoneByDefault(t *testing.T) {
	iniPath := findDefaultsIni(t)
	f, err := ini.Load(iniPath)
	require.NoError(t, err, "ini.Load(%s)", iniPath)

	require.Empty(t, extractDsRateLimitQuotas(f.Sections()),
		"conf/defaults.ini must not ship concrete datasource quotas: the correct "+
			"value is deployment-specific, and a default would throttle a backend "+
			"to a number nobody chose")
}
