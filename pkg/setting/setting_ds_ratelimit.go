package setting

import (
	"strings"

	"gopkg.in/ini.v1"
)

// DsRateLimitSettings mirrors the [datasource_ratelimit] section of
// defaults.ini / custom.ini. Each value's derivation from measured traffic is
// documented next to it in conf/defaults.ini.
type DsRateLimitSettings struct {
	Enabled          bool
	ShadowMode       bool
	DefaultUserRate  int
	DefaultUserBurst int
	CacheMaxEntries  int

	// ConcurrencyEnabled gates the in-flight cap independently of Enabled: the
	// QPS layer is already live, and this one has to be observed in production
	// before anyone can pick a limit.
	ConcurrencyEnabled bool
	// DefaultUserConcurrency is the per-identity in-flight cap. 0 = unlimited.
	DefaultUserConcurrency int
	// ConcurrencyShadowMode observes instead of rejecting, for the in-flight
	// cap only. Separate from ShadowMode so the two layers can be rolled out
	// independently once QPS is enforcing.
	ConcurrencyShadowMode bool

	// MaxRule* are the ceilings the admin API validates a submitted rule
	// against. They are guard rails against a typo -- an extra digit, or a
	// value that overflows int on a 32-bit build -- not operational settings;
	// use mode=unlimited to express "no limit".
	//
	// Configurable rather than compile-time because the right ceiling depends
	// on the deployment, and rebuilding an image to adjust a bound nobody
	// should be approaching is a poor trade. Deliberately NOT hot-reloadable:
	// a ceiling is a safety property, and one that can be raised at runtime by
	// the same API call it is meant to constrain is not a constraint. Changing
	// it is a deploy-time decision, which the restart makes explicit.
	MaxRuleRate        int
	MaxRuleBurst       int
	MaxRuleConcurrency int

	// Quotas holds the deploy-time per-datasource quotas declared as
	// [datasource_ratelimit.quota.<uid>] sections, keyed by datasource UID.
	//
	// These are the values a deployment ships with, so a fresh environment is
	// protected from the first request. Quotas differ per environment (staging
	// and production do not share a backend, nor its capacity), which is why
	// they live in the environment's ini rather than in a default.
	//
	// A row in the datasource_rate_limit table overrides the value here for the
	// same UID: the ini is the deployed baseline, the table is the runtime
	// adjustment made while an incident is in progress.
	Quotas map[string]DsRateLimitQuota
}

// DsRateLimitQuota is one datasource's deploy-time quota, in backend requests
// per second. Zero values mean the key was absent; validation happens in
// pkg/services/dsratelimit, which owns the bounds.
type DsRateLimitQuota struct {
	Rate  int
	Burst int
}

const dsRateLimitQuotaPrefix = "datasource_ratelimit.quota."

func (cfg *Cfg) readDsRateLimitSettings() {
	s := cfg.Raw.Section("datasource_ratelimit")
	cfg.DsRateLimit.Enabled = s.Key("enabled").MustBool(true)
	// Shadow by default: an upgrade must not start rejecting traffic on its
	// own. Keep in sync with conf/defaults.ini -- this fallback applies when
	// the key is absent entirely.
	cfg.DsRateLimit.ShadowMode = s.Key("shadow_mode").MustBool(true)
	// Fallback 0, not the shipped 20/40: an absent key means nobody has chosen
	// a limit, and inventing one here would enforce a number the deployment
	// never asked for. conf/defaults.ini still ships 20/40, so a normal install
	// gets them; this path is for a config that omits the key entirely.
	// dsratelimit reads 0 as "do not limit".
	cfg.DsRateLimit.DefaultUserRate = s.Key("default_user_rate").MustInt(0)
	cfg.DsRateLimit.DefaultUserBurst = s.Key("default_user_burst").MustInt(0)
	cfg.DsRateLimit.CacheMaxEntries = s.Key("cache_max_entries").MustInt(10000)
	cfg.DsRateLimit.ConcurrencyEnabled = s.Key("concurrency_enabled").MustBool(false)
	// 0 = unlimited, which is the deploy default: the number can only come
	// from the concurrency_inflight histogram after this has run for a while.
	cfg.DsRateLimit.DefaultUserConcurrency = s.Key("default_user_concurrency").MustInt(0)
	// Shadow by default, like the QPS layer: a new enforcement path must not
	// start rejecting on its own.
	cfg.DsRateLimit.ConcurrencyShadowMode = s.Key("concurrency_shadow_mode").MustBool(true)
	// Ceilings. The fallbacks match conf/defaults.ini and are sized so that a
	// legitimate value never meets them: the highest per-identity rate anyone
	// has had cause to set is two orders of magnitude below 1000, and an
	// in-flight cap is a single- or double-digit number in practice.
	//
	// A non-positive or absent value falls back rather than disabling the
	// check: a ceiling that can be switched off by omission is not a guard
	// rail. dsratelimit re-validates and logs if a configured bound is unusable.
	cfg.DsRateLimit.MaxRuleRate = s.Key("max_rule_rate").MustInt(1000)
	cfg.DsRateLimit.MaxRuleBurst = s.Key("max_rule_burst").MustInt(1000)
	cfg.DsRateLimit.MaxRuleConcurrency = s.Key("max_rule_concurrency").MustInt(100)
	cfg.DsRateLimit.Quotas = extractDsRateLimitQuotas(cfg.Raw.Sections())
}

// extractDsRateLimitQuotas collects the [datasource_ratelimit.quota.<uid>]
// sections. Same shape as extractPluginSettings, which is the established way to
// express a map in this ini file.
//
// Note the UID is a section name, so it is whatever the operator typed. It is
// not validated against existing datasources: doing so would require the
// datasource service at config-load time, and a quota for a UID that does not
// exist yet is harmless (it simply never matches) whereas failing startup over
// it would not be.
func extractDsRateLimitQuotas(sections []*ini.Section) map[string]DsRateLimitQuota {
	out := map[string]DsRateLimitQuota{}
	for _, section := range sections {
		// HasPrefix + slicing rather than strings.CutPrefix: go.mod declares
		// go 1.19 and CutPrefix arrived in 1.20. Local builds and the image
		// build both run a newer toolchain, so this compiled everywhere it was
		// tried and only failed once CI pinned the declared version.
		name := section.Name()
		if !strings.HasPrefix(name, dsRateLimitQuotaPrefix) {
			continue
		}
		uid := name[len(dsRateLimitQuotaPrefix):]
		if uid == "" {
			continue
		}
		out[uid] = DsRateLimitQuota{
			Rate:  section.Key("rate").MustInt(0),
			Burst: section.Key("burst").MustInt(0),
		}
	}
	return out
}
