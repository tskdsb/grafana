package dsratelimit

import "testing"

// Both resolution chains, tier by tier, in one place.
//
// Written to support a refactor that was then abandoned, and kept because the
// table turned out to be the more useful half. The two layers walk the same
// three tiers -- identity rule, default rule, ini -- through separate code,
// and the last defect here came from a guard added to one chain having no
// counterpart in the other. Listing both side by side is what makes a
// divergence legible; the alternative was a shared generic resolver, which
// cost more in indirection than the duplication it removed.
//
// The two subtests are deliberately parallel in shape. A tier that behaves
// differently between them should be visible by reading down the columns.
func TestResolutionChains(t *testing.T) {
	t.Run("qps", func(t *testing.T) {
		cases := []struct {
			name     string
			cfgRate  int
			rules    []*Rule
			key      string
			wantMode Mode
			wantRate int64
		}{
			{
				name: "identity rule wins", cfgRate: 20,
				rules:    []*Rule{{Kind: string(KindUser), Target: "1", Mode: string(ModeLimited), Rate: i64(5), Burst: i64(5)}},
				key:      "user:1",
				wantMode: ModeLimited, wantRate: 5,
			},
			{
				name: "default rule beats ini", cfgRate: 20,
				rules:    []*Rule{{Kind: string(KindDefault), Target: DefaultTarget, Mode: string(ModeLimited), Rate: i64(9), Burst: i64(9)}},
				key:      "user:1",
				wantMode: ModeLimited, wantRate: 9,
			},
			{
				name: "ini when nothing else", cfgRate: 20,
				key:      "user:1",
				wantMode: ModeLimited, wantRate: 20,
			},
			{
				name: "unconfigured means unlimited", cfgRate: 0,
				key:      "user:1",
				wantMode: ModeUnlimited,
			},
			{
				name: "concurrency-only rule falls through to the baseline", cfgRate: 20,
				rules:    []*Rule{{Kind: string(KindUser), Target: "1", Mode: string(ModeLimited), Concurrency: i64(3)}},
				key:      "user:1",
				wantMode: ModeLimited, wantRate: 20,
			},
			{
				name: "concurrency-only rule with no baseline is unlimited", cfgRate: 0,
				rules:    []*Rule{{Kind: string(KindUser), Target: "1", Mode: string(ModeLimited), Concurrency: i64(3)}},
				key:      "user:1",
				wantMode: ModeUnlimited,
			},
			{
				name: "anonymous is blocked by default", cfgRate: 20,
				key:      "anon:anon",
				wantMode: ModeBlocked,
			},
			{
				name: "an explicit unlimited rule stands", cfgRate: 20,
				rules:    []*Rule{{Kind: string(KindUser), Target: "1", Mode: string(ModeUnlimited)}},
				key:      "user:1",
				wantMode: ModeUnlimited,
			},
			{
				name: "an explicit blocked rule stands", cfgRate: 20,
				rules:    []*Rule{{Kind: string(KindUser), Target: "1", Mode: string(ModeBlocked)}},
				key:      "user:1",
				wantMode: ModeBlocked,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				cfg := defaultCfg()
				cfg.DefaultUserRate, cfg.DefaultUserBurst = tc.cfgRate, tc.cfgRate
				s := newTestService(cfg, tc.rules...)
				got := s.resolveRule(tc.key)
				if Mode(got.Mode) != tc.wantMode {
					t.Fatalf("mode = %s, want %s", got.Mode, tc.wantMode)
				}
				if tc.wantMode == ModeLimited {
					if got.Rate == nil || *got.Rate != tc.wantRate {
						t.Fatalf("rate = %v, want %d", got.Rate, tc.wantRate)
					}
				}
			})
		}
	})

	t.Run("concurrency", func(t *testing.T) {
		cases := []struct {
			name   string
			cfgCap int
			rules  []*Rule
			key    string
			want   int64
		}{
			{"identity rule wins", 3,
				[]*Rule{{Kind: string(KindUser), Target: "1", Mode: string(ModeLimited), Concurrency: i64(9)}},
				"user:1", 9},
			{"default rule beats ini", 3,
				[]*Rule{{Kind: string(KindDefault), Target: DefaultTarget, Mode: string(ModeLimited), Concurrency: i64(5)}},
				"user:1", 5},
			{"ini when nothing else", 3, nil, "user:1", 3},
			{"unconfigured means no cap", 0, nil, "user:1", 0},
			{"rule without a concurrency value falls through", 3,
				[]*Rule{{Kind: string(KindUser), Target: "1", Mode: string(ModeLimited), Rate: i64(5), Burst: i64(5)}},
				"user:1", 3},
			{"zero in a rule means uncapped", 3,
				[]*Rule{{Kind: string(KindUser), Target: "1", Mode: string(ModeLimited), Concurrency: i64(0)}},
				"user:1", 0},
			{"negative in a rule is ignored, falls through", 3,
				[]*Rule{{Kind: string(KindUser), Target: "1", Mode: string(ModeLimited), Concurrency: i64(-5)}},
				"user:1", 3},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				cfg := concCfg(tc.cfgCap)
				s := newTestService(cfg, tc.rules...)
				if got := s.concurrencyLimit(s.rulesPtr.Load(), tc.key); got != tc.want {
					t.Fatalf("limit = %d, want %d", got, tc.want)
				}
			})
		}
	})
}
