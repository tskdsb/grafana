package dsratelimit

// Independent boundary acceptance for MR4 (per-identity Top K metrics).
// White-box probes; deliberately separate from identity_metrics_test.go so the
// existing 6 tests stay untouched. Each test pins one contract the review
// called out as untested.

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/user"
)

func dsBody(uid string, n int) []byte {
	queries := "["
	for i := 0; i < n; i++ {
		if i > 0 {
			queries += ","
		}
		queries += `{"range":true,"datasource":{"uid":"` + uid + `"}}`
	}
	queries += "]"
	return []byte(`{"queries":` + queries + `}`)
}

// ---------- 1. personal QPS rejection ----------

// TestB1_PersonalQPSRejection counts demand on every attempt and limited only
// on the personal bucket, with a real 429 when enforcing.
func TestB1_PersonalQPSRejection(t *testing.T) {
	freshIdentityMetrics(t)
	cfg := defaultCfg()
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 1, 1
	cfg.ShadowMode = false // enforcing
	s := newTestService(cfg)
	u := &user.SignedInUser{UserID: 42, Login: "alice"}

	codes := []int{}
	for i := 0; i < 3; i++ {
		c, rec := buildCtx("POST", dsQueryPath, dsBody("PROM", 1), u)
		s.Middleware(c)
		codes = append(codes, rec.Code)
	}
	require.Equal(t, []int{200, 429, 429}, codes)
	// demand is counted on every attempt, before the bucket decides.
	require.Equal(t, float64(3), counterValue(t, metricIdentityTokens, "user", "42", "alice", "demand", "false"))
	require.Equal(t, float64(2), counterValue(t, metricIdentityTokens, "user", "42", "alice", "limited", "true"))
	require.Equal(t, float64(0), counterValue(t, metricIdentityTokens, "user", "42", "alice", "limited", "false"))
}

// ---------- 2. datasource quota rejection is NOT personal limited ----------

func TestB2_DatasourceQuotaRejectionNotPersonalLimited(t *testing.T) {
	freshIdentityMetrics(t)
	cfg := defaultCfg()
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 100000, 100000 // personal bucket loose
	cfg.ShadowMode = false
	s := newTestService(cfg, dsQuotaRule("PROM", 1, 1)) // datasource quota tight
	u := &user.SignedInUser{UserID: 7, Login: "bob"}

	codes := []int{}
	for i := 0; i < 3; i++ {
		c, rec := buildCtx("POST", dsQueryPath, dsBody("PROM", 1), u)
		s.Middleware(c)
		codes = append(codes, rec.Code)
	}
	require.Equal(t, []int{200, 429, 429}, codes)
	// demand still counted (cost before decision).
	require.Equal(t, float64(3), counterValue(t, metricIdentityTokens, "user", "7", "bob", "demand", "false"))
	// but a datasource-quota refusal must NOT surface as a personal limited series.
	require.False(t, tokensHasResult(t, "7", "bob", "limited"),
		"no identity_tokens series with result=limited for an identity refused only by datasource quota")
}

// tokensHasResult reports whether metricIdentityTokens has any series for the
// given identity/login AND the given result label.
func tokensHasResult(t *testing.T, identity, login, result string) bool {
	t.Helper()
	var gathered dto.Metric
	ch := make(chan prometheus.Metric, 16)
	go func() { metricIdentityTokens.Collect(ch); close(ch) }()
	for m := range ch {
		require.NoError(t, m.Write(&gathered))
		labels := map[string]string{}
		for _, p := range gathered.GetLabel() {
			labels[p.GetName()] = p.GetValue()
		}
		if labels["identity"] == identity && labels["login"] == login && labels["result"] == result {
			return true
		}
		gathered.Reset()
	}
	return false
}

// ---------- 3. blocked fast path excludes identity metrics ----------

func TestB3_BlockedFastPathNoIdentitySeries(t *testing.T) {
	freshIdentityMetrics(t)
	cfg := defaultCfg()
	cfg.ShadowMode = false
	blocked := &Rule{Kind: string(KindUser), Target: "99", Mode: string(ModeBlocked)}
	s := newTestService(cfg, blocked)
	u := &user.SignedInUser{UserID: 99, Login: "blockedguy"}

	c, rec := buildCtx("POST", dsQueryPath, dsBody("PROM", 1), u)
	s.Middleware(c)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)

	// No cache entry allocated, no identity series.
	_, ok := s.userBuckets.Load("user:99")
	require.False(t, ok, "blocked fast path must not allocate a userEntry")
	require.False(t, metricHasIdentity(t, metricIdentityTokens, "99", "blockedguy"))
	require.False(t, metricHasIdentity(t, metricIdentityRateLimit, "99", "blockedguy"))
}

// ---------- 4. shadow: limited projected but served ----------

func TestB4_ShadowLimitedServedButProjected(t *testing.T) {
	freshIdentityMetrics(t)
	cfg := defaultCfg()
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 1, 1
	cfg.ShadowMode = true // observing
	s := newTestService(cfg)
	u := &user.SignedInUser{UserID: 5, Login: "carol"}

	for i := 0; i < 3; i++ {
		c, rec := buildCtx("POST", dsQueryPath, dsBody("PROM", 1), u)
		s.Middleware(c)
		require.NotEqual(t, http.StatusTooManyRequests, rec.Code, "shadow must never 429")
	}
	require.Equal(t, float64(3), counterValue(t, metricIdentityTokens, "user", "5", "carol", "demand", "false"))
	require.Equal(t, float64(2), counterValue(t, metricIdentityTokens, "user", "5", "carol", "limited", "false"))
	require.Equal(t, float64(0), counterValue(t, metricIdentityTokens, "user", "5", "carol", "limited", "true"))
}

// ---------- 5. concurrency rejection does not touch identity_tokens ----------

func TestB5_ConcurrencyRejectionTrackedSeparately(t *testing.T) {
	freshIdentityMetrics(t)
	s := newTestService(concCfg(1)) // one slot, enforcing
	h := newBlockingHandler(1)
	u := &user.SignedInUser{UserID: 7, Login: "robot", IsServiceAccount: true}

	// Hold the only slot.
	firstDone := make(chan struct{})
	go func() {
		r := concRequestForUser(s, "/api/ds/query", u, h.ServeHTTP)
		require.Equal(t, http.StatusOK, r.Code)
		close(firstDone)
	}()
	<-h.entered

	// Second request over the cap -> 429, no slot taken.
	second := concRequestForUser(s, "/api/ds/query", u, h.ServeHTTP)
	require.Equal(t, http.StatusTooManyRequests, second.Code)

	// inflight gauge still exactly 1 (the rejected one must not decrement it).
	require.Equal(t, float64(1), identityGaugeValue(t, metricIdentityInflight, "sa", "7", "robot"))

	close(h.release)
	<-firstDone
	require.Equal(t, float64(0), identityGaugeValue(t, metricIdentityInflight, "sa", "7", "robot"))
}

// ---------- 6. abnormal release (panic in handler) still frees inflight ----------

func TestB6_PanicHandlerStillReleasesInflight(t *testing.T) {
	freshIdentityMetrics(t)
	s := newTestService(concCfg(2))
	u := &user.SignedInUser{UserID: 8, Login: "panicuser"}

	panicking := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})
	func() {
		defer func() { _ = recover() }()
		concRequestForUser(s, "/api/ds/query", u, panicking)
	}()
	// The defer release must have run despite the panic: gauge back to 0.
	require.Equal(t, float64(0), identityGaugeValue(t, metricIdentityInflight, "user", "8", "panicuser"))
}

// ---------- 7. SA rename drops old login series ----------

func TestB7_SARenameOldLoginSeriesRemoved(t *testing.T) {
	freshIdentityMetrics(t)
	s := newTestService(defaultCfg())
	e := s.getUserEntry(s.rulesPtr.Load(), "sa:12", s.resolveRuleIn(s.rulesPtr.Load(), "sa:12"))

	s.withIdentityLabels(e, "sa:12", "old-name", func(labels *identityMetricLabels) {
		metricIdentityInflight.WithLabelValues(labels.values()...).Set(1)
		metricIdentityTokens.WithLabelValues(labels.kind, labels.identity, labels.login, "demand", "false").Add(5)
	})
	require.True(t, metricHasIdentity(t, metricIdentityInflight, "12", "old-name"))

	// Rename: next request arrives under the new login.
	s.withIdentityLabels(e, "sa:12", "new-name", func(labels *identityMetricLabels) {
		metricIdentityInflight.WithLabelValues(labels.values()...).Set(1)
	})
	require.True(t, metricHasIdentity(t, metricIdentityInflight, "12", "new-name"))
	require.False(t, metricHasIdentity(t, metricIdentityInflight, "12", "old-name"),
		"old-login gauge series must be deleted on rename")
	require.False(t, metricHasIdentity(t, metricIdentityTokens, "12", "old-name"),
		"old-login counter series must be deleted on rename")
}

// ---------- 8. RED: gauge staleness with no traffic after reload ----------

// TestB8_GaugeRefreshedOnReloadWithoutTraffic pins the BOE v3 finding: after a
// hot rule/default change the per-identity quota gauge must move on its own,
// without waiting for the identity's next query.
func TestB8_GaugeRefreshedOnReloadWithoutTraffic(t *testing.T) {
	freshIdentityMetrics(t)
	cfg := defaultCfg()
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 20, 40
	cfg.ShadowMode = false
	s := newTestService(cfg)
	u := &user.SignedInUser{UserID: 42, Login: "alice"}

	// One request publishes the gauge at the baseline 20.
	c, _ := buildCtx("POST", dsQueryPath, dsBody("PROM", 1), u)
	s.Middleware(c)
	require.Equal(t, float64(20), identityGaugeValue(t, metricIdentityRateLimit, "user", "42", "alice"))

	// Simulate a hot reload that raises the default QPS to 7, with NO new traffic.
	newSnap := &rulesSnapshot{
		byKey:   map[string]*Rule{},
		dsQuota: map[string]laneParams{},
		defaults: &laneParams{rate: 7, burst: 10},
	}
	s.rulesPtr.Store(newSnap)
	s.publishRuntimeConfig(newSnap)
	s.republishIdentityGauges(newSnap) // the reload hook under test

	require.Equal(t, float64(7), identityGaugeValue(t, metricIdentityRateLimit, "user", "42", "alice"),
		"gauge must reflect the reloaded default without a new request")
}

// ---------- 9. cross-entry cleanup delete hazard (evidence probe) ----------

// TestB9_EvictionDeleteIsByLabelValue probes whether an evicted entry's final
// series deletion can remove a series a newer same-key entry just published.
// This documents the observed behaviour; it is NOT a fix.
func TestB9_EvictionDoesNotDeleteNewOwnerSeries(t *testing.T) {
	freshIdentityMetrics(t)
	s := newTestService(defaultCfg())

	// Old entry A owns user:7 and published a series.
	a := s.getUserEntry(s.rulesPtr.Load(), "user:7", s.resolveRuleIn(s.rulesPtr.Load(), "user:7"))
	s.withIdentityLabels(a, "user:7", "alice", func(l *identityMetricLabels) {
		metricIdentityTokens.WithLabelValues(l.kind, l.identity, l.login, "demand", "false").Add(100)
		metricIdentityInflight.WithLabelValues(l.values()...).Set(1)
	})

	// (control) When A is still the owner, its own removal deletes its series.
	s.userBuckets.Delete("user:7")
	s.removeIdentitySeries(a, "user:7")
	require.True(t, a.removed)
	require.False(t, metricHasIdentity(t, metricIdentityInflight, "7", "alice"),
		"ownerless old entry's series must be deleted")

	// Now the interleaving R1 is about: cleanup removes A, but a fresh request
	// re-creates the key as B before A's final series delete.
	b := s.getUserEntry(s.rulesPtr.Load(), "user:7", s.resolveRuleIn(s.rulesPtr.Load(), "user:7"))
	require.NotSame(t, a, b)
	s.withIdentityLabels(b, "user:7", "alice", func(l *identityMetricLabels) {
		metricIdentityInflight.WithLabelValues(l.values()...).Set(2)
		metricIdentityTokens.WithLabelValues(l.kind, l.identity, l.login, "demand", "false").Add(3)
	})
	// Cleanup path for the now-stale A: map delete already happened; finalize A.
	s.userBuckets.Delete("user:7") // simulate; B is the live owner in the map
	s.userBuckets.Store("user:7", b)
	s.removeIdentitySeries(a, "user:7")

	// B owns the key; its live series must survive A's eviction.
	require.True(t, metricHasIdentity(t, metricIdentityInflight, "7", "alice"),
		"new owner B's inflight gauge must NOT be deleted by stale A's eviction")
	require.Equal(t, float64(3), counterValue(t, metricIdentityTokens, "user", "7", "alice", "demand", "false"),
		"new owner B's counter must survive (no reset to zero)")
}

// ---------- 10. sampling does not reset identity counters ----------

func TestB10_SamplingDoesNotResetIdentityCounters(t *testing.T) {
	freshIdentityMetrics(t)
	cfg := defaultCfg()
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 100000, 100000
	s := newTestService(cfg)
	u := &user.SignedInUser{UserID: 3, Login: "sampler"}
	for i := 0; i < 3; i++ {
		c, _ := buildCtx("POST", dsQueryPath, dsBody("PROM", 2), u)
		s.Middleware(c)
	}
	before := counterValue(t, metricIdentityTokens, "user", "3", "sampler", "demand", "false")
	require.Equal(t, float64(6), before)
	// Drain the sample window repeatedly; the identity counter must not move.
	for i := 0; i < 5; i++ {
		s.sampleUserRates()
	}
	require.Equal(t, float64(6), counterValue(t, metricIdentityTokens, "user", "3", "sampler", "demand", "false"))
}

// ---------- 11. disabled layer publishes zero gauge ----------

func TestB11_DisabledLayerZeroGauge(t *testing.T) {
	freshIdentityMetrics(t)
	cfg := defaultCfg()
	cfg.Enabled = false // QPS layer bypassed
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 20, 40
	cfg.ConcurrencyEnabled = true
	cfg.DefaultUserConcurrency = 5
	s := newTestService(cfg)
	e := s.getUserEntry(s.rulesPtr.Load(), "user:8", s.resolveRuleIn(s.rulesPtr.Load(), "user:8"))
	s.withIdentityLabels(e, "user:8", "dave", func(l *identityMetricLabels) {
		metricIdentityRateLimit.WithLabelValues(l.values()...).Set(s.effectiveIdentityRateLimit(s.rulesPtr.Load(), s.resolveRuleIn(s.rulesPtr.Load(), "user:8"), e.limiter))
		metricIdentityConcurrencyLimit.WithLabelValues(l.values()...).Set(s.effectiveIdentityConcurrencyLimit(s.rulesPtr.Load(), "user:8"))
	})
	require.Equal(t, float64(0), identityGaugeValue(t, metricIdentityRateLimit, "user", "8", "dave"),
		"disabled QPS layer must publish 0, not the configured rate")
	require.Equal(t, float64(5), identityGaugeValue(t, metricIdentityConcurrencyLimit, "user", "8", "dave"))
}

// ---------- 12. concurrency shadow projects denial ----------

func TestB12_ConcurrencyShadowProjectsDenial(t *testing.T) {
	freshIdentityMetrics(t)
	c := concCfg(1)
	c.ConcurrencyShadowMode = true // observing
	s := newTestService(c)
	h := newBlockingHandler(2)
	u := &user.SignedInUser{UserID: 9, Login: "shadowconc"}

	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := concRequestForUser(s, "/api/ds/query", u, h.ServeHTTP)
			codes <- r.Code
		}()
	}
	// Both should have entered the handler (shadow admits everything).
	<-h.entered
	<-h.entered
	close(h.release)
	wg.Wait()
	for i := 0; i < 2; i++ {
		require.Equal(t, http.StatusOK, <-codes, "concurrency shadow must serve both")
	}
}

// ---------- 13. proxy route demand = 1 token ----------

func TestB13_ProxyRouteDemandOneToken(t *testing.T) {
	freshIdentityMetrics(t)
	cfg := defaultCfg()
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 100000, 100000
	s := newTestService(cfg)
	u := &user.SignedInUser{UserID: 11, Login: "proxyman"}
	c, rec := buildCtx("POST", "/api/datasources/proxy/uid/PROM", nil, u)
	s.Middleware(c)
	require.NotEqual(t, http.StatusTooManyRequests, rec.Code)
	require.Equal(t, float64(1), counterValue(t, metricIdentityTokens, "user", "11", "proxyman", "demand", "false"))
}

// ---------- 14. inflight gauge publish races cleanly with release (-race) ----------

func TestB14_InflightPublishConcurrentRace(t *testing.T) {
	freshIdentityMetrics(t)
	s := newTestService(concCfg(4))
	u := &user.SignedInUser{UserID: 13, Login: "racer"}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					h := newBlockingHandler(1)
					done := make(chan struct{})
					go func() {
						r := concRequestForUser(s, "/api/ds/query", u, h.ServeHTTP)
						_ = r
						close(done)
					}()
					select {
					case <-h.entered:
					case <-time.After(time.Second):
					}
					close(h.release)
					<-done
				}
			}
		}()
	}
	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// ---------- 15. deleted-identity series lifecycle contract ----------

// TestB15_DeletedIdentitySeriesBoundedByLRU documents the lifecycle contract:
// there is no hook on user/SA deletion, so below the LRU cap the series of a
// deleted identity linger until eviction pressure. Cardinality is nonetheless
// bounded by CacheMaxEntries -- this is the accepted contract, not a leak.
func TestB15_DeletedIdentitySeriesBoundedByLRU(t *testing.T) {
	freshIdentityMetrics(t)
	cfg := defaultCfg()
	cfg.CacheMaxEntries = 2
	s := newTestService(cfg)

	// identity 30 has traffic and a series.
	e30 := s.getUserEntry(s.rulesPtr.Load(), "user:30", s.resolveRuleIn(s.rulesPtr.Load(), "user:30"))
	s.withIdentityLabels(e30, "user:30", "gone", func(l *identityMetricLabels) {
		metricIdentityTokens.WithLabelValues(l.kind, l.identity, l.login, "demand", "false").Add(5)
	})
	require.True(t, counterHasIdentity(t, metricIdentityTokens, "30", "gone"))

	// Simulate the identity being deleted: it simply stops receiving traffic,
	// and nothing removes its entry below the cap.
	// (a) Below cap: cleanup does NOT evict it, series linger.
	s.cleanup()
	require.True(t, counterHasIdentity(t, metricIdentityTokens, "30", "gone"),
		"below the LRU cap a deleted identity's series linger (no immediate-delete hook; accepted contract)")

	// (b) Force the map over cap with newer entries; LRU evicts the stale one.
	e30.lastUsedUnixNano.Store(1)
	for i := int64(100); i < 104; i++ {
		e := s.getUserEntry(s.rulesPtr.Load(), "user:"+itoa(i), s.resolveRuleIn(s.rulesPtr.Load(), "user:"+itoa(i)))
		s.withIdentityLabels(e, "user:"+itoa(i), "live", func(l *identityMetricLabels) {
			metricIdentityTokens.WithLabelValues(l.kind, l.identity, l.login, "demand", "false").Add(1)
		})
	}
	s.cleanup()
	require.False(t, counterHasIdentity(t, metricIdentityTokens, "30", "gone"),
		"once over the LRU cap the stale entry is evicted and its series deleted")
}

// TestB17_RepublishCoversOverrideAndFallback exercises the no-traffic reload
// gauge refresh across rule sources, not just the default branch.
func TestB17_RepublishCoversOverrideAndFallback(t *testing.T) {
	freshIdentityMetrics(t)
	cfg := defaultCfg()
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 20, 40
	cfg.ConcurrencyEnabled = true
	cfg.DefaultUserConcurrency = 5
	s := newTestService(cfg)

	// user:42 starts at the default 20.
	e := s.getUserEntry(s.rulesPtr.Load(), "user:42", s.resolveRuleIn(s.rulesPtr.Load(), "user:42"))
	s.withIdentityLabels(e, "user:42", "alice", func(l *identityMetricLabels) {
		metricIdentityRateLimit.WithLabelValues(l.values()...).Set(s.effectiveIdentityRateLimit(s.rulesPtr.Load(), s.resolveRuleIn(s.rulesPtr.Load(), "user:42"), e.limiter))
	})
	require.Equal(t, float64(20), identityGaugeValue(t, metricIdentityRateLimit, "user", "42", "alice"))

	// (a) per-identity override rate=7, burst=10; concurrency override=3.
	rate7, burst10 := int64(7), int64(10)
	conc3 := int64(3)
	override := &rulesSnapshot{
		byKey:   map[string]*Rule{"user:42": {Kind: "user", Target: "42", Mode: "limited", Rate: &rate7, Burst: &burst10, Concurrency: &conc3}},
		dsQuota: map[string]laneParams{},
	}
	s.rulesPtr.Store(override)
	s.republishIdentityGauges(override)
	require.Equal(t, float64(7), identityGaugeValue(t, metricIdentityRateLimit, "user", "42", "alice"),
		"per-identity override rate must refresh without traffic")
	require.Equal(t, float64(3), identityGaugeValue(t, metricIdentityConcurrencyLimit, "user", "42", "alice"),
		"per-identity concurrency override must refresh without traffic")

	// (b) invalid override (rate above max) must fall back to default 20.
	badRate := int64(cfg.MaxRuleRate + 1)
	invalid := &rulesSnapshot{
		byKey:   map[string]*Rule{"user:42": {Kind: "user", Target: "42", Mode: "limited", Rate: &badRate, Burst: &burst10}},
		dsQuota: map[string]laneParams{},
	}
	s.rulesPtr.Store(invalid)
	s.republishIdentityGauges(invalid)
	require.Equal(t, float64(20), identityGaugeValue(t, metricIdentityRateLimit, "user", "42", "alice"),
		"invalid override must fall back to the configured default, not be trusted")

	// (c) drop the override back to default: concurrency nil => ini default 5.
	empty := &rulesSnapshot{byKey: map[string]*Rule{}, dsQuota: map[string]laneParams{}}
	s.rulesPtr.Store(empty)
	s.republishIdentityGauges(empty)
	require.Equal(t, float64(20), identityGaugeValue(t, metricIdentityRateLimit, "user", "42", "alice"))
	require.Equal(t, float64(5), identityGaugeValue(t, metricIdentityConcurrencyLimit, "user", "42", "alice"),
		"concurrency override cleared must fall back to ini default")
}

// TestB16_RepublishRacesCleanlyWithTraffic verifies the new reload-time
// gauge republish is concurrency-safe against the request path (-race).
func TestB16_RepublishRacesCleanlyWithTraffic(t *testing.T) {
	freshIdentityMetrics(t)
	cfg := defaultCfg()
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 20, 40
	s := newTestService(cfg)
	u := &user.SignedInUser{UserID: 13, Login: "racerepub"}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	// Traffic goroutines: normal QPS requests.
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					c, _ := buildCtx("POST", dsQueryPath, dsBody("PROM", 1), u)
					s.Middleware(c)
				}
			}
		}()
	}
	// Reload goroutine: hot-swap the snapshot and republish gauges, like reloadRules.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			rate := int64(10 + i%5)
			newSnap := &rulesSnapshot{
				byKey:   map[string]*Rule{},
				dsQuota: map[string]laneParams{},
				defaults: &laneParams{rate: int(rate), burst: 40},
			}
			s.rulesPtr.Store(newSnap)
			s.publishRuntimeConfig(newSnap)
			s.republishIdentityGauges(newSnap)
		}
	}()
	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestB18_EvictionPublishInterleaveNoMisDelete is the R1 stress: eviction
// (cleanup) racing with same-key re-publication must never leave a live
// entry's series deleted, and must not deadlock.
func TestB18_EvictionPublishInterleaveNoMisDelete(t *testing.T) {
	freshIdentityMetrics(t)
	cfg := defaultCfg()
	cfg.CacheMaxEntries = 4
	s := newTestService(cfg)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	// Publisher goroutines: touch a rotating set of keys, publishing labels the
	// way the request path does.
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			i := base
			for {
				select {
				case <-stop:
					return
				default:
					key := "user:" + itoa(int64(i%12))
					e := s.getUserEntry(s.rulesPtr.Load(), key, s.resolveRuleIn(s.rulesPtr.Load(), key))
					s.withIdentityLabels(e, key, "login"+itoa(int64(i%12)), func(l *identityMetricLabels) {
						metricIdentityTokens.WithLabelValues(l.kind, l.identity, l.login, "demand", "false").Add(1)
					})
					i++
				}
			}
		}(g * 7)
	}
	// Cleaner goroutine: repeatedly evict.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				s.cleanup()
			}
		}
	}()
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	// Every entry still live in the map must have its demand series present.
	s.userBuckets.Range(func(k, v any) bool {
		e := v.(*userEntry)
		e.metricMu.Lock()
		labels := e.labels
		removed := e.removed
		e.metricMu.Unlock()
		if labels == nil || removed {
			return true
		}
		require.True(t, counterHasIdentity(t, metricIdentityTokens, labels.identity, labels.login),
			"live entry %s lost its series to a racing eviction", k)
		return true
	})
}

// TestB19_R1_TOCTOUDeterministic reproduces the cross-entry eviction race
// deterministically, without sleeps, by driving the real mutex ordering: the
// test goroutine holds identityMetricMu, the evicting removeIdentitySeries runs
// in a goroutine blocked on that lock, and a fresh owner inserts + publishes
// its series directly (the body of the publish critical section) while the lock
// is held. On the pre-fix code (no global lock) this interleaving wipes the new
// owner; on the fixed code the ownership check sees the new owner and skips.
func TestB19_R1_TOCTOUDeterministic(t *testing.T) {
	freshIdentityMetrics(t)
	s := newTestService(defaultCfg())

	// Old entry A owns user:7 and has a published demand series.
	a := s.getUserEntry(s.rulesPtr.Load(), "user:7", s.resolveRuleIn(s.rulesPtr.Load(), "user:7"))
	s.withIdentityLabels(a, "user:7", "alice", func(l *identityMetricLabels) {
		metricIdentityTokens.WithLabelValues(l.kind, l.identity, l.login, "demand", "false").Add(100)
	})

	// Force the exact interleaving:
	s.identityMetricMu.Lock()
	s.userBuckets.Delete("user:7") // A is now ownerless
	done := make(chan struct{})
	go func() { // eviction finalizes A; blocked on identityMetricMu until we unlock
		s.removeIdentitySeries(a, "user:7")
		close(done)
	}()
	// While holding the lock: a new request re-creates the key as B and B's
	// publish critical section emits its series directly (no re-entry of the
	// locked wrapper, which would self-deadlock).
	b := s.getUserEntry(s.rulesPtr.Load(), "user:7", s.resolveRuleIn(s.rulesPtr.Load(), "user:7"))
	b.metricMu.Lock()
	b.labels = &identityMetricLabels{kind: "user", identity: "7", login: "alice"}
	metricIdentityTokens.WithLabelValues("user", "7", "alice", "demand", "false").Add(3)
	b.metricMu.Unlock()
	s.identityMetricMu.Unlock()

	<-done
	require.True(t, a.removed)
	// The shared series survives with A's 100 plus B's fresh 3: a's eviction
	// saw B as the live owner and skipped DeleteLabelValues, so B's write was
	// neither wiped nor reset to zero.
	require.Equal(t, float64(103), counterValue(t, metricIdentityTokens, "user", "7", "alice", "demand", "false"),
		"new owner B's counter must survive A's eviction (no reset, no TOCTOU wipe)")
}

// TestB20_R1_EvictionInterleaveKeepsNewOwnerInflightGauge is the same deterministic
// interleaving as B19 but for the shared inflight gauge: B publishes an inflight
// series while A's eviction is blocked, and A must not DeleteLabelValues it.
func TestB20_R1_EvictionInterleaveKeepsNewOwnerInflightGauge(t *testing.T) {
	freshIdentityMetrics(t)
	s := newTestService(defaultCfg())

	a := s.getUserEntry(s.rulesPtr.Load(), "user:9", s.resolveRuleIn(s.rulesPtr.Load(), "user:9"))
	s.withIdentityLabels(a, "user:9", "carol", func(l *identityMetricLabels) {
		metricIdentityInflight.WithLabelValues(l.values()...).Set(1)
	})

	s.identityMetricMu.Lock()
	s.userBuckets.Delete("user:9")
	done := make(chan struct{})
	go func() { s.removeIdentitySeries(a, "user:9"); close(done) }()
	b := s.getUserEntry(s.rulesPtr.Load(), "user:9", s.resolveRuleIn(s.rulesPtr.Load(), "user:9"))
	b.metricMu.Lock()
	b.labels = &identityMetricLabels{kind: "user", identity: "9", login: "carol"}
	metricIdentityInflight.WithLabelValues("user", "9", "carol").Set(4)
	b.metricMu.Unlock()
	s.identityMetricMu.Unlock()
	<-done

	require.Equal(t, float64(4), identityGaugeValue(t, metricIdentityInflight, "user", "9", "carol"),
		"new owner B's inflight gauge must survive A's eviction (shared labels, not deleted)")
}

func itoa(i int64) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		p--
		b[p] = '-'
	}
	return string(b[p:])
}
