package dsratelimit

import "golang.org/x/time/rate"

// identityMetricLabels is attached to the existing per-identity cache entry, so
// metric cardinality follows the same bounded lifecycle rather than growing a
// second identity map.
type identityMetricLabels struct {
	kind     string
	identity string
	login    string
}

func newIdentityMetricLabels(key, login string) *identityMetricLabels {
	for i := 0; i < len(key); i++ {
		if key[i] != ':' {
			continue
		}
		kind := key[:i]
		if kind != string(KindUser) && kind != string(KindSA) {
			return nil
		}
		return &identityMetricLabels{kind: kind, identity: key[i+1:], login: login}
	}
	return nil
}

func (m *identityMetricLabels) values() []string {
	return []string{m.kind, m.identity, m.login}
}

func (m *identityMetricLabels) deleteCurrentSeries() {
	labels := m.values()
	metricIdentityInflight.DeleteLabelValues(labels...)
	metricIdentityRateLimit.DeleteLabelValues(labels...)
	metricIdentityConcurrencyLimit.DeleteLabelValues(labels...)
}

func (m *identityMetricLabels) deleteSeries() {
	m.deleteCurrentSeries()
	metricIdentityTokens.DeleteLabelValues(m.kind, m.identity, m.login, "demand", "false")
	metricIdentityTokens.DeleteLabelValues(m.kind, m.identity, m.login, "limited", "false")
	metricIdentityTokens.DeleteLabelValues(m.kind, m.identity, m.login, "limited", "true")
}

// withIdentityLabels serialises label changes, metric updates and eviction.
// It takes the Service-wide identityMetricMu (outer) before the per-entry
// metricMu, so a fresh entry's first publish cannot race an evicting old
// entry's DeleteLabelValues for the same (kind,identity,login): the two
// critical sections are mutually exclusive. Lock order identityMetricMu ->
// metricMu, never the reverse. Prometheus keeps already-scraped history after
// a local series is deleted; if the identity returns, rate() handles reset.
func (s *Service) withIdentityLabels(e *userEntry, key, login string, f func(*identityMetricLabels)) {
	next := newIdentityMetricLabels(key, login)
	if next == nil {
		return
	}
	s.identityMetricMu.Lock()
	defer s.identityMetricMu.Unlock()
	e.metricMu.Lock()
	defer e.metricMu.Unlock()
	if e.removed {
		return
	}
	if e.labels == nil || *e.labels != *next {
		if e.labels != nil {
			e.labels.deleteSeries()
		}
		e.labels = next
	}
	f(e.labels)
}

func (e *userEntry) withCurrentIdentityLabels(f func(*identityMetricLabels)) {
	e.metricMu.Lock()
	defer e.metricMu.Unlock()
	if e.removed || e.labels == nil {
		return
	}
	f(e.labels)
}

func (e *userEntry) publishIdentityInflight() {
	e.withCurrentIdentityLabels(func(labels *identityMetricLabels) {
		// Read while holding metricMu rather than publishing a value captured
		// earlier. Concurrent acquire/release updates queue on the same lock, so a
		// late writer cannot overwrite the gauge with its stale local snapshot.
		metricIdentityInflight.WithLabelValues(labels.values()...).Set(float64(e.conc.load()))
	})
}

// removeIdentitySeries tears down an evicted entry's metric series. It is a
// Service method (not a bare entry method) because deletion is by label value,
// and two entries can own the same (kind,identity,login) for a moment: an old
// entry being evicted and a fresh entry a concurrent request just built for the
// same key. The whole [ownership check + DeleteLabelValues] runs under the
// Service-wide identityMetricMu (outer) and the entry's metricMu (inner), the
// exact same critical sections the request path takes to first-publish, so the
// check and the delete are atomic against a concurrent owner's publish. Under
// metricMu we re-check ownership against the bucket map -- if the key is now held
// by anyone but us, we leave the series alone. We do not add a generation label
// (that would grow cardinality); the ownership check lives in the cache layer
// instead. Lock order is always identityMetricMu -> metricMu, never reversed.
func (s *Service) removeIdentitySeries(e *userEntry, key string) {
	s.identityMetricMu.Lock()
	defer s.identityMetricMu.Unlock()
	e.metricMu.Lock()
	defer e.metricMu.Unlock()
	e.removed = true
	if cur, present := s.userBuckets.Load(key); present && cur != any(e) {
		return
	}
	if e.labels != nil {
		e.labels.deleteSeries()
	}
}

func (s *Service) effectiveIdentityRateLimit(snap *rulesSnapshot, rule *Rule, lim *rate.Limiter) float64 {
	if !s.activeQPS(snap) || Mode(rule.Mode) != ModeLimited {
		return 0
	}
	return float64(lim.Limit())
}

func (s *Service) effectiveIdentityConcurrencyLimit(snap *rulesSnapshot, key string) float64 {
	if !s.activeConcurrency(snap) {
		return 0
	}
	limit := s.concurrencyLimit(snap, key)
	if limit <= 0 {
		return 0
	}
	return float64(limit)
}

// republishIdentityGauges re-publishes the per-identity quota gauges after a
// hot config change. identity_rate_limit and identity_concurrency_limit are
// otherwise only written on the request path, so with no traffic an admin PUT
// leaves the dashboard showing the superseded limit until that identity next
// queries (observed on BOE: PUT rate=7, idle gauge still 20). Values are
// recomputed from the new snapshot rather than read back from e.limiter, whose
// SetLimit has not run yet because no request has arrived. No limiter is
// touched, so rate-limit decision semantics are unchanged: this only brings
// the observability gauge up to the snapshot it claims to be.
func (s *Service) republishIdentityGauges(snap *rulesSnapshot) {
	s.userBuckets.Range(func(k, v any) bool {
		e := v.(*userEntry)
		s.identityMetricMu.Lock()
		e.metricMu.Lock()
		if e.removed || e.labels == nil {
			e.metricMu.Unlock()
			s.identityMetricMu.Unlock()
			return true
		}
		key := k.(string)
		rule := s.resolveRuleIn(snap, key)
		var qps float64
		if s.activeQPS(snap) && Mode(rule.Mode) == ModeLimited {
			baseRate, _ := s.defaultParams(snap)
			qps = float64(baseRate)
			if rule.Rate != nil && rule.Burst != nil {
				if lp, ok := sanitizeParams(*rule.Rate, *rule.Burst, s.cfg.MaxRuleRate, s.cfg.MaxRuleBurst); ok {
					qps = float64(lp.rate)
				}
			}
		}
		conc := s.effectiveIdentityConcurrencyLimit(snap, key)
		metricIdentityRateLimit.WithLabelValues(e.labels.values()...).Set(qps)
		metricIdentityConcurrencyLimit.WithLabelValues(e.labels.values()...).Set(conc)
		e.metricMu.Unlock()
		s.identityMetricMu.Unlock()
		return true
	})
}
