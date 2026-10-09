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

// withIdentityLabels serializes label changes, metric updates and eviction.
// That prevents a request racing cleanup from recreating a series after its
// cache entry was removed. Prometheus keeps already-scraped history after a
// local series is deleted; if the identity returns, rate() handles the reset.
func (e *userEntry) withIdentityLabels(key, login string, f func(*identityMetricLabels)) {
	next := newIdentityMetricLabels(key, login)
	if next == nil {
		return
	}
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

func (e *userEntry) removeIdentitySeries() {
	e.metricMu.Lock()
	defer e.metricMu.Unlock()
	e.removed = true
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
