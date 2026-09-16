package dsratelimit

// Config is the internal configuration snapshot used by the service.
// It is decoupled from *setting.Cfg so tests can construct services
// directly. See ProvideService for the setting.Cfg -> Config conversion.
type Config struct {
	Enabled          bool
	ShadowMode       bool
	DefaultUserRate  int
	DefaultUserBurst int
	// IniQuotas are the deploy-time per-datasource quotas from
	// [datasource_ratelimit.quota.<uid>], already validated. A DB rule for the
	// same UID overrides the entry here.
	IniQuotas       map[string]laneParams
	CacheMaxEntries int
}
