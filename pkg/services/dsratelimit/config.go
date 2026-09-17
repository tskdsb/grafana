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

	// ConcurrencyEnabled gates the in-flight cap independently of Enabled.
	//
	// Separate from Enabled because the two ship on different schedules: the
	// QPS layer is already running in production, and the in-flight cap has to
	// be observable there for a while before anyone can pick a sane limit. One
	// combined switch would force a choice between not deploying it at all and
	// deploying it with a guessed number.
	//
	// Enabled still wins: with the service off there is no reload loop and no
	// identity cache, so a concurrency cap would have nothing to run on.
	ConcurrencyEnabled bool

	// DefaultUserConcurrency is the per-identity in-flight cap. Zero or
	// negative means unlimited, which is the deploy default until observed
	// data says otherwise.
	DefaultUserConcurrency int

	// ConcurrencyShadowMode observes instead of rejecting, for the in-flight
	// cap only.
	//
	// Deliberately not the QPS layer's ShadowMode. Once QPS is enforcing in
	// production, sharing one switch makes the two layers impossible to roll
	// out independently: validating a candidate concurrency limit in shadow
	// would require flipping the shared flag, which stops QPS rejecting at the
	// same time -- dropping the protection that is already load-bearing in
	// order to trial one that is not.
	ConcurrencyShadowMode bool
}
