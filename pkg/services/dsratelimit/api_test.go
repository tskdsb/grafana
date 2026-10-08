package dsratelimit

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/web"
)

// newAdminTestService builds a Service backed by a real (test) DB so the
// admin handlers can be driven end-to-end, including the reload that follows
// a successful upsert.
func newAdminTestService(t *testing.T) *Service {
	t.Helper()
	ss := db.InitTestDB(t)
	s := &Service{
		cfg:    defaultCfg(),
		store:  newStore(ss),
		logger: log.New("dsratelimit.test"),
	}
	s.rulesPtr.Store(&rulesSnapshot{
		byKey:   map[string]*Rule{},
		dsQuota: map[string]laneParams{},
	})
	return s
}

// adminPutCtx builds a ReqContext for PUT .../:kind/:target with a JSON body.
func adminPutCtx(kind, target string, body any) *contextmodel.ReqContext {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut,
		"/api/admin/datasource-rate-limits/"+kind+"/"+target, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req = web.SetURLParams(req, map[string]string{":kind": kind, ":target": target})
	rec := httptest.NewRecorder()
	return &contextmodel.ReqContext{
		SignedInUser: &user.SignedInUser{UserID: 1, Login: "admin"},
		Context: &web.Context{
			Req:  req,
			Resp: web.NewResponseWriter(req.Method, rec),
		},
	}
}

// TestIntegrationAdminPut_Validation locks the admin-API write guard.
//
// AdminPut is the only supported way to create a rule, so rejecting bad input
// here is what keeps the read path from ever seeing a value that would brick
// a key (see sanitizeParams). Driven against a real DB so a rejected request
// is also proven not to have written anything.
func TestIntegrationAdminPut_Validation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	s := newAdminTestService(t)
	ctx := context.Background()

	cases := []struct {
		name       string
		kind       string
		target     string
		body       map[string]any
		wantStatus int
	}{
		// --- accepted ---
		{"valid limited rule", "sa", "12",
			map[string]any{"mode": "limited", "rate": 30, "burst": 100}, http.StatusOK},
		{"unlimited needs no numbers", "sa", "13",
			map[string]any{"mode": "unlimited"}, http.StatusOK},
		{"blocked needs no numbers", "sa", "14",
			map[string]any{"mode": "blocked"}, http.StatusOK},
		{"datasource quota is writable", "datasource", "PROM_MAIN",
			map[string]any{"mode": "limited", "rate": 350, "burst": 420}, http.StatusOK},
		{"anon is a real kind", "anon", "anon",
			map[string]any{"mode": "limited", "rate": 10, "burst": 20}, http.StatusOK},

		// --- rejected: kind ---
		{"unknown kind", "lain", "default",
			map[string]any{"mode": "limited", "rate": 30, "burst": 100}, http.StatusBadRequest},
		{"removed org kind", "org", "1",
			map[string]any{"mode": "limited", "rate": 30, "burst": 100}, http.StatusBadRequest},
		{"kind is case sensitive", "SA", "12",
			map[string]any{"mode": "limited", "rate": 30, "burst": 100}, http.StatusBadRequest},
		{"lane kind is gone", "lane", "default",
			map[string]any{"mode": "limited", "rate": 100, "burst": 150}, http.StatusBadRequest},

		// --- rejected: mode ---
		{"unknown mode", "sa", "15",
			map[string]any{"mode": "throttled"}, http.StatusBadRequest},
		{"empty mode", "sa", "16",
			map[string]any{"mode": ""}, http.StatusBadRequest},

		// --- rejected: numbers ---
		{"limited without numbers", "sa", "17",
			map[string]any{"mode": "limited"}, http.StatusBadRequest},
		{"zero rate", "sa", "18",
			map[string]any{"mode": "limited", "rate": 0, "burst": 100}, http.StatusBadRequest},
		{"zero burst", "sa", "19",
			map[string]any{"mode": "limited", "rate": 30, "burst": 0}, http.StatusBadRequest},
		{"negative rate", "sa", "20",
			map[string]any{"mode": "limited", "rate": -1, "burst": 100}, http.StatusBadRequest},
		{"negative burst", "sa", "21",
			map[string]any{"mode": "limited", "rate": 30, "burst": -1}, http.StatusBadRequest},
		{"rate above ceiling", "sa", "22",
			map[string]any{"mode": "limited", "rate": DefaultMaxRuleRate + 1, "burst": 100}, http.StatusBadRequest},
		{"burst below rate", "sa", "23",
			map[string]any{"mode": "limited", "rate": 100, "burst": 50}, http.StatusBadRequest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := s.AdminPut(adminPutCtx(tc.kind, tc.target, tc.body))
			require.NotNil(t, resp)
			require.Equal(t, tc.wantStatus, resp.Status(),
				"PUT %s/%s body=%v", tc.kind, tc.target, tc.body)

			stored, err := s.store.get(ctx, tc.kind, tc.target)
			require.NoError(t, err)
			if tc.wantStatus == http.StatusOK {
				require.NotNil(t, stored, "accepted request must persist a row")
			} else {
				require.Nil(t, stored,
					"rejected request must not write anything (found %+v)", stored)
			}
		})
	}
}

// TestIntegrationAdminPut_RejectionLeavesLimiterUsable is the behavioral
// consequence of the guard: after a rejected write, the key still resolves to
// a working limiter rather than a permanently-denying one.
func TestIntegrationAdminPut_RejectionLeavesLimiterUsable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	s := newAdminTestService(t)

	resp := s.AdminPut(adminPutCtx("sa", "99",
		map[string]any{"mode": "limited", "rate": 30, "burst": -1}))
	require.Equal(t, http.StatusBadRequest, resp.Status())

	require.NoError(t, s.reloadRules(context.Background()))

	rule := s.resolveRule("sa:99")
	lim := s.getUserLimiter("sa:99", rule)
	require.True(t, lim.Allow(),
		"after a rejected write the key must still serve traffic")
	require.Equal(t, rate.Limit(s.cfg.DefaultUserRate), lim.Limit())
}

// TestIntegrationReloadRules_IgnoresInvalidDatasourceQuota covers the row that
// bypasses the API (direct SQL edit, or a row predating validation). Applying it
// would make x/time/rate deny every query to that datasource forever.
func TestIntegrationReloadRules_IgnoresInvalidDatasourceQuota(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	s := newAdminTestService(t)

	bad := int64(-5)
	require.NoError(t, s.store.upsert(context.Background(), &Rule{
		Kind: string(KindDatasource), Target: "PROM_MAIN", Mode: string(ModeLimited),
		Rate: &bad, Burst: &bad,
	}))
	require.NoError(t, s.reloadRules(context.Background()))

	require.Nil(t, s.getDatasourceLimiter("PROM_MAIN"),
		"an invalid quota must be ignored entirely, not applied: a negative rate "+
			"produces a limiter that denies every request and never refills")
}

// TestIntegrationReloadRules_AppliesValidDatasourceQuota is the negative control
// for the test above -- it proves the ignore path is selective.
func TestIntegrationReloadRules_AppliesValidDatasourceQuota(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	s := newAdminTestService(t)

	r, b := int64(123), int64(456)
	require.NoError(t, s.store.upsert(context.Background(), &Rule{
		Kind: string(KindDatasource), Target: "PROM_MAIN", Mode: string(ModeLimited),
		Rate: &r, Burst: &b,
	}))
	require.NoError(t, s.reloadRules(context.Background()))

	lim := s.getDatasourceLimiter("PROM_MAIN")
	require.NotNil(t, lim, "a valid quota must produce a bucket")
	require.Equal(t, rate.Limit(123), lim.Limit())
	require.Equal(t, 456, lim.Burst())

	// A datasource with no quota row must get no bucket -- not a permissive one.
	// Buckets are only ever created for configured quotas, which is what keeps
	// client-supplied UIDs from allocating memory.
	require.Nil(t, s.getDatasourceLimiter("MYSQL_REPORTS"),
		"an unconfigured datasource must have no bucket")
}

// TestIntegrationAdminPut_DatasourceAcceptsLimitedOnly locks the quota mode
// guard.
//
// reloadRules only applies a datasource row carrying both rate and burst, so
// accepting mode=blocked or unlimited would write a row, return 200, and list it
// back while the quota stayed exactly as it was. That precise bug shipped once
// on the lane path (PUT lane/default {"mode":"blocked"} returned 200 and changed
// nothing), which is why it is locked here rather than trusted.
func TestIntegrationAdminPut_DatasourceAcceptsLimitedOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	r, b := 350, 420

	for _, tc := range []struct {
		name string
		body map[string]any
		want int
	}{
		{"datasource rejects blocked", map[string]any{"mode": "blocked"}, http.StatusBadRequest},
		{"datasource rejects unlimited", map[string]any{"mode": "unlimited"}, http.StatusBadRequest},
		{"datasource accepts limited", map[string]any{"mode": "limited", "rate": r, "burst": b}, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newAdminTestService(t)
			c := adminPutCtx("datasource", "PROM_MAIN", tc.body)
			got := s.AdminPut(c).(*response.NormalResponse).Status()
			require.Equal(t, tc.want, got,
				"a datasource mode that reloadRules would silently skip must not "+
					"be accepted")
		})
	}

	// The accepted one must actually create the bucket -- otherwise the three
	// cases above would all pass with an endpoint that rejects everything.
	t.Run("accepted quota takes effect", func(t *testing.T) {
		s := newAdminTestService(t)
		require.Nil(t, s.getDatasourceLimiter("PROM_MAIN"), "precondition: no quota yet")

		c := adminPutCtx("datasource", "PROM_MAIN",
			map[string]any{"mode": "limited", "rate": r, "burst": b})
		require.Equal(t, http.StatusOK, s.AdminPut(c).(*response.NormalResponse).Status())

		lim := s.getDatasourceLimiter("PROM_MAIN")
		require.NotNil(t, lim,
			"an accepted quota must take effect, or the API is still lying")
		require.Equal(t, rate.Limit(r), lim.Limit())
		require.Equal(t, b, lim.Burst())
	})

	// kind=lane must be refused outright now that the global lane is gone --
	// same reasoning: never accept a write that does nothing.
	t.Run("lane kind is rejected", func(t *testing.T) {
		s := newAdminTestService(t)
		c := adminPutCtx("lane", "default",
			map[string]any{"mode": "limited", "rate": r, "burst": b})
		require.Equal(t, http.StatusBadRequest,
			s.AdminPut(c).(*response.NormalResponse).Status(),
			"the global lane was removed; accepting the write would be a silent no-op")
	})
}

// TestIntegrationQuotaSources_DBOverridesIni covers the two-source layering.
//
// The ini is the deployed baseline (present from the first request, so a fresh
// environment is protected without anyone remembering to call the API); the DB
// is the runtime override (changeable during an incident without a restart).
// Three things must hold, and the third is the one that breaks silently.
func TestIntegrationQuotaSources_DBOverridesIni(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	s := newAdminTestService(t)
	// Deployed baseline: two datasources.
	s.cfg.IniQuotas = map[string]laneParams{
		"PROM_MAIN":     {rate: 350, burst: 420},
		"MYSQL_REPORTS": {rate: 50, burst: 60},
	}
	require.NoError(t, s.reloadRules(context.Background()))

	// 1. The ini value applies with no DB row at all.
	lim := s.getDatasourceLimiter("PROM_MAIN")
	require.NotNil(t, lim, "a deployed quota must apply without any DB row")
	require.Equal(t, rate.Limit(350), lim.Limit())
	require.Equal(t, 420, lim.Burst())

	// 2. A DB row overrides it, and the existing bucket is re-pointed rather
	//    than left on the old limit.
	r, b := int64(100), int64(120)
	require.NoError(t, s.store.upsert(context.Background(), &Rule{
		Kind: string(KindDatasource), Target: "PROM_MAIN", Mode: string(ModeLimited),
		Rate: &r, Burst: &b,
	}))
	require.NoError(t, s.reloadRules(context.Background()))

	require.Equal(t, rate.Limit(100), s.getDatasourceLimiter("PROM_MAIN").Limit(),
		"a DB rule must override the deployed value")
	require.Equal(t, 120, s.getDatasourceLimiter("PROM_MAIN").Burst())

	// The untouched datasource must keep its deployed value -- an override for
	// one must not disturb the baseline of another.
	require.Equal(t, rate.Limit(50), s.getDatasourceLimiter("MYSQL_REPORTS").Limit(),
		"overriding one datasource must not affect another's deployed quota")

	// 3. Deleting the row falls back to the ini value. This is the case that
	//    fails quietly if the snapshot is built by mutating the previous one
	//    instead of rebuilding from the baseline: the override would persist
	//    forever with no row to explain it, and no way to undo it short of a
	//    restart.
	require.NoError(t, s.store.delete(context.Background(),
		string(KindDatasource), "PROM_MAIN"))
	require.NoError(t, s.reloadRules(context.Background()))

	require.Equal(t, rate.Limit(350), s.getDatasourceLimiter("PROM_MAIN").Limit(),
		"deleting the DB rule must restore the deployed quota, not keep the override")
	require.Equal(t, 420, s.getDatasourceLimiter("PROM_MAIN").Burst())
}

// TestIntegrationQuotaStats_ReportsSource locks the provenance field.
//
// With two sources for the same number, an operator asking "did my override take
// effect?" has no way to tell from the limit alone -- an override that silently
// failed to apply looks identical to one that worked, if the values happen to be
// close. /stats answers it directly.
func TestIntegrationQuotaStats_ReportsSource(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	s := newAdminTestService(t)
	s.cfg.IniQuotas = map[string]laneParams{
		"FROM_INI": {rate: 350, burst: 420},
		"FROM_DB":  {rate: 10, burst: 20},
	}
	r, b := int64(77), int64(88)
	require.NoError(t, s.store.upsert(context.Background(), &Rule{
		Kind: string(KindDatasource), Target: "FROM_DB", Mode: string(ModeLimited),
		Rate: &r, Burst: &b,
	}))
	require.NoError(t, s.reloadRules(context.Background()))

	stats := s.datasourceStatusSnapshot(time.Now())

	ini, ok := stats["FROM_INI"].(map[string]any)
	require.True(t, ok, "the deployed quota must be reported")
	require.Equal(t, "ini", ini["source"])

	db, ok := stats["FROM_DB"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "db", db["source"],
		"an overridden quota must be reported as coming from the DB")
	require.Equal(t, float64(77), db["rate"],
		"and must report the effective value, not the one it replaced")
}

// TestIntegrationAdminPut_PartialUpdate covers the three states a field can be
// in, which is the whole of this endpoint's write semantics.
//
// Absent leaves the stored value alone, explicit null clears it, a value sets
// it. The first of those is what makes the endpoint safe to use: the common
// edit is changing one thing, and forgetting to restate the rest must not
// silently drop it.
//
// This replaced whole-row replacement plus a guard that refused any write which
// would drop a stored value. The guard worked, but it could not tell a slip
// from a deliberate clear, so clearing one field meant DELETE then PUT, leaving
// the identity on the deployment baseline in between. Nothing here needs that
// detour, and there is no window.
func TestIntegrationAdminPut_PartialUpdate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	seed := map[string]any{"mode": "limited", "rate": 10, "burst": 20, "concurrency": 5}

	cases := []struct {
		name  string
		body  map[string]any
		rate  any // nil means the field must be cleared
		burst any
		conc  any
	}{
		{
			name: "omitting concurrency keeps it",
			body: map[string]any{"mode": "limited", "rate": 30, "burst": 40},
			rate: 30, burst: 40, conc: 5,
		},
		{
			name: "omitting the QPS pair keeps it",
			body: map[string]any{"mode": "limited", "concurrency": 8},
			rate: 10, burst: 20, conc: 8,
		},
		{
			name: "explicit null clears concurrency and keeps QPS",
			body: map[string]any{"mode": "limited", "rate": 10, "burst": 20, "concurrency": nil},
			rate: 10, burst: 20, conc: nil,
		},
		{
			name: "explicit null clears the QPS pair and keeps concurrency",
			body: map[string]any{"mode": "limited", "rate": nil, "burst": nil, "concurrency": 5},
			rate: nil, burst: nil, conc: 5,
		},
		{
			name: "a body with only mode changes nothing",
			body: map[string]any{"mode": "limited"},
			rate: 10, burst: 20, conc: 5,
		},
		{
			name: "every field at once",
			body: map[string]any{"mode": "limited", "rate": 50, "burst": 60, "concurrency": 9},
			rate: 50, burst: 60, conc: 9,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newAdminTestService(t)
			ctx := context.Background()
			require.Equal(t, http.StatusOK,
				s.AdminPut(adminPutCtx("user", "20", seed)).Status())

			resp := s.AdminPut(adminPutCtx("user", "20", tc.body))
			require.Equal(t, http.StatusOK, resp.Status())

			stored, err := s.store.get(ctx, "user", "20")
			require.NoError(t, err)
			requireField(t, "rate", tc.rate, stored.Rate)
			requireField(t, "burst", tc.burst, stored.Burst)
			requireField(t, "concurrency", tc.conc, stored.Concurrency)
		})
	}
}

// rawInt builds the JSON body form of a set field, for tests that construct
// UpsertBody directly rather than going through a map.
func rawInt(v int64) json.RawMessage {
	return json.RawMessage(strconv.FormatInt(v, 10))
}

func requireField(t *testing.T, name string, want any, got *int64) {
	t.Helper()
	if want == nil {
		require.Nil(t, got, "%s should have been cleared", name)
		return
	}
	require.NotNil(t, got, "%s should have been kept or set", name)
	require.EqualValues(t, want, *got, name)
}

// TestStorePartialUpdate_RejectsInvalidMergedPair is the deterministic half of
// the row-lock invariant. The store reads rate=10/burst=20, applies a concurrent
// writer's stale intention to set rate=80, validates 80/20 inside the same
// transaction, and must roll it back.
//
// The actual two-writer serialisation cannot be proved on SQLite: its XORM
// dialect drops FOR UPDATE and its table-level write lock randomly surfaced a
// 500 in 3 of 8 runs even with retries. Real MySQL concurrency is covered by
// scripts/bytedance/boe_verify_rowlock.sh T2; the test here pins the portable
// contract the locked writer executes once serialised.
func TestStorePartialUpdate_RejectsInvalidMergedPair(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	s := newAdminTestService(t)
	ctx := context.Background()
	require.NoError(t, s.store.upsert(ctx, &Rule{
		Kind: string(KindUser), Target: "90", Mode: string(ModeLimited),
		Rate: ptr64(10), Burst: ptr64(20),
	}))

	written, err := s.store.upsertPartial(ctx, string(KindUser), "90", string(ModeLimited), nil,
		fieldUpdate{present: true, value: 80}, fieldUpdate{}, fieldUpdate{},
		func(rate, burst, conc *int64) string {
			return validateMergedRule(KindUser, ModeLimited, rate, burst, conc, bounds{DefaultMaxRuleRate, DefaultMaxRuleBurst, DefaultMaxRuleConcurrency})
		})
	require.Nil(t, written)
	var invalid *ErrInvalidMergedRule
	require.ErrorAs(t, err, &invalid)
	require.Contains(t, invalid.Reason, "merged result: rate=80 burst=20")

	stored, getErr := s.store.get(ctx, string(KindUser), "90")
	require.NoError(t, getErr)
	require.EqualValues(t, 10, *stored.Rate, "the invalid transaction must roll back")
	require.EqualValues(t, 20, *stored.Burst)
}

// TestSanitizeParams_DoesNotCheckThePair pins why the check above has to happen
// at write time.
//
// sanitizeParams is the last thing between a stored rule and rate.NewLimiter,
// and it deliberately does not verify burst >= rate -- an invalid pair is
// applied rather than skipped. If that ever changes, the write-time check
// becomes belt-and-braces rather than the only guard; until then it is load
// bearing, and this test is here so nobody removes it believing otherwise.
func TestSanitizeParams_DoesNotCheckThePair(t *testing.T) {
	p, ok := sanitizeParams(80, 20, DefaultMaxRuleRate, DefaultMaxRuleBurst)
	require.True(t, ok,
		"sanitizeParams accepts burst < rate; the pairing check must happen before storage")
	require.Equal(t, 80, p.rate)
	require.Equal(t, 20, p.burst)
}

// TestIntegrationAdminPut_ValidatesTheMergedRule checks that validation judges
// the rule as it will be stored, not the body in isolation.
//
// This is where partial update could go wrong: "rate=30" alone is fine when a
// burst is already stored and invalid when it is not, and only the merged view
// can tell the difference. Validating the body alone would accept the second
// case and store a rule reloadRules silently skips -- an operator would see
// 200 and no limit.
func TestIntegrationAdminPut_ValidatesTheMergedRule(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	cases := []struct {
		name       string
		seed       map[string]any
		body       map[string]any
		wantStatus int
		wantMsg    string
	}{
		{
			name:       "rate alone is accepted when a burst is stored",
			seed:       map[string]any{"mode": "limited", "rate": 10, "burst": 100},
			body:       map[string]any{"mode": "limited", "rate": 30},
			wantStatus: http.StatusOK,
		},
		{
			name:       "rate alone is refused when no burst is stored",
			seed:       map[string]any{"mode": "limited", "concurrency": 5},
			body:       map[string]any{"mode": "limited", "rate": 30},
			wantStatus: http.StatusBadRequest,
			wantMsg:    "rate and burst must both be set",
		},
		{
			name:       "burst below the stored rate is refused",
			seed:       map[string]any{"mode": "limited", "rate": 100, "burst": 200},
			body:       map[string]any{"mode": "limited", "burst": 50},
			wantStatus: http.StatusBadRequest,
			wantMsg:    "burst must be", // JSON escapes ">=" as \u003e=
		},
		{
			name:       "clearing every field is refused",
			seed:       map[string]any{"mode": "limited", "rate": 10, "burst": 20, "concurrency": 5},
			body:       map[string]any{"mode": "limited", "rate": nil, "burst": nil, "concurrency": nil},
			wantStatus: http.StatusBadRequest,
			wantMsg:    "needs rate and burst, a concurrency cap, or both",
		},
		{
			name:       "a non-integer value is refused rather than ignored",
			seed:       map[string]any{"mode": "limited", "rate": 10, "burst": 20},
			body:       map[string]any{"mode": "limited", "rate": "thirty"},
			wantStatus: http.StatusBadRequest,
			wantMsg:    "rate must be an integer or null",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newAdminTestService(t)
			require.Equal(t, http.StatusOK,
				s.AdminPut(adminPutCtx("user", "21", tc.seed)).Status())

			resp := s.AdminPut(adminPutCtx("user", "21", tc.body))
			require.Equal(t, tc.wantStatus, resp.Status())
			if tc.wantMsg != "" {
				require.Contains(t, string(resp.Body()), tc.wantMsg)
			}
		})
	}
}

// deleteReadFailureDB fails only the pre-delete read; writes would still work.
// A fully broken DB would mask the bug because DELETE would also fail.
type deleteReadFailureDB struct {
	db.DB
	writes int
}

func (d *deleteReadFailureDB) WithDbSession(context.Context, sqlstore.DBTransactionFunc) error {
	return context.DeadlineExceeded
}

func (d *deleteReadFailureDB) WithTransactionalDbSession(ctx context.Context, fn sqlstore.DBTransactionFunc) error {
	d.writes++
	return d.DB.WithTransactionalDbSession(ctx, fn)
}

func TestIntegrationAdminDelete_ReadFailurePreservesRule(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	s := newAdminTestService(t)
	ctx := context.Background()
	require.Equal(t, http.StatusOK, s.AdminPut(adminPutCtx("user", "22",
		map[string]any{"mode": "limited", "rate": 10, "burst": 20, "concurrency": 5})).Status())
	before, err := s.store.get(ctx, "user", "22")
	require.NoError(t, err)
	snap := s.rulesPtr.Load()
	originalDB := s.store.db
	failing := &deleteReadFailureDB{DB: originalDB}
	s.store.db = failing
	defer func() { s.store.db = originalDB }()

	delCtx := adminPutCtx("user", "22", nil)
	delCtx.Req.Method = http.MethodDelete
	resp := s.AdminDelete(delCtx)
	s.store.db = originalDB
	after, err := s.store.get(ctx, "user", "22")
	require.NoError(t, err)
	require.Equal(t, http.StatusInternalServerError, resp.Status())
	require.Contains(t, string(resp.Body()), "failed to read the existing rule")
	require.Zero(t, failing.writes, "a failed audit read must stop before DELETE")
	require.Equal(t, before, after, "the stored rule must survive the failed request")
	require.Same(t, snap, s.rulesPtr.Load(), "the effective rule must not change")
}

// TestIntegrationAdminDelete_ReloadsWithoutTheRule pins that removing a rule
// takes effect immediately rather than at the next 30s reload.
//
// DELETE now means only one thing -- drop every override for this identity --
// and it is a single request, so there is no window. Clearing one field while
// keeping the rest is a PUT with that field null; DELETE is no longer part of
// editing a rule, which is what previously left an identity on the deployment
// baseline between the delete and the write.
func TestIntegrationAdminDelete_ReloadsWithoutTheRule(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	s := newAdminTestService(t)
	ctx := context.Background()

	require.Equal(t, http.StatusOK, s.AdminPut(adminPutCtx("user", "22",
		map[string]any{"mode": "limited", "rate": 10, "burst": 20, "concurrency": 5})).Status())
	require.EqualValues(t, 5, s.concurrencyLimit(s.rulesPtr.Load(), "user:22"),
		"the cap should be live after the write")

	req := httptest.NewRequest(http.MethodDelete,
		"/api/admin/datasource-rate-limits/user/22", nil)
	req = web.SetURLParams(req, map[string]string{":kind": "user", ":target": "22"})
	rec := httptest.NewRecorder()
	delCtx := &contextmodel.ReqContext{
		SignedInUser: &user.SignedInUser{UserID: 1, Login: "admin"},
		Context:      &web.Context{Req: req, Resp: web.NewResponseWriter(req.Method, rec)},
	}
	require.Equal(t, http.StatusOK, s.AdminDelete(delCtx).Status())

	// Both layers are back to the deployment baseline, immediately. Asserted
	// rather than glossed over: an operator clearing one value should know the
	// other goes with it until the rule is rewritten.
	require.EqualValues(t, s.cfg.DefaultUserConcurrency,
		s.concurrencyLimit(s.rulesPtr.Load(), "user:22"),
		"the cap must fall back the moment the rule is deleted")
	_, err := s.store.get(ctx, "user", "22")
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, s.AdminPut(adminPutCtx("user", "22",
		map[string]any{"mode": "limited", "concurrency": 7})).Status())
	stored, err := s.store.get(ctx, "user", "22")
	require.NoError(t, err)
	require.Nil(t, stored.Rate, "the QPS override was meant to go")
	require.EqualValues(t, 7, *stored.Concurrency)
}

// TestAdminPut_SwitchKindsRequireTheDefaultTarget covers a reviewer-found gap.
//
// The four deployment-wide switches are resolved by reloadRules on r.Kind
// alone; r.Target is never read. So a row written under a mistyped target is
// not the harmless no-op that a mistyped kind=default row would be -- it takes
// effect deployment-wide. Two rows of one kind disagreeing then resolve by
// whichever store.list returns last, and list does no ordering, so the switch
// would follow row order rather than intent.
//
// Found because mode=unlimited needs no rate/burst: the "needs rate and burst"
// check happens to mask this for mode=limited, which made the gap look absent
// until a rule that skips that check was tried.
func TestIntegrationAdminPut_SwitchKindsRequireTheDefaultTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	for _, kind := range []string{
		"activation", "concurrency_activation", "enforcement", "concurrency_enforcement",
	} {
		t.Run(kind, func(t *testing.T) {
			s := newAdminTestService(t)

			// mode=unlimited carries no rate/burst, so it reaches the target
			// check instead of being turned away by the pairing rule first.
			resp := s.AdminPut(adminPutCtx(kind, "typo", map[string]any{"mode": "unlimited"}))
			require.Equal(t, http.StatusBadRequest, resp.Status(),
				"a non-default target must be refused: reloadRules ignores Target, "+
					"so this row would act as a second deployment-wide switch")

			// Nothing may have been stored, or a later reload would apply it.
			stored, err := s.store.get(context.Background(), kind, "typo")
			require.NoError(t, err)
			require.Nil(t, stored, "a refused switch row must not reach the table")

			// The documented target still works.
			require.Equal(t, http.StatusOK,
				s.AdminPut(adminPutCtx(kind, DefaultTarget,
					map[string]any{"mode": "unlimited"})).Status())
		})
	}
}

// TestIntegrationAdminPut_SwitchKindsTakeModeAlone covers a gap that only a
// real PUT found.
//
// A switch kind's entire payload is its mode -- there is no rate, burst or
// concurrency to send. The "mode=limited needs rate and burst" rule exempted
// the two enforcement kinds by name, so when the activation kinds were added
// they fell under it: PUT /activation/default {"mode":"limited"} returned 400
// and there was no way to turn the layer back on through the API. Turning it
// off worked, because mode=unlimited skips that rule -- so the switch was
// one-way.
//
// The exemption is now a predicate shared with validateTarget, rather than a
// list repeated at each site, since the list has grown twice and a site was
// missed both times.
func TestIntegrationAdminPut_SwitchKindsTakeModeAlone(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	for _, kind := range []string{
		"activation", "concurrency_activation", "enforcement", "concurrency_enforcement",
	} {
		for _, mode := range []string{"limited", "unlimited"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				s := newAdminTestService(t)
				require.Equal(t, http.StatusOK,
					s.AdminPut(adminPutCtx(kind, DefaultTarget,
						map[string]any{"mode": mode})).Status(),
					"a switch carries only a mode; both directions must be writable "+
						"or the switch is one-way")
			})
		}
		t.Run(kind+"/rejects-blocked", func(t *testing.T) {
			s := newAdminTestService(t)
			ctx := context.Background()
			for _, existing := range []bool{false, true} {
				if existing {
					require.Equal(t, http.StatusOK, s.AdminPut(adminPutCtx(kind, DefaultTarget,
						map[string]any{"mode": "limited"})).Status())
				}
				before, err := s.store.get(ctx, kind, DefaultTarget)
				require.NoError(t, err)
				snap := s.rulesPtr.Load()
				resp := s.AdminPut(adminPutCtx(kind, DefaultTarget, map[string]any{"mode": "blocked"}))
				require.Equal(t, http.StatusBadRequest, resp.Status(), "existing=%v", existing)
				after, err := s.store.get(ctx, kind, DefaultTarget)
				require.NoError(t, err)
				require.Equal(t, before, after, "rejection must not create or overwrite a switch")
				require.Same(t, snap, s.rulesPtr.Load(), "rejection must leave runtime state unchanged")
			}
		})
	}
	// The inverse: a switch kind must not accept numbers either. The two
	// activation kinds used to store rate/burst/concurrency that reloadRules
	// ignores, so the PUT returned 200 while no limit changed.
	for _, kind := range []string{
		"activation", "concurrency_activation", "enforcement", "concurrency_enforcement",
	} {
		for _, body := range []map[string]any{
			{"mode": "limited", "rate": 20},
			{"mode": "limited", "burst": 40},
			{"mode": "limited", "concurrency": 4},
		} {
			t.Run(kind+"/rejects-numbers", func(t *testing.T) {
				s := newAdminTestService(t)
				require.Equal(t, http.StatusBadRequest, s.AdminPut(adminPutCtx(kind, DefaultTarget, body)).Status(),
					"a switch takes mode only; persisting ignored numbers would falsely report success")
				got, err := s.store.get(context.Background(), kind, DefaultTarget)
				require.NoError(t, err)
				require.Nil(t, got, "a rejected switch PUT must not leave a row behind")
			})
		}
	}
}
