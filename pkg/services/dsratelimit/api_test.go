package dsratelimit

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
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
			map[string]any{"mode": "limited", "rate": MaxRuleRate + 1, "burst": 100}, http.StatusBadRequest},
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
