package dsratelimit

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/grafana/grafana/pkg/services/user"
	"github.com/stretchr/testify/require"
)

// multiDsBody builds a /api/ds/query body charging `small` one query and `big`
// thirty, so the request total and either datasource's share are far apart.
func multiDsBody(small, big string) []byte {
	b := `{"queries":[{"datasource":{"uid":"` + small + `"}}`
	for i := 0; i < 30; i++ {
		b += `,{"datasource":{"uid":"` + big + `"}}`
	}
	return []byte(b + `]}`)
}

// A denial must be judged by what the refusing bucket was asked for, not by the
// request total.
//
// The two diverge as soon as a panel spans datasources. A request charging
// SMALL one token and BIG thirty has n=31; comparing that against SMALL's
// burst=2 declares a request that can never succeed, when the truth is "wait
// about a second". Everything downstream then agrees on the wrong answer: the
// metrics label gains _oversized, the deny log says permanent=true, the user is
// told to split the dashboard, and Retry-After is computed from a deficit that
// this bucket was never asked to cover.
//
// Found in review by writing exactly this case; reading the code did not reveal
// it, because each of the four sites looks correct in isolation.
func TestOversized_JudgedPerDeniedBucketNotRequestTotal(t *testing.T) {
	cfg := defaultCfg()
	cfg.ShadowMode = false
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 1000, 1000 // keep the identity bucket out of the way

	s := newTestService(cfg,
		dsQuotaRule("SMALL", 2, 2),
		dsQuotaRule("BIG", 1000, 1000),
	)
	u := &user.SignedInUser{UserID: 1}

	// Drain SMALL so the multi-datasource request below is refused by it.
	for i := 0; i < 3; i++ {
		c, _ := buildCtx("POST", "/api/ds/query",
			[]byte(`{"queries":[{"datasource":{"uid":"SMALL"}}]}`), u)
		s.Middleware(c)
	}

	c, rec := buildCtx("POST", "/api/ds/query", multiDsBody("SMALL", "BIG"), u)
	s.Middleware(c)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	msg, _ := resp["message"].(string)

	require.NotContains(t, msg, "too small for this request",
		"SMALL was charged 1 against burst=2, so this is throttling, not a "+
			"permanently impossible request")
	require.NotContains(t, msg, "Split the dashboard",
		"telling the user to shrink the request cannot help when the request "+
			"already fits")
	require.Contains(t, msg, "try again",
		"a transient denial must say when to retry")

	// Retry-After must cover SMALL's deficit (~1 token at 2/s), not the 31 the
	// whole request happened to cost.
	require.Equal(t, "1", rec.Header().Get("Retry-After"),
		"the wait must be derived from what this bucket was asked for")
}

// The permanent case must still be reported as permanent: a single datasource
// asked for more than its own burst can never be admitted, however long the
// caller waits, and saying "try again" there would send them into a retry loop.
func TestOversized_StillPermanentWhenOneBucketCannotEverAdmit(t *testing.T) {
	cfg := defaultCfg()
	cfg.ShadowMode = false
	cfg.DefaultUserRate, cfg.DefaultUserBurst = 1000, 1000

	s := newTestService(cfg, dsQuotaRule("TINY", 2, 2))
	u := &user.SignedInUser{UserID: 1}

	// Five queries against a bucket whose burst is 2.
	body := []byte(`{"queries":[` +
		`{"datasource":{"uid":"TINY"}},{"datasource":{"uid":"TINY"}},` +
		`{"datasource":{"uid":"TINY"}},{"datasource":{"uid":"TINY"}},` +
		`{"datasource":{"uid":"TINY"}}]}`)

	c, rec := buildCtx("POST", "/api/ds/query", body, u)
	s.Middleware(c)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	msg, _ := resp["message"].(string)
	require.Contains(t, msg, "too small for this request",
		"5 tokens against burst=2 can never be admitted; the fix must not "+
			"turn every permanent failure into a retry suggestion")
}
