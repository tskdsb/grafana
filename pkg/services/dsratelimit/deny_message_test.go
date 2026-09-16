package dsratelimit

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/user"
)

// The 429 body was previously untested: nothing asserted on it, so the fixed
// "datasource rate limit exceeded" could have said anything at all -- including
// nothing -- and every test would still have passed. These lock the sentence a
// user actually reads, since the frontend renders err.data.message verbatim
// (backend_srv.ts:321).

// decodeDeny pulls the JSON body out of a recorded 429.
func decodeDeny(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body), "429 body must be JSON: %s", raw)
	return body
}

func TestDenyMessage_PersonalQPS_NamesLimitAndWait(t *testing.T) {
	// rate=1/burst=1 so the second request is refused with the identity bucket
	// as the culprit.
	one := int64(1)
	s := newTestService(Config{Enabled: true, DefaultUserRate: 1, DefaultUserBurst: 1},
		&Rule{Kind: string(KindUser), Target: "5", Mode: string(ModeLimited), Rate: &one, Burst: &one})
	u := &user.SignedInUser{UserID: 5}

	c, _ := buildCtx("POST", "/api/datasources/proxy/uid/PROM", nil, u)
	s.Middleware(c)

	c, rec := buildCtx("POST", "/api/datasources/proxy/uid/PROM", nil, u)
	s.Middleware(c)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)

	body := decodeDeny(t, rec.Body.Bytes())
	msg, _ := body["message"].(string)

	// The four things a throttled user needs. Asserted as separate checks so a
	// failure names which one regressed rather than diffing a whole sentence.
	require.Contains(t, msg, "Your personal", "must say whose limit fired: %q", msg)
	require.Contains(t, msg, "query rate", "must say which kind of limit: %q", msg)
	require.Contains(t, msg, "1 queries/sec", "must quote the actual limit: %q", msg)
	require.Contains(t, msg, "try again in", "must say what to do next: %q", msg)

	// Machine-readable twins, so a client need not parse prose.
	require.Equal(t, "personal", body["scope"])
	require.Equal(t, "qps", body["kind"])
	require.EqualValues(t, 1, body["limit"])

	// The old message must be gone, not merely supplemented.
	require.NotEqual(t, "datasource rate limit exceeded", msg)
}

func TestDenyMessage_DatasourceQuota_NamesTheDatasourceNotTheUser(t *testing.T) {
	// Identity limit generous, datasource quota exhausted: the message must
	// point at the datasource, because telling the user "your limit" would send
	// them to fix something that is not the cause.
	s := newTestService(defaultCfg(), dsQuotaRule("PROM_MAIN", 1, 1))
	u := &user.SignedInUser{UserID: 9}

	c, _ := buildCtx("POST", "/api/datasources/proxy/uid/PROM_MAIN", nil, u)
	s.Middleware(c)

	c, rec := buildCtx("POST", "/api/datasources/proxy/uid/PROM_MAIN", nil, u)
	s.Middleware(c)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)

	body := decodeDeny(t, rec.Body.Bytes())
	msg, _ := body["message"].(string)

	// The sentence must attribute the denial to the datasource, and must not
	// contain the UID: a 36-character hex string identifies nothing the reader
	// can act on and crowds out the part that matters. Resolving it to a display
	// name is not an option either -- that needs a cache lookup that falls
	// through to SQL exactly during the surge this limiter exists to survive.
	require.Contains(t, msg, "This datasource's", "must attribute the denial to the datasource: %q", msg)
	require.NotContains(t, msg, "PROM_MAIN", "a raw UID is noise in a user-facing sentence: %q", msg)
	require.Equal(t, "datasource", body["scope"])
	// The UID still belongs in the machine-readable field, for whoever debugs.
	require.Equal(t, "PROM_MAIN", body["datasource"])
	// Must report the datasource's limit, not the caller's much larger one.
	require.EqualValues(t, 1, body["limit"], "must quote the limit that refused, not the caller's")
	// Must NOT blame the caller's own quota.
	require.NotContains(t, msg, "Your personal", "datasource denial must not read as a personal limit: %q", msg)
}

func TestDenyMessage_Blocked_DoesNotPromiseARetry(t *testing.T) {
	// mode=blocked never succeeds by waiting, so advice to retry would send the
	// caller into a loop that cannot terminate. Also the default for anonymous
	// traffic, so this is a path real users hit.
	s := newTestService(defaultCfg(),
		&Rule{Kind: string(KindUser), Target: "3", Mode: string(ModeBlocked)})
	c, rec := buildCtx("POST", "/api/datasources/proxy/uid/PROM", nil, &user.SignedInUser{UserID: 3})
	s.Middleware(c)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)

	body := decodeDeny(t, rec.Body.Bytes())
	msg, _ := body["message"].(string)

	require.Equal(t, "blocked", body["scope"])
	require.NotContains(t, strings.ToLower(msg), "try again",
		"blocked is permanent; promising a retry is misleading: %q", msg)
	require.Contains(t, msg, "admin", "must say who can change it: %q", msg)
}

func TestDenyMessage_OversizedRequest_TellsUserToShrinkNotWait(t *testing.T) {
	// A request costing more than burst is refused on every attempt
	// (rate.go:371 gates on n <= burst). Waiting cannot help, so the advice has
	// to change -- this is the case most likely to produce an infinite retry.
	in := denyMessageInput{
		Scope:     scopePersonal,
		Kind:      denyKindQPS,
		Limit:     20,
		Permanent: true,
		Cost:      35,
		Burst:     20,
	}
	msg := in.String()

	require.Contains(t, msg, "35", "must quote what the request needs: %q", msg)
	require.Contains(t, msg, "20", "must quote the ceiling: %q", msg)
	require.NotContains(t, strings.ToLower(msg), "try again in",
		"an over-burst request can never succeed by waiting: %q", msg)
	require.Contains(t, strings.ToLower(msg), "fewer", "must suggest shrinking: %q", msg)
}

func TestDenyMessage_BodyWaitMatchesRetryAfterHeader(t *testing.T) {
	// Header and prose come from one value; if they diverge, a client honouring
	// Retry-After and a human reading the sentence disagree about when to retry.
	one := int64(1)
	s := newTestService(Config{Enabled: true, DefaultUserRate: 1, DefaultUserBurst: 1},
		&Rule{Kind: string(KindUser), Target: "8", Mode: string(ModeLimited), Rate: &one, Burst: &one})
	u := &user.SignedInUser{UserID: 8}

	c, _ := buildCtx("POST", "/api/datasources/proxy/uid/PROM", nil, u)
	s.Middleware(c)
	c, rec := buildCtx("POST", "/api/datasources/proxy/uid/PROM", nil, u)
	s.Middleware(c)

	hdr := rec.Header().Get("Retry-After")
	require.NotEmpty(t, hdr)
	secs, err := strconv.Atoi(hdr)
	require.NoError(t, err)

	msg, _ := decodeDeny(t, rec.Body.Bytes())["message"].(string)
	require.Contains(t, msg, strconv.Itoa(secs),
		"body wait must match Retry-After=%d: %q", secs, msg)
}

func TestDenyMessage_ConcurrentKind_UsesDistinctWording(t *testing.T) {
	// QPS and concurrency call for opposite remedies (slow down vs. run fewer
	// at once), so they must not be describable by the same sentence. Guards
	// the vocabulary the concurrency limiter will reuse.
	qps := denyMessageInput{Scope: scopePersonal, Kind: denyKindQPS, Limit: 20, RetryAfter: time.Second}
	conc := denyMessageInput{Scope: scopePersonal, Kind: denyKindConcurrent, Limit: 20, RetryAfter: time.Second}

	require.NotEqual(t, qps.String(), conc.String(),
		"the two layers must not produce identical text")
	require.Contains(t, conc.String(), "concurrent request")
	require.Contains(t, conc.String(), "at a time", "must disambiguate 20-at-once from 20/sec")
	require.Contains(t, qps.String(), "queries/sec")
	require.Equal(t, "concurrent", conc.kindLabel())
}

func TestDenyMessage_UnknownLimitOmitsTheNumber(t *testing.T) {
	// Limit<=0 means "not known here"; printing "(0 queries/sec)" would read as
	// "your limit is zero", which is both wrong and alarming.
	in := denyMessageInput{Scope: scopePersonal, Kind: denyKindQPS, Limit: 0, RetryAfter: 2 * time.Second}
	msg := in.String()
	require.NotContains(t, msg, "(0", "must not advertise a zero limit: %q", msg)
	require.Contains(t, msg, "try again in 2 seconds")
}

func TestDenyMessage_SingularSecond(t *testing.T) {
	// "1 seconds" is the kind of detail that makes an error message look
	// machine-generated and lowers trust in it.
	in := denyMessageInput{Scope: scopePersonal, Kind: denyKindQPS, Limit: 5, RetryAfter: time.Second}
	require.Contains(t, in.String(), "1 second.")
	require.NotContains(t, in.String(), "1 seconds")
}

func TestDenyMessage_NeverLeaksInternalIdentity(t *testing.T) {
	// The response is visible to whoever made the request; user IDs and IPs
	// belong in the server-side deny log, not here.
	s := newTestService(defaultCfg(), dsQuotaRule("PROM_MAIN", 1, 1))
	u := &user.SignedInUser{UserID: 424242, Login: "secret.person"}

	c, _ := buildCtx("POST", "/api/datasources/proxy/uid/PROM_MAIN", nil, u)
	s.Middleware(c)
	c, rec := buildCtx("POST", "/api/datasources/proxy/uid/PROM_MAIN", nil, u)
	s.Middleware(c)

	raw := rec.Body.String()
	require.NotContains(t, raw, "424242", "must not leak the user ID: %s", raw)
	require.NotContains(t, raw, "secret.person", "must not leak the login: %s", raw)
}

func TestDenyMessage_HeaderCarriesClosedSetNotClientText(t *testing.T) {
	// X-RateLimit-Lane used to carry the datasource UID, which is client-supplied
	// text: validateTarget bounds a UID's length but never its charset, so a
	// newline or markup reached the header verbatim. Not header injection --
	// net/http rewrites CR/LF on the wire, verified with a raw TCP read -- but
	// an unread header is no place for arbitrary caller input.
	//
	// Scope is one of three fixed words, so the header cannot carry a surprise.
	// The UID is still in the body, JSON-escaped.
	hostile := "PROM\r\nX-Injected: evil"
	s := newTestService(defaultCfg(), dsQuotaRule(hostile, 1, 1))
	u := &user.SignedInUser{UserID: 77}
	body, err := json.Marshal(map[string]any{
		"queries": []map[string]any{{"datasource": map[string]any{"uid": hostile}}},
	})
	require.NoError(t, err)

	c, _ := buildCtx("POST", "/api/ds/query", body, u)
	s.Middleware(c)
	c, rec := buildCtx("POST", "/api/ds/query", body, u)
	s.Middleware(c)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)

	require.Empty(t, rec.Header().Get("X-RateLimit-Lane"), "the lane header names a concept that no longer exists")
	require.Equal(t, "datasource", rec.Header().Get("X-RateLimit-Scope"))

	for name := range rec.Header() {
		require.NotContains(t, strings.ToLower(name), "injected")
		require.NotContains(t, rec.Header().Get(name), "\n", "header %s must not contain a newline", name)
		require.NotContains(t, rec.Header().Get(name), "\r", "header %s must not contain a CR", name)
	}
}

func TestDenyMessage_NeverEmptyOrMalformed(t *testing.T) {
	// Swept adversarially: every scope/kind combination, plus zero and absurd
	// values, must still yield one clean printable line. A message that comes
	// out empty or with a %!(EXTRA) artifact is worse than the fixed string it
	// replaced, because it looks like a server fault.
	for _, sc := range []denyScope{scopePersonal, scopeDatasource, scopeBlocked} {
		for _, kd := range []denyKind{denyKindQPS, denyKindConcurrent} {
			for _, perm := range []bool{false, true} {
				for _, ra := range []time.Duration{0, -5 * time.Second, time.Millisecond, time.Hour} {
					in := denyMessageInput{Scope: sc, Kind: kd, Limit: 20, Target: "PROM", RetryAfter: ra, Permanent: perm, Cost: 35, Burst: 20}
					msg := in.String()
					require.NotEmpty(t, msg)
					require.NotContains(t, msg, "%!", "formatting artifact: %q", msg)
					require.NotContains(t, msg, "in -", "negative wait: %q", msg)
					require.NotContains(t, msg, "\n", "must stay one line: %q", msg)
				}
			}
		}
	}
}

func TestDenyMessage_BodyNamesTheDatasourceOnlyWhenOneIsResponsible(t *testing.T) {
	// The field used to be called `lane` and was always present. Both were
	// wrong: the value is a datasource UID, and lanes no longer exist. A
	// personal denial has no datasource to name, so the key is absent rather
	// than empty -- absent is unambiguous, "" reads as a datasource named "".
	u := &user.SignedInUser{UserID: 91}

	// Personal bucket: rate 1/burst 1, so the second request is denied by the
	// user's own limit and no datasource is implicated.
	cfg := defaultCfg()
	cfg.DefaultUserRate = 1
	cfg.DefaultUserBurst = 1
	s := newTestService(cfg)
	c, _ := buildCtx("POST", dsQueryPath, dsQueryBodyFor("SOME_DS"), u)
	s.Middleware(c)
	c, rec := buildCtx("POST", dsQueryPath, dsQueryBodyFor("SOME_DS"), u)
	s.Middleware(c)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)

	var personal map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &personal))
	require.NotContains(t, personal, "lane", "lane names a deleted concept")
	require.NotContains(t, personal, "datasource", "a personal denial has no datasource to blame")
	require.Equal(t, "personal", personal["scope"])

	// Datasource quota: generous personal limit, tight datasource quota, so the
	// datasource is the one that refuses and must be named.
	s2 := newTestService(defaultCfg(), dsQuotaRule("PROM_X", 1, 1))
	c, _ = buildCtx("POST", dsQueryPath, dsQueryBodyFor("PROM_X"), u)
	s2.Middleware(c)
	c, rec = buildCtx("POST", dsQueryPath, dsQueryBodyFor("PROM_X"), u)
	s2.Middleware(c)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)

	var ds map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &ds))
	require.NotContains(t, ds, "lane")
	require.Equal(t, "PROM_X", ds["datasource"])
	require.Equal(t, "datasource", ds["scope"])
}

// One range query against the named datasource: costs exactly 1 token, so the
// arithmetic in the tests above stays readable.
func dsQueryBodyFor(uid string) []byte {
	return []byte(`{"queries":[{"range":true,"datasource":{"uid":"` + uid + `"}}]}`)
}

func TestDenyMessage_ScopeSurvivesADenyReasonRename(t *testing.T) {
	// scope is derived from denyTarget, not from matching denyReason against
	// "datasource". denyReason is a metrics label that already grows a suffix
	// (_oversized), so a string match would silently rot: scope would fall back
	// to personal and the message would blame the caller for a backend's quota.
	//
	// The oversized variant is the case that would break first, so it is the one
	// asserted: cost above burst, denied permanently, still scope=datasource.
	u := &user.SignedInUser{UserID: 92}
	s := newTestService(defaultCfg(), dsQuotaRule("PROM_Y", 2, 2))

	// 5 range queries against a burst-2 datasource: over burst, so permanently
	// refused, and denyReason becomes "datasource_oversized".
	body := []byte(`{"queries":[` +
		`{"range":true,"datasource":{"uid":"PROM_Y"}},` +
		`{"range":true,"datasource":{"uid":"PROM_Y"}},` +
		`{"range":true,"datasource":{"uid":"PROM_Y"}},` +
		`{"range":true,"datasource":{"uid":"PROM_Y"}},` +
		`{"range":true,"datasource":{"uid":"PROM_Y"}}]}`)

	c, rec := buildCtx("POST", dsQueryPath, body, u)
	s.Middleware(c)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)

	var got map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, "datasource", got["scope"], "an oversized datasource denial is still a datasource denial")
	require.Equal(t, "PROM_Y", got["datasource"])
	require.Equal(t, "datasource", rec.Header().Get("X-RateLimit-Scope"))
	// Permanent: must not promise a retry that can never succeed.
	msg, _ := got["message"].(string)
	require.Contains(t, msg, "too small for this request")
	require.NotContains(t, msg, "try again")
}
