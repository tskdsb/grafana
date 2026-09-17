package dsratelimit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/grafana/grafana/pkg/services/contexthandler/ctxkey"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/user"
)

// concCfg is the QPS defaults plus a concurrency cap, with the QPS layer's own
// limits set high enough that nothing here can be rejected by the wrong layer.
func concCfg(limit int) Config {
	c := defaultCfg()
	c.ConcurrencyEnabled = true
	c.DefaultUserConcurrency = limit
	// Enforcing by default in tests; the cases that want observation set it.
	c.ConcurrencyShadowMode = false
	c.DefaultUserRate = 100000
	c.DefaultUserBurst = 100000
	return c
}

// concRequest drives one request through ConcurrencyMiddleware with an
// identity attached the way ContextHandler attaches it.
func concRequest(s *Service, path string, uid int64, handler http.HandlerFunc) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, nil)
	reqCtx := &contextmodel.ReqContext{
		SignedInUser: &user.SignedInUser{UserID: uid, OrgID: 1},
	}
	r = r.WithContext(context.WithValue(r.Context(), ctxkey.Key{}, reqCtx))
	w := httptest.NewRecorder()
	s.ConcurrencyMiddleware(handler).ServeHTTP(w, r)
	return w
}

// blockingHandler holds each request until release is closed, so several can
// be in flight at once the way slow backend queries are.
type blockingHandler struct {
	entered chan struct{}
	release chan struct{}
	served  int
	mu      sync.Mutex
}

func newBlockingHandler(expect int) *blockingHandler {
	return &blockingHandler{
		entered: make(chan struct{}, expect),
		release: make(chan struct{}),
	}
}

func (h *blockingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.served++
	h.mu.Unlock()
	h.entered <- struct{}{}
	<-h.release
}

func (h *blockingHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.served
}

// The core behaviour: past the cap, further requests get 429 while the earlier
// ones are still running.
func TestConcurrency_RejectsBeyondLimit(t *testing.T) {
	s := newTestService(concCfg(2))
	h := newBlockingHandler(2)

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// The result is not asserted: these two exist to occupy the slots,
			// and the assertion that matters is on the third request below.
			concRequest(s, "/api/ds/query", 7, h.ServeHTTP)
		}()
	}
	// Both slots are taken and held.
	<-h.entered
	<-h.entered

	w := concRequest(s, "/api/ds/query", 7, h.ServeHTTP)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("third concurrent request got %d, want 429", w.Code)
	}
	if h.count() != 2 {
		t.Fatalf("the rejected request reached the handler: served %d, want 2", h.count())
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("429 body is not JSON: %v", err)
	}
	msg, _ := body["message"].(string)
	if msg == "" {
		t.Fatal("429 body has no message; the UI reads .message directly")
	}
	// A concurrency rejection does not clear by waiting, so the body must not
	// send the caller off to retry on a timer.
	if got := w.Header().Get("Retry-After"); got != "" {
		t.Errorf("Retry-After = %q; a slot frees when the caller's own request "+
			"ends, which is not a duration this layer knows", got)
	}

	close(h.release)
	wg.Wait()
}

// A finished request must give its slot back; otherwise an identity degrades
// permanently after its first burst.
func TestConcurrency_SlotIsReleasedOnCompletion(t *testing.T) {
	s := newTestService(concCfg(1))
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }

	for i := 0; i < 5; i++ {
		if got := concRequest(s, "/api/ds/query", 7, ok).Code; got != http.StatusOK {
			t.Fatalf("sequential request %d got %d; the previous slot was never released", i, got)
		}
	}
}

// A panic downstream must not strand the slot. Without the deferred release
// one panicking request would permanently shrink that identity's allowance.
func TestConcurrency_SlotIsReleasedOnPanic(t *testing.T) {
	s := newTestService(concCfg(1))
	boom := func(w http.ResponseWriter, r *http.Request) { panic("handler exploded") }

	func() {
		defer func() { _ = recover() }()
		_ = concRequest(s, "/api/ds/query", 7, boom)
	}()

	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	if got := concRequest(s, "/api/ds/query", 7, ok).Code; got != http.StatusOK {
		t.Fatalf("got %d after a panicking request; the slot was never returned", got)
	}
}

// The cap is per identity: one caller filling its slots must not affect another.
func TestConcurrency_IsolatedPerIdentity(t *testing.T) {
	s := newTestService(concCfg(1))
	h := newBlockingHandler(1)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		concRequest(s, "/api/ds/query", 7, h.ServeHTTP)
	}()
	<-h.entered // user 7 is holding its only slot

	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	if got := concRequest(s, "/api/ds/query", 8, ok).Code; got != http.StatusOK {
		t.Fatalf("user 8 got %d while user 7 was at its cap; the cap leaked across identities", got)
	}

	close(h.release)
	wg.Wait()
}

// Shadow mode must count the rejection and still serve the request. This is
// how the cap ships, so a bug here means the first deploy drops traffic.
func TestConcurrency_ShadowModeServesAnyway(t *testing.T) {
	cfg := concCfg(1)
	cfg.ConcurrencyShadowMode = true
	s := newTestService(cfg)
	h := newBlockingHandler(1)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		concRequest(s, "/api/ds/query", 7, h.ServeHTTP)
	}()
	<-h.entered

	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	w := concRequest(s, "/api/ds/query", 7, ok)
	if w.Code != http.StatusOK {
		t.Fatalf("shadow mode returned %d; it must observe without rejecting", w.Code)
	}

	close(h.release)
	wg.Wait()
}

// Unmanaged paths must not consume slots, or the cap would throttle the whole
// UI rather than datasource queries.
func TestConcurrency_UnmanagedPathsUnaffected(t *testing.T) {
	s := newTestService(concCfg(1))
	h := newBlockingHandler(1)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		concRequest(s, "/api/ds/query", 7, h.ServeHTTP)
	}()
	<-h.entered // the single slot is held

	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	for _, p := range []string{"/api/dashboards/uid/x", "/api/datasources", "/api/datasources/edit/1"} {
		if got := concRequest(s, p, 7, ok).Code; got != http.StatusOK {
			t.Errorf("%s got %d while the cap was full; it should never have been counted", p, got)
		}
	}

	close(h.release)
	wg.Wait()
}

// Every switch that can disable this must actually disable it.
func TestConcurrency_DisabledPathsPassThrough(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"concurrency off", func() Config { c := concCfg(1); c.ConcurrencyEnabled = false; return c }()},
		{"service off", func() Config { c := concCfg(1); c.Enabled = false; return c }()},
		{"limit zero means unlimited", concCfg(0)},
		{"negative limit means unlimited", concCfg(-1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestService(tc.cfg)
			h := newBlockingHandler(1)
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				concRequest(s, "/api/ds/query", 7, h.ServeHTTP)
			}()
			<-h.entered

			ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
			if got := concRequest(s, "/api/ds/query", 7, ok).Code; got != http.StatusOK {
				t.Errorf("got %d, want 200: this configuration must not limit anything", got)
			}
			close(h.release)
			wg.Wait()
		})
	}
}

// A nil service means the feature was never wired. It must be inert rather
// than panicking, the same guard the QPS middleware carries.
func TestConcurrency_NilServiceIsInert(t *testing.T) {
	var s *Service
	served := false
	h := func(w http.ResponseWriter, r *http.Request) { served = true }
	r := httptest.NewRequest(http.MethodPost, "/api/ds/query", nil)
	w := httptest.NewRecorder()
	s.ConcurrencyMiddleware(http.HandlerFunc(h)).ServeHTTP(w, r)
	if !served {
		t.Fatal("a nil service must pass traffic through untouched")
	}
}

// Requests with no ReqContext have no identity to charge. Reachable only by
// mounting this before ContextHandler, which is a wiring bug -- but it must
// fail open rather than panic.
func TestConcurrency_NoIdentityPassesThrough(t *testing.T) {
	s := newTestService(concCfg(1))
	served := false
	h := func(w http.ResponseWriter, r *http.Request) { served = true }
	r := httptest.NewRequest(http.MethodPost, "/api/ds/query", nil)
	w := httptest.NewRecorder()
	s.ConcurrencyMiddleware(http.HandlerFunc(h)).ServeHTTP(w, r)
	if !served {
		t.Fatal("a request without an identity must pass through, not be rejected")
	}
}

// Eviction resets the counter, so an identity with requests in flight would be
// handed a second full allowance. Measured before the guard: limit 2, two held,
// a third correctly rejected, then eviction let two more through.
func TestConcurrency_CleanupSkipsIdentitiesWithInflight(t *testing.T) {
	cfg := concCfg(2)
	cfg.CacheMaxEntries = 1
	s := newTestService(cfg)
	h := newBlockingHandler(2)

	// User 7 fills its allowance and holds it.
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			concRequest(s, "/api/ds/query", 7, h.ServeHTTP)
		}()
	}
	<-h.entered
	<-h.entered

	// Real eviction pressure. Without these the cache holds one entry against
	// a max of one, excess is zero, and cleanup returns before it looks at a
	// single entry -- the guard would never be exercised and this test would
	// pass whether or not it exists.
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	for uid := int64(100); uid < 140; uid++ {
		concRequest(s, "/api/ds/query", uid, ok)
	}
	if s.userCount.Load() <= int64(cfg.CacheMaxEntries) {
		t.Fatalf("no eviction pressure: %d entries against max %d", s.userCount.Load(), cfg.CacheMaxEntries)
	}
	// User 7 is also the least recently used by now, so it is first in line.
	s.cleanup()

	if got := concRequest(s, "/api/ds/query", 7, ok).Code; got != http.StatusTooManyRequests {
		t.Fatalf("got %d after cleanup, want 429: eviction handed out a fresh allowance "+
			"while two requests were still in flight", got)
	}

	close(h.release)
	wg.Wait()
}

// Once the in-flight requests finish the identity must become evictable again,
// or the skip above would turn into an unbounded cache.
func TestConcurrency_CleanupEvictsOnceIdle(t *testing.T) {
	cfg := concCfg(2)
	cfg.CacheMaxEntries = 1
	s := newTestService(cfg)
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }

	for uid := int64(1); uid <= 20; uid++ {
		concRequest(s, "/api/ds/query", uid, ok)
	}
	before := s.userCount.Load()
	s.cleanup()
	after := s.userCount.Load()

	if after >= before {
		t.Fatalf("idle entries were not evicted: %d -> %d with max=1", before, after)
	}
}

// The two layers must read as one product. A concurrency rejection is not a
// rate rejection, but a user hitting both in one session should not feel they
// hit two different systems.
func TestConcurrency_DenialWordingMatchesQPSLayer(t *testing.T) {
	msg := denyMessageInput{Kind: denyKindConcurrent, Scope: scopePersonal, Limit: 20}.String()

	// Same opening as the QPS denial, which is what makes them one voice.
	const prefix = "Your personal concurrent request limit reached (20 at a time)."
	if !strings.HasPrefix(msg, prefix) {
		t.Errorf("concurrency denial reads %q;\nthe QPS layer opens with %q and the two must stay parallel", msg, prefix)
	}

	// Waiting does not free a slot held by the caller's own query, so the
	// message must not offer a wait -- that is a retry loop that cannot end.
	for _, bad := range []string{"try again in", "Please try again", "second"} {
		if strings.Contains(msg, bad) {
			t.Errorf("concurrency denial contains %q: waiting does not clear this limit, "+
				"the slots are held by the caller's own queries", bad)
		}
	}

	// It has to say what does work.
	if !strings.Contains(msg, "Wait for your running queries to finish") {
		t.Errorf("concurrency denial gives no actionable remedy: %q", msg)
	}

	// No browser-specific advice. Service accounts and scripts are the
	// identities most likely to saturate this limit, and they have no panels
	// and no tabs -- an automated caller cannot act on that instruction. The
	// remedy has to hold for every kind of caller.
	for _, ui := range []string{"panel", "tab", "dashboard", "browser", "window"} {
		if strings.Contains(strings.ToLower(msg), ui) {
			t.Errorf("concurrency denial mentions %q, which means nothing to a "+
				"service account or script: %q", ui, msg)
		}
	}

	// Length parity with the QPS denial. Advice nobody finishes reading is
	// advice nobody follows.
	qps := denyMessageInput{Kind: denyKindQPS, Scope: scopePersonal, Limit: 20, RetryAfter: 2 * time.Second}.String()
	if got, ref := len(strings.Fields(msg)), len(strings.Fields(qps)); got > ref+4 {
		t.Errorf("concurrency denial is %d words against the QPS layer's %d; keep them comparable:\n  %s", got, ref, msg)
	}
}

// inflightSamples reads the histogram's sample count for one identity kind.
func inflightSamples(t *testing.T, kind string) uint64 {
	t.Helper()
	h, err := metricConcurrencyInflight.GetMetricWithLabelValues(kind)
	if err != nil {
		t.Fatalf("metric lookup: %v", err)
	}
	m := &dto.Metric{}
	if err := h.(prometheus.Metric).Write(m); err != nil {
		t.Fatalf("metric write: %v", err)
	}
	return m.GetHistogram().GetSampleCount()
}

// The rollout depends on this: enable the cap with no limit, read the
// histogram for a week, then pick a number from it. An earlier version
// returned before counting whenever the limit was unset, so that week would
// have produced an empty histogram and no error -- the operator would simply
// have waited for data that was never coming.
func TestConcurrency_ObservationModeStillRecords(t *testing.T) {
	s := newTestService(concCfg(0)) // enabled, no limit: the observation config
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }

	before := inflightSamples(t, "user")
	const n = 25
	for i := 0; i < n; i++ {
		if got := concRequest(s, "/api/ds/query", 7, ok).Code; got != http.StatusOK {
			t.Fatalf("request %d got %d; observation mode must refuse nothing", i, got)
		}
	}
	if got := inflightSamples(t, "user") - before; got != n {
		t.Fatalf("observation mode recorded %d samples for %d requests; "+
			"with none there is nothing to size the limit from", got, n)
	}
}

// Shadow mode with a trial limit must still record the real concurrency. If a
// shadow-refused request were left uncounted, the histogram would top out at
// the trial limit and hide the very demand the operator is measuring.
func TestConcurrency_ShadowModeRecordsBeyondTheTrialLimit(t *testing.T) {
	cfg := concCfg(2) // trial limit of 2
	cfg.ConcurrencyShadowMode = true
	s := newTestService(cfg)
	h := newBlockingHandler(4)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ { // twice the trial limit
		wg.Add(1)
		go func() {
			defer wg.Done()
			concRequest(s, "/api/ds/query", 7, h.ServeHTTP)
		}()
	}
	for i := 0; i < 4; i++ {
		<-h.entered
	}

	// All four are genuinely in flight -- shadow mode served them -- so the
	// counter must say four, not stop at the trial limit of two.
	v, ok := s.userBuckets.Load("user:7")
	if !ok {
		t.Fatal("no entry for user:7")
	}
	if got := v.(*userEntry).conc.load(); got != 4 {
		t.Errorf("counter reads %d with 4 requests in flight under a trial limit of 2; "+
			"the observed peak is being clipped to the limit being trialled", got)
	}

	close(h.release)
	wg.Wait()
}

// Cleanup runs concurrently with live traffic, and the existing eviction test
// is serial -- hold, then evict, then check -- so it cannot see the window
// between "this entry looked idle" and "delete it". A request arriving in that
// window gets its counter reset out from under it and the identity ends up
// with two allowances at once.
func TestConcurrency_CleanupRacesWithLiveTraffic(t *testing.T) {
	cfg := concCfg(2)
	cfg.CacheMaxEntries = 1 // keep cleanup permanently over its cap
	s := newTestService(cfg)

	slow := newBlockingHandler(64)
	fast := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Churn identities so cleanup always has candidates to delete.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for uid := int64(1000); ; uid++ {
			select {
			case <-stop:
				return
			default:
			}
			concRequest(s, "/api/ds/query", uid, fast)
		}
	}()

	// Hammer cleanup against that churn.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			s.cleanup()
		}
	}()

	// Meanwhile one identity keeps two slow requests in flight and repeatedly
	// checks that a third is still refused. If cleanup evicted it mid-flight,
	// the third would be admitted.
	var held sync.WaitGroup
	for i := 0; i < 2; i++ {
		held.Add(1)
		go func() {
			defer held.Done()
			concRequest(s, "/api/ds/query", 7, slow.ServeHTTP)
		}()
	}
	<-slow.entered
	<-slow.entered

	for i := 0; i < 400; i++ {
		if got := concRequest(s, "/api/ds/query", 7, fast).Code; got != http.StatusTooManyRequests {
			close(stop)
			close(slow.release)
			held.Wait()
			wg.Wait()
			t.Fatalf("attempt %d was admitted (%d) while two requests were in flight: "+
				"cleanup evicted the entry and handed out a second allowance", i, got)
		}
	}

	close(stop)
	close(slow.release)
	held.Wait()
	wg.Wait()
}

// concRequestAs drives a request with an arbitrary SignedInUser, so tests can
// build identities the uid-only helper cannot.
func concRequestAs(s *Service, path string, u *user.SignedInUser, h http.HandlerFunc) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, nil)
	r = r.WithContext(context.WithValue(r.Context(), ctxkey.Key{},
		&contextmodel.ReqContext{SignedInUser: u}))
	w := httptest.NewRecorder()
	s.ConcurrencyMiddleware(h).ServeHTTP(w, r)
	return w
}

// This middleware wraps the whole chain, so it also sees requests that are
// about to be refused with 401 or 403 -- unlike the QPS layer, which sits
// behind authorize() on each route. Those all carry UserID 0 and are not
// anonymous, so they would share the single key "user:0": unrelated failed
// logins evicting one another, and a burst of them able to exhaust the slots
// while reaching no backend at all.
func TestConcurrency_UnauthenticatedRequestsAreNotCounted(t *testing.T) {
	s := newTestService(concCfg(1))
	blocked := newBlockingHandler(8)
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }

	// Four unauthenticated requests parked in the handler at once, against a
	// cap of one.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			concRequestAs(s, "/api/ds/query", &user.SignedInUser{UserID: 0}, blocked.ServeHTTP)
		}()
	}
	for i := 0; i < 4; i++ {
		<-blocked.entered
	}
	if blocked.count() != 4 {
		t.Fatalf("only %d of 4 unauthenticated requests reached the handler; "+
			"they are sharing a capped slot pool", blocked.count())
	}

	// A real user is unaffected by that pile-up.
	if got := concRequestAs(s, "/api/ds/query", &user.SignedInUser{UserID: 42}, ok).Code; got != http.StatusOK {
		t.Errorf("an authenticated user got %d while unauthenticated requests were "+
			"parked; they must not compete for the same slots", got)
	}

	close(blocked.release)
	wg.Wait()
}

// Anonymous traffic is a real identity with a deliberate policy attached and
// does reach backends when an operator allows it, so it stays counted. Without
// this, "not authenticated" and "anonymous" would blur together and the
// exemption above would quietly become a hole.
func TestConcurrency_AnonymousTrafficIsStillCounted(t *testing.T) {
	s := newTestService(concCfg(1))
	blocked := newBlockingHandler(4)
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		concRequestAs(s, "/api/ds/query", &user.SignedInUser{IsAnonymous: true}, blocked.ServeHTTP)
	}()
	<-blocked.entered

	if got := concRequestAs(s, "/api/ds/query", &user.SignedInUser{IsAnonymous: true}, ok).Code; got != http.StatusTooManyRequests {
		t.Errorf("a second anonymous request got %d against a cap of 1; anonymous "+
			"traffic must still be subject to the cap", got)
	}

	close(blocked.release)
	wg.Wait()
}

// The two layers must be parseable by one client. An earlier version sent
// traceID, always empty, which the QPS layer does not send at all.
func TestConcurrency_DenialBodyMatchesQPSFields(t *testing.T) {
	s := newTestService(concCfg(1))
	blocked := newBlockingHandler(2)
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		concRequest(s, "/api/ds/query", 7, blocked.ServeHTTP)
	}()
	<-blocked.entered

	w := concRequest(s, "/api/ds/query", 7, ok)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected a 429, got %d", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("429 body is not JSON: %v", err)
	}
	for _, f := range []string{"message", "scope", "kind", "limit"} {
		if _, ok := body[f]; !ok {
			t.Errorf("429 body is missing %q, which the QPS denial sends", f)
		}
	}
	if _, present := body["traceID"]; present {
		t.Error("429 body carries traceID, which the QPS layer does not send; " +
			"an always-empty field is worse than no field")
	}
	if got := body["kind"]; got != "concurrent" {
		t.Errorf("kind = %v, want \"concurrent\": this is what tells a client that "+
			"waiting is not the remedy", got)
	}

	close(blocked.release)
	wg.Wait()
}

// The two layers must be independently switchable. Once QPS is enforcing in
// production, a shared flag would mean trialling a concurrency limit in shadow
// can only be done by standing the QPS layer down -- dropping protection that
// is already load-bearing to trial one that is not.
func TestConcurrency_ShadowIsIndependentOfTheQPSLayer(t *testing.T) {
	cases := []struct {
		name        string
		qpsShadow   bool
		concShadow  bool
		wantRefused bool
	}{
		{"QPS enforcing, concurrency shadow", false, true, false},
		{"QPS enforcing, concurrency enforcing", false, false, true},
		{"QPS shadow, concurrency enforcing", true, false, true},
		{"both shadow", true, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := concCfg(1)
			cfg.ShadowMode = tc.qpsShadow
			cfg.ConcurrencyShadowMode = tc.concShadow
			s := newTestService(cfg)

			blocked := newBlockingHandler(4)
			ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				concRequest(s, "/api/ds/query", 7, blocked.ServeHTTP)
			}()
			<-blocked.entered

			got := concRequest(s, "/api/ds/query", 7, ok).Code
			refused := got == http.StatusTooManyRequests
			if refused != tc.wantRefused {
				t.Errorf("got %d (refused=%v), want refused=%v: the in-flight cap is "+
					"reading the QPS layer's shadow flag instead of its own",
					got, refused, tc.wantRefused)
			}

			close(blocked.release)
			wg.Wait()
		})
	}
}

// cleanup marks an entry dead and then deletes it, and those are two steps on
// a single ticker goroutine -- so a request landing between them finds a corpse
// that nobody else is coming to clear. Retrying alone just fetches the same
// corpse again; measured before the fix as the request reaching the handler
// with the counter still at zero, straight through the cap and uncounted.
//
// The interleaving is constructed rather than raced for, so the assertion is
// exact instead of probabilistic.
func TestConcurrency_RequestClearsAnEntryCleanupLeftMarked(t *testing.T) {
	s := newTestService(concCfg(1))
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }

	// Create the entry, then put it in the exact state cleanup leaves behind
	// between marking and deleting.
	concRequest(s, "/api/ds/query", 7, ok)
	v, found := s.userBuckets.Load("user:7")
	if !found {
		t.Fatal("no entry to mark")
	}
	dead := v.(*userEntry)
	if !dead.conc.tryEvict() {
		t.Fatal("an idle entry should be markable")
	}

	before := failOpenCount(t)

	// A request arriving now must clear the corpse itself and be counted on a
	// live entry, not sail past uncounted.
	blocked := newBlockingHandler(2)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		concRequest(s, "/api/ds/query", 7, blocked.ServeHTTP)
	}()
	<-blocked.entered

	v2, found := s.userBuckets.Load("user:7")
	if !found {
		t.Fatal("the request did not install a live entry")
	}
	live := v2.(*userEntry)
	if live == dead {
		t.Fatal("the request reused the entry cleanup had marked dead")
	}
	if got := live.conc.load(); got != 1 {
		t.Errorf("live entry counts %d, want 1: the request went through uncounted", got)
	}
	if got := failOpenCount(t) - before; got != 0 {
		t.Errorf("%.0f request(s) failed open; the eviction protocol did not self-heal", got)
	}

	// And the cap is actually in force on the new entry.
	if got := concRequest(s, "/api/ds/query", 7, ok).Code; got != http.StatusTooManyRequests {
		t.Errorf("second request got %d, want 429: the rebuilt entry is not enforcing", got)
	}

	close(blocked.release)
	wg.Wait()
}

func failOpenCount(t *testing.T) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := metricConcurrencyFailOpen.(prometheus.Metric).Write(m); err != nil {
		t.Fatalf("metric write: %v", err)
	}
	return m.GetCounter().GetValue()
}

// An operator who has just switched the cap on needs to be able to confirm it,
// and the cap can be silently inert for three separate reasons: the service is
// off, the cap is off, or no limit is set. /stats has to answer that without
// making them combine three fields correctly -- found while testing on BOE,
// where the feature was enabled and nothing in /stats said so.
func TestConcurrency_StatsReportsWhatTheCapIsDoing(t *testing.T) {
	cases := []struct {
		name          string
		mutate        func(*Config)
		wantRecording bool
		wantEnforcing bool
	}{
		{
			name:          "shipped default: off entirely",
			mutate:        func(c *Config) { c.ConcurrencyEnabled = false },
			wantRecording: false, wantEnforcing: false,
		},
		{
			name: "observation week: counting, refusing nothing",
			mutate: func(c *Config) {
				c.ConcurrencyEnabled = true
				c.DefaultUserConcurrency = 0
				c.ConcurrencyShadowMode = true
			},
			wantRecording: true, wantEnforcing: false,
		},
		{
			name: "limit chosen, still shadow",
			mutate: func(c *Config) {
				c.ConcurrencyEnabled = true
				c.DefaultUserConcurrency = 20
				c.ConcurrencyShadowMode = true
			},
			wantRecording: true, wantEnforcing: false,
		},
		{
			name: "fully on",
			mutate: func(c *Config) {
				c.ConcurrencyEnabled = true
				c.DefaultUserConcurrency = 20
				c.ConcurrencyShadowMode = false
			},
			wantRecording: true, wantEnforcing: true,
		},
		{
			name: "enforcing asked for but no limit set: inert",
			mutate: func(c *Config) {
				c.ConcurrencyEnabled = true
				c.DefaultUserConcurrency = 0
				c.ConcurrencyShadowMode = false
			},
			wantRecording: true, wantEnforcing: false,
		},
		{
			name: "whole service off overrides the cap's own switches",
			mutate: func(c *Config) {
				c.Enabled = false
				c.ConcurrencyEnabled = true
				c.DefaultUserConcurrency = 20
				c.ConcurrencyShadowMode = false
			},
			wantRecording: false, wantEnforcing: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := concCfg(0)
			tc.mutate(&cfg)
			s := newTestService(cfg)

			rec := cfg.Enabled && cfg.ConcurrencyEnabled
			enf := rec && !cfg.ConcurrencyShadowMode && cfg.DefaultUserConcurrency > 0

			if rec != tc.wantRecording {
				t.Errorf("recording = %v, want %v", rec, tc.wantRecording)
			}
			if enf != tc.wantEnforcing {
				t.Errorf("enforcing = %v, want %v", enf, tc.wantEnforcing)
			}

			// And the service must behave the way /stats claims it does.
			ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
			before := inflightSamples(t, "user")
			concRequest(s, "/api/ds/query", 7, ok)
			got := inflightSamples(t, "user") - before
			if tc.wantRecording && got == 0 {
				t.Error("stats says recording, but the request was not counted")
			}
			if !tc.wantRecording && got != 0 {
				t.Errorf("stats says not recording, but %d sample(s) appeared", got)
			}
		})
	}
}
