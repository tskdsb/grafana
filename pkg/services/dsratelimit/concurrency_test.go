package dsratelimit

import (
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// The route table this mirrors lives in pkg/api/api.go. If a datasource query
// route is added there without being added here, the in-flight cap silently
// stops covering it -- the request just flows through. These cases are the
// only thing tying the two together.
// mustAcquire wraps acquire for tests that never evict, where the second
// return is always true.
func mustAcquire(f *inflight, limit int64) bool {
	admitted, ok := f.acquire(limit)
	if !ok {
		panic("entry evicted in a test that never evicts")
	}
	return admitted
}

func TestIsManagedPath(t *testing.T) {
	managed := []struct{ path, why string }{
		{"/api/ds/query", "the main query endpoint"},
		{"/api/ds/query/", "same endpoint, trailing slash: tree.go trims it too"},
		{"/api/datasources/proxy/1/api/v1/query", "proxy by id"},
		{"/api/datasources/proxy/uid/abc123/api/v1/query", "proxy by uid"},
		{"/api/datasources/proxy/1", "proxy by id, no suffix"},
		{"/api/datasources/proxy/uid/abc123", "proxy by uid, no suffix"},
		{"/api/datasources/1/resources", "resources by id"},
		{"/api/datasources/uid/abc/resources", "resources by uid"},
		{"/api/datasources/1/resources/foo/bar", "nested resources"},
		{"/api/datasources/uid/abc/resources/foo", "nested resources by uid"},
		{"/api/datasources/1/health", "health by id: CheckHealth really calls the backend"},
		{"/api/datasources/uid/abc/health", "health by uid"},
		{"/api/datasources/uid/proxy/health", "a datasource whose uid is literally 'proxy'"},
		{"/api/datasources/proxy/uid/health", "a datasource whose uid is literally 'health'"},
	}
	for _, c := range managed {
		if !isManagedPath(c.path) {
			t.Errorf("%s should be managed (%s)", c.path, c.why)
		}
	}

	// Everything under /api/datasources/ that does not reach a backend. A
	// prefix match would sweep these in and make the datasource settings UI
	// fail under load while protecting nothing.
	unmanaged := []struct{ path, why string }{
		{"/api/datasources", "listing datasources reads our own DB"},
		{"/api/datasources/", "same, trailing slash"},
		{"/api/datasources/1", "reading one datasource's config"},
		{"/api/datasources/uid/abc", "same, by uid"},
		{"/api/datasources/name/foo", "lookup by name"},
		{"/api/datasources/new", "the create form"},
		{"/api/datasources/edit/1", "the edit form -- 'edit' sits where an id would"},
		{"/api/datasources/edit/abc/foo", "nested edit route"},
		{"/api/datasources/correlations", "correlations metadata"},
		{"/api/admin/datasource-rate-limits/stats", "our own admin API must never self-limit"},
		{"/api/dashboards/uid/x", "unrelated"},
		{"/api/health", "unrelated"},
		{"/login", "unrelated"},
		{"/", "root"},
	}
	for _, c := range unmanaged {
		if isManagedPath(c.path) {
			t.Errorf("%s should NOT be managed (%s)", c.path, c.why)
		}
	}
}

// The property that matters: however the callers interleave, no more than
// limit of them are ever admitted at once.
func TestInflightNeverOverAdmits(t *testing.T) {
	const limit, callers = 3, 200
	for round := 0; round < 300; round++ {
		var f inflight
		var granted atomic.Int64
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				// Hold the slot: releasing immediately would let the same slot
				// be reused and the count would prove nothing.
				if mustAcquire(&f, limit) {
					granted.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if got := granted.Load(); got != limit {
			t.Fatalf("round %d: admitted %d, want exactly %d", round, got, limit)
		}
		if got := f.load(); got != limit {
			t.Fatalf("round %d: counter reads %d, want %d", round, got, limit)
		}
	}
}

// The counter must never publish a value above the limit, not even briefly.
// Add-then-check passes the admission test above but fails this one, and this
// is the reading the gauge exports and the next caller is compared against.
func TestInflightNeverPublishesAboveLimit(t *testing.T) {
	const limit, callers = 3, 64
	var f inflight
	var peak atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok := mustAcquire(&f, limit)
			for {
				cur, p := f.load(), peak.Load()
				if cur <= p || peak.CompareAndSwap(p, cur) {
					break
				}
			}
			if ok {
				f.release()
			}
		}()
	}
	close(start)
	wg.Wait()
	if p := peak.Load(); p > limit {
		t.Fatalf("counter reached %d, above the limit of %d", p, limit)
	}
}

func TestInflightReleaseFreesSlot(t *testing.T) {
	var f inflight
	const limit = 2
	// Taken one at a time rather than chained with ||, which would short-circuit
	// and never attempt the second call if the first failed -- the failure
	// message would then be true of a case that was never exercised.
	for i := 1; i <= limit; i++ {
		if !mustAcquire(&f, limit) {
			t.Fatalf("call %d should be admitted with %d free slots", i, limit)
		}
	}
	if mustAcquire(&f, limit) {
		t.Fatal("third should be rejected while the first two are held")
	}
	f.release()
	if !mustAcquire(&f, limit) {
		t.Fatal("a freed slot should be reusable")
	}
}

// A release with no matching acquire must not create capacity out of nothing.
// It should be unreachable -- every acquire path defers its release -- but an
// unclamped counter going negative would grant extra slots silently and
// forever, which is far worse than a lost decrement.
func TestInflightReleaseClampsAtZero(t *testing.T) {
	var f inflight
	f.release()
	f.release()
	if got := f.load(); got != 0 {
		t.Fatalf("counter went to %d, want 0", got)
	}
	const limit = 1
	if !mustAcquire(&f, limit) {
		t.Fatal("should admit one")
	}
	if mustAcquire(&f, limit) {
		t.Fatal("the spurious releases must not have created extra capacity")
	}
}

// Observation mode admits everything but still counts. The counter is what
// feeds the histogram the limit gets chosen from, so not counting here would
// leave the observation period with no data at all -- and no way to pick a
// limit except by guessing.
func TestInflightZeroLimitAdmitsButStillCounts(t *testing.T) {
	var f inflight
	const calls = 1000
	for i := 0; i < calls; i++ {
		if !mustAcquire(&f, 0) {
			t.Fatalf("limit 0 must admit everything, but call %d was refused", i)
		}
	}
	if got := f.load(); got != calls {
		t.Fatalf("observation mode counted %d of %d slots; the histogram is fed "+
			"from this counter, so an uncounted slot is a sample the operator never sees",
			got, calls)
	}
	for i := 0; i < calls; i++ {
		f.release()
	}
	if got := f.load(); got != 0 {
		t.Fatalf("counter did not return to zero: %d", got)
	}
}

// The concurrency middleware must stay mounted, and stay mounted after
// ContextHandler. Both are invisible at runtime if broken: mounted too early
// it silently sees no identity and passes everything through, and removed
// entirely it simply stops limiting. Neither shows up as a failing request.
//
// Source-level assertion for the same reason TestRouteRegistrations is one --
// there is no runtime handle on the middleware chain to inspect.
func TestConcurrencyMiddlewareIsMountedAfterContextHandler(t *testing.T) {
	src, err := os.ReadFile("../../api/http_server.go")
	if err != nil {
		t.Fatalf("cannot read http_server.go: %v", err)
	}
	body := string(src)

	const ctxMount = "m.UseMiddleware(hs.ContextHandler.Middleware)"
	const concMount = "m.UseMiddleware(hs.DsRateLimit.ConcurrencyMiddleware)"

	ctxAt := strings.Index(body, ctxMount)
	concAt := strings.Index(body, concMount)
	if ctxAt < 0 {
		t.Fatalf("%s is gone from http_server.go", ctxMount)
	}
	if concAt < 0 {
		t.Fatalf("%s is gone from http_server.go: the in-flight cap is no longer "+
			"mounted and limits nothing", concMount)
	}
	if concAt < ctxAt {
		t.Fatalf("the concurrency middleware is mounted before ContextHandler, so " +
			"every request reaches it without an identity and passes through unlimited")
	}
}

// tryEvict is what closes the window between "this entry is idle" and "delete
// it". A plain load()>0 check leaves that window open: a request arriving in
// it takes a slot on an entry that is about to vanish, and the identity ends
// up tracked by two counters at once.
//
// Driven at the type rather than through the middleware, because reproducing
// the interleaving from outside depends on the scheduler -- here it is exact.
func TestInflightTryEvictClosesTheWindow(t *testing.T) {
	t.Run("idle entry can be evicted", func(t *testing.T) {
		var f inflight
		if !f.tryEvict() {
			t.Fatal("an idle entry must be evictable")
		}
		if admitted, ok := f.acquire(10); ok || admitted {
			t.Fatal("an evicted entry must refuse acquisition so the caller retries " +
				"against the live entry")
		}
	})

	t.Run("busy entry cannot be evicted", func(t *testing.T) {
		var f inflight
		if _, ok := f.acquire(10); !ok {
			t.Fatal("acquire on a fresh entry")
		}
		if f.tryEvict() {
			t.Fatal("an entry with a request in flight must not be evicted: " +
				"eviction resets the counter and hands out a second allowance")
		}
		f.release()
		if !f.tryEvict() {
			t.Fatal("once idle it must become evictable again, or the cache grows " +
				"without bound")
		}
	})

	t.Run("acquire racing eviction never counts on a dead entry", func(t *testing.T) {
		// The exact interleaving a load()>0 check cannot survive: the entry
		// reads as idle, then a request arrives, then the delete lands.
		for round := 0; round < 2000; round++ {
			var f inflight
			var wg sync.WaitGroup
			var admitted, ok atomic.Bool
			var evicted atomic.Bool

			start := make(chan struct{})
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				a, o := f.acquire(1)
				admitted.Store(a)
				ok.Store(o)
			}()
			go func() {
				defer wg.Done()
				<-start
				evicted.Store(f.tryEvict())
			}()
			close(start)
			wg.Wait()

			// Exactly one of the two may win. Both succeeding means a slot was
			// taken on an entry that was then removed -- the caller keeps
			// running while its counter is unreachable, and the next request
			// starts from zero.
			if evicted.Load() && ok.Load() && admitted.Load() {
				t.Fatalf("round %d: eviction and acquisition both succeeded; the "+
					"identity is now counted in a discarded entry", round)
			}
		}
	})

	t.Run("a busy entry is refused before it is ever claimed", func(t *testing.T) {
		var f inflight
		if _, ok := f.acquire(2); !ok {
			t.Fatal("first acquire on a fresh entry")
		}
		if f.tryEvict() {
			t.Fatal("an entry with a request in flight must not be claimed")
		}
		if got := f.state.Load(); got != stateLive {
			t.Fatalf("state is %d, want stateLive", got)
		}
	})

	t.Run("a claim retreats when a holder wins the race", func(t *testing.T) {
		// The path where tryEvict has already taken the claim and only then
		// discovers a holder. Reaching it needs the holder to arrive between
		// the idle check and the CAS, so the arrival is staged here rather
		// than raced for.
		//
		// The retreat must be complete. An entry left dying refuses every
		// acquire, and since nothing else puts it back, that identity is
		// locked out of datasource queries entirely -- until some later
		// cleanup tick happens to remove the entry.
		var f inflight
		if !f.state.CompareAndSwap(stateLive, stateDying) {
			t.Fatal("fresh entry should be claimable")
		}
		f.cur.Add(1) // the holder that slipped in

		if f.tryEvict() {
			t.Fatal("tryEvict reported success on a busy entry")
		}
		if got := f.state.Load(); got != stateLive {
			t.Fatalf("state is %d, want stateLive: the claim never retreated, so "+
				"this identity can no longer acquire anything", got)
		}
		if admitted, ok := f.acquire(5); !ok || !admitted {
			t.Fatal("a spared entry must keep accepting traffic")
		}
	})
}

// A miss is not by itself permission to delete the entry.
//
// Three-party interleaving, from review: tryEvict claims an idle entry, a
// holder slips in, a second request samples the claim and gets a miss, and
// tryEvict then puts the entry back because it is no longer idle. The second
// request is now holding a miss for an entry that is alive and counting, and
// with a separate "removing" flag it went on to delete it -- measured passing
// both the claim and the pointer check with a request in flight.
//
// Constructed rather than raced for: the window is a few instructions wide and
// would otherwise show up as an occasional flake nobody can reproduce.
func TestInflightMissDoesNotAuthoriseRemoval(t *testing.T) {
	var f inflight

	// tryEvict has claimed the entry; a holder then arrives.
	if !f.state.CompareAndSwap(stateLive, stateDying) {
		t.Fatal("fresh entry should be claimable")
	}
	f.cur.Add(1) // the holder

	// The second request samples the claim and is told to look elsewhere.
	if admitted, ok := f.acquire(2); ok || admitted {
		t.Fatal("a claimed entry must report a miss")
	}

	// tryEvict finishes, sees the entry is busy, and puts it back.
	if f.cur.Load() != 0 {
		f.state.Store(stateLive)
	}

	// The second request now tries to clear what it thinks is a corpse.
	if f.claimRemoval() {
		t.Fatal("removal was authorised on an entry that is live with a request " +
			"in flight: deleting it strands that request's count and hands the " +
			"identity a second full allowance")
	}
	if got := f.state.Load(); got != stateLive {
		t.Fatalf("state is %d, want stateLive", got)
	}
	// And it still works.
	if admitted, ok := f.acquire(2); !ok || !admitted {
		t.Fatal("the spared entry must keep accepting traffic")
	}
}

// Only one caller may commit a removal, or userCount is decremented twice and
// cleanup's idea of how full the cache is drifts down forever.
func TestInflightRemovalIsClaimedOnce(t *testing.T) {
	var f inflight
	if !f.tryEvict() {
		t.Fatal("idle entry should be claimable")
	}

	var wins int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if f.claimRemoval() {
				atomic.AddInt64(&wins, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d callers committed the same removal, want exactly 1", wins)
	}
}

// Once removed, an entry never comes back. A caller that somehow still holds a
// pointer to it must be sent to build a fresh one rather than counting on an
// object no lookup can reach.
func TestInflightRemovedIsTerminal(t *testing.T) {
	var f inflight
	if !f.tryEvict() || !f.claimRemoval() {
		t.Fatal("idle entry should evict and be claimable")
	}
	if admitted, ok := f.acquire(10); ok || admitted {
		t.Fatal("a removed entry must refuse acquisition")
	}
	if f.tryEvict() {
		t.Fatal("a removed entry must not be claimable again")
	}
	if f.claimRemoval() {
		t.Fatal("a removed entry must not be committed twice")
	}
}

// The second idle check inside tryEvict, under real contention.
//
// It guards the case where the claim is taken and a holder arrives
// immediately after. Reaching it needs the holder to land inside a
// few-instruction window, which no staged test can hit, so this hammers
// acquire against tryEvict and asserts the invariant that window exists to
// preserve: an entry that ends up with a holder must not be left claimed, and
// an entry reported as claimable must have no holder.
func TestInflightEvictAndAcquireStayConsistent(t *testing.T) {
	for round := 0; round < 40000; round++ {
		var f inflight
		var ready sync.WaitGroup
		var done sync.WaitGroup
		var evicted, admitted atomic.Bool

		// Both goroutines park on the same gate after signalling readiness, so
		// they resume together instead of one finishing before the other is
		// scheduled. Without this the two rarely overlap and the window this
		// test exists for is almost never entered.
		start := make(chan struct{})
		ready.Add(2)
		done.Add(2)
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			a, ok := f.acquire(4)
			admitted.Store(a && ok)
		}()
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			evicted.Store(f.tryEvict())
		}()
		ready.Wait()
		close(start)
		done.Wait()

		held := f.cur.Load()
		state := f.state.Load()

		switch {
		case evicted.Load():
			// Claimed for removal, so nothing may be holding it.
			if held != 0 {
				t.Fatalf("round %d: claimed for removal with %d holder(s); "+
					"removing it would strand that request's count", round, held)
			}
			if state != stateDying {
				t.Fatalf("round %d: reported claimed but state is %d", round, state)
			}
		default:
			// Not claimed, so it must be usable again -- a claim left behind
			// makes every later acquire miss and locks the identity out.
			if state != stateLive {
				t.Fatalf("round %d: not claimed but state is %d, so this entry "+
					"refuses all traffic with nobody left to release it", round, state)
			}
			if admitted.Load() && held != 1 {
				t.Fatalf("round %d: admitted but count is %d", round, held)
			}
		}
	}
}
