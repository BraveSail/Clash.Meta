package mesh

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakeClock is the point of the Clock interface: a test can move time to a
// known instant instead of sleeping and hoping.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestNewStatusRegistryTakesSinceFromClock(t *testing.T) {
	c := newFakeClock()
	r := NewStatusRegistry(c, "http://hub:8080")

	st := r.Status()
	if !st.Since.Equal(c.Now()) {
		t.Fatalf("Since = %v, want %v", st.Since, c.Now())
	}
	if st.Directory.URL != "http://hub:8080" {
		t.Fatalf("Directory.URL = %q", st.Directory.URL)
	}
	if st.Directory.Peers == nil {
		t.Fatal("Directory.Peers must be an empty map, not nil, so a reader can range it")
	}
	if len(st.Directory.Routes) != 0 {
		t.Fatalf("Routes = %v, want empty", st.Directory.Routes)
	}
}

func TestNilClockFallsBackToSystemClock(t *testing.T) {
	r := NewStatusRegistry(nil, "")
	if r.Status().Since.IsZero() {
		t.Fatal("Since is zero with a nil clock")
	}
}

func TestSetIdentity(t *testing.T) {
	r := NewStatusRegistry(newFakeClock(), "")
	r.SetIdentity("node-a", "10.0.0.1", 9090)

	st := r.Status()
	if st.ID != "node-a" || st.Address != "10.0.0.1" || st.Port != 9090 {
		t.Fatalf("identity = %q/%q/%d", st.ID, st.Address, st.Port)
	}
}

func TestNoteRouteCountsAndTimestamps(t *testing.T) {
	c := newFakeClock()
	r := NewStatusRegistry(c, "")

	c.advance(time.Minute)
	r.NoteRoute("direct", nil)
	okAt := c.Now()

	c.advance(time.Minute)
	r.NoteRoute("direct", errors.New("i/o timeout"))
	r.NoteRoute("proxy", nil)

	st := r.Status()
	if st.Directory.Route != "proxy" {
		t.Fatalf("Directory.Route = %q, want the route that last answered", st.Directory.Route)
	}
	byName := routeByName(t, st.Directory.Routes)
	if len(byName) != 2 {
		t.Fatalf("routes = %v, want 2", st.Directory.Routes)
	}
	direct := byName["direct"]
	if direct.Attempts != 2 || direct.Failures != 1 {
		t.Fatalf("direct attempts/failures = %d/%d, want 2/1", direct.Attempts, direct.Failures)
	}
	if !direct.LastOK.Equal(okAt) {
		t.Fatalf("direct LastOK = %v, want %v", direct.LastOK, okAt)
	}
	if direct.LastError != "i/o timeout" {
		t.Fatalf("direct LastError = %q", direct.LastError)
	}
	if direct.Name != "direct" {
		t.Fatalf("direct Name = %q", direct.Name)
	}
	proxy := byName["proxy"]
	if proxy.Attempts != 1 || proxy.Failures != 0 || proxy.LastError != "" {
		t.Fatalf("proxy = %+v", proxy)
	}
	if !proxy.LastOK.Equal(c.Now()) {
		t.Fatalf("proxy LastOK = %v, want %v", proxy.LastOK, c.Now())
	}
}

// The point of LastError: a route that failed and then worked reads as healthy,
// because the failure is history and the route is not.
func TestRouteLastErrorClearedByNextSuccess(t *testing.T) {
	c := newFakeClock()
	r := NewStatusRegistry(c, "")

	r.NoteRoute("direct", errors.New("dial tcp: refused"))
	if got := r.Status().Directory.Routes[0].LastError; got == "" {
		t.Fatal("LastError not recorded")
	}

	c.advance(time.Second)
	r.NoteRoute("direct", nil)

	rs := r.Status().Directory.Routes[0]
	if rs.LastError != "" {
		t.Fatalf("LastError = %q after a success, want empty", rs.LastError)
	}
	// The failure still happened, so it is still counted.
	if rs.Attempts != 2 || rs.Failures != 1 {
		t.Fatalf("counters lost on success: %d/%d", rs.Attempts, rs.Failures)
	}
}

func TestDirectoryLastErrorFollowsRouteOutcome(t *testing.T) {
	r := NewStatusRegistry(newFakeClock(), "")

	r.NoteRoute("direct", errors.New("boom"))
	if got := r.Status().Directory.LastError; got != "boom" {
		t.Fatalf("Directory.LastError = %q", got)
	}
	r.NoteRoute("direct", nil)
	if got := r.Status().Directory.LastError; got != "" {
		t.Fatalf("Directory.LastError = %q after a success", got)
	}
}

func TestNoteReport(t *testing.T) {
	c := newFakeClock()
	r := NewStatusRegistry(c, "")

	r.NoteReport("203.0.113.7:9090")
	c.advance(90 * time.Second)
	r.NoteReport("203.0.113.8:9090")

	st := r.Status().Directory
	if st.Address != "203.0.113.8:9090" {
		t.Fatalf("Address = %q", st.Address)
	}
	if !st.Reported.Equal(c.Now()) {
		t.Fatalf("Reported = %v, want %v", st.Reported, c.Now())
	}
}

// A report that got through is the directory answering, so it is a success on
// the directory's own error field.
func TestNoteReportClearsDirectoryError(t *testing.T) {
	r := NewStatusRegistry(newFakeClock(), "")
	r.NoteRoute("direct", errors.New("boom"))
	r.NoteReport("10.0.0.1:1")

	if got := r.Status().Directory.LastError; got != "" {
		t.Fatalf("Directory.LastError = %q after a report got through", got)
	}
}

func TestNotePeerAnswer(t *testing.T) {
	c := newFakeClock()
	r := NewStatusRegistry(c, "")

	c.advance(time.Minute)
	r.NotePeerAnswer("node-b", PeerAnswer{
		Addr:   "10.0.0.2",
		Port:   9090,
		Self:   false,
		Source: "directory",
		At:     c.Now(),
	})

	got := r.Status().Directory.Peers["node-b"]
	want := PeerStatus{
		Addr:         "10.0.0.2",
		Port:         9090,
		Self:         false,
		Source:       "directory",
		LastResolved: c.Now(),
		Active:       0,
	}
	if got != want {
		t.Fatalf("peer = %+v, want %+v", got, want)
	}
}

// A self answer is reported as one: a caller reading this must be able to tell
// before it dials itself through a peer tunnel.
func TestNotePeerAnswerSelf(t *testing.T) {
	c := newFakeClock()
	r := NewStatusRegistry(c, "")
	r.NotePeerAnswer("node-a", PeerAnswer{Addr: "10.0.0.1", Port: 9090, Self: true, Source: "memory", At: c.Now()})

	p := r.Status().Directory.Peers["node-a"]
	if !p.Self || p.Source != "memory" {
		t.Fatalf("peer = %+v", p)
	}
}

func TestNotePeerAnswerClearsPeerError(t *testing.T) {
	c := newFakeClock()
	r := NewStatusRegistry(c, "")

	r.NotePeerError("node-b", errors.New("no such key"))
	if got := r.Status().Directory.Peers["node-b"].LastError; got != "no such key" {
		t.Fatalf("LastError = %q", got)
	}

	c.advance(time.Second)
	r.NotePeerAnswer("node-b", PeerAnswer{Addr: "10.0.0.2", Port: 9090, Source: "directory", At: c.Now()})
	if got := r.Status().Directory.Peers["node-b"].LastError; got != "" {
		t.Fatalf("LastError = %q after an answer arrived", got)
	}
}

// A failed lookup does not disprove the address already in hand: the peer is
// still reachable there, and dropping it would lose a working address.
func TestNotePeerErrorKeepsKnownAnswer(t *testing.T) {
	c := newFakeClock()
	r := NewStatusRegistry(c, "")
	r.NotePeerAnswer("node-b", PeerAnswer{Addr: "10.0.0.2", Port: 9090, Source: "memory", At: c.Now()})

	r.NotePeerError("node-b", errors.New("hub unreachable"))

	p := r.Status().Directory.Peers["node-b"]
	if p.Addr != "10.0.0.2" || p.Port != 9090 || p.Source != "memory" {
		t.Fatalf("answer lost on lookup failure: %+v", p)
	}
	if p.LastError != "hub unreachable" {
		t.Fatalf("LastError = %q", p.LastError)
	}
}

func TestNotePeerErrorNilClears(t *testing.T) {
	r := NewStatusRegistry(newFakeClock(), "")
	r.NotePeerError("node-b", errors.New("x"))
	r.NotePeerError("node-b", nil)
	if got := r.Status().Directory.Peers["node-b"].LastError; got != "" {
		t.Fatalf("LastError = %q", got)
	}
}

// The live count is a fact about open connections, so it must go up on dial and
// come back down on release, and nowhere else.
func TestNoteDialCountsOpenConnections(t *testing.T) {
	r := NewStatusRegistry(newFakeClock(), "")

	rel1 := r.NoteDial("node-b")
	rel2 := r.NoteDial("node-b")
	rel3 := r.NoteDial("node-c")

	if got := r.Status().Directory.Peers["node-b"].Active; got != 2 {
		t.Fatalf("node-b Active = %d, want 2", got)
	}
	if got := r.Status().Directory.Peers["node-c"].Active; got != 1 {
		t.Fatalf("node-c Active = %d, want 1", got)
	}
	if got := r.Status().Open; got != 3 {
		t.Fatalf("Open = %d, want 3", got)
	}

	rel1()
	if got := r.Status().Directory.Peers["node-b"].Active; got != 1 {
		t.Fatalf("node-b Active = %d after one release", got)
	}
	rel3()
	if got := r.Status().Open; got != 1 {
		t.Fatalf("Open = %d after two releases", got)
	}
	rel2()
	st := r.Status()
	if st.Open != 0 {
		t.Fatalf("Open = %d after all releases", st.Open)
	}
	if got := st.Directory.Peers["node-b"].Active; got != 0 {
		t.Fatalf("node-b Active = %d", got)
	}
}

// A release called twice is a bug in the caller, but it must not report a
// connection that never closed.
func TestNoteDialReleaseIsIdempotent(t *testing.T) {
	r := NewStatusRegistry(newFakeClock(), "")
	rel := r.NoteDial("node-b")
	rel()
	rel()
	rel()

	if got := r.Status().Open; got != 0 {
		t.Fatalf("Open = %d after repeated release, want 0", got)
	}
}

func TestNoteDialFailureRecordsFailure(t *testing.T) {
	c := newFakeClock()
	r := NewStatusRegistry(c, "")
	r.NotePeerAnswer("node-b", PeerAnswer{Addr: "10.0.0.2", Port: 9090, Source: "memory", At: c.Now()})

	rel := r.NoteDial("node-b")
	r.NoteDialFailure("node-b")
	rel()

	p := r.Status().Directory.Peers["node-b"]
	if p.LastError != dialFailed {
		t.Fatalf("LastError = %q, want %q", p.LastError, dialFailed)
	}
	// The dial failed, the address did not: it is still the one to try again.
	if p.Addr != "10.0.0.2" {
		t.Fatalf("Addr = %q after a dial failure", p.Addr)
	}
	if p.Active != 0 {
		t.Fatalf("Active = %d after release", p.Active)
	}
}

func TestNoteApply(t *testing.T) {
	c := newFakeClock()
	r := NewStatusRegistry(c, "")

	c.advance(time.Minute)
	r.NoteApply("etag-1")
	first := c.Now()
	c.advance(time.Minute)
	r.NoteApply("etag-2")

	ch := r.Status().Channel
	if ch.ETag != "etag-2" {
		t.Fatalf("ETag = %q", ch.ETag)
	}
	if !ch.LastApply.Equal(c.Now()) || ch.LastApply.Equal(first) {
		t.Fatalf("LastApply = %v, want %v", ch.LastApply, c.Now())
	}
	if ch.Applies != 2 {
		t.Fatalf("Applies = %d, want 2", ch.Applies)
	}
}

func TestNoteApplyClearsChannelError(t *testing.T) {
	r := NewStatusRegistry(newFakeClock(), "")
	r.NoteChannelError(errors.New("pull failed"))
	if got := r.Status().Channel.LastError; got != "pull failed" {
		t.Fatalf("LastError = %q", got)
	}
	r.NoteApply("etag-1")
	if got := r.Status().Channel.LastError; got != "" {
		t.Fatalf("LastError = %q after an apply", got)
	}
}

func TestNoteChannelErrorAndRoute(t *testing.T) {
	r := NewStatusRegistry(newFakeClock(), "")

	r.NoteChannelRoute("proxy")
	r.NoteChannelError(errors.New("watch closed"))

	ch := r.Status().Channel
	if ch.Route != "proxy" {
		t.Fatalf("Route = %q", ch.Route)
	}
	if ch.LastError != "watch closed" {
		t.Fatalf("LastError = %q", ch.LastError)
	}

	r.NoteChannelError(nil)
	if got := r.Status().Channel.LastError; got != "" {
		t.Fatalf("LastError = %q after nil", got)
	}
	// A route note is not an outcome, so it must not invent an apply.
	if ch := r.Status().Channel; ch.Applies != 0 || !ch.LastApply.IsZero() {
		t.Fatalf("NoteChannelRoute changed the apply counters: %+v", ch)
	}
}

// Status hands out copies: a reader that sorts the routes it got back must not
// be able to disturb what the mesh holds.
func TestStatusReturnsCopies(t *testing.T) {
	r := NewStatusRegistry(newFakeClock(), "")
	r.NoteRoute("direct", nil)
	r.NotePeerAnswer("node-b", PeerAnswer{Addr: "10.0.0.2", Port: 1, Source: "memory"})

	st := r.Status()
	st.Directory.Routes[0].Name = "mutated"
	st.Directory.Routes[0].Attempts = 99
	st.Directory.Peers["node-b"] = PeerStatus{Addr: "mutated"}
	st.Directory.Peers["node-z"] = PeerStatus{}

	again := r.Status()
	if again.Directory.Routes[0].Name != "direct" || again.Directory.Routes[0].Attempts != 1 {
		t.Fatalf("routes mutated through Status: %+v", again.Directory.Routes)
	}
	if again.Directory.Peers["node-b"].Addr != "10.0.0.2" {
		t.Fatalf("peers mutated through Status: %+v", again.Directory.Peers)
	}
	if len(again.Directory.Peers) != 1 {
		t.Fatalf("peers gained an entry through Status: %+v", again.Directory.Peers)
	}
}

// Routes are a slice, so the order is the reporter's choice; two reads of an
// unchanged mesh must compare equal or nobody can diff them.
func TestRoutesAreOrdered(t *testing.T) {
	r := NewStatusRegistry(newFakeClock(), "")
	for _, name := range []string{"zulu", "alpha", "mike"} {
		r.NoteRoute(name, nil)
	}
	for i := 0; i < 20; i++ {
		got := []string{}
		for _, rs := range r.Status().Directory.Routes {
			got = append(got, rs.Name)
		}
		if got[0] != "alpha" || got[1] != "mike" || got[2] != "zulu" {
			t.Fatalf("route order = %v", got)
		}
	}
}

// Every event is recorded even for a peer never answered, because the first
// thing a dial to an unknown peer does is fail.
func TestEventsForUnknownPeerAreRecorded(t *testing.T) {
	r := NewStatusRegistry(newFakeClock(), "")
	r.NoteDialFailure("node-x")
	r.NotePeerError("node-y", errors.New("not found"))

	peers := r.Status().Directory.Peers
	if peers["node-x"].LastError != dialFailed {
		t.Fatalf("node-x = %+v", peers["node-x"])
	}
	if peers["node-y"].LastError != "not found" {
		t.Fatalf("node-y = %+v", peers["node-y"])
	}
}

// The whole layer exists to be read while the mesh is working, so every method
// is exercised from several goroutines at once. Run under -race this is the
// test that fails if a field was left outside the mutex.
func TestConcurrentUse(t *testing.T) {
	c := newFakeClock()
	r := NewStatusRegistry(c, "http://hub:8080")
	r.SetIdentity("node-a", "10.0.0.1", 9090)

	const workers = 8
	const rounds = 200

	var wg sync.WaitGroup
	start := make(chan struct{})

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			key := fmt.Sprintf("node-%d", w)
			for i := 0; i < rounds; i++ {
				rel := r.NoteDial(key)
				r.NotePeerAnswer(key, PeerAnswer{Addr: "10.0.0.2", Port: 9090, Source: "directory", At: c.Now()})
				r.NoteRoute("direct", nil)
				r.NoteRoute("proxy", errors.New("timeout"))
				r.NoteReport("10.0.0.1:9090")
				r.NoteApply(fmt.Sprintf("etag-%d", i))
				r.NoteChannelRoute("direct")
				r.NoteChannelError(errors.New("watch closed"))
				r.NoteChannelError(nil)
				r.NoteDialFailure(key)
				r.NotePeerError(key, errors.New("stale"))
				r.NotePeerError(key, nil)
				rel()
			}
		}(w)
	}

	// A reader runs throughout: Status must be safe to call while the writers
	// are mid-flight, which is the only time it is called in production.
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < rounds; i++ {
				st := r.Status()
				_ = st.Directory.Peers
				for range st.Directory.Routes {
				}
			}
		}()
	}

	close(start)
	wg.Wait()

	st := r.Status()
	if st.ID != "node-a" || st.Address != "10.0.0.1" || st.Port != 9090 {
		t.Fatalf("identity = %q/%q/%d", st.ID, st.Address, st.Port)
	}
	if len(st.Directory.Peers) != workers {
		t.Fatalf("peers = %d, want %d", len(st.Directory.Peers), workers)
	}
	for key, p := range st.Directory.Peers {
		if p.Active != 0 {
			t.Fatalf("%s Active = %d after every release", key, p.Active)
		}
	}
	if st.Open != 0 {
		t.Fatalf("Open = %d after every release", st.Open)
	}
	if st.Channel.Applies != int64(workers*rounds) {
		t.Fatalf("Applies = %d, want %d", st.Channel.Applies, workers*rounds)
	}
	byName := routeByName(t, st.Directory.Routes)
	if byName["direct"].Attempts != int64(workers*rounds) || byName["direct"].Failures != 0 {
		t.Fatalf("direct = %+v", byName["direct"])
	}
	if byName["proxy"].Attempts != int64(workers*rounds) || byName["proxy"].Failures != int64(workers*rounds) {
		t.Fatalf("proxy = %+v", byName["proxy"])
	}
}

func routeByName(t *testing.T, routes []RouteStatus) map[string]RouteStatus {
	t.Helper()
	out := make(map[string]RouteStatus, len(routes))
	for _, rs := range routes {
		if _, dup := out[rs.Name]; dup {
			t.Fatalf("route %q reported twice", rs.Name)
		}
		out[rs.Name] = rs
	}
	return out
}
