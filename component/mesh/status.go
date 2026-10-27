package mesh

import (
	"sort"
	"sync"
	"time"
)

// StatusRegistry is the mesh's memory of what already happened, kept apart from
// the code that makes it happen. Every field it reports is the value or the
// timestamp of a real event, never a conclusion drawn from other events, so a
// wrong answer here means the events were wrong rather than the reporting.
//
// The zero value is not usable: a registry without a Clock cannot timestamp
// anything, and a status with no timestamps cannot answer "since when".
type StatusRegistry struct {
	mu    sync.Mutex
	clock Clock

	id      string
	address string
	port    int
	since   time.Time

	dirURL   string
	dirRoute string
	routes   map[string]*RouteStatus
	reported string
	reportAt time.Time
	dirErr   string
	peers    map[string]*peerState

	chanRoute string
	chanETag  string
	chanApply time.Time
	chanCount int64
	chanErr   string
}

// peerState is one peer's row. It is separate from PeerStatus so that Status
// hands out copies and a reader can never write back into live state.
type peerState struct {
	addr     string
	port     int
	self     bool
	source   string
	resolved time.Time
	err      string
	active   int
}

// dialFailed is what a failed dial is recorded as. NoteDialFailure is called by
// the dial site, which has the connection's error but does not hand it here, so
// the fact recorded is the failure itself rather than a reason that was never
// observed.
const dialFailed = "dial failed"

// NewStatusRegistry starts a registry for one mesh. Since is taken here, from
// the same clock every later timestamp comes from, so a test that moves the
// clock sees a consistent timeline.
func NewStatusRegistry(clock Clock, directoryURL string) *StatusRegistry {
	if clock == nil {
		clock = SystemClock{}
	}
	return &StatusRegistry{
		clock:  clock,
		since:  clock.Now(),
		dirURL: directoryURL,
		routes: make(map[string]*RouteStatus),
		peers:  make(map[string]*peerState),
	}
}

// SetIdentity records who this node is. The address here is the one the node
// serves on; what the directory was told is separate, because a node behind NAT
// publishes an address it does not serve on, and conflating the two would hide
// exactly that case.
func (r *StatusRegistry) SetIdentity(id, address string, port int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.id, r.address, r.port = id, address, port
}

// NoteRoute records one request's outcome on a named route. A nil error is a
// success and is the only thing that clears LastError: a route that failed once
// and then carried traffic reads as healthy, which is the point of clearing it.
func (r *StatusRegistry) NoteRoute(route string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rs, ok := r.routes[route]
	if !ok {
		rs = &RouteStatus{Name: route}
		r.routes[route] = rs
	}
	rs.Attempts++
	if err != nil {
		rs.Failures++
		rs.LastError = err.Error()
		// The directory's routes are the routes that carry its requests, so a
		// failed one is a failed lookup: that is the event DirectoryStatus
		// reports.
		r.dirErr = err.Error()
		return
	}
	rs.LastOK = r.clock.Now()
	rs.LastError = ""
	// Only a route that answered is the one that last answered.
	r.dirRoute = route
	r.dirErr = ""
}

// NoteReport records that the directory accepted this node's address, and when.
// A report that got through is the directory answering, so it clears the
// directory's error as well.
func (r *StatusRegistry) NoteReport(addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reported = addr
	r.reportAt = r.clock.Now()
	r.dirErr = ""
}

// NotePeerAnswer records where a peer was found. The answer's At is used as
// LastResolved because the answer in hand is the confirmation: there is no
// second event that confirms it, and inventing one would put a timestamp on
// something that did not happen.
func (r *StatusRegistry) NotePeerAnswer(key string, a PeerAnswer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.peer(key)
	p.addr, p.port, p.self, p.source = a.Addr, a.Port, a.Self, a.Source
	p.resolved = a.At
	p.err = ""
}

// NotePeerError records why a peer could not be resolved. The answer already in
// hand is kept: a peer whose lookup failed is still reachable at the address
// that was learned earlier, and dropping it would lose that.
func (r *StatusRegistry) NotePeerError(key string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.peer(key)
	if err == nil {
		p.err = ""
		return
	}
	p.err = err.Error()
}

// NoteDial records that a connection to a peer is opening, and returns the
// release for it. The caller must call release exactly once when the connection
// ends; a second call is swallowed, because a double release would report a
// connection that never closed.
func (r *StatusRegistry) NoteDial(key string) func() {
	r.mu.Lock()
	r.peer(key).active++
	r.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			if p, ok := r.peers[key]; ok && p.active > 0 {
				p.active--
			}
		})
	}
}

// NoteDialFailure records that a dial to a peer failed. It does not touch the
// peer's address: the address was not disproved, only the dial.
func (r *StatusRegistry) NoteDialFailure(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.peer(key).err = dialFailed
}

// NoteApply records a profile being applied, and the revision it left the node
// running. A successful apply clears LastError for the same reason a route
// does.
func (r *StatusRegistry) NoteApply(etag string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.chanETag = etag
	r.chanApply = r.clock.Now()
	r.chanCount++
	r.chanErr = ""
}

// NoteChannelError records why a pull or a watch failed.
func (r *StatusRegistry) NoteChannelError(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err == nil {
		r.chanErr = ""
		return
	}
	r.chanErr = err.Error()
}

// NoteChannelRoute records the route the profile channel last answered on.
func (r *StatusRegistry) NoteChannelRoute(route string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.chanRoute = route
}

// Status reads everything in one pass. The result is a copy: the peer map and
// the route rows belong to the caller from here on, so a reader that sorts or
// edits what it got back cannot disturb the mesh.
func (r *StatusRegistry) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()

	st := Status{
		ID:      r.id,
		Address: r.address,
		Port:    r.port,
		Since:   r.since,
	}
	st.Directory = DirectoryStatus{
		URL:       r.dirURL,
		Route:     r.dirRoute,
		Address:   r.reported,
		Reported:  r.reportAt,
		LastError: r.dirErr,
		Peers:     make(map[string]PeerStatus, len(r.peers)),
	}
	for _, rs := range r.routes {
		st.Directory.Routes = append(st.Directory.Routes, *rs)
	}
	// Routes are a slice, so their order is this function's choice; sorting by
	// name makes two reads of an unchanged mesh compare equal.
	sort.Slice(st.Directory.Routes, func(i, j int) bool {
		return st.Directory.Routes[i].Name < st.Directory.Routes[j].Name
	})
	for key, p := range r.peers {
		st.Directory.Peers[key] = PeerStatus{
			Addr:         p.addr,
			Port:         p.port,
			Self:         p.self,
			Source:       p.source,
			LastResolved: p.resolved,
			LastError:    p.err,
			Active:       p.active,
		}
		st.Open += p.active
	}
	st.Channel = ChannelStatus{
		Route:     r.chanRoute,
		ETag:      r.chanETag,
		LastApply: r.chanApply,
		Applies:   r.chanCount,
		LastError: r.chanErr,
	}
	return st
}

// peer returns the row for a key, creating it on first mention so that an event
// about an unknown peer is recorded rather than dropped.
func (r *StatusRegistry) peer(key string) *peerState {
	p, ok := r.peers[key]
	if !ok {
		p = &peerState{}
		r.peers[key] = p
	}
	return p
}
