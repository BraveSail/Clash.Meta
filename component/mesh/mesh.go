// Package mesh is the runtime identity of one node's mesh: what this node is,
// where its peers are, and what the hub and the peers are doing right now.
//
// It exists because the same work used to be spread over three packages with
// three route policies and three sets of counters, and a fault showed up in one
// of them while reading like a network problem in all three. One package owns
// the node's whole relationship with the mesh, and answers for it in one place.
//
// THIS FILE IS THE FROZEN CONTRACT. Types and signatures here are what the rest
// of the tree compiles against; implementations live beside it.
package mesh

import (
	"context"
	"time"
)

// Config is everything one node needs to join a mesh.
type Config struct {
	// ID is the name this node reports under. Required.
	ID string
	// Port is the port this node serves its peers on.
	Port int
	// Name and OS are what the directory shows for this node.
	Name string
	OS   string
	// DirectoryURL and DirectoryToken are the directory this node talks to.
	DirectoryURL   string
	DirectoryToken string
	// DirectoryProxy is an HTTP proxy URL the directory requests go through,
	// when the profile names one. Empty means the direct route only.
	DirectoryProxy string
	// Heartbeat is how often this node reports when nothing changed.
	Heartbeat time.Duration
	// CacheDir is where persisted peer answers live. Empty disables
	// persistence.
	CacheDir string
}

// PeerAnswer is where one peer was found, and how.
type PeerAnswer struct {
	Addr string
	Port int
	// Self is true when the directory resolved the key back to this node. A
	// caller must never dial a self answer through a peer tunnel.
	Self bool
	// Source says where the answer came from: "memory", "persisted", or
	// "directory". It is what makes "why is this address stale?" answerable.
	Source string
	// At is when the answer was learned.
	At time.Time
}

// RouteStatus is one route's health, as observed by the requests that used it.
type RouteStatus struct {
	Name string
	// LastOK is the last time this route carried a request that got an answer.
	LastOK time.Time
	// LastError is the last reason it did not, cleared by the next success.
	LastError string
	// Attempts and Failures are cumulative since the mesh started.
	Attempts int64
	Failures int64
}

// PeerStatus is one peer, as far as this node can tell.
type PeerStatus struct {
	Addr string
	Port int
	Self bool
	// Source is where the answer in hand came from ("memory", "persisted",
	// "directory", or empty when nothing is known).
	Source string
	// LastResolved is when the answer was last confirmed by the directory.
	LastResolved time.Time
	LastError    string
	// Active is the number of connections currently open to this peer.
	Active int
}

// DirectoryStatus is the discovery half.
type DirectoryStatus struct {
	URL string
	// Route is the route that last answered, by name.
	Route  string
	Routes []RouteStatus
	// Address is what this node last published, Reported is when.
	Address  string
	Reported time.Time
	// LastError is the last failed report or lookup.
	LastError string
	Peers     map[string]PeerStatus
}

// ChannelStatus is the profile half.
type ChannelStatus struct {
	// Route is the route that last answered.
	Route string
	// ETag is the revision this node runs.
	ETag string
	// LastApply is when a pulled or pushed profile was last applied, and
	// Applies how many times since start. A count that climbs while nobody is
	// editing is the answer to "is something reloading my config under me?".
	LastApply time.Time
	Applies   int64
	// LastError is the last failed pull or watch.
	LastError string
}

// Status is the whole answer, from one read.
type Status struct {
	ID      string
	Address string
	Port    int
	// Directory and Channel are the two halves of the node's relationship with
	// the hub.
	Directory DirectoryStatus
	Channel   ChannelStatus
	// Open is the number of connections this node currently carries to peers.
	Open int
	// Since is when this mesh started.
	Since time.Time
}

// Mesh is one node's mesh. It is constructed once per running configuration and
// closed when that configuration is replaced.
type Mesh interface {
	// PeerAnswer answers where [key] is. It never blocks on the directory: an
	// answer in hand is returned, and a stale one is refreshed behind the
	// caller.
	PeerAnswer(ctx context.Context, key string) (PeerAnswer, error)

	// NoteDial records that a connection to [key] is being opened, and returns
	// the release for it. A caller must call release exactly once, when the
	// connection ends. Nothing is closed by this call; it is a counter, so a
	// peer's live connection count is a fact rather than a guess.
	NoteDial(key string) func()

	// NoteDialFailure records that a dial to [key] failed, so the next answer
	// for it is asked of the directory rather than repeated from the cache.
	NoteDialFailure(key string)

	// Status answers everything this node knows about its mesh, in one read.
	Status() Status

	// Close releases the mesh. Connections already open are not touched: they
	// belong to whoever opened them.
	Close() error
}

// Clock is the time source a Mesh reads, so a test can move time without
// sleeping.
type Clock interface {
	Now() time.Time
}

// SystemClock is the real one.
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }
