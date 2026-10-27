package outbound

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/profile/cachefile"
)

// A dial must not wait on the directory. These tests pin the three behaviours
// that make that true: a persisted answer answers the first dial after a
// restart, a stale in-memory answer is handed out while the refresh runs behind
// it, and an unreachable directory never turns into a failed dial for a peer
// that was seen before.

// cacheDirectory builds a directory pointed at a stub that answers /lookup with
// a fixed address and counts the calls.
func cacheDirectory(t *testing.T, url string, id string, addr string, calls *atomic.Int64) *PeerDirectory {
	t.Helper()
	directory, err := NewPeerDirectory(PeerDirectoryOption{
		Name: "cache test directory",
		URL:  url,
		ID:   id,
		Port: 23333,
	})
	if err != nil {
		t.Fatalf("NewPeerDirectory: %v", err)
	}
	t.Cleanup(func() { _ = directory.Close() })
	return directory
}

// lookupStub answers /lookup with [addr] for any id, counting the calls, and
// can be told to fail.
func lookupStub(t *testing.T, addr string, calls *atomic.Int64, failing *atomic.Bool) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/lookup":
			calls.Add(1)
			if failing != nil && failing.Load() {
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			id := request.URL.Query().Get("id")
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"nodes": map[string]any{
					id: map[string]any{"id": id, "addr": addr, "port": 23333},
				},
			})
		default:
			writer.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// TestPeerAddressDoesNotWaitOnASlowDirectory pins the fix: an answer that has
// aged out is handed to the caller immediately and refreshed in the background,
// so a directory that takes seconds to answer cannot stall a dial.
func TestPeerAddressDoesNotWaitOnASlowDirectory(t *testing.T) {
	var calls atomic.Int64
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/lookup" {
			writer.WriteHeader(http.StatusOK)
			return
		}
		calls.Add(1)
		<-release // hold the answer until the test lets go
		id := request.URL.Query().Get("id")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"nodes": map[string]any{id: map[string]any{"id": id, "addr": "2408::9", "port": 23333}},
		})
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })

	directory, err := NewPeerDirectory(PeerDirectoryOption{
		Name: "slow directory", URL: server.URL, ID: "self", Port: 23333,
	})
	if err != nil {
		t.Fatalf("NewPeerDirectory: %v", err)
	}
	t.Cleanup(func() { _ = directory.Close() })

	// Seed an answer that is already past its TTL.
	directory.storePeer("peer-a", cachedPeer{addr: "2408::1", port: 23333, at: time.Now().Add(-2 * peerDirectoryLookupTTL)})

	done := make(chan struct{})
	var addr string
	var err2 error
	go func() {
		addr, _, _, err2 = directory.PeerAddress(context.Background(), "peer-a")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("PeerAddress waited on the directory instead of answering from the cache")
	}
	if err2 != nil {
		t.Fatalf("PeerAddress: %v", err2)
	}
	if addr != "2408::1" {
		t.Fatalf("PeerAddress = %q, want the cached answer 2408::1", addr)
	}
	// The refresh runs behind the caller; give it a moment to reach the stub.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && calls.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() == 0 {
		t.Fatal("no background refresh was started for a stale answer")
	}
}

// TestPeerAddressSurvivesAnUnreachableDirectory pins the second half: a peer
// seen before keeps answering while the directory is down, and a peer never
// seen is the only case that reports the failure.
func TestPeerAddressSurvivesAnUnreachableDirectory(t *testing.T) {
	var calls atomic.Int64
	var failing atomic.Bool
	server := lookupStub(t, "2408::2", &calls, &failing)
	directory, err := NewPeerDirectory(PeerDirectoryOption{
		Name: "flaky directory", URL: server.URL, ID: "self", Port: 23333,
	})
	if err != nil {
		t.Fatalf("NewPeerDirectory: %v", err)
	}
	t.Cleanup(func() { _ = directory.Close() })

	addr, _, _, err := directory.PeerAddress(context.Background(), "peer-b")
	if err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if addr != "2408::2" {
		t.Fatalf("first lookup = %q, want 2408::2", addr)
	}

	failing.Store(true)
	directory.storePeer("peer-b", cachedPeer{addr: addr, port: 23333, at: time.Now().Add(-2 * peerDirectoryLookupTTL)})
	kept, _, _, err := directory.PeerAddress(context.Background(), "peer-b")
	if err != nil {
		t.Fatalf("a peer seen before must not fail when the directory is down: %v", err)
	}
	if kept != "2408::2" {
		t.Fatalf("kept = %q, want the last known address 2408::2", kept)
	}
}

// TestPersistedPeerAnswersAfterRestart pins the cache service: an answer written
// by one directory is read back by the next one built for the same URL, so a
// restart does not pay a lookup before the first dial can go out.
func TestPersistedPeerAnswersAfterRestart(t *testing.T) {
	directory, err := NewPeerDirectory(PeerDirectoryOption{
		Name: "persist directory", URL: "https://directory.invalid", ID: "self", Port: 23333,
	})
	if err != nil {
		t.Fatalf("NewPeerDirectory: %v", err)
	}
	directory.storePersistedPeer("peer-c", "2408::3", 23333)
	_ = directory.Close()

	restarted, err := NewPeerDirectory(PeerDirectoryOption{
		Name: "persist directory", URL: "https://directory.invalid", ID: "self", Port: 23333,
	})
	if err != nil {
		t.Fatalf("NewPeerDirectory (restart): %v", err)
	}
	t.Cleanup(func() { _ = restarted.Close() })

	restarted.mu.Lock()
	entry, ok := restarted.peers["peer-c"]
	restarted.mu.Unlock()
	if !ok {
		t.Fatal("the persisted answer was not restored on startup")
	}
	if entry.addr != "2408::3" || entry.port != 23333 {
		t.Fatalf("restored = %q:%d, want 2408::3:23333", entry.addr, entry.port)
	}
}

// TestUsableStalePeerBoundsHowOldAnAnswerMayBe keeps a stale entry from
// outliving its usefulness: a device that moved long ago is not dialled at an
// address it has left.
func TestUsableStalePeerBoundsHowOldAnAnswerMayBe(t *testing.T) {
	if !usableStalePeer(time.Now().Add(-time.Hour)) {
		t.Fatal("an answer from an hour ago should still be usable")
	}
	if usableStalePeer(time.Now().Add(-stalePeerTTL - time.Minute)) {
		t.Fatal("an answer older than the stale window must not be used")
	}
	if usableStalePeer(time.Time{}) {
		t.Fatal("an entry with no timestamp must not be used")
	}
	// The window has to outlast the in-memory TTL, or "aged out but still
	// worth keeping" would be an empty range and the boundary would be a
	// no-op however it is written.
	if stalePeerTTL <= peerDirectoryLookupTTL {
		t.Fatalf("stalePeerTTL = %s, want it longer than the lookup TTL %s", stalePeerTTL, peerDirectoryLookupTTL)
	}
}

// TestPeerAddressAsksAgainWhenThePersistedAnswerIsTooOld pins the boundary on
// the path that actually reaches it: only a persisted entry can be a day old,
// because a running process refreshes behind every dial past
// peerDirectoryLookupTTL. An entry past stalePeerTTL is not handed out - the
// directory is asked instead - so a device that has been off the network for a
// day is not dialled where it used to be.
func TestPeerAddressAsksAgainWhenThePersistedAnswerIsTooOld(t *testing.T) {
	var calls atomic.Int64
	server := lookupStub(t, "2408::7", &calls, nil)
	url := server.URL

	// An answer this node learned, aged past the window the way a machine left
	// off the network for a day would find it.
	persistWithAge(t, url, "peer-d", "2408::6", 23333, stalePeerTTL+time.Hour)

	// The process reads it back on startup, but must not dial it: the
	// directory is asked instead.
	directory, err := NewPeerDirectory(PeerDirectoryOption{
		Name: "aging directory", URL: url, ID: "self", Port: 23333,
	})
	if err != nil {
		t.Fatalf("NewPeerDirectory (restart): %v", err)
	}
	t.Cleanup(func() { _ = directory.Close() })

	addr, _, _, err := directory.PeerAddress(context.Background(), "peer-d")
	if err != nil {
		t.Fatalf("PeerAddress: %v", err)
	}
	if addr != "2408::7" {
		t.Fatalf("PeerAddress = %q, want the fresh answer 2408::7 rather than the aged 2408::6", addr)
	}
	if calls.Load() == 0 {
		t.Fatal("an answer past stalePeerTTL was handed out without asking the directory")
	}
}

// TestPeerAddressRefusesAnAnswerTooOldToBeWorthKeeping is the other half of the
// same boundary: when the directory cannot be reached either, an answer past
// stalePeerTTL is not handed out as a last resort. Reporting the failure is the
// truth - the caller's own retry follows - while dialling a day-old address
// costs a failed connection first.
func TestPeerAddressRefusesAnAnswerTooOldToBeWorthKeeping(t *testing.T) {
	var calls atomic.Int64
	var failing atomic.Bool
	server := lookupStub(t, "2408::8", &calls, &failing)
	directory, err := NewPeerDirectory(PeerDirectoryOption{
		Name: "aging fallback directory", URL: server.URL, ID: "self", Port: 23333,
	})
	if err != nil {
		t.Fatalf("NewPeerDirectory: %v", err)
	}
	t.Cleanup(func() { _ = directory.Close() })

	// An answer the directory gave a moment ago is still the best guess when
	// the directory goes down.
	directory.storePeer("peer-e", cachedPeer{
		addr: "2408::9", port: 23333, at: time.Now().Add(-2 * peerDirectoryLookupTTL),
	})
	failing.Store(true)
	kept, _, _, err := directory.PeerAddress(context.Background(), "peer-e")
	if err != nil || kept != "2408::9" {
		t.Fatalf("a fresh-enough answer was not kept: %q err=%v", kept, err)
	}

	// One past the window is not: the failure is reported instead.
	directory.storePeer("peer-e", cachedPeer{
		addr: "2408::9", port: 23333, at: time.Now().Add(-stalePeerTTL - time.Hour),
	})
	if addr, _, _, err := directory.PeerAddress(context.Background(), "peer-e"); err == nil {
		t.Fatalf("an answer past stalePeerTTL was handed out as %q while the directory was down", addr)
	}
}

// persistWithAge writes the persisted entry for [id] with a timestamp [age] in
// the past, so a test can describe a machine that has been off the network for
// that long without waiting for it.
func persistWithAge(t *testing.T, url, id, addr string, port int, age time.Duration) {
	t.Helper()
	probe, err := NewPeerDirectory(PeerDirectoryOption{
		Name: "aging probe", URL: url, ID: "self", Port: 23333,
	})
	if err != nil {
		t.Fatalf("NewPeerDirectory (probe): %v", err)
	}
	prefix := probe.peerCacheStoragePrefix()
	_ = probe.Close()

	cache := cachefile.Cache()
	if cache == nil {
		t.Skip("no cache file on this machine to age an entry in")
	}
	raw, err := json.Marshal(persistedPeer{Addr: addr, Port: port, At: time.Now().Add(-age).Unix()})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	cache.SetStorage(prefix+id, raw)
	t.Cleanup(func() { cache.DeleteStorage(prefix + id) })
}

// TestPeerCacheStoragePrefixNamespacesByDirectory pins the key every persisted
// answer is written under: one cache file is shared by every profile on the
// machine, so two directories must not read each other's answers.
func TestPeerCacheStoragePrefixNamespacesByDirectory(t *testing.T) {
	first, err := NewPeerDirectory(PeerDirectoryOption{
		Name: "first", URL: "https://hub.example", ID: "pc", Port: 23333,
	})
	if err != nil {
		t.Fatalf("NewPeerDirectory: %v", err)
	}
	t.Cleanup(func() { _ = first.Close() })
	second, err := NewPeerDirectory(PeerDirectoryOption{
		Name: "second", URL: "https://other.example", ID: "pc", Port: 23333,
	})
	if err != nil {
		t.Fatalf("NewPeerDirectory: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })

	prefix := first.peerCacheStoragePrefix()
	if prefix != "peer-directory/"+cacheKeyDigest("https://hub.example")+"/" {
		t.Fatalf("prefix = %q, want it built from the directory digest", prefix)
	}
	if prefix == second.peerCacheStoragePrefix() {
		t.Fatal("two directories share one storage prefix")
	}
}

// TestCacheKeyDigestSeparatesDirectories keeps two directories' answers apart:
// one cache file is shared by every profile on the machine.
func TestCacheKeyDigestSeparatesDirectories(t *testing.T) {
	a := cacheKeyDigest("https://hub.see.moe")
	b := cacheKeyDigest("https://other.example")
	if a == b {
		t.Fatalf("two directories hashed to the same key %q", a)
	}
	if a != cacheKeyDigest("https://hub.see.moe ") {
		t.Fatal("a trailing space must not change the key")
	}
	if len(a) != 16 {
		t.Fatalf("digest = %q, want 16 hex digits", a)
	}
}

// TestCachedSelfIsNeverHandedOutAsAPeer pins a trap the fast path could fall
// into: "this name is me" is a judgement about the directory's current data, so
// an alias that is added or removed changes it. Handing a cached self back as
// another device would point this node at itself, so a cached self must be
// re-confirmed against the directory rather than reused.
func TestCachedSelfIsNeverHandedOutAsAPeer(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/lookup" {
			writer.WriteHeader(http.StatusOK)
			return
		}
		calls.Add(1)
		// The directory now says this name is another device, not this node.
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"nodes": map[string]any{
				"gt7": map[string]any{"id": "gt7", "addr": "2409:895a::1", "port": 8443},
			},
		})
	}))
	t.Cleanup(server.Close)

	directory, err := NewPeerDirectory(PeerDirectoryOption{
		Name: "alias directory", URL: server.URL, ID: "pc", Port: 8443,
	})
	if err != nil {
		t.Fatalf("NewPeerDirectory: %v", err)
	}
	t.Cleanup(func() { _ = directory.Close() })

	// An alias was in place a moment ago and the answer was cached as "this is
	// me". The directory has since changed its mind.
	directory.storePeer("gt7", cachedPeer{addr: "2409:895a::1", port: 8443, self: true, at: time.Now()})

	before := calls.Load()
	addr, port, self, err := directory.PeerAddress(context.Background(), "gt7")
	if err != nil {
		t.Fatalf("PeerAddress: %v", err)
	}
	if self {
		t.Fatal("a cached self was handed out without re-confirming it")
	}
	if addr != "2409:895a::1" || port != 8443 {
		t.Fatalf("PeerAddress = %q:%d, want 2409:895a::1:8443", addr, port)
	}
	if calls.Load() == before {
		t.Fatal("the directory was not asked again for a cached self")
	}
}
