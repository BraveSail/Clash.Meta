package outbound

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
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
