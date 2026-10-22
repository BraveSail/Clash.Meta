package adapter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// meshDirectory answers lookups for several devices, which is what a mesh entry
// asks: one entry serves every device, so the answer depends on the record the
// connection's name resolved to.
type meshDirectory struct {
	mu    sync.Mutex
	addrs map[string]string
}

func (m *meshDirectory) serve(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/report":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"id": "this-device", "addr": "2409:8a55::1", "port": 8443, "changed": true,
			})
		case "/lookup":
			m.mu.Lock()
			addr, ok := m.addrs[request.URL.Query().Get("id")]
			m.mu.Unlock()
			if !ok {
				writer.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"nodes": map[string]any{
					request.URL.Query().Get("id"): map[string]any{"addr": addr, "port": 8443},
				},
			})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// A mesh entry carries the domains its devices claimed, and the name a
// connection asked for decides which record is looked up: this is what lets a
// profile's rule point at the mesh alone.
func TestMeshEntryResolvesByTheRequestedName(t *testing.T) {
	directory := &meshDirectory{addrs: map[string]string{
		"record-pc":  "2409:895a::aa",
		"record-gt7": "2409:895a::bb",
	}}
	server := directory.serve(t)

	peer := newTestPeer(t, TailnetPeerOption{
		Name: "mesh",
		Port: 8443,
		Proxy: map[string]any{
			"type": "direct", "name": "inner",
		},
		DirectoryURL:   server.URL,
		DirectoryToken: "secret",
		DirectoryID:    "this-device",
		Domains: map[string]string{
			"pc.lan":  "record-pc",
			"gt7.lan": "record-gt7",
		},
	})

	// Two names, two devices: one entry has to keep both answers, or the second
	// connection would be served by whichever device was looked up first.
	pcHost, _, _, err := peer.resolveFor(context.Background(), "pc.lan")
	if err != nil {
		t.Fatal(err)
	}
	gt7Host, _, _, err := peer.resolveFor(context.Background(), "gt7.lan")
	if err != nil {
		t.Fatal(err)
	}
	if pcHost != "2409:895a::aa" {
		t.Fatalf("pc.lan resolved to %q, want the record it maps to", pcHost)
	}
	if gt7Host != "2409:895a::bb" {
		t.Fatalf("gt7.lan resolved to %q, want the record it maps to", gt7Host)
	}
}

// A name the entry was not given falls back to the configured peer: a profile
// may address a device by the name in its own outbound, and only mapped names
// are guaranteed to be in the map.
func TestMeshEntryFallsBackForAnUnmappedName(t *testing.T) {
	directory := &meshDirectory{addrs: map[string]string{"record-pc": "2409:895a::aa"}}
	server := directory.serve(t)

	peer := newTestPeer(t, TailnetPeerOption{
		Name:           "mesh",
		Peer:           "record-pc",
		Port:           8443,
		Proxy:          map[string]any{"type": "direct", "name": "inner"},
		DirectoryURL:   server.URL,
		DirectoryToken: "secret",
		DirectoryID:    "this-device",
		Domains:        map[string]string{"other.lan": "record-other"},
	})

	host, _, _, err := peer.resolveFor(context.Background(), "unmapped.lan")
	if err != nil {
		t.Fatal(err)
	}
	if host != "2409:895a::aa" {
		t.Fatalf("an unmapped name resolved to %q, want the configured peer", host)
	}
}

// The requested name is what a mesh entry maps; a connection without one (an
// IP, a rule that never carried a name) is resolved as the configured peer, so
// an entry that also names a device keeps working the way it always did.
func TestMeshEntryWithoutANameUsesTheConfiguredPeer(t *testing.T) {
	directory := &meshDirectory{addrs: map[string]string{"record-pc": "2409:895a::aa"}}
	server := directory.serve(t)

	peer := newTestPeer(t, TailnetPeerOption{
		Name:           "mesh",
		Peer:           "record-pc",
		Port:           8443,
		Proxy:          map[string]any{"type": "direct", "name": "inner"},
		DirectoryURL:   server.URL,
		DirectoryToken: "secret",
		DirectoryID:    "this-device",
		Domains:        map[string]string{"pc.lan": "record-somewhere-else"},
	})

	host, _, _, err := peer.resolveFor(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if host != "2409:895a::aa" {
		t.Fatalf("a nameless connection resolved to %q, want the configured peer", host)
	}
}

// The name is matched lower case: a domain is case-insensitive, and the map is
// written from what the dashboard stored, which is lower case too.
func TestMeshEntryMatchesTheRequestedNameCaseInsensitively(t *testing.T) {
	peer := newTestPeer(t, TailnetPeerOption{
		Name:           "mesh",
		Port:           8443,
		Proxy:          map[string]any{"type": "direct", "name": "inner"},
		DirectoryURL:   "http://127.0.0.1:1",
		DirectoryToken: "secret",
		DirectoryID:    "this-device",
		Domains:        map[string]string{"pc.lan": "record-pc"},
	})

	if got := peer.recordKey(requestedHost(&C.Metadata{Host: "PC.LAN"})); got != "record-pc" {
		t.Fatalf("recordKey for PC.LAN = %q, want the mapped record", got)
	}
}
