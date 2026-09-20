package adapter

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
)

func TestDirectoryIDIsWhateverTheAppComputed(t *testing.T) {
	option := TailnetPeerOption{DirectoryID: "a3f8b2c91d04"}
	if got := option.directoryID(); got != "a3f8b2c91d04" {
		t.Fatalf("directoryID() = %q, want the id the app computed", got)
	}
	// A profile that never got the id carries none: the outbound warns rather
	// than inventing one.
	if got := (TailnetPeerOption{}).directoryID(); got != "" {
		t.Fatalf("directoryID() = %q, want empty without the app's id", got)
	}
}

func TestTailnetPeerRejectsIncompleteOptions(t *testing.T) {
	if _, err := NewTailnetPeer(TailnetPeerOption{Name: "x", Port: 1, Proxy: map[string]any{"type": "direct"}}); err == nil {
		t.Fatal("missing peer accepted")
	}
	if _, err := NewTailnetPeer(TailnetPeerOption{Name: "x", Peer: "pc", Proxy: map[string]any{"type": "direct"}}); err == nil {
		t.Fatal("missing port accepted")
	}
	if _, err := NewTailnetPeer(TailnetPeerOption{Name: "x", Peer: "pc", Port: 1}); err == nil {
		t.Fatal("missing proxy accepted")
	}
	if _, err := NewTailnetPeer(TailnetPeerOption{Name: "x", Peer: "pc", Port: 1, Proxy: map[string]any{"type": "direct"}}); err == nil {
		t.Fatal("missing directory accepted")
	}
}

// stubDirectory is a directory service: it answers where [peerID] is with the
// address the test last set, and counts the reports this node sent.
type stubDirectory struct {
	mu       sync.Mutex
	ownID    string
	peerID   string
	peerAddr string
	reports  atomic.Int64
}

func (s *stubDirectory) serve() *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/report":
			s.reports.Add(1)
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"id":      s.ownID,
				"addr":    "2409:8a55::1",
				"port":    8443,
				"changed": true,
			})
		case "/lookup":
			if request.URL.Query().Get("id") != s.peerID {
				writer.WriteHeader(http.StatusNotFound)
				return
			}
			s.mu.Lock()
			addr := s.peerAddr
			s.mu.Unlock()
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"nodes": map[string]any{
					s.peerID: map[string]any{"addr": addr, "port": 8443},
				},
			})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	return server
}

func (s *stubDirectory) movePeer(addr string) {
	s.mu.Lock()
	s.peerAddr = addr
	s.mu.Unlock()
}

func newTestPeer(t *testing.T, option TailnetPeerOption) *TailnetPeer {
	t.Helper()
	created, err := NewTailnetPeer(option)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = created.Close() })
	return created
}

func TestTailnetPeerResolvesThroughTheDirectory(t *testing.T) {
	stub := &stubDirectory{ownID: "pc", peerID: "gt7", peerAddr: "2409:895a::1"}
	server := stub.serve()
	t.Cleanup(server.Close)

	peer := newTestPeer(t, TailnetPeerOption{
		Name:           "gt7",
		Peer:           "gt7",
		Port:           23333,
		Proxy:          map[string]any{"type": "direct", "name": "inner"},
		DirectoryURL:   server.URL,
		DirectoryToken: "secret",
		DirectoryID:    "pc",
	})

	host, self, err := peer.resolve(context.Background())
	if err != nil || self || host != "2409:895a::1" {
		t.Fatalf("resolve = %q self=%v err=%v", host, self, err)
	}

	proxy, err := peer.proxyForDial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if proxy.Type() != C.Direct {
		t.Fatalf("inner proxy type = %v, want the configured inner type", proxy.Type())
	}
	if got := peer.Addr(); got != "2409:895a::1:23333" {
		t.Fatalf("Addr() = %q, want the resolved address and this outbound's port", got)
	}

	stub.movePeer("2409:895a::9")
	// Both the outbound and the directory client cache for a moment, so the
	// next connection after that window dials the new address.
	time.Sleep(2300 * time.Millisecond)
	peer.invalidate()
	host, _, err = peer.resolve(context.Background())
	if err != nil || host != "2409:895a::9" {
		t.Fatalf("resolve after the peer moved = %q err=%v", host, err)
	}
}

func TestTailnetPeerDegradesToDirectForItself(t *testing.T) {
	stub := &stubDirectory{ownID: "pc", peerID: "gt7", peerAddr: "2409:895a::1"}
	server := stub.serve()
	t.Cleanup(server.Close)

	peer := newTestPeer(t, TailnetPeerOption{
		Name:         "pc",
		Peer:         "pc",
		Port:         23333,
		Proxy:        map[string]any{"type": "direct", "name": "inner"},
		DirectoryURL: server.URL,
		DirectoryID:  "pc",
	})

	host, self, err := peer.resolve(context.Background())
	if err != nil || !self || host != "" {
		t.Fatalf("resolve(self) = %q self=%v err=%v", host, self, err)
	}
	proxy, err := peer.proxyForDial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if proxy.Type() != C.Direct {
		t.Fatalf("self peer proxy type = %v, want DIRECT", proxy.Type())
	}
}

func TestTailnetPeerWithoutADirectoryNameFails(t *testing.T) {
	stub := &stubDirectory{ownID: "pc", peerID: "gt7", peerAddr: "2409:895a::1"}
	server := stub.serve()
	t.Cleanup(server.Close)

	// No id computed, so this device has no name: the outbound refuses instead
	// of resolving somewhere else.
	peer := newTestPeer(t, TailnetPeerOption{
		Name:         "gt7",
		Peer:         "gt7",
		Port:         23333,
		Proxy:        map[string]any{"type": "direct", "name": "inner"},
		DirectoryURL: server.URL,
	})
	if _, _, err := peer.resolve(context.Background()); err == nil {
		t.Fatal("a device without a directory name resolved a peer")
	}
}

func TestTailnetPeerUnknownPeerFails(t *testing.T) {
	stub := &stubDirectory{ownID: "pc", peerID: "gt7", peerAddr: "2409:895a::1"}
	server := stub.serve()
	t.Cleanup(server.Close)

	peer := newTestPeer(t, TailnetPeerOption{
		Name:         "nobody",
		Peer:         "nobody",
		Port:         23333,
		Proxy:        map[string]any{"type": "direct", "name": "inner"},
		DirectoryURL: server.URL,
		DirectoryID:  "pc",
	})
	if _, _, err := peer.resolve(context.Background()); err == nil {
		t.Fatal("unknown peer resolved")
	}
}

// A peer that is this node is reachable on the loopback address: dialing the
// destination as it stands would come back through the rule that selected this
// outbound.
func TestTailnetPeerDialsLocalServiceForItself(t *testing.T) {
	previousIPv6 := resolver.DisableIPv6
	resolver.DisableIPv6 = false
	t.Cleanup(func() { resolver.DisableIPv6 = previousIPv6 })

	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte("local"))
	}()

	stub := &stubDirectory{ownID: "pc", peerID: "gt7", peerAddr: "2409:895a::1"}
	server := stub.serve()
	t.Cleanup(server.Close)

	self := netip.MustParseAddr("fd7a:115c:a1e0::f638:aa6c")
	peer := newTestPeer(t, TailnetPeerOption{
		Name:         "self",
		Peer:         "self",
		Port:         int(port),
		Proxy:        map[string]any{"type": "direct", "name": "inner"},
		DirectoryURL: server.URL,
		DirectoryID:  "self",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := peer.DialContext(ctx, &C.Metadata{
		NetWork: C.TCP,
		Host:    self.String(),
		DstIP:   self,
		DstPort: port,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	buf := make([]byte, 16)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "local" {
		t.Fatalf("read %q, want the local service", got)
	}
}

// A shared profile lists one outbound per node, so both peers in one config ask
// the same directory: the client is shared and this node reports itself once.
func TestTailnetPeersShareOneDirectoryClient(t *testing.T) {
	stub := &stubDirectory{ownID: "pc", peerID: "gt7", peerAddr: "2409:895a::1"}
	server := stub.serve()
	t.Cleanup(server.Close)

	for _, name := range []string{"gt7", "pc"} {
		peer := newTestPeer(t, TailnetPeerOption{
			Name:           name,
			Peer:           name,
			Port:           8443,
			Proxy:          map[string]any{"type": "direct", "name": "inner"},
			DirectoryURL:   server.URL,
			DirectoryToken: "secret",
			DirectoryID:    "pc",
		})
		if _, _, err := peer.resolve(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	// The first report leaves the machine from the outbound's own goroutine.
	deadline := time.Now().Add(2 * time.Second)
	for stub.reports.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	if reports := stub.reports.Load(); reports != 1 {
		t.Fatalf("reports = %d, want one client per node", reports)
	}
}
