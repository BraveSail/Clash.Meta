package outbound

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/peerdirectory"
)

type directoryStub struct {
	reports  atomic.Int64
	lookups  atomic.Int64
	fail     atomic.Bool
	lastEtag atomic.Value
	lastBody atomic.Value
}

func newDirectoryStub(t *testing.T, addr string) (*directoryStub, *httptest.Server) {
	t.Helper()
	stub := &directoryStub{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("authorization") != "Bearer secret" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch request.URL.Path {
		case "/report":
			stub.reports.Add(1)
			stub.lastEtag.Store(request.Header.Get("if-none-match"))
			body := map[string]any{}
			_ = json.NewDecoder(request.Body).Decode(&body)
			stub.lastBody.Store(body)
			if request.Header.Get("if-none-match") == `"`+addr+`:8443"` {
				writer.Header().Set("etag", `"`+addr+`:8443"`)
				writer.WriteHeader(http.StatusNotModified)
				return
			}
			writer.Header().Set("etag", `"`+addr+`:8443"`)
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"id":      body["id"],
				"addr":    addr,
				"port":    body["port"],
				"changed": true,
			})
		case "/lookup":
			stub.lookups.Add(1)
			if stub.fail.Load() {
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			id := request.URL.Query().Get("id")
			if id != "gt7" {
				writer.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"nodes": map[string]any{"gt7": map[string]any{"addr": "2409:895a::1", "port": 8443}},
			})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return stub, server
}

func newTestDirectory(t *testing.T, url string) *PeerDirectory {
	t.Helper()
	directory, err := NewPeerDirectory(PeerDirectoryOption{
		Name:    "dir",
		URL:     url,
		Token:   "secret",
		ID:      "pc",
		Port:    8443,
		Refresh: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = directory.Close() })
	return directory
}

func TestPeerDirectoryReportsAndFollowsTheObservedAddress(t *testing.T) {
	stub, server := newDirectoryStub(t, "2409:8a55::1")
	directory := newTestDirectory(t, server.URL)

	deadline := time.Now().Add(2 * time.Second)
	for stub.reports.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if stub.reports.Load() == 0 {
		t.Fatal("the directory never received a report")
	}
	body, _ := stub.lastBody.Load().(map[string]any)
	if body["id"] != "pc" || body["port"] != float64(8443) {
		t.Fatalf("report body = %v", body)
	}
	if got := directory.Addr(); got != "2409:8a55::1:8443" {
		t.Fatalf("Addr() = %q, want the address the directory observed", got)
	}

	// A second report carries the etag, so an unchanged address answers 304.
	sent := ""
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		directory.mu.Lock()
		sent = directory.sentAddr
		directory.mu.Unlock()
		if sent != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if sent == "" {
		t.Fatal("the first report never completed")
	}
	directory.report(context.Background(), sent)
	if etag, _ := stub.lastEtag.Load().(string); etag != `"2409:8a55::1:8443"` {
		t.Fatalf("second report sent etag %q", etag)
	}
}

func TestPeerDirectorySkipsAnUnchangedReport(t *testing.T) {
	stub, server := newDirectoryStub(t, "2409:8a55::1")
	directory := newTestDirectory(t, server.URL)
	deadline := time.Now().Add(2 * time.Second)
	for stub.reports.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	reports := stub.reports.Load()
	if reports == 0 {
		t.Fatal("the first report never left the machine")
	}

	// The machine's address did not change, so the periodic check is local only.
	directory.maybeReport(false)
	if got := stub.reports.Load(); got != reports {
		t.Fatalf("reports = %d, want the unchanged address to stay off the wire", got)
	}
	// A node that moved reports again even though the cadence has not passed.
	directory.maybeReport(true)
	if got := stub.reports.Load(); got != reports+1 {
		t.Fatalf("reports = %d, want a forced report after a change", got)
	}
}

func TestPeerDirectoryLooksUpPeersAndAnswersForItself(t *testing.T) {
	stub, server := newDirectoryStub(t, "2409:8a55::1")
	directory := newTestDirectory(t, server.URL)
	ctx := context.Background()

	addr, port, self, err := directory.PeerAddress(ctx, "pc")
	if err != nil || !self || addr != "" || port != 8443 {
		t.Fatalf("PeerAddress(self) = %q %d self=%v err=%v", addr, port, self, err)
	}
	if stub.lookups.Load() != 0 {
		t.Fatal("a self lookup reached the network")
	}

	addr, port, self, err = directory.PeerAddress(ctx, "gt7")
	if err != nil || self || addr != "2409:895a::1" || port != 8443 {
		t.Fatalf("PeerAddress(gt7) = %q %d self=%v err=%v", addr, port, self, err)
	}
	if _, _, _, err := directory.PeerAddress(ctx, "gt7"); err != nil {
		t.Fatal(err)
	}
	if lookups := stub.lookups.Load(); lookups != 1 {
		t.Fatalf("lookups = %d, want the second one to come from the cache", lookups)
	}
	if _, _, _, err := directory.PeerAddress(ctx, "missing"); err == nil {
		t.Fatal("an unknown peer resolved")
	}

	// A directory that stops answering must not break a peer we already saw.
	stub.fail.Store(true)
	time.Sleep(peerDirectoryLookupTTL)
	addr, port, self, err = directory.PeerAddress(ctx, "gt7")
	if err != nil || self || addr != "2409:895a::1" || port != 8443 {
		t.Fatalf("stale lookup = %q %d self=%v err=%v", addr, port, self, err)
	}
}

// A directory that reports which nodes are up needs a heartbeat: the address
// did not move, but the node is still there.
func TestPeerDirectoryHeartbeatsWhenTheAddressIsUnchanged(t *testing.T) {
	stub, server := newDirectoryStub(t, "2409:8a55::1")
	directory := newTestDirectory(t, server.URL)
	directory.heartbeat = 60 * time.Millisecond

	directory.maybeReport(true)
	first := stub.reports.Load()
	if first == 0 {
		t.Fatal("the first report did not leave the machine")
	}
	directory.maybeReport(false)
	if reported := stub.reports.Load(); reported != first {
		t.Fatalf("reports = %d, want no report inside the heartbeat", reported)
	}
	time.Sleep(80 * time.Millisecond)
	directory.maybeReport(false)
	if reported := stub.reports.Load(); reported != first+1 {
		t.Fatalf("reports = %d, want one heartbeat after the interval", reported)
	}
}

// The probe tells the tunnel interfaces apart from the NIC carrying traffic: a
// protected socket must never resolve to the VPN this outbound runs inside.
func TestUnderlayVirtualInterface(t *testing.T) {
	for _, name := range []string{"tun0", "utun3", "tap0", "wg0", "tailscale0", "ppp0", "ipsec0", "lo", "lo0"} {
		if !underlayVirtualInterface(name) {
			t.Fatalf("%q is a tunnel or loopback, want it refused", name)
		}
	}
	// A Windows wintun adapter is named after the application that made it
	// ("FlClash", "Meta"), so a name check cannot spot it; Windows classifies
	// those by adapter type and description instead (see
	// peer_directory_virtual_windows.go).
	for _, name := range []string{"Ethernet", "以太网", "WLAN", "wlan0", "rmnet_data0", "en0", "eth0", "Meta", "FlClash"} {
		if underlayVirtualInterface(name) {
			t.Fatalf("%q carries traffic, want it accepted", name)
		}
	}
}

func TestPeerDirectoryRegistersItselfForPeersOutbounds(t *testing.T) {
	_, server := newDirectoryStub(t, "2409:8a55::1")
	directory := newTestDirectory(t, server.URL)

	_, _, self, err := peerdirectory.Lookup(context.Background(), "dir", "pc")
	if err != nil {
		t.Fatalf("registered directory is not reachable: %v", err)
	}
	if !self {
		t.Fatal("the directory did not report this node as itself")
	}

	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := peerdirectory.Lookup(context.Background(), "dir", "pc"); err == nil {
		t.Fatal("a closed directory is still registered")
	}
}

func TestPeerDirectoryRejectsIncompleteOptions(t *testing.T) {
	if _, err := NewPeerDirectory(PeerDirectoryOption{Name: "x", URL: "not-a-url", ID: "pc"}); err == nil {
		t.Fatal("an invalid url was accepted")
	}
	if _, err := NewPeerDirectory(PeerDirectoryOption{Name: "x", URL: "https://example.com", ID: "bad id"}); err == nil {
		t.Fatal("an invalid id was accepted")
	}
	if _, err := NewPeerDirectory(PeerDirectoryOption{Name: "x", URL: "https://example.com", ID: "pc", Port: 70000}); err == nil {
		t.Fatal("an invalid port was accepted")
	}
}

func TestPickReportAddressPrefersAGlobalIpv6OnRealInterfaces(t *testing.T) {
	candidates := map[string][]netip.Addr{
		"tun0": {
			netip.MustParseAddr("fdfe:dcba:9876::1"),
			netip.MustParseAddr("127.0.0.1"),
		},
		"eth0": {
			netip.MustParseAddr("fe80::1"),
			netip.MustParseAddr("2409:8a55::2"),
			netip.MustParseAddr("2409:8a55::1"),
		},
	}

	if got := pickReportAddress(candidates); got != "2409:8a55::1" {
		t.Fatalf("pickReportAddress = %q, want the lowest global IPv6", got)
	}
	onlyInternal := map[string][]netip.Addr{
		"tun0": {netip.MustParseAddr("fdfe:dcba:9876::1")},
		"eth0": {netip.MustParseAddr("fe80::1"), netip.MustParseAddr("192.168.1.2")},
	}
	if got := pickReportAddress(onlyInternal); got != "" {
		t.Fatalf("pickReportAddress = %q, want nothing to publish", got)
	}
}
