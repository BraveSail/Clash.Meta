package outbound

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/peerdirectory"
)

type directoryStub struct {
	reports atomic.Int64
	lookups atomic.Int64
	fail    atomic.Bool
	// selfAlias makes the stub answer a peer name with this node's own id:
	// that is how the directory resolves an alias back to the device asking.
	selfAlias atomic.Bool
	lastEtag  atomic.Value
	lastBody  atomic.Value
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
			nodeID := "gt7"
			if stub.selfAlias.Load() {
				nodeID = "pc"
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"nodes": map[string]any{"gt7": map[string]any{"id": nodeID, "addr": "2409:895a::1", "port": 8443}},
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

// An alias set on the dashboard names a device, and the directory answers a
// lookup of it with that device's record: the id in the answer is what lets a
// client recognise itself behind a name it never configured.
func TestPeerDirectoryResolvesAnAliasBackToItself(t *testing.T) {
	stub, server := newDirectoryStub(t, "2409:8a55::1")
	directory := newTestDirectory(t, server.URL)
	ctx := context.Background()

	// The directory resolves the name to this node's own record - the way an
	// alias set on the dashboard does - and the answer is this node.
	stub.selfAlias.Store(true)
	addr, port, self, err := directory.PeerAddress(ctx, "gt7")
	if err != nil || !self || addr != "" || port != 8443 {
		t.Fatalf("PeerAddress(alias of self) = %q %d self=%v err=%v", addr, port, self, err)
	}

	// The same name after the alias is gone is another machine again; the
	// cache is short, so wait it out.
	time.Sleep(peerDirectoryLookupTTL)
	stub.selfAlias.Store(false)
	addr, port, self, err = directory.PeerAddress(ctx, "gt7")
	if err != nil || self || addr != "2409:895a::1" || port != 8443 {
		t.Fatalf("PeerAddress(gt7) = %q %d self=%v err=%v", addr, port, self, err)
	}
}

// A route change arrives as a burst - the platform reports every route the
// change touches - and the directory is asked once, not once per event.
func TestNetworkChangeCoalescesARouteBurst(t *testing.T) {
	stub, server := newDirectoryStub(t, "2409:8a55::1")
	directory := newTestDirectory(t, server.URL)

	// Let the report the directory makes on its own when it starts finish, and
	// wait for the reports to go quiet: this test measures the injections.
	quiet := time.Now().Add(5 * time.Second)
	last := stub.reports.Load()
	for time.Now().Before(quiet) {
		time.Sleep(50 * time.Millisecond)
		if now := stub.reports.Load(); now != last {
			last = now
			quiet = time.Now().Add(500 * time.Millisecond)
		}
	}

	directory.InjectNetworkChange()
	reported := time.Now().Add(5 * time.Second)
	for stub.reports.Load() == last && time.Now().Before(reported) {
		time.Sleep(10 * time.Millisecond)
	}
	first := stub.reports.Load()
	if first == last {
		t.Fatal("a network change did not report")
	}
	directory.InjectNetworkChange()
	directory.InjectNetworkChange()
	time.Sleep(500 * time.Millisecond)
	if got := stub.reports.Load(); got != first {
		t.Fatalf("reports = %d, want the burst to be one report", got)
	}
}

// A directory that reports which nodes are up needs a heartbeat: the address
// did not move, but the node is still there.
func TestPeerDirectoryHeartbeatsWhenTheAddressIsUnchanged(t *testing.T) {
	stub, server := newDirectoryStub(t, "2409:8a55::1")
	directory := newTestDirectory(t, server.URL)
	// The interval has to outlast the report itself, or the test measures the
	// machine's speed rather than the heartbeat: a report is an HTTP request.
	directory.heartbeat = 3 * time.Second

	// A directory reports once on its own when it starts; wait for that report
	// so this test measures its own calls and not the background one.
	settle := time.Now().Add(2 * time.Second)
	for stub.reports.Load() == 0 && time.Now().Before(settle) {
		time.Sleep(5 * time.Millisecond)
	}
	directory.maybeReport(true)
	first := stub.reports.Load()
	if first == 0 {
		t.Fatal("the first report did not leave the machine")
	}
	directory.maybeReport(false)
	if reported := stub.reports.Load(); reported != first {
		t.Fatalf("reports = %d, want no report inside the heartbeat", reported)
	}
	// The heartbeat is due after its interval; how long the report itself takes
	// depends on the machine, so the test waits for it rather than for a fixed
	// moment.
	deadline := time.Now().Add(12 * time.Second)
	for stub.reports.Load() != first+1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		directory.maybeReport(false)
	}
	if reported := stub.reports.Load(); reported != first+1 {
		t.Fatalf("reports = %d, want one heartbeat after the interval", reported)
	}
}

// The decision layer tells tunnel interfaces apart from the NIC carrying
// traffic; a protected socket must never resolve to the VPN this outbound runs
// inside.
func TestIsVirtualInterfaceName(t *testing.T) {
	for _, name := range []string{"tun0", "utun3", "tap0", "wg0", "tailscale0", "ppp0", "ipsec0"} {
		if !isVirtualInterfaceName(name) {
			t.Fatalf("%q is a tunnel or loopback, want it refused", name)
		}
	}
	if runtime.GOOS != "windows" {
		// Windows names its loopback "Loopback Pseudo-Interface 1" and refuses
		// it by adapter type, so the Unix names are not in this list.
		for _, name := range []string{"lo", "lo0"} {
			if !isVirtualInterfaceName(name) {
				t.Fatalf("%q is the loopback, want it refused", name)
			}
		}
	}
	// A Windows wintun adapter is named after the application that made it
	// ("FlClash", "Meta"), so a name check cannot spot it; Windows classifies
	// those by adapter type and description instead (see
	// peer_directory_virtual_windows.go), which is why those names are not in
	// this list: the answer depends on the adapters the machine actually has.
	for _, name := range []string{"Ethernet", "以太网", "WLAN", "wlan0", "rmnet_data0", "en0", "eth0"} {
		if isVirtualInterfaceName(name) {
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

func TestDirectoryProxyTransportRejectsBadURLs(t *testing.T) {
	for name, raw := range map[string]string{
		"socks":       "socks5://127.0.0.1:1080",
		"no scheme":   "127.0.0.1:7890",
		"no host":     "http://",
		"unparseable": "http://%zz",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := directoryProxyTransport(raw); err == nil {
				t.Fatalf("proxy url %q was accepted", raw)
			}
		})
	}
}

// A network that resets the direct connection to the directory leaves the node
// unable to report where it is; the proxy it was given is the way back in. The
// directory address here is one no direct route can reach, so anything that
// arrives at the proxy arrived because it took the proxy.
func TestPeerDirectoryReachesTheDirectoryThroughItsProxy(t *testing.T) {
	var sawReport, sawLookup atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("content-type", "application/json")
		switch request.URL.Path {
		case "/report":
			sawReport.Store(true)
			writer.Header().Set("etag", `"2409:8a55::1:8443"`)
			_, _ = writer.Write([]byte(`{"addr":"2409:8a55::1","port":8443}`))
		case "/lookup":
			sawLookup.Store(true)
			_, _ = writer.Write([]byte(`{"nodes":{"peer":{"id":"peer","addr":"::1","port":8443}}}`))
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer proxy.Close()

	node, err := NewPeerDirectory(PeerDirectoryOption{
		Name:     "proxy directory",
		URL:      "http://127.0.0.1:1",
		Token:    "secret",
		ID:       "this-device",
		Port:     8443,
		ViaProxy: proxy.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = node.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, _, err := node.lookup(ctx, "peer"); err != nil {
		t.Fatalf("lookup through the proxy failed: %v", err)
	}
	node.report(ctx, "2409:8a55::1")

	if !sawLookup.Load() {
		t.Fatal("the lookup never reached the proxy")
	}
	if !sawReport.Load() {
		t.Fatal("the report never reached the proxy")
	}
}
