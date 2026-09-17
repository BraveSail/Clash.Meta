package adapter

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/tailnet"
	C "github.com/metacubex/mihomo/constant"
)

type stubTailnetProvider struct {
	status tailnet.Status
}

func (s *stubTailnetProvider) TailnetStatus(context.Context) (tailnet.Status, error) {
	return s.status, nil
}

func testTailnetPeer(t *testing.T, peer string, port int) *TailnetPeer {
	t.Helper()
	created, err := NewTailnetPeer(TailnetPeerOption{
		Name:  "pc",
		Peer:  peer,
		Port:  port,
		Proxy: map[string]any{"type": "direct", "name": "inner"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = created.Close() })
	return created
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
}

func TestTailnetPeerResolvesAddressAndFollowsChanges(t *testing.T) {
	provider := &stubTailnetProvider{status: tailnet.Status{
		Peers: []tailnet.NodeStatus{{
			Name:           "pc",
			TailscaleIPs:   []string{"100.64.0.5"},
			Addrs:          []string{"[2409:8a55:aaaa::1]:41641"},
			CurAddr:        "[2409:8a55:aaaa::1]:41641",
			DirectVerified: true,
		}},
	}}
	tailnet.RegisterStatusProvider("ts", provider)
	t.Cleanup(func() { tailnet.UnregisterStatusProvider("ts", provider) })

	peer := testTailnetPeer(t, "pc", 23333)

	host, self, err := peer.resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if self || host != "2409:8a55:aaaa::1" {
		t.Fatalf("resolve = %q self=%v, want the verified address", host, self)
	}

	proxy, err := peer.proxyForDial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if proxy.Type() != C.Direct {
		t.Fatalf("inner proxy type = %v, want the configured inner type", proxy.Type())
	}
	if got := peer.Addr(); got != "2409:8a55:aaaa::1:23333" {
		t.Fatalf("Addr() = %q, want the resolved address", got)
	}

	provider.status.Peers[0].Addrs = []string{"[2409:8a55:ffff::9]:41641"}
	provider.status.Peers[0].CurAddr = "[2409:8a55:ffff::9]:41641"
	peer.invalidate()

	host, _, err = peer.resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if host != "2409:8a55:ffff::9" {
		t.Fatalf("resolve after change = %q, want the new address", host)
	}
}

func TestTailnetPeerDegradesToDirectForItself(t *testing.T) {
	provider := &stubTailnetProvider{status: tailnet.Status{
		Self: &tailnet.NodeStatus{Name: "pc", HostName: "pc"},
	}}
	tailnet.RegisterStatusProvider("ts", provider)
	t.Cleanup(func() { tailnet.UnregisterStatusProvider("ts", provider) })

	peer := testTailnetPeer(t, "pc", 23333)
	proxy, err := peer.proxyForDial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if proxy.Type() != C.Direct {
		t.Fatalf("self peer proxy type = %v, want DIRECT", proxy.Type())
	}
}

func TestTailnetPeerMissingPeerFails(t *testing.T) {
	peer := testTailnetPeer(t, "nobody", 23333)
	if _, _, err := peer.resolve(context.Background()); err == nil {
		t.Fatal("unknown peer resolved")
	}
}

// A service that this node runs is reachable on the loopback address: dialing
// the destination as it stands would come back through the rule that selected
// this outbound.
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

	self := netip.MustParseAddr("fd7a:115c:a1e0::f638:aa6c")
	provider := &stubTailnetProvider{status: tailnet.Status{
		Self: &tailnet.NodeStatus{Name: "pc", HostName: "pc", TailscaleIPs: []string{self.String()}},
	}}
	tailnet.RegisterStatusProvider("ts", provider)
	t.Cleanup(func() { tailnet.UnregisterStatusProvider("ts", provider) })

	peer := testTailnetPeer(t, self.String(), int(port))
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
