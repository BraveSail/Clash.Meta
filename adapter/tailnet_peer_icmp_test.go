package adapter

import (
	"context"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

var _ C.ICMPProxy = (*TailnetPeer)(nil)
var _ C.ICMPRedirect = (*TailnetPeer)(nil)

// The outbound the rules pick has to be the one the handler can ask: the
// wrapper the config produces is what the TUN sees, so it is the wrapper the
// test asks.
func TestTailnetPeerOutboundCarriesAnEcho(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":            "pc",
		"type":            "tailnet-peer",
		"peer":            "pc",
		"port":            8443,
		"directory-id":    "pc",
		"directory-url":   "https://directory.invalid",
		"directory-token": "token",
		"proxy": map[string]any{
			"type":   "vless",
			"server": "127.0.0.1",
			"port":   8443,
			"uuid":   "9351949c-4db4-4392-a8ab-3d06f75e74d5",
			"udp":    true,
		},
	})
	if err != nil {
		t.Fatalf("ParseProxy: %v", err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	if _, ok := C.ICMPCarrierOf(proxy.Adapter()); !ok {
		t.Fatalf("%s (%T) does not carry ICMP", proxy.Name(), proxy.Adapter())
	}
	if _, ok := C.ICMPRedirectOf(proxy.Adapter()); !ok {
		t.Fatalf("%s (%T) does not name where an echo has to go", proxy.Name(), proxy.Adapter())
	}
}

// A peer this node cannot locate is not answered: the tunnel side turns the
// error into the one a router would send.
func TestICMPDestinationRefusesWithoutAnAddress(t *testing.T) {
	peer := &TailnetPeer{option: TailnetPeerOption{Name: "pc", Peer: "pc"}}
	if _, err := peer.ICMPDestination(context.Background(), &C.Metadata{Host: "pc.lan"}); err == nil {
		t.Fatal("a peer with no directory named an address")
	}
}
