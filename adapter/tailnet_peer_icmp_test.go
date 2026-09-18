package adapter

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

var _ C.ICMPProxy = (*TailnetPeer)(nil)

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
}

func echoRequest(kind byte) []byte {
	request := make([]byte, 8)
	request[0] = kind
	return request
}

// An echo aimed at the peer goes to the peer's own address: this node asks the
// same question the tool asked, and the peer's stack answers it. The loopback
// stands in for the peer here, so the test fails when the path is broken rather
// than when a network is.
func TestDirectEchoAsksThePeerAndAnswersTheTool(t *testing.T) {
	request := echoRequest(8)
	binary.BigEndian.PutUint16(request[4:6], 0x1234)
	binary.BigEndian.PutUint16(request[6:8], 3)

	reply, err := directEcho(context.Background(), netip.MustParseAddr("127.0.0.1"), request)
	if err != nil {
		t.Fatalf("directEcho: %v", err)
	}
	if reply[0] != 0 {
		t.Fatalf("reply type = %d, want an echo reply", reply[0])
	}
	if binary.BigEndian.Uint16(reply[4:6]) != 0x1234 || binary.BigEndian.Uint16(reply[6:8]) != 3 {
		t.Fatalf("reply carries identifier %#x sequence %d",
			binary.BigEndian.Uint16(reply[4:6]), binary.BigEndian.Uint16(reply[6:8]))
	}
}

// The tool's own message is what travels, and only a peer that speaks its
// family can be asked directly: an ICMPv4 message cannot be put on an IPv6
// path, and re-typing it would be inventing a packet the tool never sent.
func TestEchoSpeaksForThePeerFamily(t *testing.T) {
	v4, v6 := echoRequest(8), echoRequest(128)
	if !echoSpeaksFor(netip.MustParseAddr("127.0.0.1"), v4) {
		t.Fatal("an IPv4 echo was refused by an IPv4 peer")
	}
	if echoSpeaksFor(netip.IPv6Loopback(), v4) {
		t.Fatal("an IPv4 echo was accepted by an IPv6 peer")
	}
	if !echoSpeaksFor(netip.IPv6Loopback(), v6) {
		t.Fatal("an IPv6 echo was refused by an IPv6 peer")
	}
	if echoSpeaksFor(netip.MustParseAddr("127.0.0.1"), v6) {
		t.Fatal("an IPv6 echo was accepted by an IPv4 peer")
	}
}
