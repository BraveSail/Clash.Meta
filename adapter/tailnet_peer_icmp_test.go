package adapter

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/resolver"
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

// A ping aimed at the peer's name is answered where the peer is: the echo goes
// to the peer's own loopback, which every stack answers without a network, and
// the round trip the caller measures is the tunnel.
func TestEchoTargetForThePeerIsItsLoopback(t *testing.T) {
	peer := &TailnetPeer{option: TailnetPeerOption{Name: "pc", Peer: "pc"}}
	metadata := &C.Metadata{Host: "pc.lan", DstIP: netip.MustParseAddr("7.1.2.3")}

	target, err := peer.echoTarget(context.Background(), metadata, echoRequest(8))
	if err != nil {
		t.Fatalf("echoTarget: %v", err)
	}
	if target != ipv4Loopback {
		t.Fatalf("an IPv4 echo targets %s, want %s", target, ipv4Loopback)
	}

	if target, err = peer.echoTarget(context.Background(), metadata, echoRequest(128)); err != nil {
		t.Fatalf("echoTarget: %v", err)
	}
	if target != netip.IPv6Loopback() {
		t.Fatalf("an IPv6 echo targets %s, want ::1", target)
	}
}

// A flow that only carries a placeholder names a host, and the peer cannot do
// anything with the placeholder: the address the peer is asked to reach is the
// one the host resolves to.
func TestEchoTargetResolvesAPlaceholder(t *testing.T) {
	restore := resolver.DefaultHostMapper
	resolver.DefaultHostMapper = placeholderMapper{address: netip.MustParseAddr("7.9.9.9"), host: "localhost"}
	defer func() { resolver.DefaultHostMapper = restore }()

	peer := &TailnetPeer{option: TailnetPeerOption{Name: "pc", Peer: "pc"}}
	metadata := &C.Metadata{Host: "localhost", DstIP: netip.MustParseAddr("7.9.9.9")}
	target, err := peer.echoTarget(context.Background(), metadata, echoRequest(8))
	if err != nil {
		t.Fatalf("echoTarget: %v", err)
	}
	if target != ipv4Loopback {
		t.Fatalf("target is %s, want the address localhost resolves to", target)
	}
}

// The message and the address travel as one pair, and the peer's echo API is
// chosen by the address: a pair whose families disagree can only end in silence,
// so it is refused where the reason is still known.
func TestEchoTargetRefusesAMismatchedFamily(t *testing.T) {
	peer := &TailnetPeer{option: TailnetPeerOption{Name: "pc", Peer: "pc"}}
	metadata := &C.Metadata{DstIP: netip.MustParseAddr("223.5.5.5")}
	if _, err := peer.echoTarget(context.Background(), metadata, echoRequest(128)); err == nil {
		t.Fatal("an IPv6 echo aimed at an IPv4 address was accepted")
	}
	metadata = &C.Metadata{}
	if _, err := peer.echoTarget(context.Background(), metadata, echoRequest(8)); err == nil {
		t.Fatal("an echo without an address was accepted")
	}
}

func echoRequest(kind byte) []byte {
	request := make([]byte, 8)
	request[0] = kind
	return request
}

// A session carries one echo at a time, and the answer to an echo that already
// timed out can still arrive: the identifier and sequence are what tells the
// two apart, so an answer for another echo is never handed to this one.
func TestSameEchoComparesIdentifierAndSequence(t *testing.T) {
	request := make([]byte, 8)
	binary.BigEndian.PutUint16(request[4:6], 0x1234)
	binary.BigEndian.PutUint16(request[6:8], 7)

	answer := append([]byte(nil), request...)
	answer[0] = 0
	if !sameEcho(request, answer) {
		t.Fatal("the answer to this echo was refused")
	}
	answer[4]++
	if sameEcho(request, answer) {
		t.Fatal("an answer for another identifier was accepted")
	}
	answer[4]--
	answer[7]++
	if sameEcho(request, answer) {
		t.Fatal("an answer for another sequence was accepted")
	}
}

type placeholderMapper struct {
	address netip.Addr
	host    string
}

func (placeholderMapper) FakeIPEnabled() bool               { return true }
func (placeholderMapper) MappingEnabled() bool              { return true }
func (m placeholderMapper) IsFakeIP(ip netip.Addr) bool     { return ip == m.address }
func (placeholderMapper) IsFakeBroadcastIP(netip.Addr) bool { return false }
func (placeholderMapper) IsExistFakeIP(netip.Addr) bool     { return false }
func (m placeholderMapper) FindHostByIP(ip netip.Addr) (string, bool) {
	if ip == m.address {
		return m.host, true
	}
	return "", false
}
func (placeholderMapper) FlushFakeIP() error                { return nil }
func (placeholderMapper) InsertHostByIP(netip.Addr, string) {}
func (placeholderMapper) StoreFakePoolState()               {}
