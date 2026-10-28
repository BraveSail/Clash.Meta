package tunnel

import (
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// TestLoopbackService pins the rule a mesh stream depends on.
//
// A peer asks this device for a service on its own loopback, and the destination
// crosses already resolved. Sniffing it or waiting for its first byte both stall
// every protocol whose server speaks first - sshd's banner, SMTP's greeting -
// leaving a stream that opens, says nothing and times out while both ends report
// the connection as established.
func TestLoopbackService(t *testing.T) {
	cases := []struct {
		name string
		addr string
		want bool
	}{
		{"loopback", "127.0.0.1", true},
		{"loopback ipv6", "::1", true},
		{"public v4", "1.1.1.1", false},
		{"public v6", "2606:4700:4700::1111", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			metadata := &C.Metadata{DstIP: netip.MustParseAddr(c.addr)}
			if got := loopbackService(metadata); got != c.want {
				t.Fatalf("loopbackService(%s) = %v, want %v", c.addr, got, c.want)
			}
		})
	}

	if loopbackService(nil) {
		t.Fatal("a stream with no metadata is not a service on this device")
	}
	// An unresolved destination is an ordinary stream: it may be sniffed, and
	// its first byte may be waited for.
	if loopbackService(&C.Metadata{}) {
		t.Fatal("an unresolved destination must not be mistaken for loopback")
	}
}

// TestPeekableFirstByte pins the other half: a proxy client that says nothing
// must not be waited for. The peek is only there to keep a TUN packet whole.
func TestPeekableFirstByte(t *testing.T) {
	if !peekableFirstByte(&C.Metadata{Type: C.TUN}) {
		t.Fatal("a TUN stream arrives with its first packet")
	}
	for _, typ := range []C.Type{C.HTTPS, C.SOCKS5, C.VLESS, C.INNER} {
		if peekableFirstByte(&C.Metadata{Type: typ}) {
			t.Fatalf("a %v stream may stay silent; it must not be waited for", typ)
		}
	}
	if peekableFirstByte(nil) {
		t.Fatal("a stream with no metadata must not be waited for")
	}
}
