package tunnel

import (
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// TestSniffableDestination pins the rule a mesh stream depends on: a stream
// addressed to this device's own loopback is a service request, and waiting for
// the client to speak first is what made every server-speaks-first protocol
// (sshd's banner, SMTP's greeting) hang behind the proxy.
func TestSniffableDestination(t *testing.T) {
	cases := []struct {
		name string
		addr string
		want bool
	}{
		{"loopback", "127.0.0.1", false},
		{"loopback ipv6", "::1", false},
		{"public v4", "1.1.1.1", true},
		{"public v6", "2606:4700:4700::1111", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			metadata := &C.Metadata{DstIP: netip.MustParseAddr(c.addr)}
			if got := sniffableDestination(metadata); got != c.want {
				t.Fatalf("sniffableDestination(%s) = %v, want %v", c.addr, got, c.want)
			}
		})
	}

	if sniffableDestination(nil) {
		t.Fatal("a stream with no metadata cannot be sniffed")
	}
	// A destination still unnamed is exactly what sniffing is for.
	if !sniffableDestination(&C.Metadata{}) {
		t.Fatal("an unresolved destination must still be sniffable")
	}
}
