//go:build !windows

package icmptunnel

import (
	"net"
	"net/netip"
	"testing"
)

// The two socket flavours report where an answer came from in their own type,
// and a reply from either has to be read the same way.
func TestEchoSourceReadsBothSocketFlavours(t *testing.T) {
	if got := echoSource(&net.UDPAddr{IP: net.ParseIP("2409:8a55::1"), Port: 1}); got != netip.MustParseAddr("2409:8a55::1") {
		t.Fatalf("UDP flavour answered %s", got)
	}
	if got := echoSource(&net.IPAddr{IP: net.ParseIP("223.5.5.5")}); got != netip.MustParseAddr("223.5.5.5") {
		t.Fatalf("IP flavour answered %s", got)
	}
	if got := echoSource(&net.UDPAddr{}); got.IsValid() {
		t.Fatalf("an address-less answer became %s", got)
	}
}
