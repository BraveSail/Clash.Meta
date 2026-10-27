//go:build !windows && !linux && !android && !darwin

package icmptunnel

import (
	"net"
	"net/netip"

	"golang.org/x/net/icmp"
)

// listenEchoSocket opens the unprivileged ICMP socket one echo travels on. The
// platforms that need the dialer's control hook have their own file; here the
// socket speaks for itself.
func listenEchoSocket(target netip.Addr) (net.PacketConn, error) {
	network := "udp4"
	if target.Is6() {
		network = "udp6"
	}
	return icmp.ListenPacket(network, "")
}
