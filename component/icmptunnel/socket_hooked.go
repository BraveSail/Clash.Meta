//go:build linux || android || darwin

package icmptunnel

import (
	"net"
	"net/netip"
	"os"

	"golang.org/x/sys/unix"

	"github.com/metacubex/mihomo/component/dialer"
)

// listenEchoSocket opens the unprivileged ICMP socket one echo travels on.
//
// The socket is made by hand so the dialer's control hook can be applied to it
// before anything is sent: on Android that hook is VpnService.protect, and a
// socket without it has its packet routed back into this node's own tunnel,
// where the kernel refuses the write. Elsewhere the same hook binds the socket
// to the interface that carries the traffic, exactly like the DIRECT path does.
func listenEchoSocket(target netip.Addr) (net.PacketConn, error) {
	family, protocol, network := unix.AF_INET, unix.IPPROTO_ICMP, "ip4"
	if target.Is6() {
		family, protocol, network = unix.AF_INET6, unix.IPPROTO_ICMPV6, "ip6"
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM, protocol)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "icmp")
	defer file.Close()
	rawConn, err := file.SyscallConn()
	if err != nil {
		return nil, err
	}
	if err := dialer.ICMPControl(target)(network, target.String(), rawConn); err != nil {
		return nil, err
	}
	return net.FilePacketConn(file)
}
