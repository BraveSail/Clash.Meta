package outbound

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/log"
)

// errNoUnderlyingInterface is what a platform returns when it has no specific
// way of seeing past its own tunnel.
var errNoUnderlyingInterface = errors.New("no platform-specific underlying interface detection")

// The strategy seams exist so the decision order can be tested without a tun,
// a sandbox or a second SIM: production points them at the real detectors.
var (
	platformDefaultInterface    = defaultRouteInterfaceViaPlatform
	underlyingInterfaceName     = underlyingDefaultInterface
	socketProbeDefaultInterface = defaultRouteInterfaceViaSocket
)

// The tailscale fork learned the interface that carries traffic the hard way
// (netmon: detect the underlying default interface, reject virtual adapters,
// log the decision through the caller's logger). A directory that publishes a
// node's address needs exactly the same knowledge, so the preference order is
// the fork's: the platform's own answer first, then the platform-specific
// underlying-route detection, then a socket route probe as the last resort.
// Whoever answers, the result is rejected when it names a virtual adapter and
// the caller falls back to keeping every physical address rather than none.

// peerDirectoryProbeV6 is an arbitrary globally-routable IPv6 address used to
// ask the kernel which interface a default-route packet would leave from. No
// packet is ever sent: a UDP connect only performs a route lookup and binds the
// socket to the selected source address.
const peerDirectoryProbeV6 = "2400:3200::1" // OneDNS public address (CN)

// isTunnelInterface reports whether name looks like a userspace tunnel
// interface (VPN TUN/TAP, WireGuard, PPP). While such an interface is up it
// owns the system default route, which makes route probes resolve to the tunnel
// instead of the physical NIC that actually carries traffic.
func isTunnelInterface(name string) bool {
	n := strings.ToLower(name)
	for _, prefix := range []string{"tun", "utun", "tap", "wg", "ppp", "ipsec", "tailscale"} {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	return false
}

// defaultRouteInterfaceViaPlatform asks mihomo's interface finder, which
// sing-tun's monitor keeps current with the interface outbound sockets bind to
// (it excludes this app's own tun, so the answer is the physical NIC).
func defaultRouteInterfaceViaPlatform() string {
	finder := dialer.DefaultInterfaceFinder.Load()
	if finder == nil {
		return ""
	}
	addr, err := netip.ParseAddr(peerDirectoryProbeV6)
	if err != nil {
		return ""
	}
	return finder.FindInterfaceName(addr)
}

// defaultRouteInterfaceViaSocket performs the route lookup on an unconnected
// UDP socket's local end and maps the source address back to its interface.
// While a tun owns the default route this resolves to the tunnel, which the
// caller rejects; it exists for sandboxes where nothing else answers.
func defaultRouteInterfaceViaSocket() (string, error) {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.Dial("udp6", "["+peerDirectoryProbeV6+"]:53")
	if err != nil {
		return "", fmt.Errorf("route probe dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local == nil || local.IP == nil || local.IP.IsUnspecified() {
		return "", fmt.Errorf("route probe: no local socket address")
	}
	src, ok := netip.AddrFromSlice(local.IP)
	if !ok {
		return "", fmt.Errorf("route probe: unusable local socket address")
	}
	ifc, err := iface.ResolveInterfaceByAddr(src.Unmap())
	if err != nil {
		return "", fmt.Errorf("route probe: %w", err)
	}
	return ifc.Name, nil
}

// dialectableOn lists the addresses of [name] this node could publish, best
// first, so a decision names an address that is actually dialable.
func dialableOn(candidates map[string][]netip.Addr, name string) []netip.Addr {
	var addrs []netip.Addr
	for _, addr := range candidates[name] {
		if dialableReportAddress(addr) {
			addrs = append(addrs, addr)
		}
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Compare(addrs[j]) < 0 })
	return addrs
}

// physicalAddresses drops what virtual interfaces own, so a decision can fail
// open with the physical NICs instead of publishing the tunnel's own address.
func physicalAddresses(candidates map[string][]netip.Addr) []netip.Addr {
	names := make([]string, 0, len(candidates))
	for name := range candidates {
		names = append(names, name)
	}
	sort.Strings(names)
	var addrs []netip.Addr
	for _, name := range names {
		if isVirtualInterfaceName(name) {
			continue
		}
		addrs = append(addrs, dialableOn(candidates, name)...)
	}
	return addrs
}

// chooseReportAddress answers which address this node publishes, and how it
// decided: the strategy name matches the fork's vocabulary (platform,
// uid-route, main-table, rpdb-main-rule, winipcfg-metric, socket-probe,
// protected-probe, interface-scan).
func (d *PeerDirectory) chooseReportAddress(candidates map[string][]netip.Addr) (string, string, string) {
	if addr, ifcName := d.underlay(); ifcName != "" && dialableReportAddress(addr) {
		// Android: a protected socket names both the interface and the exact
		// source address the system would use, which beats an interface lookup.
		return addr.String(), ifcName, "protected-probe"
	}
	strategies := []struct {
		how string
		ask func() string
	}{
		{"platform", platformDefaultInterface},
		{"", func() string {
			name, how, err := underlyingInterfaceName()
			if err != nil || name == "" {
				return ""
			}
			return how + "\x00" + name
		}},
		{"socket-probe", func() string {
			name, err := socketProbeDefaultInterface()
			if err != nil {
				return ""
			}
			return name
		}},
	}
	for _, strategy := range strategies {
		answer := strategy.ask()
		if answer == "" {
			continue
		}
		how, name := strategy.how, answer
		if how == "" {
			parts := strings.SplitN(answer, "\x00", 2)
			if len(parts) != 2 {
				continue
			}
			how, name = parts[0], parts[1]
		}
		if isVirtualInterfaceName(name) {
			log.Debugln("[PeerDirectory](%s) default route interface %q is virtual (via=%s); asking the next strategy",
				d.Name(), name, how)
			continue
		}
		if addrs := dialableOn(candidates, name); len(addrs) > 0 {
			return addrs[0].String(), name, how
		}
		log.Debugln("[PeerDirectory](%s) default route interface %q carries no dialable IPv6 (via=%s, kept 0 of %d)",
			d.Name(), name, how, len(candidates[name]))
	}
	// Nothing named the carrying interface: keep the physical addresses so a
	// prefix change is still published instead of the node advertising nothing.
	if addrs := physicalAddresses(candidates); len(addrs) > 0 {
		return addrs[0].String(), "", "interface-scan"
	}
	if addr := pickReportAddress(candidates); addr != "" {
		return addr, "", "interface-scan"
	}
	return "", "", "none"
}
