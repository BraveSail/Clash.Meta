//go:build with_gvisor && !no_tailscale && android

package outbound

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/tailscale/net/netmon"
)

// The Android app sandbox forbids netlink route lookups (every RTM_GETROUTE
// and RTM_GETRULE dump fails with EPERM), so netmon cannot identify the
// underlying (non-VPN) default interface on its own and its endpoint filter
// degrades to reporting every physical interface's addresses. The one
// reliable signal left is a socket the VPN has exempted: mihomo routes every
// connection it creates through VpnService.protect, and a protected socket
// uses the underlying network, so its local address belongs to the SIM that
// is actually carrying data. Probe one periodically and hand the interface
// name to netmon via its Android update hook.

// underlayProbeTargets are route anchors only: the sockets are connected but
// never written to, so no packets are sent and no replies are needed.
var underlayProbeTargets = []struct{ network, addr string }{
	{"udp6", "[2400:3200::1]:53"}, // OneDNS, IPv6
	{"udp4", "223.5.5.5:53"},      // AliDNS, IPv4
}

// underlayVirtualInterface reports whether name looks like a tunnel/loopback
// interface rather than a physical NIC. A protected socket should never
// resolve to one; if it does, the result is not usable as an underlay.
func underlayVirtualInterface(name string) bool {
	n := strings.ToLower(name)
	if n == "lo" || strings.HasPrefix(n, "lo") && len(n) > 2 {
		return true
	}
	for _, prefix := range []string{"tun", "utun", "tap", "wg", "tailscale", "ppp", "ipsec"} {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	return false
}

// probeUnderlayInterface connects a VPN-exempt socket and resolves the
// interface owning its local address. The empty string means no interface
// could be identified this round.
func (t *Tailscale) probeUnderlayInterface() string {
	ctx, cancel := context.WithTimeout(t.ctx, 5*time.Second)
	defer cancel()
	for _, target := range underlayProbeTargets {
		conn, err := t.dialer.DialContext(ctx, target.network, target.addr)
		if err != nil {
			log.Debugln("[Tailscale](%s) underlay probe: protected %s dial %s failed: %v", t.Name(), target.network, target.addr, err)
			continue
		}
		local := conn.LocalAddr()
		_ = conn.Close()
		udpAddr, ok := local.(*net.UDPAddr)
		if !ok || udpAddr == nil || udpAddr.IP == nil {
			log.Debugln("[Tailscale](%s) underlay probe: %s local address unavailable", t.Name(), target.network)
			continue
		}
		addr, ok := netip.AddrFromSlice(udpAddr.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		ifc, err := iface.ResolveInterfaceByAddr(addr)
		if err != nil {
			log.Debugln("[Tailscale](%s) underlay probe: source %s resolved to no interface: %v", t.Name(), addr, err)
			continue
		}
		if underlayVirtualInterface(ifc.Name) {
			log.Debugln("[Tailscale](%s) underlay probe: source %s on virtual interface %s; keeping next candidate", t.Name(), addr, ifc.Name)
			continue
		}
		return ifc.Name
	}
	log.Debugln("[Tailscale](%s) underlay probe: no underlying interface found", t.Name())
	return ""
}

// watchUnderlayInterface keeps netmon's Android default-route knowledge in
// sync with the SIM currently carrying data. The protected channel and the
// underlying interface become available asynchronously after the outbound
// starts, so a first phase retries every few seconds until the first
// success; the steady phase then refreshes every 30s to follow SIM switches.
// It runs until the outbound is closed (t.cancel cancels t.ctx).
func (t *Tailscale) watchUnderlayInterface() {
	var last string
	apply := func(why string) bool {
		name := t.probeUnderlayInterface()
		if name == "" {
			return false
		}
		if name != last {
			log.Infoln("[Tailscale](%s) underlay interface: %s (%s); updating netmon default route", t.Name(), name, why)
			last = name
		}
		netmon.UpdateLastKnownDefaultRouteInterface(name)
		return true
	}

	// Phase 1: dense retries covering the VPN bring-up window. Until the
	// VPN service installs its protect hook this probe fails immediately
	// (errTunNotReady), so a few seconds between attempts is enough to
	// land within one interval of the channel becoming usable.
	for i := 0; i < 40; i++ {
		if apply("startup") {
			if i > 0 {
				log.Infoln("[Tailscale](%s) underlay probe: succeeded after %d retries", t.Name(), i)
			}
			break
		}
		select {
		case <-t.ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}

	// Phase 2: steady cadence follows SIM switches.
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-ticker.C:
			apply("periodic")
		}
	}
}
