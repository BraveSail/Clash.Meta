//go:build android

package outbound

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/log"
)

// The Android app sandbox forbids netlink route lookups (every RTM_GETROUTE and
// RTM_GETRULE dump fails with EPERM), so the interface list alone cannot say
// which network is carrying traffic: it reports every physical NIC, including
// the SIM that is idle, and a phone that moved from Wi-Fi to cellular would go
// on publishing the Wi-Fi address. The one reliable signal left is a socket the
// VPN has exempted: mihomo routes every connection it creates through
// VpnService.protect, and a protected socket uses the underlying network, so
// its local address belongs to the SIM that is actually carrying data. Probe
// one periodically and publish from the interface it resolves to.

// peerDirectoryProbeTargets are route anchors only: the sockets are connected
// but never written to, so no packets are sent and no replies are needed.
var peerDirectoryProbeTargets = []struct{ network, addr string }{
	{"udp6", "[2400:3200::1]:53"}, // OneDNS, IPv6
	{"udp4", "223.5.5.5:53"},      // AliDNS, IPv4
}

// startUnderlayWatch keeps this outbound's idea of the carrying interface in
// sync with the network actually in use. It runs until the outbound is closed
// (d.ctx). The protected channel becomes usable asynchronously after the VPN
// comes up, so a first phase retries every few seconds until the first success;
// the steady phase then follows SIM switches every 30s.
func (d *PeerDirectory) startUnderlayWatch() {
	for i := 0; i < 40; i++ {
		if d.refreshUnderlayInterface("startup") {
			if i > 0 {
				log.Infoln("[PeerDirectory](%s) underlay probe: succeeded after %d retries", d.Name(), i)
			}
			break
		}
		select {
		case <-d.ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.refreshUnderlayInterface("periodic")
		}
	}
}

// refreshUnderlayInterface re-probes the protected channel once and reports
// whether it learned anything. A network change the host observed calls it with
// its own reason, so the answer is current before the next report goes out.
func (d *PeerDirectory) refreshUnderlayInterface(why string) bool {
	addr, name := d.probeUnderlayInterface()
	if name == "" {
		return false
	}
	previous, previousName := d.underlay()
	d.storeUnderlay(addr, name)
	if previous != addr || previousName != name {
		log.Infoln("[PeerDirectory](%s) underlay interface: %s is carrying traffic (%s), now using %s",
			d.Name(), name, why, addr)
	}
	return true
}

// probeUnderlayInterface connects a socket the VPN has exempted and resolves
// the interface owning its local address. An empty name means this round could
// not tell, and the caller keeps what it had.
func (d *PeerDirectory) probeUnderlayInterface() (netip.Addr, string) {
	ctx, cancel := context.WithTimeout(d.ctx, 5*time.Second)
	defer cancel()
	for _, target := range peerDirectoryProbeTargets {
		conn, err := dialer.DialContext(ctx, target.network, target.addr)
		if err != nil {
			log.Debugln("[PeerDirectory](%s) underlay probe: protected %s dial %s failed: %v",
				d.Name(), target.network, target.addr, err)
			continue
		}
		local := conn.LocalAddr()
		_ = conn.Close()
		udpAddr, ok := local.(*net.UDPAddr)
		if !ok || udpAddr == nil || udpAddr.IP == nil {
			log.Debugln("[PeerDirectory](%s) underlay probe: %s local address unavailable", d.Name(), target.network)
			continue
		}
		addr, ok := netip.AddrFromSlice(udpAddr.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		ifc, err := iface.ResolveInterfaceByAddr(addr)
		if err != nil {
			log.Debugln("[PeerDirectory](%s) underlay probe: source %s resolved to no interface: %v", d.Name(), addr, err)
			continue
		}
		if isVirtualInterfaceName(ifc.Name) {
			log.Debugln("[PeerDirectory](%s) underlay probe: source %s sits on virtual interface %s; trying the next anchor",
				d.Name(), addr, ifc.Name)
			continue
		}
		return addr, ifc.Name
	}
	log.Debugln("[PeerDirectory](%s) underlay probe: no underlying interface found this round", d.Name())
	return netip.Addr{}, ""
}
