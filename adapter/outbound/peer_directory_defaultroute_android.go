//go:build android

package outbound

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

// underlyingDefaultInterface returns the name of the interface carrying the
// underlying (non-VPN) default route on Android, so the published address is
// the SIM currently carrying data instead of the VPN tunnel.
//
// Three independent probes are tried in order; all of them name the physical
// NIC while a VPN tunnel owns the routing policy database:
//
//  1. route lookup for this process's own UID (Android steers VPN-app traffic
//     to the underlying network);
//  2. the non-tunnel default route of the main table (desktop Linux approach);
//  3. an RPDB scan for a plain fallback rule pointing at the main table.
//
// how reports which probe matched ("uid-route", "main-table" or
// "rpdb-main-rule"); when all fail, err carries each probe's reason plus a
// bounded dump of the routing policy database.
func underlyingDefaultInterface() (name string, how string, err error) {
	if n, e := defaultInterfaceByUID(); e == nil {
		return n, "uid-route", nil
	} else {
		err = fmt.Errorf("uid-route: %v", e)
	}
	if n, e := defaultRouteInTable(unix.RT_TABLE_MAIN); e == nil {
		return n, "main-table", nil
	} else {
		err = fmt.Errorf("%v; main-table: %v", err, e)
	}
	if n, e := defaultInterfaceViaRPDB(); e == nil {
		return n, "rpdb-main-rule", nil
	} else {
		err = fmt.Errorf("%v; rpdb: %v", err, e)
	}
	return "", "", err
}

// defaultInterfaceByUID asks the kernel which interface a packet from this
// process's own UID would use. Android routes a VPN app's own traffic to the
// underlying network, so the answer names the physical NIC; a result resolving
// to a tunnel means the ROM steers differently and the caller tries the next
// probe.
func defaultInterfaceByUID() (string, error) {
	uid := uint32(os.Getuid())
	ip := net.ParseIP(peerDirectoryProbeV6)
	routes, err := netlink.RouteGetWithOptions(ip, &netlink.RouteGetOptions{UID: &uid})
	if err != nil {
		return "", err
	}
	for _, route := range routes {
		link, err := netlink.LinkByIndex(route.LinkIndex)
		if err != nil {
			continue
		}
		if name := link.Attrs().Name; !isTunnelInterface(name) {
			return name, nil
		}
	}
	return "", errors.New("no non-tunnel route for own uid")
}

// defaultRouteInTable returns the interface of the first non-tunnel default
// route (Dst == nil) in the given routing table.
func defaultRouteInTable(table int) (string, error) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return "", err
	}
	for _, route := range routes {
		if route.Dst != nil {
			continue
		}
		link, err := netlink.LinkByIndex(route.LinkIndex)
		if err != nil {
			continue
		}
		if name := link.Attrs().Name; !isTunnelInterface(name) {
			return name, nil
		}
	}
	return "", fmt.Errorf("no non-tunnel default route in table %d", table)
}

// defaultInterfaceViaRPDB scans the routing policy database for a plain
// fallback rule ("from all lookup main") and resolves that table's default
// route. A fwmark mask of 0x20000 marks Android's VPN steering rules and
// uidrange rules are the per-app isolation rules; both are skipped. When
// nothing matches, the error carries a bounded dump of every rule.
func defaultInterfaceViaRPDB() (string, error) {
	rules, err := netlink.RuleList(netlink.FAMILY_ALL)
	if err != nil {
		return "", err
	}
	var dump []string
	for _, rule := range rules {
		if len(dump) < 16 {
			dump = append(dump, fmt.Sprintf("prio=%d table=%d mask=%#x mark=%#x uid=%v",
				rule.Priority, rule.Table, rule.Mask, rule.Mark, rule.UIDRange))
		}
		if rule.UIDRange != nil || rule.Mask == 0x20000 {
			continue
		}
		if rule.Src.IsValid() || rule.Dst.IsValid() {
			continue
		}
		if rule.Table == unix.RT_TABLE_MAIN {
			if name, err := defaultRouteInTable(rule.Table); err == nil {
				return name, nil
			}
		}
	}
	return "", fmt.Errorf("no plain lookup-main rule among %d rules: %s", len(rules), strings.Join(dump, " | "))
}
