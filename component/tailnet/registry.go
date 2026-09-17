package tailnet

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"sync"
)

// Registry connects an outbound that needs a peer's current address with the
// tailscale outbound that knows it. The tailscale outbound publishes itself
// here on construction and removes itself on Close; consumers resolve a peer
// through it instead of importing the tailscale outbound.
var (
	registryMu      sync.Mutex
	statusProviders = map[string]StatusProvider{}
)

func RegisterStatusProvider(name string, provider StatusProvider) {
	if name == "" || provider == nil {
		return
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	statusProviders[name] = provider
}

// UnregisterStatusProvider removes [provider] only if it is still the one
// registered under [name]: a config reload builds the replacement before the
// previous outbound stops, and removing by name alone would drop the new one.
func UnregisterStatusProvider(name string, provider StatusProvider) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if current, ok := statusProviders[name]; ok && sameProvider(current, provider) {
		delete(statusProviders, name)
	}
}

// sameProvider compares identity without assuming the implementation is
// comparable: a provider backed by a slice or map would panic on ==.
func sameProvider(a, b StatusProvider) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	kind := reflect.TypeOf(a)
	if kind != reflect.TypeOf(b) || !kind.Comparable() {
		return false
	}
	return a == b
}

func RegisteredProviderCount() int {
	registryMu.Lock()
	defer registryMu.Unlock()
	return len(statusProviders)
}

func statusProviderSnapshot() []StatusProvider {
	registryMu.Lock()
	defer registryMu.Unlock()
	providers := make([]StatusProvider, 0, len(statusProviders))
	for _, provider := range statusProviders {
		providers = append(providers, provider)
	}
	return providers
}

// ResolvePeer finds the node [name] refers to - a host name, a MagicDNS name
// or any tailscale IP. self reports that the name is this node, which lets a
// caller degrade to DIRECT instead of dialing itself through a listener. The
// two results are mutually exclusive.
func ResolvePeer(ctx context.Context, name string) (peer NodeStatus, self bool, found bool) {
	query := normalizePeerName(name)
	if query == "" {
		return NodeStatus{}, false, false
	}
	for _, provider := range statusProviderSnapshot() {
		status, err := provider.TailnetStatus(ctx)
		if err != nil {
			continue
		}
		if status.Self != nil && peerMatches(*status.Self, query) {
			return NodeStatus{}, true, true
		}
		for _, candidate := range status.Peers {
			if peerMatches(candidate, query) {
				return candidate, false, true
			}
		}
	}
	return NodeStatus{}, false, false
}

// DescribeProviders summarizes what the registered tailscale outbounds report,
// so a lookup that finds nothing names its reason instead of only its query.
func DescribeProviders(ctx context.Context) string {
	providers := statusProviderSnapshot()
	if len(providers) == 0 {
		return "no tailscale outbound is registered"
	}
	described := make([]string, 0, len(providers))
	for _, provider := range providers {
		status, err := provider.TailnetStatus(ctx)
		if err != nil {
			described = append(described, status.Proxy+": "+err.Error())
			continue
		}
		peers := make([]string, 0, len(status.Peers))
		for _, peer := range status.Peers {
			peers = append(peers, fmt.Sprintf("%s=%s", peer.Name, strings.Join(peer.TailscaleIPs, ",")))
		}
		summary := fmt.Sprintf("%s: backend=%s peers=%d", status.Proxy, status.BackendState, len(status.Peers))
		if len(peers) > 0 {
			summary += " [" + strings.Join(peers, " ") + "]"
		}
		described = append(described, summary)
	}
	return strings.Join(described, "; ")
}

// OrderPeerAddresses returns the addresses to dial for a peer, best first: the
// verified direct path, then IPv6 sharing a /64 with one of localPrefixes,
// then other IPv6, then IPv4. Addresses that cannot be dialed as they stand
// (loopback, link-local, malformed) are dropped.
func OrderPeerAddresses(peer NodeStatus, localPrefixes []netip.Prefix) []netip.Addr {
	verified, ok := parseEndpointAddr(peer.CurAddr)
	if !peer.DirectVerified || !ok {
		verified = netip.Addr{}
	}
	var sameLan, globalV6, others []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, endpoint := range peer.Addrs {
		addr, ok := parseEndpointAddr(endpoint)
		if !ok || addr == verified || seen[addr] {
			continue
		}
		seen[addr] = true
		switch {
		case addr.Is4():
			others = append(others, addr)
		case sharesPrefix64(addr, localPrefixes):
			sameLan = append(sameLan, addr)
		default:
			globalV6 = append(globalV6, addr)
		}
	}
	ordered := make([]netip.Addr, 0, 1+len(sameLan)+len(globalV6)+len(others))
	if verified.IsValid() {
		ordered = append(ordered, verified)
	}
	ordered = append(ordered, sameLan...)
	ordered = append(ordered, globalV6...)
	ordered = append(ordered, others...)
	return ordered
}

func peerMatches(peer NodeStatus, query string) bool {
	for _, name := range []string{peer.Name, peer.HostName, peer.DNSName} {
		if normalizePeerName(name) == query {
			return true
		}
	}
	for _, ip := range peer.TailscaleIPs {
		if normalizePeerName(ip) == query {
			return true
		}
	}
	return false
}

func normalizePeerName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// parseEndpointAddr accepts "host:port" (IPv6 bracketed) and a bare address.
func parseEndpointAddr(endpoint string) (netip.Addr, bool) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return netip.Addr{}, false
	}
	if addrPort, err := netip.ParseAddrPort(endpoint); err == nil {
		return usableAddr(addrPort.Addr())
	}
	addr, err := netip.ParseAddr(endpoint)
	if err != nil {
		return netip.Addr{}, false
	}
	return usableAddr(addr)
}

func usableAddr(addr netip.Addr) (netip.Addr, bool) {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() {
		return netip.Addr{}, false
	}
	return addr, true
}

func sharesPrefix64(addr netip.Addr, prefixes []netip.Prefix) bool {
	if !addr.Is6() {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Addr().Is6() && prefix.Bits() >= 64 && prefix.Contains(addr) {
			return true
		}
	}
	return false
}
