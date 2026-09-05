//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/iface"

	"github.com/metacubex/tailscale/tailcfg"
	"github.com/metacubex/tailscale/types/netmap"
	D "github.com/miekg/dns"
)

func TestTailscaleMagicDNSDirectRequiresMagicDNS(t *testing.T) {
	_, err := NewTailscale(TailscaleOption{
		Name: "test",
		MagicDNSDirect: TailscaleMagicDNSDirectOption{
			Enabled: true,
		},
	})
	if err == nil {
		t.Fatal("magic-dns-direct without magic-dns did not fail")
	}
}

func TestTailscaleMagicDNSDirectOptionValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		option TailscaleMagicDNSDirectOption
	}{
		{name: "negative probe timeout", option: TailscaleMagicDNSDirectOption{ProbeTimeout: -1}},
		{name: "negative cache ttl", option: TailscaleMagicDNSDirectOption{CacheTTL: -1}},
		{name: "negative answer ttl", option: TailscaleMagicDNSDirectOption{AnswerTTL: -1}},
		{name: "large probe timeout", option: TailscaleMagicDNSDirectOption{ProbeTimeout: tailscaleMagicDNSDirectMaxProbeTimeout + 1}},
		{name: "large cache ttl", option: TailscaleMagicDNSDirectOption{CacheTTL: tailscaleMagicDNSDirectMaxTTL + 1}},
		{name: "large answer ttl", option: TailscaleMagicDNSDirectOption{AnswerTTL: tailscaleMagicDNSDirectMaxTTL + 1}},
		{name: "empty interface", option: TailscaleMagicDNSDirectOption{Interfaces: []string{" "}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newTailscaleMagicDNSDirectResolver(testTailscaleForMagicDNSDirect(), tc.option); err == nil {
				t.Fatal("invalid option did not fail")
			}
		})
	}
}

func TestTailscaleMagicDNSDirectRewriteIPv6(t *testing.T) {
	tailnetIP := netip.MustParseAddr("fd7a:115c:a1e0::1737:675b")
	directIP := netip.MustParseAddr("2409:896d:541:138d::20")
	resolver := testMagicDNSDirectResolver(tailnetIP)
	resolver.probeEndpoint = func(context.Context, netip.Addr) (netip.Addr, error) {
		return directIP, nil
	}
	resolver.lookupInterface = func(netip.Addr) (*iface.Interface, error) {
		return &iface.Interface{
			Name:      "en0",
			Flags:     net.FlagUp,
			Addresses: []netip.Prefix{netip.MustParsePrefix("2409:896d:541:138d::1/64")},
		}, nil
	}
	response := &D.Msg{Answer: []D.RR{&D.AAAA{
		Hdr:  D.RR_Header{Name: "peer.tailnet.test.", Rrtype: D.TypeAAAA, Class: D.ClassINET, Ttl: 600},
		AAAA: net.IP(tailnetIP.AsSlice()),
	}}}
	resolver.rewriteResponse(context.Background(), response)
	record := response.Answer[0].(*D.AAAA)
	got, _ := netip.AddrFromSlice(record.AAAA)
	if got != directIP {
		t.Fatalf("rewritten IPv6 = %s, want %s", got, directIP)
	}
}

func TestTailscaleMagicDNSDirectLeavesUnknownAnswersAlone(t *testing.T) {
	peerIP := netip.MustParseAddr("100.90.103.91")
	unknownIP := netip.MustParseAddr("100.64.0.99")
	resolver := testMagicDNSDirectResolver(peerIP)
	resolver.probeEndpoint = func(context.Context, netip.Addr) (netip.Addr, error) {
		t.Fatal("unknown address was probed")
		return netip.Addr{}, errors.New("unreachable")
	}
	response := magicDNSAResponse(unknownIP, 600)
	resolver.rewriteResponse(context.Background(), response)
	record := response.Answer[0].(*D.A)
	if record.Hdr.Ttl != 600 {
		t.Fatalf("unknown answer TTL = %d, want 600", record.Hdr.Ttl)
	}
}

func TestTailscaleMagicDNSDirectOnlyRewritesExternalDNS(t *testing.T) {
	tailnetIP := netip.MustParseAddr("100.90.103.91")
	directIP := netip.MustParseAddr("192.168.1.20")
	resolver := testMagicDNSDirectResolver(tailnetIP)
	probeCount := 0
	resolver.probeEndpoint = func(context.Context, netip.Addr) (netip.Addr, error) {
		probeCount++
		return directIP, nil
	}
	resolver.lookupInterface = func(netip.Addr) (*iface.Interface, error) {
		return &iface.Interface{Name: "br-lan", Flags: net.FlagUp, Addresses: []netip.Prefix{netip.MustParsePrefix("192.168.1.1/24")}}, nil
	}
	proxy := &Tailscale{magicDNSDirect: resolver}

	internalResponse := magicDNSAResponse(tailnetIP, 600)
	(tailscaleDNSTransport{tailscale: proxy}).rewriteResponse(context.Background(), internalResponse)
	internalAddr, _ := netip.AddrFromSlice(internalResponse.Answer[0].(*D.A).A)
	if internalAddr.Unmap() != tailnetIP || probeCount != 0 {
		t.Fatalf("internal Tailscale DNS was rewritten to %s after %d probes", internalAddr.Unmap(), probeCount)
	}

	externalResponse := magicDNSAResponse(tailnetIP, 600)
	(tailscaleDNSTransport{tailscale: proxy, allowDirect: true}).rewriteResponse(context.Background(), externalResponse)
	externalAddr, _ := netip.AddrFromSlice(externalResponse.Answer[0].(*D.A).A)
	if externalAddr.Unmap() != directIP || probeCount != 1 {
		t.Fatalf("external MagicDNS address = %s after %d probes, want %s after 1", externalAddr.Unmap(), probeCount, directIP)
	}
}

func TestTailscaleMagicDNSDirectRewriteAndCache(t *testing.T) {
	tailnetIP := netip.MustParseAddr("100.90.103.91")
	directIP := netip.MustParseAddr("192.168.1.20")
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	probeCount := 0
	resolver := testMagicDNSDirectResolver(tailnetIP)
	resolver.now = func() time.Time { return now }
	resolver.probeEndpoint = func(context.Context, netip.Addr) (netip.Addr, error) {
		probeCount++
		return directIP, nil
	}
	resolver.lookupInterface = func(netip.Addr) (*iface.Interface, error) {
		return &iface.Interface{
			Name:      "br-lan",
			Flags:     net.FlagUp | net.FlagBroadcast,
			Addresses: []netip.Prefix{netip.MustParsePrefix("192.168.1.1/24")},
		}, nil
	}

	for i := 0; i < 2; i++ {
		response := magicDNSAResponse(tailnetIP, 600)
		resolver.rewriteResponse(context.Background(), response)
		record, ok := response.Answer[0].(*D.A)
		if !ok {
			t.Fatalf("answer type = %T, want *dns.A", response.Answer[0])
		}
		got, ok := netip.AddrFromSlice(record.A)
		if !ok || got.Unmap() != directIP {
			t.Fatalf("rewritten address = %v, want %s", record.A, directIP)
		}
		if record.Hdr.Ttl != resolver.answerTTL {
			t.Fatalf("rewritten TTL = %d, want %d", record.Hdr.Ttl, resolver.answerTTL)
		}
	}
	if probeCount != 1 {
		t.Fatalf("probe count = %d, want 1 while cached", probeCount)
	}

	now = now.Add(resolver.cacheTTL + time.Second)
	resolver.rewriteResponse(context.Background(), magicDNSAResponse(tailnetIP, 600))
	if probeCount != 2 {
		t.Fatalf("probe count after expiry = %d, want 2", probeCount)
	}
}

func TestTailscaleMagicDNSDirectFallback(t *testing.T) {
	tailnetIP := netip.MustParseAddr("100.90.103.91")
	resolver := testMagicDNSDirectResolver(tailnetIP)
	resolver.probeEndpoint = func(context.Context, netip.Addr) (netip.Addr, error) {
		return netip.MustParseAddr("203.0.113.20"), nil
	}
	resolver.lookupInterface = func(netip.Addr) (*iface.Interface, error) {
		return nil, iface.ErrIfaceNotFound
	}

	response := magicDNSAResponse(tailnetIP, 600)
	resolver.rewriteResponse(context.Background(), response)
	record := response.Answer[0].(*D.A)
	got, _ := netip.AddrFromSlice(record.A)
	if got.Unmap() != tailnetIP {
		t.Fatalf("fallback address = %s, want %s", got.Unmap(), tailnetIP)
	}
	if record.Hdr.Ttl != resolver.answerTTL {
		t.Fatalf("fallback TTL = %d, want %d", record.Hdr.Ttl, resolver.answerTTL)
	}
}

func TestTailscaleMagicDNSDirectAddressValidation(t *testing.T) {
	resolver := testMagicDNSDirectResolver(netip.MustParseAddr("100.90.103.91"))
	resolver.interfaces = map[string]struct{}{"br-lan": {}}
	resolver.lookupInterface = func(addr netip.Addr) (*iface.Interface, error) {
		switch {
		case addr.Is4():
			return &iface.Interface{Name: "br-lan", Flags: net.FlagUp, Addresses: []netip.Prefix{netip.MustParsePrefix("192.168.1.1/24")}}, nil
		case addr.Is6():
			return &iface.Interface{Name: "br-lan", Flags: net.FlagUp, Addresses: []netip.Prefix{netip.MustParsePrefix("2409:896d:541:138d::1/64")}}, nil
		default:
			return nil, iface.ErrIfaceNotFound
		}
	}

	for _, addr := range []string{"192.168.1.20", "2409:896d:541:138d::20"} {
		if err := resolver.validateDirectAddr(netip.MustParseAddr(addr)); err != nil {
			t.Fatalf("connected endpoint %s rejected: %v", addr, err)
		}
	}
	for _, addr := range []string{"127.0.0.1", "169.254.1.2", "100.90.103.91", "fd7a:115c:a1e0::1", "192.168.2.20"} {
		if err := resolver.validateDirectAddr(netip.MustParseAddr(addr)); err == nil {
			t.Fatalf("ineligible endpoint %s accepted", addr)
		}
	}

	resolver.lookupInterface = func(netip.Addr) (*iface.Interface, error) {
		return &iface.Interface{Name: "wan", Flags: net.FlagUp, Addresses: []netip.Prefix{netip.MustParsePrefix("192.168.1.1/24")}}, nil
	}
	if err := resolver.validateDirectAddr(netip.MustParseAddr("192.168.1.20")); err == nil {
		t.Fatal("endpoint on an interface outside the allowlist was accepted")
	}

	resolver.interfaces = nil
	resolver.lookupInterface = func(netip.Addr) (*iface.Interface, error) {
		return &iface.Interface{Name: "tun0", Flags: net.FlagUp | net.FlagPointToPoint, Addresses: []netip.Prefix{netip.MustParsePrefix("192.168.1.1/24")}}, nil
	}
	if err := resolver.validateDirectAddr(netip.MustParseAddr("192.168.1.20")); err == nil {
		t.Fatal("endpoint on a point-to-point interface was accepted")
	}
}

func TestTailscaleMagicDNSDirectNetMapPeers(t *testing.T) {
	peerIP := netip.MustParseAddr("100.90.103.91")
	resolver := testMagicDNSDirectResolver(netip.MustParseAddr("100.64.0.99"))
	peer := (&tailcfg.Node{Addresses: []netip.Prefix{netip.PrefixFrom(peerIP, peerIP.BitLen())}}).View()
	resolver.updateNetMap(&netmap.NetworkMap{Peers: []tailcfg.NodeView{peer}})
	if !resolver.isPeerAddr(peerIP) {
		t.Fatalf("peer address %s was not published", peerIP)
	}
	if resolver.isPeerAddr(netip.MustParseAddr("100.64.0.99")) {
		t.Fatal("stale peer address survived netmap replacement")
	}
}

func testTailscaleForMagicDNSDirect() *Tailscale {
	return &Tailscale{Base: NewBase(BaseOption{Name: "test"})}
}

func testMagicDNSDirectResolver(peerIP netip.Addr) *tailscaleMagicDNSDirectResolver {
	return &tailscaleMagicDNSDirectResolver{
		name:         "test",
		probeTimeout: time.Second,
		cacheTTL:     10 * time.Second,
		answerTTL:    5,
		now:          time.Now,
		peerAddrs:    map[netip.Addr]struct{}{peerIP: {}},
		cache:        map[netip.Addr]tailscaleMagicDNSDirectCacheEntry{},
	}
}

func magicDNSAResponse(addr netip.Addr, ttl uint32) *D.Msg {
	return &D.Msg{Answer: []D.RR{&D.A{
		Hdr: D.RR_Header{Name: "peer.tailnet.test.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: ttl},
		A:   net.IP(addr.AsSlice()),
	}}}
}
