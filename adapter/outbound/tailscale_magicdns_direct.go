//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/tailscale/tailcfg"
	"github.com/metacubex/tailscale/types/netmap"
	D "github.com/miekg/dns"
)

const (
	tailscaleMagicDNSDirectDefaultProbeTimeout = 750 * time.Millisecond
	tailscaleMagicDNSDirectDefaultCacheTTL     = 10 * time.Second
	tailscaleMagicDNSDirectDefaultAnswerTTL    = 5
	tailscaleMagicDNSDirectMaxProbeTimeout     = 60_000
	tailscaleMagicDNSDirectMaxTTL              = 86_400
)

var (
	tailscaleIPv4Range = netip.MustParsePrefix("100.64.0.0/10")
	tailscaleIPv6Range = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

type tailscaleMagicDNSDirectCacheEntry struct {
	addr    netip.Addr
	expires time.Time
}

type tailscaleMagicDNSDirectResolver struct {
	tailscale       *Tailscale
	name            string
	probeTimeout    time.Duration
	cacheTTL        time.Duration
	answerTTL       uint32
	interfaces      map[string]struct{}
	lookupInterface func(netip.Addr) (*iface.Interface, error)
	probeEndpoint   func(context.Context, netip.Addr) (netip.Addr, error)
	now             func() time.Time

	mu        sync.RWMutex
	peerAddrs map[netip.Addr]struct{}
	cache     map[netip.Addr]tailscaleMagicDNSDirectCacheEntry
}

func newTailscaleMagicDNSDirectResolver(tailscale *Tailscale, option TailscaleMagicDNSDirectOption) (*tailscaleMagicDNSDirectResolver, error) {
	if option.ProbeTimeout < 0 {
		return nil, errors.New("tailscale magic-dns-direct probe-timeout must not be negative")
	}
	if option.ProbeTimeout > tailscaleMagicDNSDirectMaxProbeTimeout {
		return nil, fmt.Errorf("tailscale magic-dns-direct probe-timeout must not exceed %d milliseconds", tailscaleMagicDNSDirectMaxProbeTimeout)
	}
	if option.CacheTTL < 0 {
		return nil, errors.New("tailscale magic-dns-direct cache-ttl must not be negative")
	}
	if option.CacheTTL > tailscaleMagicDNSDirectMaxTTL {
		return nil, fmt.Errorf("tailscale magic-dns-direct cache-ttl must not exceed %d seconds", tailscaleMagicDNSDirectMaxTTL)
	}
	if option.AnswerTTL < 0 {
		return nil, errors.New("tailscale magic-dns-direct answer-ttl must not be negative")
	}
	if option.AnswerTTL > tailscaleMagicDNSDirectMaxTTL {
		return nil, fmt.Errorf("tailscale magic-dns-direct answer-ttl must not exceed %d seconds", tailscaleMagicDNSDirectMaxTTL)
	}

	probeTimeout := tailscaleMagicDNSDirectDefaultProbeTimeout
	if option.ProbeTimeout > 0 {
		probeTimeout = time.Duration(option.ProbeTimeout) * time.Millisecond
	}
	cacheTTL := tailscaleMagicDNSDirectDefaultCacheTTL
	if option.CacheTTL > 0 {
		cacheTTL = time.Duration(option.CacheTTL) * time.Second
	}
	answerTTL := uint32(tailscaleMagicDNSDirectDefaultAnswerTTL)
	if option.AnswerTTL > 0 {
		answerTTL = uint32(option.AnswerTTL)
	}

	interfaceNames := make(map[string]struct{}, len(option.Interfaces))
	for _, name := range option.Interfaces {
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, errors.New("tailscale magic-dns-direct interface name must not be empty")
		}
		interfaceNames[name] = struct{}{}
	}

	resolver := &tailscaleMagicDNSDirectResolver{
		tailscale:       tailscale,
		name:            tailscale.Name(),
		probeTimeout:    probeTimeout,
		cacheTTL:        cacheTTL,
		answerTTL:       answerTTL,
		interfaces:      interfaceNames,
		lookupInterface: iface.ResolveInterfaceByAddr,
		now:             time.Now,
		peerAddrs:       map[netip.Addr]struct{}{},
		cache:           map[netip.Addr]tailscaleMagicDNSDirectCacheEntry{},
	}
	resolver.probeEndpoint = resolver.probeTailscaleEndpoint
	return resolver, nil
}

func (r *tailscaleMagicDNSDirectResolver) interfaceNames() []string {
	names := make([]string, 0, len(r.interfaces))
	for name := range r.interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (r *tailscaleMagicDNSDirectResolver) updateNetMap(nm *netmap.NetworkMap) {
	peerAddrs := map[netip.Addr]struct{}{}
	if nm != nil {
		for _, peer := range nm.Peers {
			addresses := peer.Addresses()
			for index := 0; index < addresses.Len(); index++ {
				prefix := addresses.At(index)
				addr := prefix.Addr().Unmap()
				if addr.IsValid() {
					peerAddrs[addr] = struct{}{}
				}
			}
		}
	}

	r.mu.Lock()
	r.peerAddrs = peerAddrs
	r.cache = map[netip.Addr]tailscaleMagicDNSDirectCacheEntry{}
	r.mu.Unlock()
}

func (r *tailscaleMagicDNSDirectResolver) rewriteResponse(ctx context.Context, response *D.Msg) {
	if response == nil {
		return
	}
	for index, answer := range response.Answer {
		var tailnetIP netip.Addr
		switch rr := answer.(type) {
		case *D.A:
			if addr, ok := netip.AddrFromSlice(rr.A); ok {
				tailnetIP = addr.Unmap()
			}
		case *D.AAAA:
			if addr, ok := netip.AddrFromSlice(rr.AAAA); ok {
				tailnetIP = addr.Unmap()
			}
		default:
			continue
		}
		if !r.isPeerAddr(tailnetIP) {
			continue
		}

		capDNSAnswerTTL(answer, r.answerTTL)
		directIP, err := r.directAddr(ctx, tailnetIP)
		if err != nil {
			log.Debugln("[Tailscale](%s) MagicDNS LAN-direct fallback for %s: %v", r.name, tailnetIP, err)
			continue
		}
		if directIP.Is4() != tailnetIP.Is4() {
			continue
		}

		switch rr := answer.(type) {
		case *D.A:
			rewritten := *rr
			rewritten.A = net.IP(directIP.AsSlice())
			response.Answer[index] = &rewritten
		case *D.AAAA:
			rewritten := *rr
			rewritten.AAAA = net.IP(directIP.AsSlice())
			response.Answer[index] = &rewritten
		}
		log.Debugln("[Tailscale](%s) MagicDNS LAN-direct %s -> %s", r.name, tailnetIP, directIP)
	}
}

func capDNSAnswerTTL(answer D.RR, ttl uint32) {
	if header := answer.Header(); header != nil && header.Ttl > ttl {
		header.Ttl = ttl
	}
}

func (r *tailscaleMagicDNSDirectResolver) isPeerAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	r.mu.RLock()
	_, ok := r.peerAddrs[addr.Unmap()]
	r.mu.RUnlock()
	return ok
}

func (r *tailscaleMagicDNSDirectResolver) directAddr(ctx context.Context, tailnetIP netip.Addr) (netip.Addr, error) {
	now := r.now()
	r.mu.RLock()
	entry, cached := r.cache[tailnetIP]
	r.mu.RUnlock()
	if cached && now.Before(entry.expires) {
		if entry.addr.IsValid() {
			return entry.addr, nil
		}
		return netip.Addr{}, errors.New("no connected direct endpoint")
	}

	probeCtx, cancel := context.WithTimeout(ctx, r.probeTimeout)
	defer cancel()
	directIP, err := r.probeEndpoint(probeCtx, tailnetIP)
	if err == nil {
		err = r.validateDirectAddr(directIP)
	}
	if err != nil {
		directIP = netip.Addr{}
	}

	r.mu.Lock()
	if _, stillPeer := r.peerAddrs[tailnetIP]; stillPeer {
		r.cache[tailnetIP] = tailscaleMagicDNSDirectCacheEntry{
			addr:    directIP,
			expires: now.Add(r.cacheTTL),
		}
	}
	r.mu.Unlock()
	if err != nil {
		return netip.Addr{}, err
	}
	return directIP, nil
}

func (r *tailscaleMagicDNSDirectResolver) probeTailscaleEndpoint(ctx context.Context, tailnetIP netip.Addr) (netip.Addr, error) {
	lc, err := r.tailscale.server.LocalClient()
	if err != nil {
		return netip.Addr{}, err
	}
	result, err := lc.Ping(ctx, tailnetIP, tailcfg.PingDisco)
	if err != nil {
		return netip.Addr{}, err
	}
	if result == nil {
		return netip.Addr{}, errors.New("empty Tailscale ping result")
	}
	if result.Err != "" {
		return netip.Addr{}, errors.New(result.Err)
	}
	if result.Endpoint == "" {
		return netip.Addr{}, errors.New("Tailscale path is not direct")
	}
	endpoint, err := netip.ParseAddrPort(result.Endpoint)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid Tailscale endpoint %q: %w", result.Endpoint, err)
	}
	return endpoint.Addr().Unmap(), nil
}

func (r *tailscaleMagicDNSDirectResolver) validateDirectAddr(addr netip.Addr) error {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.Zone() != "" || addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
		return fmt.Errorf("endpoint %s is not a usable unicast DNS address", addr)
	}
	if tailscaleIPv4Range.Contains(addr) || tailscaleIPv6Range.Contains(addr) {
		return fmt.Errorf("endpoint %s is a Tailnet address", addr)
	}

	localInterface, err := r.lookupInterface(addr)
	if err != nil {
		return fmt.Errorf("endpoint %s is not on a connected subnet: %w", addr, err)
	}
	if localInterface == nil {
		return fmt.Errorf("endpoint %s is not on a connected subnet", addr)
	}
	if localInterface.Flags&net.FlagUp == 0 || localInterface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
		return fmt.Errorf("endpoint %s uses ineligible interface %s", addr, localInterface.Name)
	}
	if len(r.interfaces) > 0 {
		if _, allowed := r.interfaces[localInterface.Name]; !allowed {
			return fmt.Errorf("endpoint %s uses interface %s, which is not allowed", addr, localInterface.Name)
		}
	}
	for _, prefix := range localInterface.Addresses {
		prefix = prefix.Masked()
		if prefix.Contains(addr) && prefix.Bits() < addr.BitLen() {
			return nil
		}
	}
	return fmt.Errorf("endpoint %s is not covered by a connected subnet on %s", addr, localInterface.Name)
}
