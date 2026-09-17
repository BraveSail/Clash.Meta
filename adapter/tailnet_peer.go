package adapter

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/component/tailnet"
	C "github.com/metacubex/mihomo/constant"
)

// tailnetPeerResolveTTL keeps a burst of connections from re-reading the
// tailscale status while still following a peer that changes networks.
const tailnetPeerResolveTTL = 2 * time.Second

// TailnetPeerOption dials a tailscale peer whose underlay address changes. The
// inner `proxy` configuration supplies the protocol; its `server` and `port`
// are replaced with the peer's current address.
type TailnetPeerOption struct {
	outbound.BasicOption
	Name  string         `proxy:"name"`
	Peer  string         `proxy:"peer"`
	Port  int            `proxy:"port"`
	Proxy map[string]any `proxy:"proxy"`
}

type TailnetPeer struct {
	*outbound.Base

	option TailnetPeerOption
	direct C.Proxy

	mu         sync.Mutex
	inner      C.Proxy
	innerHost  string
	cachedHost string
	cachedSelf bool
	resolvedAt time.Time
}

func NewTailnetPeer(option TailnetPeerOption) (*TailnetPeer, error) {
	if strings.TrimSpace(option.Peer) == "" {
		return nil, errors.New("tailnet-peer: peer is required")
	}
	if option.Port <= 0 || option.Port > 65535 {
		return nil, fmt.Errorf("tailnet-peer: invalid port %d", option.Port)
	}
	if len(option.Proxy) == 0 {
		return nil, errors.New("tailnet-peer: proxy is required")
	}
	peer := &TailnetPeer{
		Base: outbound.NewBase(outbound.BaseOption{
			Name:         option.Name,
			Addr:         option.Peer,
			Type:         C.TailnetPeer,
			ProviderName: option.ProviderName,
			UDP:          true,
		}),
		option: option,
		direct: NewProxy(outbound.NewDirect()),
	}
	inner, err := peer.buildInner("")
	if err != nil {
		return nil, err
	}
	peer.inner = inner
	return peer, nil
}

// buildInner re-parses the inner proxy configuration with the address this
// node resolved; an empty host keeps a placeholder until the first dial.
func (t *TailnetPeer) buildInner(host string) (C.Proxy, error) {
	mapping := make(map[string]any, len(t.option.Proxy)+4)
	for key, value := range t.option.Proxy {
		mapping[key] = value
	}
	if host == "" {
		host = "0.0.0.0"
	}
	mapping["server"] = host
	mapping["port"] = t.option.Port
	if _, ok := mapping["name"]; !ok {
		mapping["name"] = t.option.Name + " (inner)"
	}
	return ParseProxy(mapping)
}

func (t *TailnetPeer) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	proxy, err := t.proxyForDial(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := proxy.DialContext(ctx, metadata)
	if err != nil {
		t.invalidate()
	}
	return conn, err
}

func (t *TailnetPeer) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	proxy, err := t.proxyForDial(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := proxy.ListenPacketContext(ctx, metadata)
	if err != nil {
		t.invalidate()
	}
	return conn, err
}

// proxyForDial returns the proxy to use for one connection: DIRECT when the
// configured peer is this node, otherwise the inner proxy bound to the peer's
// current address.
func (t *TailnetPeer) proxyForDial(ctx context.Context) (C.Proxy, error) {
	host, self, err := t.resolve(ctx)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if self {
		return t.direct, nil
	}
	if host == t.innerHost && t.inner != nil {
		return t.inner, nil
	}
	inner, err := t.buildInner(host)
	if err != nil {
		return nil, err
	}
	previous := t.inner
	t.inner = inner
	t.innerHost = host
	if previous != nil {
		_ = previous.Close()
	}
	return inner, nil
}

func (t *TailnetPeer) resolve(ctx context.Context) (host string, self bool, err error) {
	t.mu.Lock()
	if (t.cachedHost != "" || t.cachedSelf) && time.Since(t.resolvedAt) < tailnetPeerResolveTTL {
		host, self = t.cachedHost, t.cachedSelf
		t.mu.Unlock()
		return host, self, nil
	}
	t.mu.Unlock()

	peer, isSelf, found := tailnet.ResolvePeer(ctx, t.option.Peer)
	if !found {
		return "", false, fmt.Errorf("tailnet-peer: no tailnet peer matches %q (%s)", t.option.Peer, tailnet.DescribeProviders(ctx))
	}
	if isSelf {
		t.storeResolved("", true)
		return "", true, nil
	}
	addresses := tailnet.OrderPeerAddresses(peer, localIPv6Prefixes())
	if len(addresses) == 0 {
		return "", false, fmt.Errorf("tailnet-peer: peer %q has no dialable address", t.option.Peer)
	}
	host = addresses[0].String()
	t.storeResolved(host, false)
	return host, false, nil
}

func (t *TailnetPeer) storeResolved(host string, self bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cachedHost = host
	t.cachedSelf = self
	t.resolvedAt = time.Now()
}

func (t *TailnetPeer) invalidate() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.resolvedAt = time.Time{}
}

func (t *TailnetPeer) innerProxy() C.Proxy {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.inner
}

func localIPv6Prefixes() []netip.Prefix {
	interfaces, err := iface.Interfaces()
	if err != nil {
		return nil
	}
	var prefixes []netip.Prefix
	for _, item := range interfaces {
		for _, prefix := range item.Addresses {
			if prefix.Addr().Is6() {
				prefixes = append(prefixes, netip.PrefixFrom(prefix.Addr(), 64).Masked())
			}
		}
	}
	return prefixes
}

func (t *TailnetPeer) Addr() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.innerHost != "" {
		return t.innerHost + ":" + strconv.Itoa(t.option.Port)
	}
	return t.option.Peer
}

func (t *TailnetPeer) SupportUDP() bool {
	inner := t.innerProxy()
	return inner != nil && inner.SupportUDP()
}

func (t *TailnetPeer) SupportUOT() bool {
	inner := t.innerProxy()
	return inner != nil && inner.SupportUOT()
}

func (t *TailnetPeer) IsL3Protocol(metadata *C.Metadata) bool {
	inner := t.innerProxy()
	return inner != nil && inner.IsL3Protocol(metadata)
}

func (t *TailnetPeer) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	return nil
}

func (t *TailnetPeer) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.inner != nil {
		_ = t.inner.Close()
		t.inner = nil
	}
	if t.direct != nil {
		_ = t.direct.Close()
	}
	return nil
}
