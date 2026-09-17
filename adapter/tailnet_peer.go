package adapter

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/component/tailnet"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// tailnetPeerResolveTTL keeps a burst of connections from re-reading the
// tailscale status while still following a peer that changes networks.
const tailnetPeerResolveTTL = 2 * time.Second

// TailnetPeerOption dials a tailscale peer whose underlay address changes. The
// inner `proxy` configuration supplies the protocol; its `server` and `port`
// are replaced with the peer's current address.
type TailnetPeerOption struct {
	outbound.BasicOption
	Name string `proxy:"name"`
	Peer string `proxy:"peer"`
	Port int    `proxy:"port"`
	// Directory names another outbound that answers the peer's address.
	Directory string `proxy:"directory,omitempty"`
	// DirectoryURL and DirectoryToken configure that directory inline instead,
	// with DirectoryID naming this node in it. A build that predates these
	// fields simply ignores them, so a shared profile can carry them before
	// every device is updated.
	DirectoryURL   string `proxy:"directory-url,omitempty"`
	DirectoryToken string `proxy:"directory-token,omitempty"`
	DirectoryID    string `proxy:"directory-id,omitempty"`
	// DirectoryIDByPlatform names this node per platform (the runtime.GOOS
	// names: windows, android, linux, darwin), so a shared profile can tell each
	// device who it is without any per-device setting. DirectoryID, which the app
	// fills from its own setting, wins when both are present.
	DirectoryIDByPlatform map[string]string `proxy:"directory-id-by-platform,omitempty"`
	// DirectoryPeer is the name to ask the directory for; it defaults to [Peer],
	// which may be a tailscale address the directory does not know.
	DirectoryPeer string         `proxy:"directory-peer,omitempty"`
	Proxy         map[string]any `proxy:"proxy"`
}

// directoryID is the name this node reports under: the app's own setting when it
// is present, otherwise the profile's per-platform entry.
func (o TailnetPeerOption) directoryID() string {
	if o.DirectoryID != "" {
		return o.DirectoryID
	}
	return o.DirectoryIDByPlatform[runtime.GOOS]
}

type TailnetPeer struct {
	*outbound.Base

	option TailnetPeerOption
	direct C.Proxy
	// directory is this outbound's handle on the shared directory client, if one
	// was configured inline.
	directory *outbound.PeerDirectory

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
	if option.DirectoryURL != "" {
		if option.directoryID() == "" {
			// The profile asks for the directory but this device was never told
			// which node it is: say so instead of quietly resolving somewhere
			// else.
			log.Warnln("tailnet-peer: %s configures a directory but this device has no name for it", option.Name)
		} else {
			directory, err := acquireDirectoryClient(outbound.PeerDirectoryOption{
				Name:  option.Name + " directory",
				URL:   option.DirectoryURL,
				Token: option.DirectoryToken,
				ID:    option.directoryID(),
				Port:  option.Port,
			})
			if err != nil {
				return nil, err
			}
			peer.directory = directory
		}
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
	if _, self, err := t.resolve(ctx); err != nil {
		return nil, err
	} else if self {
		if conn, err := t.dialLocalService(ctx, metadata); err == nil {
			return conn, nil
		}
		return t.direct.DialContext(ctx, metadata)
	}

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

// dialLocalService reaches a service that runs on this node. The destination of
// such a connection is this node's own tailnet address, and dialing it as it
// stands would route the connection back into the rule that chose this
// outbound; the service is listening on the loopback address with the same port.
func (t *TailnetPeer) dialLocalService(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if metadata == nil || metadata.DstPort == 0 {
		return nil, errors.New("tailnet-peer: no port to dial on this node")
	}
	var lastErr error
	for _, loopback := range []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")} {
		local := *metadata
		local.Host = ""
		local.DstIP = loopback
		conn, err := t.direct.DialContext(ctx, &local)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
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

// directoryNameKey is the name this outbound asks the directory for.
func (t *TailnetPeer) directoryNameKey() string {
	if t.option.DirectoryPeer != "" {
		return t.option.DirectoryPeer
	}
	return t.option.Peer
}

func (t *TailnetPeer) resolve(ctx context.Context) (host string, self bool, err error) {
	t.mu.Lock()
	if (t.cachedHost != "" || t.cachedSelf) && time.Since(t.resolvedAt) < tailnetPeerResolveTTL {
		host, self = t.cachedHost, t.cachedSelf
		t.mu.Unlock()
		return host, self, nil
	}
	t.mu.Unlock()

	if t.directory != nil {
		addr, _, self, err := t.directory.PeerAddress(ctx, t.directoryNameKey())
		if err != nil {
			return "", false, fmt.Errorf("tailnet-peer: %w", err)
		}
		if self {
			t.storeResolved("", true)
			return "", true, nil
		}
		t.storeResolved(addr, false)
		return addr, false, nil
	}

	if t.option.DirectoryURL != "" {
		return "", false, fmt.Errorf(
			"tailnet-peer: %s is configured for the peer directory but this device has no directory name; set one in the app",
			t.option.Name,
		)
	}

	if t.option.Directory != "" {
		addr, _, self, err := tailnet.LookupDirectoryPeer(ctx, t.option.Directory, t.directoryNameKey())
		if err != nil {
			return "", false, fmt.Errorf("tailnet-peer: %w", err)
		}
		if self {
			t.storeResolved("", true)
			return "", true, nil
		}
		t.storeResolved(addr, false)
		return addr, false, nil
	}

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
	if t.directory != nil {
		releaseDirectoryClient(t.directory)
		t.directory = nil
	}
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
