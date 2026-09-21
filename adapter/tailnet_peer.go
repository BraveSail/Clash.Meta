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
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// tailnetPeerResolveTTL keeps a burst of connections from re-asking the
// directory while still following a peer that changes networks.
const tailnetPeerResolveTTL = 2 * time.Second

// TailnetPeerOption dials a peer whose underlay address changes. The inner
// `proxy` configuration supplies the protocol; its `server` and `port` are
// replaced with the address the directory reports for the peer.
type TailnetPeerOption struct {
	outbound.BasicOption
	Name string `proxy:"name"`
	// Peer is the device this outbound dials. A mesh entry that answers by
	// domain map alone has no single peer, so the field is optional here;
	// NewTailnetPeer refuses an entry that has neither.
	Peer string `proxy:"peer,omitempty"`
	Port int    `proxy:"port"`
	// DirectoryURL and DirectoryToken configure the directory this outbound
	// asks, with DirectoryID naming this node in it. A build that predates
	// these fields simply ignores them, so a shared profile can carry them
	// before every device is updated.
	DirectoryURL   string `proxy:"directory-url,omitempty"`
	DirectoryToken string `proxy:"directory-token,omitempty"`
	// DirectoryID is the id this device reports under. One profile runs on
	// every device, so the app computes it per device from what the machine
	// itself carries.
	DirectoryID string `proxy:"directory-id,omitempty"`
	// DirectoryPeer is the name to ask the directory for; it defaults to [Peer],
	// which may be an address the directory does not know.
	DirectoryPeer string `proxy:"directory-peer,omitempty"`
	// Domains maps a name a connection may ask for to the directory record
	// that answers it, e.g. {"pc.lan": "a1b2c3d4e5f6"}. An entry configured
	// with it serves whichever device the requested name belongs to, so a
	// profile's rules can point at the mesh alone and no device has to be
	// named in the profile; a name that is not in the map falls back to
	// DirectoryPeer.
	Domains map[string]string `proxy:"domains,omitempty"`
	// DirectoryProxy is an HTTP proxy URL this outbound's directory requests
	// go through, for a device whose network cannot reach the directory
	// directly.
	DirectoryProxy string `proxy:"directory-proxy,omitempty"`
	// Hostname and OS are what this device reports itself as: the name the
	// machine carries (a phone's system host name is "localhost") and its
	// system with version. The app writes them per device, so one shared
	// profile carries its own values here.
	Hostname string `proxy:"hostname,omitempty"`
	OS       string `proxy:"os,omitempty"`
	// Heartbeat is how often the directory client this outbound shares reports
	// even when nothing changed, in seconds; the inline form of the directory
	// takes the same option as a `peer-directory` outbound would.
	Heartbeat int            `proxy:"heartbeat,omitempty"`
	Proxy     map[string]any `proxy:"proxy"`
}

// directoryID is the id this node reports under; it is empty when the app has
// not computed one yet.
func (o TailnetPeerOption) directoryID() string {
	return o.DirectoryID
}

type TailnetPeer struct {
	*outbound.Base

	option TailnetPeerOption
	direct C.Proxy
	// directory is this outbound's handle on the shared directory client, if one
	// was configured inline.
	directory *outbound.PeerDirectory

	mu        sync.Mutex
	inner     C.Proxy
	innerHost string
	// cachedPeers is one answer per directory record, not one per outbound: a
	// mesh entry serves every device, so a single slot would answer every
	// connection with whichever device it looked up first.
	cachedPeers map[string]resolvedPeer
}

// resolvedPeer is where one directory record was last seen.
type resolvedPeer struct {
	host string
	port int
	self bool
	at   time.Time
}

func NewTailnetPeer(option TailnetPeerOption) (*TailnetPeer, error) {
	// A mesh entry is configured by its domain map alone: it has no single
	// peer, because the name the connection asked for is what decides which
	// device answers. An entry with neither has nothing to resolve.
	if strings.TrimSpace(option.Peer) == "" && len(option.Domains) == 0 {
		return nil, errors.New("tailnet-peer: peer is required unless domains maps the names it answers")
	}
	if option.Port <= 0 || option.Port > 65535 {
		return nil, fmt.Errorf("tailnet-peer: invalid port %d", option.Port)
	}
	if len(option.Proxy) == 0 {
		return nil, errors.New("tailnet-peer: proxy is required")
	}
	if option.DirectoryURL == "" {
		return nil, fmt.Errorf("tailnet-peer: %s needs directory-url, the peer directory that names this node", option.Name)
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
	if option.directoryID() == "" {
		// The profile asks for the directory but this device was never told
		// which node it is: say so instead of quietly resolving somewhere else.
		log.Warnln("tailnet-peer: %s configures a directory but this device has no id for it", option.Name)
	} else {
		directory, err := acquireDirectoryClient(outbound.PeerDirectoryOption{
			Name:      option.Name + " directory",
			URL:       option.DirectoryURL,
			Token:     option.DirectoryToken,
			ID:        option.directoryID(),
			Port:      option.Port,
			Heartbeat: option.Heartbeat,
			ViaProxy:  option.DirectoryProxy,
			Hostname:  option.Hostname,
			OS:        option.OS,
		})
		if err != nil {
			return nil, err
		}
		peer.directory = directory
	}
	inner, err := peer.buildInner("", 0)
	if err != nil {
		return nil, err
	}
	peer.inner = inner
	return peer, nil
}

// buildInner re-parses the inner proxy configuration with the address this
// node resolved; an empty host keeps a placeholder until the first dial. The
// port is the one the device's own record carries: a mesh entry serves devices
// that listen on whatever port each of them reports, so the entry's own port is
// not the port to dial.
func (t *TailnetPeer) buildInner(host string, port int) (C.Proxy, error) {
	mapping := make(map[string]any, len(t.option.Proxy)+4)
	for key, value := range t.option.Proxy {
		mapping[key] = value
	}
	if host == "" {
		host = "0.0.0.0"
	}
	if port <= 0 || port > 65535 {
		port = t.option.Port
	}
	mapping["server"] = host
	mapping["port"] = port
	if _, ok := mapping["name"]; !ok {
		mapping["name"] = t.option.Name + " (inner)"
	}
	return ParseProxy(mapping)
}

func (t *TailnetPeer) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if _, _, self, err := t.resolveFor(ctx, requestedHost(metadata)); err != nil {
		return nil, err
	} else if self {
		if conn, err := t.dialLocalService(ctx, metadata); err == nil {
			return conn, nil
		}
		return t.direct.DialContext(ctx, metadata)
	}

	proxy, err := t.proxyForDial(ctx, requestedHost(metadata))
	if err != nil {
		return nil, err
	}
	conn, err := proxy.DialContext(ctx, metadata)
	if err != nil {
		t.invalidate()
	}
	return conn, err
}

// requestedHost is the name a connection asked for, lower case, or empty when
// it has none (an IP, or a connection that never carried a name). It is what a
// mesh entry maps to a device: the rule chose the entry, and the name the
// caller used is what decides which device serves it.
func requestedHost(metadata *C.Metadata) string {
	if metadata == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(metadata.Host))
}

// recordKey is the directory record this connection should be resolved
// through: the device that claimed the requested name, when the entry was
// given a mapping for it, and the configured peer otherwise. A name the map
// does not know is not an error - a profile may address a device by its own
// name, and only names someone mapped are guaranteed to be there.
func (t *TailnetPeer) recordKey(host string) string {
	if host == "" || len(t.option.Domains) == 0 {
		return t.directoryNameKey()
	}
	if id, ok := t.option.Domains[host]; ok && id != "" {
		return id
	}
	return t.directoryNameKey()
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
	proxy, err := t.proxyForDial(ctx, requestedHost(metadata))
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
// resolved device is this node, otherwise the inner proxy bound to that
// device's current address, dialled at the port its own record carries.
func (t *TailnetPeer) proxyForDial(ctx context.Context, host string) (C.Proxy, error) {
	resolved, port, self, err := t.resolveFor(ctx, host)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if self {
		return t.direct, nil
	}
	if resolved == t.innerHost && t.inner != nil {
		return t.inner, nil
	}
	inner, err := t.buildInner(resolved, port)
	if err != nil {
		return nil, err
	}
	previous := t.inner
	t.inner = inner
	t.innerHost = resolved
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

// resolve answers where the configured peer is. It is the form used when a
// caller has no name to resolve by (the mesh entry resolves per connection).
func (t *TailnetPeer) resolve(ctx context.Context) (host string, self bool, err error) {
	host, _, self, err = t.resolveFor(ctx, "")
	return host, self, err
}

// resolveFor answers where the device for [host] is, falling back to the
// configured peer when the name is not one this entry was given. The answer is
// cached per record, because one mesh entry serves every device: a cache keyed
// by the entry alone would hand every connection the first device it looked up.
// The port is the device's own: a record carries the port its service listens
// on, and that is what a name is dialled at.
func (t *TailnetPeer) resolveFor(ctx context.Context, host string) (resolved string, port int, self bool, err error) {
	key := t.recordKey(host)
	t.mu.Lock()
	if cached, ok := t.cachedPeers[key]; ok && time.Since(cached.at) < tailnetPeerResolveTTL {
		resolved, port, self = cached.host, cached.port, cached.self
		t.mu.Unlock()
		return resolved, port, self, nil
	}
	t.mu.Unlock()

	if t.directory != nil {
		addr, addrPort, isSelf, err := t.directory.PeerAddress(ctx, key)
		if err != nil {
			return "", 0, false, fmt.Errorf("tailnet-peer: %w", err)
		}
		if isSelf {
			t.storeResolved(key, "", 0, true)
			return "", 0, true, nil
		}
		t.storeResolved(key, addr, addrPort, false)
		return addr, addrPort, false, nil
	}

	if t.option.DirectoryURL != "" {
		return "", 0, false, fmt.Errorf(
			"tailnet-peer: %s is configured for the peer directory but this device has not computed its id yet",
			t.option.Name,
		)
	}

	return "", 0, false, fmt.Errorf("tailnet-peer: %s has no peer directory to ask", t.option.Name)
}

func (t *TailnetPeer) storeResolved(key, host string, port int, self bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cachedPeers == nil {
		t.cachedPeers = make(map[string]resolvedPeer)
	}
	t.cachedPeers[key] = resolvedPeer{host: host, port: port, self: self, at: time.Now()}
}

// invalidate forgets every resolved record, so the next dial asks the
// directory again: a failed connection is the signal that an address moved.
func (t *TailnetPeer) invalidate() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cachedPeers = nil
}

func (t *TailnetPeer) innerProxy() C.Proxy {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.inner
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
