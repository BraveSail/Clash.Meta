package adapter

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/mesh"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// tailnetPeerResolveTTL keeps a burst of connections from re-asking the
// directory while still following a peer that changes networks. It is long
// enough that a steady peer is not re-resolved between the connections of one
// session, and short enough that a move is followed within a few seconds; the
// resolve is also what carries a failed dial's invalidation, so it does not
// have to be tiny for correctness.
const tailnetPeerResolveTTL = 30 * time.Second

// tailnetPeerRetiredLimit bounds how many superseded inner proxies are kept
// alive for the streams still running through them. Each one is a protocol
// client with its own connection pool, so the set is small on purpose: the
// limit only has to outlast the connections a peer's move interrupted.
const tailnetPeerRetiredLimit = 4

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
	// DirectoryUUID and DirectoryEncryption are the transport identity this
	// node reports: the VLESS user it listens as and the public half of the
	// key it listens with. They travel in the record so a peer can dial it
	// without a key the whole mesh shares.
	DirectoryUUID       string `proxy:"directory-uuid,omitempty"`
	DirectoryEncryption string `proxy:"directory-encryption,omitempty"`
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
	// registry is this node's mesh status registry, shared by every entry the
	// block expanded into (see PublishIfAbsent).
	registry *mesh.StatusRegistry

	mu        sync.Mutex
	inner     C.Proxy
	innerHost string
	// innerIdentity is the peer's VLESS user the current inner proxy was
	// built with. A peer that reinstalls keeps its address but changes its key,
	// so an identity change has to rebuild the proxy just like a move does.
	innerIdentity string
	// retired holds inner proxies this outbound has replaced, kept alive until
	// the streams still running through them finish (see proxyForDial).
	retired []C.Proxy
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
			UUID:       option.DirectoryUUID,
			Encryption: option.DirectoryEncryption,
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
	// The mesh publishes one status registry for the whole node, not one per
	// outbound: a `mesh:` block expands into several entries that all describe
	// the same node, and "how many connections does this node carry" is a
	// question about the node. The first entry to be built installs it; the
	// rest find it already running.
	peer.registry = mesh.PublishIfAbsent(option.directoryID(), option.Port, option.DirectoryURL)
	// The directory reports its routes and its accepted address to the same
	// surface, so "which way did the hub answer" and "where does the hub think
	// this node is" are readable beside the mesh's own state.
	if peer.directory != nil {
		peer.directory.SetRegistry(peer.registry)
	}
	inner, err := peer.buildInner("", 0, "")
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
func (t *TailnetPeer) buildInner(host string, port int, peerKey string) (C.Proxy, error) {
	return ParseProxy(t.innerMapping(host, port, peerKey))
}

// innerMapping is buildInner's configuration without the parse, so the
// identity a dial carries can be read back in a test.
func (t *TailnetPeer) innerMapping(host string, port int, peerKey string) map[string]any {
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
	// The peer's own transport identity, when the directory has told us: a
	// dial that carried this node's key would be answered by nobody, since in
	// a mesh with no token every device listens under its own.
	if t.directory != nil && peerKey != "" {
		if uuid, encryption, known := t.directory.PeerIdentity(peerKey); known {
			mapping["uuid"] = uuid
			if encryption != "" {
				mapping["encryption"] = encryption
			}
		}
	}
	if _, ok := mapping["name"]; !ok {
		mapping["name"] = t.option.Name + " (inner)"
	}
	return mapping
}

func (t *TailnetPeer) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if miss, ok := t.meshNameMiss(requestedHost(metadata)); ok {
		log.Warnln("[Mesh] %s", miss)
		return nil, errors.New("tailnet-peer: " + miss)
	}
	key := t.recordKey(requestedHost(metadata))
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
		t.noteDialFailure(key, err)
		return nil, err
	}
	// The connection is counted while it is open, and the count is what makes
	// "how many streams does this peer carry" a fact rather than a guess. The
	// release is wrapped so the count follows the connection's own lifetime,
	// not the caller's bookkeeping.
	return t.countConnection(key, conn), nil
}

// countConnection wraps [conn] so the node's registry sees the connection while
// it is open. The wrapper is what a reader counts; nothing here closes anything,
// because a connection's lifetime belongs to whoever opened it.
func (t *TailnetPeer) countConnection(key string, conn C.Conn) C.Conn {
	if t.registry == nil {
		return conn
	}
	release := t.registry.NoteDial(key)
	return &countedConn{Conn: conn, release: release}
}

func (t *TailnetPeer) noteDialFailure(key string, err error) {
	if t.registry != nil {
		t.registry.NoteDialFailure(key)
	}
	if err != nil {
		log.Debugln("[Mesh] %s could not be reached: %v", key, err)
	}
}

// countedConn releases the registry's connection count when the connection
// closes. Close is the only place a connection ends, and a double Close must not
// report two connections ending: the registry's release is idempotent, so this
// stays a plain delegation.
type countedConn struct {
	C.Conn
	release func()
}

func (c *countedConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
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

// meshNameMiss answers whether a name was meant for this mesh but is not in it.
//
// Falling back to the node's own record for such a name made a missing device
// look like a refused port: the connection was dialled somewhere else and the
// only thing left to see was the proxy's generic failure. A name that carries
// this mesh's suffix and is not in its map is a configuration fact, and saying
// so is the difference between a five-minute fix and an afternoon.
func (t *TailnetPeer) meshNameMiss(host string) (string, bool) {
	if host == "" || len(t.option.Domains) == 0 {
		return "", false
	}
	if _, ok := t.option.Domains[host]; ok {
		return "", false
	}
	for name := range t.option.Domains {
		suffix := name[strings.LastIndex(name, "."):]
		if suffix != "" && strings.HasSuffix(host, suffix) {
			known := make([]string, 0, len(t.option.Domains))
			for candidate := range t.option.Domains {
				known = append(known, candidate)
			}
			sort.Strings(known)
			return fmt.Sprintf(
				"no device answers to %q in this mesh (known names: %s)",
				host,
				strings.Join(known, ", "),
			), true
		}
	}
	return "", false
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
	// IPv4 first: a box's web server commonly binds only its LAN address, and
	// the loopback that answers is then 127.0.0.1 - reaching it through the
	// NAT rule the box already carries. Trying ::1 first made every connection
	// to such a service wait out a refused IPv6 connect, which on this box was
	// an extra second per request; the connection itself took milliseconds.
	for _, loopback := range []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")} {
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
//
// A peer that moves gets a new inner proxy, and the one it replaced is NOT
// closed: an inner proxy holds the pooled connections of every stream already
// running through it, so closing it on an address change would cut a live
// session (a remote-desktop stream is the case that made this visible). The
// superseded proxy is kept in a small set and released once nothing is using
// it, which is what makes an address change cost the new connections only.
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
	key := t.recordKey(host)
	identity := ""
	if t.directory != nil {
		if uuid, _, known := t.directory.PeerIdentity(key); known {
			identity = uuid
		}
	}
	if resolved == t.innerHost && identity == t.innerIdentity && t.inner != nil {
		return t.inner, nil
	}
	inner, err := t.buildInner(resolved, port, key)
	if err != nil {
		return nil, err
	}
	previous := t.inner
	previousHost := t.innerHost
	t.inner = inner
	t.innerHost = resolved
	t.innerIdentity = identity
	if previous != nil && previousHost != "" {
		// Kept, not closed: a stream that is already running through the old
		// proxy has to finish. The next connection builds a new proxy, so the
		// old one is reachable only by connections it already carries.
		t.retired = append(t.retired, previous)
		if len(t.retired) > tailnetPeerRetiredLimit {
			oldest := t.retired[0]
			t.retired = t.retired[1:]
			go func() { _ = oldest.Close() }()
		}
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

// resolveForEcho answers where an echo aimed at this outbound has to travel.
// It asks by the name the flow carried, the same way a dial does, because an
// entry that serves every device (the mesh entry) names no peer of its own:
// resolving by the entry alone would ask the directory with an empty id and be
// refused, which is what left a ping unanswered while a connection worked.
func (t *TailnetPeer) resolveForEcho(ctx context.Context, metadata *C.Metadata) (host string, self bool, err error) {
	host, _, self, err = t.resolveFor(ctx, requestedHost(metadata))
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
			t.noteResolveError(key, err)
			return "", 0, false, fmt.Errorf("tailnet-peer: %w", err)
		}
		if isSelf {
			t.storeResolved(key, "", 0, true)
			t.noteResolved(key, "", 0, true)
			return "", 0, true, nil
		}
		t.storeResolved(key, addr, addrPort, false)
		t.noteResolved(key, addr, addrPort, false)
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

// noteResolved and noteResolveError report one resolution to the node's
// registry. They are separate from storeResolved because the cache and the
// status surface answer different questions: the cache is what a dial reads, the
// status is what an operator reads, and a resolution the cache drops (a failed
// one) is still worth showing.
func (t *TailnetPeer) noteResolved(key, addr string, port int, self bool) {
	if t.registry == nil {
		return
	}
	t.registry.NotePeerAnswer(key, mesh.PeerAnswer{
		Addr: addr, Port: port, Self: self, Source: "directory", At: time.Now(),
	})
}

func (t *TailnetPeer) noteResolveError(key string, err error) {
	if t.registry == nil {
		return
	}
	t.registry.NotePeerError(key, err)
}

// invalidate forgets every resolved record, so the next dial asks the
// directory again: a failed connection is the signal that an address moved.
// The directory's own answer for those records is dropped with it - otherwise
// the next dial would be handed the same address that just failed and wait for
// a background refresh to correct it.
func (t *TailnetPeer) invalidate() {
	t.mu.Lock()
	keys := make([]string, 0, len(t.cachedPeers))
	for key := range t.cachedPeers {
		keys = append(keys, key)
	}
	t.cachedPeers = nil
	directory := t.directory
	t.mu.Unlock()
	if directory != nil {
		for _, key := range keys {
			directory.ForgetPeer(key)
		}
	}
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
	if t.registry != nil {
		// Only the registry still published is withdrawn, so a reload that has
		// already installed the replacement does not lose it (see Withdraw).
		mesh.Withdraw(t.registry)
		t.registry = nil
	}
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
	for _, proxy := range t.retired {
		_ = proxy.Close()
	}
	t.retired = nil
	if t.direct != nil {
		_ = t.direct.Close()
	}
	return nil
}
