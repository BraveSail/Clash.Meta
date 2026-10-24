package outbound

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/iface"
	meshident "github.com/metacubex/mihomo/component/mesh"
	"github.com/metacubex/mihomo/component/mesh"
	"github.com/metacubex/mihomo/component/peerdirectory"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// localAddresses is the interface scan this package reasons about. It is a
// variable so a test can describe the interfaces it wants the decision to see
// instead of the ones the machine happens to have.
var localAddresses = localAddressesByInterface

const (
	// The port a peer-directory reports when the profile names none: the same
	// value the mesh block falls back to, because an entry that reports a port
	// nobody listens on is worse than one that reports the default.
	peerDirectoryDefaultPort    = 23333
	peerDirectoryDefaultRefresh = 30 * time.Second
	peerDirectoryDefaultTimeout = 10 * time.Second
	// A directory request is one HTTPS round trip, and on a network whose path
	// to the directory is slow (a direct connection to a CDN edge that is far
	// away or deprioritised takes seconds) it costs more than the dial that
	// asked for it. A dial cannot wait seconds per connection, so the answer is
	// held long enough that a burst and a stream of new connections share one
	// lookup; the heartbeat keeps the address itself fresh, so a cached entry
	// cannot outlive a peer's move by more than this window.
	//
	// The window no longer gates a dial: an answer past it is still handed to
	// the caller and refreshed in the background, so a directory that is slow
	// or down costs a connection nothing.
	peerDirectoryLookupTTL = 60 * time.Second
	// A background refresh is allowed more time than a dial would be: nothing
	// waits on it, and a directory that is merely slow should still answer.
	peerDirectoryRefreshTimeout = 20 * time.Second
	// A directory that shows which nodes are up needs to hear from a node even
	// when its address did not move, so a report goes out at least this often.
	peerDirectoryDefaultHeartbeat = 2 * time.Minute
	peerDirectoryMinimumHeartbeat = 30 * time.Second
)

var peerDirectoryIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,63}$`)

// directoryTokenParam is the query parameter a directory link carries its
// token in, mirroring what the hub accepts.
const directoryTokenParam = "token"

// splitDirectoryURL lifts the credential out of a directory address that
// carries one as a parameter. The caller appends its own paths by string
// concatenation, so the address it is given has to be free of a query; the
// token travels in the request header either way. An address with no such
// parameter is returned untouched.
func splitDirectoryURL(raw string) (token string, stripped string) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || !strings.Contains(trimmed, directoryTokenParam+"=") {
		return "", trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", trimmed
	}
	query := parsed.Query()
	carried := strings.TrimSpace(query.Get(directoryTokenParam))
	if carried == "" {
		return "", trimmed
	}
	query.Del(directoryTokenParam)
	parsed.RawQuery = query.Encode()
	return carried, parsed.String()
}

// PeerDirectoryOption configures the directory outbound: it reports this node
// under [ID] and answers where other ids are.
type PeerDirectoryOption struct {
	BasicOption
	Name    string `proxy:"name"`
	URL     string `proxy:"url"`
	Token   string `proxy:"token,omitempty"`
	ID      string `proxy:"id"`
	Port    int    `proxy:"port,omitempty"`
	Refresh int    `proxy:"refresh,omitempty"`
	Timeout int    `proxy:"timeout,omitempty"`
	// Heartbeat is how often this node reports even when nothing changed, in
	// seconds. Keep it well inside the directory's online window.
	Heartbeat int `proxy:"heartbeat,omitempty"`
	// ViaProxy is an HTTP proxy URL every request to the directory goes
	// through. A device whose network resets a direct connection to the
	// directory can still report and look up through a proxy it can reach.
	ViaProxy string `proxy:"via-proxy,omitempty"`
	// Hostname is the name this node reports under, for a platform whose own
	// host name says nothing useful (a phone's UTS name is "localhost" and
	// an app cannot change it). The app reads the name the machine carries
	// and writes it here; empty keeps the system host name.
	Hostname string `proxy:"hostname,omitempty"`
	// OS is the system this node runs, e.g. "Android 14", shown by the
	// directory beside the name. Empty sends nothing.
	OS string `proxy:"os,omitempty"`
	// UUID is the VLESS user this device listens as, and Encryption the public
	// half of the key pair it listens with. Both are public by construction;
	// together they let a peer dial this device with a key of its own instead
	// of one the whole mesh shares. Empty sends nothing, which is what an
	// older profile does.
	UUID       string `proxy:"uuid,omitempty"`
	Encryption string `proxy:"encryption,omitempty"`
}

// PeerDirectory keeps one node's address current in a directory service and
// reads its peers' addresses back. The address is the one the directory
// observed for this node, so nothing here has to discover the public address.
type PeerDirectory struct {
	*Base

	option PeerDirectoryOption
	// ways are the routes a request to the directory may take, in the order
	// they are tried: the proxy first when one is configured, the direct route
	// last. A node that can only reach the directory one way stays in it, and a
	// node whose proxy is down still reports straight out.
	ways []directoryWay
	// wayIndex is the route the last success came over, so the walk starts
	// where the directory was last reachable. It only outranks the configured
	// order while a fallback is in force (see wayFallbackGrace).
	wayIndex int
	// fallbackUntil is when the configured first route is worth trying again
	// after a fallback answered. Zero means the first route is preferred now.
	fallbackUntil time.Time
	// registry is this node's mesh status surface, if one is running. It is
	// optional: a PeerDirectory can be built by a caller that has no mesh (a
	// test, or a bare lookup client), and the status surface must not be a
	// requirement for the directory to work.
	registry *mesh.StatusRegistry
	ctx      context.Context
	cancel   context.CancelFunc

	mu         sync.Mutex
	etag       string
	addr       string
	lastInject time.Time
	// underlayAddr is the address of the network carrying traffic; only
	// Android maintains it (see peer_directory_underlay_android.go).
	underlayAddr      netip.Addr
	underlayInterface string
	sentAddr          string
	sentPort          int
	sentAt            time.Time
	heartbeat         time.Duration
	peers             map[string]cachedPeer
	// signingSeed is this device's Ed25519 seed, used when no token is
	// configured: the id names the device, this proves it.
	signingSeed []byte
	// registered records that the key has been handed to the directory once in
	// this process, so a pending device does not re-register on every beat.
	registered bool
	warnedOnce        bool
	// refreshMu guards refreshing, the set of ids a background refresh is
	// already in flight for: a burst of connections that all find the same
	// stale answer still costs one lookup.
	refreshMu  sync.Mutex
	refreshing map[string]bool
	// lastSeen remembers the address last handed out per id, so a move is worth
	// one log line rather than one per connection.
	lastSeen map[string]string
}

type cachedPeer struct {
	addr string
	port int
	self bool
	at   time.Time
	// uuid and encryption are what this peer listens as, when the directory
	// said. They are cached with the address so a dial can use the peer's own
	// key instead of one the whole mesh shares.
	uuid       string
	encryption string
}

func NewPeerDirectory(option PeerDirectoryOption) (*PeerDirectory, error) {
	// The address a node is given may carry the credential as a parameter, so
	// that one link configures the hub and the token together. The paths this
	// type appends to it (`/report`, `/lookup`) are built by string
	// concatenation, which a query would corrupt, so the token is lifted out
	// here and carried as a header instead. A plain address with a token field
	// keeps working unchanged.
	if token, stripped := splitDirectoryURL(option.URL); token != "" {
		if strings.TrimSpace(option.Token) == "" {
			option.Token = token
		}
		option.URL = stripped
	}
	parsed, err := url.Parse(strings.TrimSpace(option.URL))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("peer-directory: invalid url %q", option.URL)
	}
	if !peerDirectoryIDPattern.MatchString(option.ID) {
		return nil, fmt.Errorf("peer-directory: invalid id %q", option.ID)
	}
	if option.Port == 0 {
		option.Port = peerDirectoryDefaultPort
	}
	if option.Port < 1 || option.Port > 65535 {
		return nil, fmt.Errorf("peer-directory: invalid port %d", option.Port)
	}
	timeout := peerDirectoryDefaultTimeout
	if option.Timeout > 0 {
		timeout = time.Duration(option.Timeout) * time.Second
	}
	// Every request to the directory walks these routes in order: the proxy
	// first when the profile names one, then the direct route. Both stay in the
	// list, so a proxy that is down does not take the directory away and a
	// direct path the network resets does not either - the one that works is
	// remembered and tried first next time.
	ways := make([]directoryWay, 0, 2)
	if strings.TrimSpace(option.ViaProxy) != "" {
		proxyTransport, err := directoryProxyTransport(option.ViaProxy)
		if err != nil {
			return nil, err
		}
		ways = append(ways, directoryWay{
			name:   "proxy",
			client: &http.Client{Timeout: timeout, Transport: proxyTransport},
		})
	}
	ways = append(ways, directoryWay{
		name:   "direct",
		client: &http.Client{Timeout: timeout, Transport: directoryTransport()},
	})
	ctx, cancel := context.WithCancel(context.Background())
	heartbeat := peerDirectoryDefaultHeartbeat
	if option.Heartbeat > 0 {
		heartbeat = time.Duration(option.Heartbeat) * time.Second
	}
	if heartbeat < peerDirectoryMinimumHeartbeat {
		heartbeat = peerDirectoryMinimumHeartbeat
	}
	// The directory is the one thing this node cannot ask a peer about, so its
	// requests use mihomo's own dialer: that resolves names for real - the
	// system resolver hands out this node's fake-ip placeholders - and binds the
	// socket to the interface carrying traffic, so a request made to find out
	// where a peer is cannot end up inside this node's own tunnel.
	directory := &PeerDirectory{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         parsed.String(),
			Type:         C.PeerDirectory,
			ProviderName: option.ProviderName,
		}),
		option:    option,
		ways:      ways,
		ctx:       ctx,
		cancel:    cancel,
		heartbeat: heartbeat,
		peers:     map[string]cachedPeer{},
	}
	peerdirectory.Register(option.Name, directory)
	log.Debugln("[PeerDirectory](%s) reporting as %s every %s when nothing changes", option.Name, option.ID, heartbeat)
	// Addresses learned before a restart are read back first: a dial that
	// arrives before the first lookup completes then answers from disk instead
	// of waiting on the directory.
	directory.loadPersistedPeers()
	go directory.startUnderlayWatch()
	go directory.run()
	// A device with no token proves its id with a key instead. The key lives
	// in the core's home, not in the profile: one profile runs everywhere.
	if option.Token == "" {
		if keys, err := meshident.LoadOrCreateKeys(""); err == nil {
			directory.signingSeed = keys.Signing
			if directory.option.UUID == "" {
				directory.option.UUID = keys.UUID
			}
			if directory.option.Encryption == "" {
				directory.option.Encryption = keys.Encryption
			}
		} else {
			log.Errorln("[PeerDirectory](%s) cannot use the device key: %v", option.Name, err)
		}
	}
	return directory, nil
}

// directoryTransport is how a request to the peer directory leaves the machine:
// mihomo's own dialer, bound to the interface carrying traffic, rather than an
// ordinary client that would resolve names through the tunnel and connect
// inside it. Everything here talks to the directory through this.
func directoryTransport() *http.Transport {
	return &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
	}
}

// directoryProxyTransport sends the request through an HTTP proxy instead of
// straight out of this machine. A network that resets the direct connection to
// the directory leaves the node unable to report where it is, which is exactly
// when a proxy the node can reach is the only way to stay in the directory.
// The proxy is dialled with mihomo's own dialer like every other directory
// request, so reaching the proxy cannot depend on the tunnel either.
func directoryProxyTransport(rawProxyURL string) (*http.Transport, error) {
	proxyURL, err := url.Parse(strings.TrimSpace(rawProxyURL))
	if err != nil {
		return nil, fmt.Errorf("peer-directory: invalid proxy url %q: %w", rawProxyURL, err)
	}
	if proxyURL.Scheme != "http" && proxyURL.Scheme != "https" {
		return nil, fmt.Errorf("peer-directory: proxy url %q must be http or https", rawProxyURL)
	}
	if proxyURL.Host == "" {
		return nil, fmt.Errorf("peer-directory: proxy url %q names no host", rawProxyURL)
	}
	transport := directoryTransport()
	transport.Proxy = http.ProxyURL(proxyURL)
	return transport, nil
}

// directoryWay is one route a request to the directory may take: the client it
// goes through and the name a log line can call it.
type directoryWay struct {
	name   string
	client *http.Client
}

// do sends [request] over the routes in order, starting with the one the last
// success came over. A route that answers - including an error status, which is
// the directory speaking and not the route failing - ends the walk; only an
// unreachable route moves on to the next. A request body has to be re-readable
// for the second attempt, which is why the caller passes a builder rather than
// a request.
func (d *PeerDirectory) do(ctx context.Context, build func() (*http.Request, error)) (*http.Response, error) {
	ways := d.orderedWays()
	var lastErr error
	for i, way := range ways {
		request, err := build()
		if err != nil {
			return nil, err
		}
		response, err := way.client.Do(request)
		if err == nil {
			// The route answered. A response with an error status is still the
			// route working: the directory replied, and asking the other way
			// would get the same reply. That is why only a transport failure
			// moves the walk on.
			d.noteRoute(way.name, nil)
			if i != 0 {
				d.rememberWay(way.name)
				log.Debugln("[PeerDirectory](%s) reached the directory over %s", d.Name(), way.name)
			}
			return response, nil
		}
		d.noteRoute(way.name, err)
		lastErr = err
		if len(ways) > 1 {
			log.Debugln("[PeerDirectory](%s) %s route to the directory failed: %v", d.Name(), way.name, err)
		}
	}
	return nil, lastErr
}

// SetRegistry gives the directory a status surface to report its routes to. It
// is a setter rather than a constructor argument because the registry is built
// by the mesh, and the directory can be shared with a caller that has no mesh.
func (d *PeerDirectory) SetRegistry(registry *mesh.StatusRegistry) {
	d.registry = registry
}

// noteRoute reports one route's outcome, and does nothing when no status surface
// is attached: a directory without a mesh is a normal configuration.
func (d *PeerDirectory) noteRoute(route string, err error) {
	if d.registry == nil {
		return
	}
	d.registry.NoteRoute(route, err)
}

// noteReport reports that the directory accepted this node's address. A node
// whose address the hub has never acknowledged is a node nobody can reach, so
// this is worth surfacing separately from the route that carried it.
func (d *PeerDirectory) noteReport(addr string) {
	if d.registry == nil {
		return
	}
	d.registry.NoteReport(addr)
}

// wayFallbackGrace is how long a fallback route keeps its place at the front of
// the walk before the configured first route is tried again.
//
// Without it the walk degrades silently and permanently: one success on the
// direct route promotes it above the proxy, and every later request starts
// there - so a proxy that came back is never used again, which is the exact
// failure this design was meant to avoid. With it, the proxy is retried on this
// interval and takes the lead back as soon as it answers.
const wayFallbackGrace = 5 * time.Minute

// orderedWays is the routes in the order to try them: the configured order,
// except that a fallback that answered recently is tried first so a request
// does not pay a failing attempt every time.
//
// The promoted route is index 0 unless a fallback is in force, so a healthy
// proxy keeps its configured place at the front.
func (d *PeerDirectory) orderedWays() []directoryWay {
	d.mu.Lock()
	ways := d.ways
	preferred := d.wayIndex
	fallbackUntil := d.fallbackUntil
	d.mu.Unlock()
	// The configured order is the answer whenever the first route is the one
	// that worked, or when the fallback's grace has run out.
	if len(ways) < 2 || preferred <= 0 || preferred >= len(ways) || time.Now().After(fallbackUntil) {
		return ways
	}
	ordered := make([]directoryWay, 0, len(ways))
	ordered = append(ordered, ways[preferred])
	ordered = append(ordered, ways[:preferred]...)
	ordered = append(ordered, ways[preferred+1:]...)
	return ordered
}

// rememberWay records the route that answered.
//
// A fallback (anything but the configured first route) is only promoted for
// wayFallbackGrace; the first route keeps its place outright, so a proxy that
// recovers is used again on the next request rather than on some later one.
func (d *PeerDirectory) rememberWay(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, way := range d.ways {
		if way.name != name {
			continue
		}
		d.wayIndex = i
		if i == 0 {
			d.fallbackUntil = time.Time{}
			return
		}
		d.fallbackUntil = time.Now().Add(wayFallbackGrace)
		return
	}
}

func (d *PeerDirectory) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"type": d.Type().String(),
		"id":   d.option.ID,
		"url":  d.option.URL,
	})
}

// PeerAddress answers where [id] is: this node answers for itself without a
// request, everyone else comes from the directory with a short cache so a burst
// of connections shares one lookup. A directory that resolves this name to a
// record carrying this node's own id has answered with this node - that is how
// a profile addresses a device by the alias the dashboard gave it and is still
// handed back to itself.
//
// A dial must never wait on the directory. An answer inside peerDirectoryLookupTTL
// is returned as it stands; an answer that has aged out is returned as it stands
// too, and the refresh runs in the background, so a slow or unreachable directory
// costs a dial nothing. Only a peer never seen before - no memory, no persisted
// entry - waits for a lookup, and that wait is bounded by the client's timeout.
func (d *PeerDirectory) PeerAddress(ctx context.Context, id string) (string, int, bool, error) {
	if id == d.option.ID {
		return "", d.option.Port, true, nil
	}
	d.mu.Lock()
	cached, ok := d.peers[id]
	d.mu.Unlock()
	// Only an answer that names another device can be handed out without
	// asking: "this name is me" is a judgement about the directory's current
	// data (an alias added or removed changes it) and a stale one would hand
	// this node its own address, which a dial must never do. A cached self is
	// therefore re-confirmed rather than reused.
	//
	// An answer past stalePeerTTL is not handed out either: only a persisted
	// entry can reach that age (a running process refreshes behind every dial
	// past peerDirectoryLookupTTL, and a report keeps the directory's own copy
	// fresh), and a device that has been off the network for a day has had time
	// to move. Asking in front of the dial costs a wait; dialling where the
	// peer used to be costs a failed dial plus the retry that follows.
	if ok && cached.addr != "" && !cached.self && usableStalePeer(cached.at) {
		// An answer in hand is returned now; a stale one is refreshed behind
		// the dial rather than in front of it.
		if time.Since(cached.at) >= peerDirectoryLookupTTL {
			d.refreshPeerAsync(id)
		}
		return cached.addr, cached.port, false, nil
	}
	answer, err := d.lookup(ctx, id)
	addr, port, nodeID := answer.addr, answer.port, answer.id
	if err != nil {
		if ok && !cached.self && usableStalePeer(cached.at) {
			// The directory is unreachable or the record expired: an address we
			// saw a moment ago is still the best guess, and the caller's dial
			// either works or fails into its own retry. A cached "this is me"
			// is not a guess worth making: answering it would point this node
			// at itself.
			log.Debugln("[PeerDirectory](%s) lookup %s failed (%v); keeping %s from %s ago", d.Name(), id, err, cached.addr, time.Since(cached.at).Round(time.Second))
			return cached.addr, cached.port, false, nil
		}
		return "", 0, false, err
	}
	self := nodeID != "" && nodeID == d.option.ID
	d.storePeer(id, cachedPeer{addr: addr, port: port, self: self, at: time.Now(),
		uuid: answer.uuid, encryption: answer.encryption})
	if !self {
		// A peer whose address is known survives a restart: the next dial after
		// one does not have to reach the directory first.
		d.storePersistedPeer(id, addr, port)
	} else {
		// The directory resolved this name to this node: the service the name
		// reaches is the one this node serves. Nothing to persist for a peer
		// that is this node.
		d.forgetPersistedPeer(id)
		return "", d.option.Port, true, nil
	}
	return addr, port, false, nil
}

// storePeer records one answer in memory under the lock the rest of the type
// uses, so a reader never sees a half-written entry.
// PeerIdentity answers what the peer last told the directory it listens as.
// The third value is false when nothing is known - a peer that has not been
// resolved yet, or one running an older build that reports no identity - and
// a caller must then fall back to the key it already has rather than guess.
func (d *PeerDirectory) PeerIdentity(id string) (uuid, encryption string, known bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	cached, ok := d.peers[id]
	if !ok || cached.uuid == "" {
		return "", "", false
	}
	return cached.uuid, cached.encryption, true
}

func (d *PeerDirectory) storePeer(id string, entry cachedPeer) {
	d.mu.Lock()
	if d.peers == nil {
		d.peers = map[string]cachedPeer{}
	}
	d.peers[id] = entry
	d.mu.Unlock()
}

// ForgetPeer drops what this directory holds for [id], so the next question is
// answered by the directory rather than by the answer just proven wrong. A dial
// that failed is the signal: it calls this through the outbound that owns the
// record, and the next dial then asks instead of repeating the failure.
func (d *PeerDirectory) ForgetPeer(id string) {
	d.mu.Lock()
	delete(d.peers, id)
	d.mu.Unlock()
	d.forgetPersistedPeer(id)
}

// refreshPeerAsync asks the directory again for [id] without making a dial wait
// for it. The refresh is skipped when one is already in flight for that id, so a
// burst of connections that all find the same stale answer still costs one
// lookup.
func (d *PeerDirectory) refreshPeerAsync(id string) {
	d.refreshMu.Lock()
	if d.refreshing == nil {
		d.refreshing = map[string]bool{}
	}
	if d.refreshing[id] {
		d.refreshMu.Unlock()
		return
	}
	d.refreshing[id] = true
	d.refreshMu.Unlock()

	go func() {
		defer func() {
			d.refreshMu.Lock()
			delete(d.refreshing, id)
			d.refreshMu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(d.ctx, peerDirectoryRefreshTimeout)
		defer cancel()
		answer, err := d.lookup(ctx, id)
		addr, port, nodeID := answer.addr, answer.port, answer.id
		if err != nil {
			log.Debugln("[PeerDirectory](%s) background refresh of %s failed (%v); keeping the answer in hand", d.Name(), id, err)
			return
		}
		self := nodeID != "" && nodeID == d.option.ID
		if self {
			d.forgetPersistedPeer(id)
			return
		}
		d.storePeer(id, cachedPeer{addr: addr, port: port, self: false, at: time.Now(),
			uuid: answer.uuid, encryption: answer.encryption})
		d.storePersistedPeer(id, addr, port)
		if d.moved(id, addr) {
			log.Infoln("[PeerDirectory](%s) %s moved to %s:%d", d.Name(), id, addr, port)
		}
	}()
}

// moved reports whether [id]'s address differs from the one last published to
// this node's own dialers, so a move is worth one log line.
func (d *PeerDirectory) moved(id, addr string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.lastSeen == nil {
		d.lastSeen = map[string]string{}
	}
	previous, ok := d.lastSeen[id]
	d.lastSeen[id] = addr
	return ok && previous != addr
}

// directoryAnswer is what the directory says about one peer: where it is, and
// when the peer reported them, the transport identity it listens as.
type directoryAnswer struct {
	addr       string
	port       int
	id         string
	uuid       string
	encryption string
}

func (d *PeerDirectory) lookup(ctx context.Context, id string) (directoryAnswer, error) {
	target, err := url.Parse(d.option.URL)
	if err != nil {
		return directoryAnswer{}, err
	}
	target.Path = strings.TrimSuffix(target.Path, "/") + "/lookup"
	query := target.Query()
	query.Set("id", id)
	target.RawQuery = query.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return directoryAnswer{}, err
	}
	d.authorize(request, nil)
	response, err := d.do(ctx, func() (*http.Request, error) {
		attempt := request.Clone(ctx)
		return attempt, nil
	})
	if err != nil {
		return directoryAnswer{}, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	if err != nil {
		return directoryAnswer{}, err
	}
	if response.StatusCode == http.StatusNotFound {
		return directoryAnswer{}, fmt.Errorf("peer %q is unknown or expired", id)
	}
	if response.StatusCode != http.StatusOK {
		return directoryAnswer{}, fmt.Errorf("directory answered %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload struct {
		Nodes map[string]struct {
			ID         string `json:"id"`
			Addr       string `json:"addr"`
			Port       int    `json:"port"`
			UUID       string `json:"uuid"`
			Encryption string `json:"encryption"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return directoryAnswer{}, err
	}
	node, ok := payload.Nodes[id]
	if !ok || node.Addr == "" {
		return directoryAnswer{}, fmt.Errorf("peer %q is unknown or expired", id)
	}
	return directoryAnswer{
		addr:       node.Addr,
		port:       node.Port,
		id:         node.ID,
		uuid:       node.UUID,
		encryption: node.Encryption,
	}, nil
}

// run reports this node now and then on a jittered cadence: the directory
// keeps the record until the node changes it, so the cadence only re-reads the
// local interfaces - a report leaves the machine only when the address it would
// publish is different from the one it last published.
func (d *PeerDirectory) run() {
	d.maybeReport(true)
	interval := peerDirectoryDefaultRefresh
	if d.option.Refresh > 0 {
		interval = time.Duration(d.option.Refresh) * time.Second
	}
	for {
		jitter := time.Duration(rand.Int63n(int64(interval / 2)))
		timer := time.NewTimer(interval - interval/4 + jitter)
		select {
		case <-d.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			d.maybeReport(false)
		}
	}
}

// maybeReport sends the node's address when it is worth sending: the first
// time, after the address this node would publish changes, and once every
// heartbeat so the directory can tell a quiet node from an absent one.
func (d *PeerDirectory) maybeReport(force bool) {
	candidates := localAddresses()
	// Which interface carries traffic decides what to publish: an interface
	// scan alone reports every physical NIC, including the SIM that is idle.
	addr, ifaceName, how := d.chooseReportAddress(candidates)
	d.mu.Lock()
	previous := d.sentAddr
	unchanged := !force &&
		addr == d.sentAddr &&
		d.option.Port == d.sentPort &&
		!d.sentAt.IsZero() &&
		time.Since(d.sentAt) < d.heartbeat
	d.mu.Unlock()
	if unchanged {
		return
	}
	// A device that moved to a network without a global IPv6 has nothing to
	// publish; saying so is the difference between "the directory is stale" and
	// "this network cannot be dialled", which is otherwise invisible.
	switch {
	case addr == "" && previous != "":
		log.Warnln("[PeerDirectory](%s) %s has no global IPv6 on this network; the directory keeps the address it already has",
			d.Name(), d.option.ID)
	case addr != "" && previous == "":
		log.Infoln("[PeerDirectory](%s) %s publishes %s again", d.Name(), d.option.ID, addr)
	}
	// What the core can see, what it chose and how: this is the line that
	// answers "did it notice the network changed?" without guesswork, and it is
	// where the fork's kept/dropped decision trace lives now.
	log.Debugln("[PeerDirectory](%s) address candidates %s -> %s (via=%s, iface=%s)",
		d.Name(), describeCandidates(candidates), orNone(addr), how, orNone(ifaceName))
	d.report(d.ctx, addr)
}

// underlay is the address and interface of the network currently carrying
// traffic, as far as the platform can tell. Android fills it from a probe (see
// peer_directory_underlay_android.go); elsewhere it stays empty and the
// interface scan answers.
func (d *PeerDirectory) underlay() (netip.Addr, string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.underlayAddr, d.underlayInterface
}

func (d *PeerDirectory) storeUnderlay(addr netip.Addr, name string) {
	d.mu.Lock()
	changed := name != d.underlayInterface || addr != d.underlayAddr
	d.underlayAddr = addr
	d.underlayInterface = name
	d.mu.Unlock()
	if changed && name != "" {
		log.Infoln("[PeerDirectory](%s) underlay interface: %s (%s); publishing from it", d.Name(), name, addr)
	}
}

// describeCandidates lists the IPv6 addresses the core can see, per interface,
// so a log says which networks it is looking at rather than only what it chose.
func describeCandidates(candidates map[string][]netip.Addr) string {
	names := make([]string, 0, len(candidates))
	for name := range candidates {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		addrs := make([]string, 0, len(candidates[name]))
		for _, addr := range candidates[name] {
			if addr.Is6() {
				addrs = append(addrs, addr.String())
			}
		}
		if len(addrs) > 0 {
			parts = append(parts, name+"=["+strings.Join(addrs, " ")+"]")
		}
	}
	if len(parts) == 0 {
		return "(no IPv6 on any interface)"
	}
	return strings.Join(parts, " ")
}

func orNone(addr string) string {
	if addr == "" {
		return "(nothing to publish)"
	}
	return addr
}

// ensureRegistered hands this device's public key to the directory, once per
// process, when it has no token to prove itself with. Registration grants
// nothing: the device stays pending until an operator approves it, and learns
// it was let in by its next report succeeding.
func (d *PeerDirectory) ensureRegistered(ctx context.Context) {
	if d.option.Token != "" || len(d.signingSeed) == 0 {
		return
	}
	d.mu.Lock()
	done := d.registered
	d.mu.Unlock()
	if done {
		return
	}
	payload := map[string]any{
		"id":        d.option.ID,
		"publicKey": meshident.PublicKeyBase64(d.signingSeed),
	}
	if hostname := strings.TrimSpace(d.option.Hostname); hostname != "" {
		payload["name"] = hostname
	}
	if osName := strings.TrimSpace(d.option.OS); osName != "" {
		payload["os"] = osName
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	response, err := d.do(ctx, func() (*http.Request, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(d.option.URL, "/")+"/register", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		request.Header.Set("content-type", "application/json")
		return request, nil
	})
	if err != nil {
		log.Debugln("[PeerDirectory](%s) could not register: %v", d.Name(), err)
		return
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode/100 == 2 {
		d.mu.Lock()
		d.registered = true
		d.mu.Unlock()
		log.Infoln("[PeerDirectory](%s) registered %s with the directory; waiting to be approved", d.Name(), d.option.ID)
	}
}

func (d *PeerDirectory) report(ctx context.Context, addr string) {
	d.ensureRegistered(ctx)
	payload := map[string]any{
		"id":   d.option.ID,
		"port": d.option.Port,
		// The platform travels with the report so the directory can show what
		// kind of machine each name is: the profile is shared, so nothing in it
		// says whether a name is this phone or that desktop.
		"platform": runtime.GOOS,
	}
	// The host name travels too: an id is a digest, and a digest is not what a
	// reader recognises a machine by until they name it themselves. The name
	// the app read outranks the system one, which on a phone is the useless
	// "localhost" an app cannot change.
	hostname := strings.TrimSpace(d.option.Hostname)
	if hostname == "" {
		if system, err := os.Hostname(); err == nil {
			hostname = system
		}
	}
	if hostname != "" {
		payload["hostname"] = hostname
	}
	if osName := strings.TrimSpace(d.option.OS); osName != "" {
		payload["os"] = osName
	}
	if addr != "" {
		payload["addr"] = addr
	}
	if uuid := strings.TrimSpace(d.option.UUID); uuid != "" {
		payload["uuid"] = uuid
	}
	if encryption := strings.TrimSpace(d.option.Encryption); encryption != "" {
		payload["encryption"] = encryption
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	d.mu.Lock()
	etag := d.etag
	d.mu.Unlock()
	response, err := d.do(ctx, func() (*http.Request, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(d.option.URL, "/")+"/report", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		request.Header.Set("content-type", "application/json")
		d.authorize(request, body)
		if etag != "" {
			request.Header.Set("if-none-match", etag)
		}
		return request, nil
	})
	if err != nil {
		d.logFailure("report failed: %v", err)
		return
	}
	defer func() { _ = response.Body.Close() }()
	switch response.StatusCode {
	case http.StatusNotModified:
		elapsed := d.markSent(addr)
		d.resetWarning()
		d.logHeartbeat(elapsed)
		d.noteReport(addr)
	case http.StatusOK:
		var payload struct {
			Addr string `json:"addr"`
			Port int    `json:"port"`
		}
		if err := json.NewDecoder(io.LimitReader(response.Body, 1<<16)).Decode(&payload); err != nil {
			d.logFailure("report answer is not readable: %v", err)
			return
		}
		d.mu.Lock()
		previous := d.addr
		d.addr = payload.Addr
		d.etag = response.Header.Get("etag")
		d.mu.Unlock()
		elapsed := d.markSent(addr)
		if previous != payload.Addr {
			log.Infoln("[PeerDirectory](%s) %s is at %s:%d", d.Name(), d.option.ID, payload.Addr, d.option.Port)
		} else {
			d.logHeartbeat(elapsed)
		}
		d.resetWarning()
		d.noteReport(payload.Addr)
	default:
		d.logFailure("report rejected with %d", response.StatusCode)
	}
}

// logHeartbeat says that a report went out and nothing changed: at debug level
// this is the line that shows a node is alive, as opposed to quiet.
func (d *PeerDirectory) logHeartbeat(elapsed time.Duration) {
	d.mu.Lock()
	addr := d.addr
	d.mu.Unlock()
	if addr == "" {
		addr = "(no address yet)"
	}
	log.Debugln("[PeerDirectory](%s) heartbeat %s: still at %s:%d, %s since the last one",
		d.Name(), d.option.ID, addr, d.option.Port, elapsed.Round(time.Second))
}

// markSent records what went out and answers how long the previous report ago
// went out, which is the number a heartbeat log wants to show.
func (d *PeerDirectory) markSent(addr string) time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	elapsed := time.Duration(0)
	if !d.sentAt.IsZero() {
		elapsed = time.Since(d.sentAt)
	}
	d.sentAddr = addr
	d.sentPort = d.option.Port
	d.sentAt = time.Now()
	return elapsed
}

// pickReportAddress chooses the address this node publishes: a peer has to dial
// it, so a global unicast IPv6 on a real interface is the only useful answer.
// Nothing is published when there is none, and the directory then falls back to
// the address it observed for the report.
func pickReportAddress(candidates map[string][]netip.Addr) string {
	names := make([]string, 0, len(candidates))
	for name := range candidates {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		addrs := append([]netip.Addr(nil), candidates[name]...)
		sort.Slice(addrs, func(i, j int) bool {
			return addrs[i].Compare(addrs[j]) < 0
		})
		for _, addr := range addrs {
			if dialableReportAddress(addr) {
				return addr.String()
			}
		}
	}
	return ""
}

func dialableReportAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsLoopback() {
		return false
	}
	if addr.Is4() {
		return dialableReportIPv4(addr)
	}
	return !addr.IsPrivate() && !isReservedIPv6(addr)
}

// dialableReportIPv4 reports whether an IPv4 address is one a peer could dial.
//
// netip's IsPrivate only covers RFC 1918, so the other blocks that are not
// routable on the public internet are listed here: a peer handed one of these
// would report an address nothing outside its own network can reach.
func dialableReportIPv4(addr netip.Addr) bool {
	raw := addr.As4()
	// The reserved blocks, as (first, last) pairs in address order.
	for _, block := range reservedIPv4Blocks {
		if block.contains(raw) {
			return false
		}
	}
	return true
}

type ipv4Block struct {
	first [4]byte
	last  [4]byte
}

func (b ipv4Block) contains(raw [4]byte) bool {
	for i := 0; i < 4; i++ {
		if raw[i] < b.first[i] {
			return false
		}
		if raw[i] > b.last[i] {
			return false
		}
	}
	return true
}

// The blocks that are not reachable from the public internet, plus the
// benchmarking range and the address space reserved for future use.
var reservedIPv4Blocks = []ipv4Block{
	{first: [4]byte{0, 0, 0, 0}, last: [4]byte{0, 255, 255, 255}},       // "this network" (RFC 1122)
	{first: [4]byte{10, 0, 0, 0}, last: [4]byte{10, 255, 255, 255}},     // private (RFC 1918)
	{first: [4]byte{100, 64, 0, 0}, last: [4]byte{100, 127, 255, 255}},  // carrier-grade NAT (RFC 6598)
	{first: [4]byte{127, 0, 0, 0}, last: [4]byte{127, 255, 255, 255}},   // loopback
	{first: [4]byte{169, 254, 0, 0}, last: [4]byte{169, 254, 255, 255}}, // link local (RFC 3927)
	{first: [4]byte{172, 16, 0, 0}, last: [4]byte{172, 31, 255, 255}},   // private (RFC 1918)
	{first: [4]byte{192, 0, 0, 0}, last: [4]byte{192, 0, 0, 255}},       // IETF protocol assignments
	{first: [4]byte{192, 0, 2, 0}, last: [4]byte{192, 0, 2, 255}},       // documentation (RFC 5737)
	{first: [4]byte{192, 168, 0, 0}, last: [4]byte{192, 168, 255, 255}}, // private (RFC 1918)
	{first: [4]byte{198, 18, 0, 0}, last: [4]byte{198, 19, 255, 255}},   // benchmarking (RFC 2544)
	{first: [4]byte{198, 51, 100, 0}, last: [4]byte{198, 51, 100, 255}}, // documentation (RFC 5737)
	{first: [4]byte{203, 0, 113, 0}, last: [4]byte{203, 0, 113, 255}},   // documentation (RFC 5737)
	{first: [4]byte{224, 0, 0, 0}, last: [4]byte{255, 255, 255, 255}},   // multicast and reserved
}

// isReservedIPv6 covers what IsPrivate misses: the documentation range and the
// unique-local block, which is routable only inside one site.
func isReservedIPv6(addr netip.Addr) bool {
	if addr.Is4In6() {
		raw := addr.As16()
		var v4 [4]byte
		copy(v4[:], raw[12:16])
		return !dialableReportIPv4(netip.AddrFrom4(v4))
	}
	raw := addr.As16()
	// fc00::/7 — unique local (RFC 4193).
	if raw[0]&0xfe == 0xfc {
		return true
	}
	// 2001:db8::/32 — documentation (RFC 3849).
	if raw[0] == 0x20 && raw[1] == 0x01 && raw[2] == 0x0d && raw[3] == 0xb8 {
		return true
	}
	return false
}

func localAddressesByInterface() map[string][]netip.Addr {
	interfaces, err := iface.Interfaces()
	if err != nil {
		return nil
	}
	addresses := make(map[string][]netip.Addr, len(interfaces))
	for name, item := range interfaces {
		for _, prefix := range item.Addresses {
			addresses[name] = append(addresses[name], prefix.Addr())
		}
	}
	return addresses
}

// authorize proves who is asking. A token is the old way and still works; a
// device with no token signs the request with the key it never sends.
func (d *PeerDirectory) authorize(request *http.Request, body []byte) {
	if d.option.Token != "" {
		request.Header.Set("authorization", "Bearer "+d.option.Token)
		return
	}
	if len(d.signingSeed) == 0 {
		return
	}
	for header, value := range meshident.SignRequest(d.signingSeed, request.Method, request.URL.Path, body, d.option.ID, time.Now()) {
		request.Header.Set(header, value)
	}
}

func (d *PeerDirectory) logFailure(format string, args ...any) {
	d.mu.Lock()
	first := !d.warnedOnce
	d.warnedOnce = true
	d.mu.Unlock()
	if first {
		log.Warnln("[PeerDirectory](%s) %s", d.Name(), fmt.Sprintf(format, args...))
		return
	}
	log.Debugln("[PeerDirectory](%s) %s", d.Name(), fmt.Sprintf(format, args...))
}

func (d *PeerDirectory) resetWarning() {
	d.mu.Lock()
	d.warnedOnce = false
	d.mu.Unlock()
}

// InjectNetworkChange republishes this node now: a changed address is the one
// reason a report leaves the machine, and the app knows about an interface
// switch before the next poll does.
func (d *PeerDirectory) InjectNetworkChange() {
	// A route change is a burst, not one event: the platform reports every route
	// the change touches, and each report would ask the directory the same
	// question. One answer per few seconds is the same answer.
	d.mu.Lock()
	if !d.lastInject.IsZero() && time.Since(d.lastInject) < 3*time.Second {
		d.mu.Unlock()
		return
	}
	d.lastInject = time.Now()
	d.mu.Unlock()
	// Refresh the underlay answer first: a network change is exactly when the
	// interface carrying traffic moves, and the report that follows should name
	// the new one rather than wait for the next probe.
	d.refreshUnderlayInterface("network change")
	go d.maybeReport(true)
}

func (d *PeerDirectory) Addr() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.addr == "" {
		return d.option.URL
	}
	return d.addr + ":" + strconv.Itoa(d.option.Port)
}

func (d *PeerDirectory) SupportUDP() bool                 { return false }
func (d *PeerDirectory) SupportUOT() bool                 { return false }
func (d *PeerDirectory) IsL3Protocol(*C.Metadata) bool    { return false }
func (d *PeerDirectory) Unwrap(*C.Metadata, bool) C.Proxy { return nil }

func (d *PeerDirectory) DialContext(_ context.Context, _ *C.Metadata) (C.Conn, error) {
	return nil, errors.New("peer-directory: not a dialable proxy; reference it from a tailnet-peer outbound")
}

func (d *PeerDirectory) ListenPacketContext(_ context.Context, _ *C.Metadata) (C.PacketConn, error) {
	return nil, errors.New("peer-directory: not a dialable proxy; reference it from a tailnet-peer outbound")
}

func (d *PeerDirectory) Close() error {
	d.cancel()
	peerdirectory.Unregister(d.option.Name, d)
	return nil
}
