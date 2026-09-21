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
	"github.com/metacubex/mihomo/component/peerdirectory"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// localAddresses is the interface scan this package reasons about. It is a
// variable so a test can describe the interfaces it wants the decision to see
// instead of the ones the machine happens to have.
var localAddresses = localAddressesByInterface

const (
	peerDirectoryDefaultPort    = 8443
	peerDirectoryDefaultRefresh = 30 * time.Second
	peerDirectoryDefaultTimeout = 10 * time.Second
	peerDirectoryLookupTTL      = 2 * time.Second
	// A directory that shows which nodes are up needs to hear from a node even
	// when its address did not move, so a report goes out at least this often.
	peerDirectoryDefaultHeartbeat = 2 * time.Minute
	peerDirectoryMinimumHeartbeat = 30 * time.Second
)

var peerDirectoryIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,63}$`)

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
}

// PeerDirectory keeps one node's address current in a directory service and
// reads its peers' addresses back. The address is the one the directory
// observed for this node, so nothing here has to discover the public address.
type PeerDirectory struct {
	*Base

	option PeerDirectoryOption
	client *http.Client
	ctx    context.Context
	cancel context.CancelFunc

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
	warnedOnce        bool
}

type cachedPeer struct {
	addr string
	port int
	self bool
	at   time.Time
}

func NewPeerDirectory(option PeerDirectoryOption) (*PeerDirectory, error) {
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
		client:    &http.Client{Timeout: timeout, Transport: directoryTransport()},
		ctx:       ctx,
		cancel:    cancel,
		heartbeat: heartbeat,
		peers:     map[string]cachedPeer{},
	}
	peerdirectory.Register(option.Name, directory)
	log.Debugln("[PeerDirectory](%s) reporting as %s every %s when nothing changes", option.Name, option.ID, heartbeat)
	go directory.startUnderlayWatch()
	go directory.run()
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
func (d *PeerDirectory) PeerAddress(ctx context.Context, id string) (string, int, bool, error) {
	if id == d.option.ID {
		return "", d.option.Port, true, nil
	}
	d.mu.Lock()
	cached, ok := d.peers[id]
	d.mu.Unlock()
	if ok && time.Since(cached.at) < peerDirectoryLookupTTL {
		return cached.addr, cached.port, cached.self, nil
	}
	addr, port, nodeID, err := d.lookup(ctx, id)
	if err != nil {
		if ok {
			// The directory is unreachable or the record expired: an address we
			// saw a moment ago is still the best guess, and the caller's dial
			// either works or fails into its own retry.
			log.Debugln("[PeerDirectory](%s) lookup %s failed (%v); keeping %s from %s ago", d.Name(), id, err, cached.addr, time.Since(cached.at).Round(time.Second))
			return cached.addr, cached.port, cached.self, nil
		}
		return "", 0, false, err
	}
	self := nodeID != "" && nodeID == d.option.ID
	d.mu.Lock()
	d.peers[id] = cachedPeer{addr: addr, port: port, self: self, at: time.Now()}
	d.mu.Unlock()
	if self {
		// The directory resolved this name to this node: the service the name
		// reaches is the one this node serves.
		return "", d.option.Port, true, nil
	}
	return addr, port, false, nil
}

func (d *PeerDirectory) lookup(ctx context.Context, id string) (string, int, string, error) {
	target, err := url.Parse(d.option.URL)
	if err != nil {
		return "", 0, "", err
	}
	target.Path = strings.TrimSuffix(target.Path, "/") + "/lookup"
	query := target.Query()
	query.Set("id", id)
	target.RawQuery = query.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return "", 0, "", err
	}
	d.authorize(request)
	response, err := d.client.Do(request)
	if err != nil {
		return "", 0, "", err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	if err != nil {
		return "", 0, "", err
	}
	if response.StatusCode == http.StatusNotFound {
		return "", 0, "", fmt.Errorf("peer %q is unknown or expired", id)
	}
	if response.StatusCode != http.StatusOK {
		return "", 0, "", fmt.Errorf("directory answered %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload struct {
		Nodes map[string]struct {
			ID   string `json:"id"`
			Addr string `json:"addr"`
			Port int    `json:"port"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", 0, "", err
	}
	node, ok := payload.Nodes[id]
	if !ok || node.Addr == "" {
		return "", 0, "", fmt.Errorf("peer %q is unknown or expired", id)
	}
	return node.Addr, node.Port, node.ID, nil
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

func (d *PeerDirectory) report(ctx context.Context, addr string) {
	payload := map[string]any{
		"id":   d.option.ID,
		"port": d.option.Port,
		// The platform travels with the report so the directory can show what
		// kind of machine each name is: the profile is shared, so nothing in it
		// says whether a name is this phone or that desktop.
		"platform": runtime.GOOS,
	}
	// The host name travels too: an id is a digest, and a digest is not what a
	// reader recognises a machine by until they name it themselves.
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		payload["hostname"] = hostname
	}
	if addr != "" {
		payload["addr"] = addr
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(d.option.URL, "/")+"/report", bytes.NewReader(body))
	if err != nil {
		return
	}
	request.Header.Set("content-type", "application/json")
	d.authorize(request)
	d.mu.Lock()
	etag := d.etag
	d.mu.Unlock()
	if etag != "" {
		request.Header.Set("if-none-match", etag)
	}
	response, err := d.client.Do(request)
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
	return addr.Is6() && addr.IsGlobalUnicast() && !addr.IsPrivate() && !addr.IsLoopback()
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

func (d *PeerDirectory) authorize(request *http.Request) {
	if d.option.Token != "" {
		request.Header.Set("authorization", "Bearer "+d.option.Token)
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
