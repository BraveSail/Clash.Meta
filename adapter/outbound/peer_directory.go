package outbound

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/component/peerdirectory"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

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
	sentAddr   string
	sentPort   int
	sentAt     time.Time
	heartbeat  time.Duration
	peers      map[string]cachedPeer
	warnedOnce bool
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
	directory := &PeerDirectory{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         parsed.String(),
			Type:         C.PeerDirectory,
			ProviderName: option.ProviderName,
		}),
		option:    option,
		client:    &http.Client{Timeout: timeout},
		ctx:       ctx,
		cancel:    cancel,
		heartbeat: heartbeat,
		peers:     map[string]cachedPeer{},
	}
	peerdirectory.Register(option.Name, directory)
	log.Debugln("[PeerDirectory](%s) reporting as %s every %s when nothing changes", option.Name, option.ID, heartbeat)
	go directory.run()
	return directory, nil
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
// of connections shares one lookup.
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
	addr, port, err := d.lookup(ctx, id)
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
	d.mu.Lock()
	d.peers[id] = cachedPeer{addr: addr, port: port, at: time.Now()}
	d.mu.Unlock()
	return addr, port, false, nil
}

func (d *PeerDirectory) lookup(ctx context.Context, id string) (string, int, error) {
	target, err := url.Parse(d.option.URL)
	if err != nil {
		return "", 0, err
	}
	target.Path = strings.TrimSuffix(target.Path, "/") + "/lookup"
	query := target.Query()
	query.Set("id", id)
	target.RawQuery = query.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return "", 0, err
	}
	d.authorize(request)
	response, err := d.client.Do(request)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	if err != nil {
		return "", 0, err
	}
	if response.StatusCode == http.StatusNotFound {
		return "", 0, fmt.Errorf("peer %q is unknown or expired", id)
	}
	if response.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("directory answered %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload struct {
		Nodes map[string]struct {
			Addr string `json:"addr"`
			Port int    `json:"port"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", 0, err
	}
	node, ok := payload.Nodes[id]
	if !ok || node.Addr == "" {
		return "", 0, fmt.Errorf("peer %q is unknown or expired", id)
	}
	return node.Addr, node.Port, nil
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
	addr := pickReportAddress(localAddressesByInterface())
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
	d.report(d.ctx, addr)
}

func (d *PeerDirectory) report(ctx context.Context, addr string) {
	payload := map[string]any{
		"id":   d.option.ID,
		"port": d.option.Port,
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
