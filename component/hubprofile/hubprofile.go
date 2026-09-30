// Package hubprofile keeps a device's configuration in step with the hub that
// owns it.
//
// A device that runs the core without the app had no way to be given a
// configuration: the core reads its file once at start and never looks again,
// so both the pull and the push lived in the app, and a box running the core
// alone - an ONT, a router, anything with the binary and no Flutter - could
// only ever be configured by hand and by restart. This package closes that:
// the device names the hub it belongs to, pulls its YAML from it, and holds
// the socket that hands it a new one the moment the dashboard saves, then
// applies it through the same path the app uses.
//
// The identity fields (directory-id, device-name, device-os) stay local. What
// the hub stores is one YAML shared by devices, and which device this is has
// to be decided by the device: a shared profile cannot name one, the same way
// the mesh block it carries does not.
package hubprofile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/metacubex/mihomo/common/yaml"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

const (
	// defaultPollInterval is how often a device re-reads its profile while the
	// socket carries nothing. The socket is the fast path; this is what makes
	// the state converge when it is down, so it is a backstop rather than the
	// mechanism.
	defaultPollInterval = 5 * time.Minute
	// retryFloor and retryCeiling bound the socket's backoff. A hub that is
	// down should not be hammered, and a hub that comes back should be picked
	// up promptly.
	retryFloor   = 2 * time.Second
	retryCeiling = 2 * time.Minute
	// fetchTimeout bounds one pull, on the core's own dialer.
	fetchTimeout = 30 * time.Second
	// watchReadDeadline is how long the socket waits for a message before it
	// is treated as dead. The hub pings; a silence longer than this means the
	// connection is gone in a way that never produced an error.
	watchReadDeadline = 3 * time.Minute
	// maxProfileLen caps a pulled profile. The hub enforces its own limit;
	// this is the reading side of the same bound, so a hub that misbehaves
	// cannot make the core read without end.
	maxProfileLen = 4 << 20
)

// Config is the block a device writes to be kept in step with a hub.
type Config struct {
	// URL is the hub root, e.g. https://hub.see.moe.
	URL string `yaml:"url" json:"url"`
	// Token is the bearer the hub accepts, the same one the directory uses.
	Token string `yaml:"token" json:"token"`
	// ID is the record this device answers to, the name the dashboard shows.
	ID string `yaml:"id" json:"id"`
	// File is where the pulled YAML is kept. Empty keeps it in the home
	// directory, named after the id.
	File string `yaml:"file,omitempty" json:"file,omitempty"`
	// PollSeconds overrides defaultPollInterval. Zero keeps the default.
	PollSeconds int `yaml:"poll-seconds,omitempty" json:"poll-seconds,omitempty"`
	// Proxy is an HTTP proxy the requests go through, for a network that
	// resets the direct connection. Empty dials straight out.
	Proxy string `yaml:"proxy,omitempty" json:"proxy,omitempty"`
	// Keep is merged into every pulled YAML, last, so a device's own identity
	// survives a profile shared with devices that differ.
	Keep map[string]any `yaml:"keep,omitempty" json:"keep,omitempty"`
}

// Enabled reports whether a profile block asks for anything at all. An absent
// or empty block leaves the core on the file it was started with.
func (c *Config) Enabled() bool {
	return c != nil && (strings.TrimSpace(c.URL) != "" ||
		strings.TrimSpace(c.Token) != "" ||
		strings.TrimSpace(c.ID) != "")
}

// hubTokenParam is the query parameter an address may carry its credential in,
// mirroring what the hub accepts on the other end.
const hubTokenParam = "token"

// Validate reports whether the block can be used, before anything is dialled:
// a device that names no hub has nothing to pull from, and one that names no
// id has no record to be given.
//
// The credential may arrive either in its own field or inside the url, so a
// single link can configure this block the same way it configures a device's
// directory outbound. The url form is the one that cannot drift: an address and
// the token it belongs to are written and replaced together.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.URL) == "" {
		return errors.New("profile: url is required, the hub this device takes its configuration from")
	}
	if token, stripped := splitHubLink(c.URL); token != "" {
		if strings.TrimSpace(c.Token) == "" {
			c.Token = token
		}
		c.URL = stripped
	}
	if strings.TrimSpace(c.Token) == "" {
		return errors.New("profile: token is required, the credential the hub accepts")
	}
	if strings.TrimSpace(c.ID) == "" {
		return errors.New("profile: id is required, the record this device answers to")
	}
	return nil
}

// splitHubLink lifts a credential out of an address that carries one as a
// parameter, returning the address with the parameter removed. Callers build
// their endpoints by appending a path to the address, so what they are given
// must be free of a query; the token travels in the request header instead.
func splitHubLink(raw string) (token string, stripped string) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || !strings.Contains(trimmed, hubTokenParam+"=") {
		return "", trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", trimmed
	}
	query := parsed.Query()
	carried := strings.TrimSpace(query.Get(hubTokenParam))
	if carried == "" {
		return "", trimmed
	}
	query.Del(hubTokenParam)
	parsed.RawQuery = query.Encode()
	return carried, parsed.String()
}

// filePath is where the pulled YAML is written.
func (c *Config) filePath() string {
	if strings.TrimSpace(c.File) != "" {
		return c.File
	}
	return filepath.Join(C.Path.HomeDir(), "profile-"+sanitize(c.ID)+".yaml")
}

// pollInterval is how often the pull runs while the socket is quiet.
func (c *Config) pollInterval() time.Duration {
	if c.PollSeconds > 0 {
		return time.Duration(c.PollSeconds) * time.Second
	}
	return defaultPollInterval
}

// ApplyFunc takes a pulled YAML and puts it into service. Supplied by the
// caller so this package does not have to know how the core reloads.
type ApplyFunc func(yaml []byte) error

// Client keeps one device's configuration in step with its hub.
type Client struct {
	config Config
	apply  ApplyFunc
	// direct reaches the hub straight out; through reaches it by way of the
	// configured proxy. Both are tried, direct first, so a hub that is only
	// reachable one way is still reachable and a device never depends on the
	// path it may be about to install. Either may be nil when that way is not
	// available at all.
	direct  *http.Client
	through *http.Client
	// dialDirect and dialThrough are the same two ways for the watch socket,
	// which dials a connection rather than going through a transport.
	dialDirect  func(ctx context.Context, network, address string) (net.Conn, error)
	dialThrough func(ctx context.Context, network, address string) (net.Conn, error)
	// proxyConfigured records whether a proxy was asked for, so the failure
	// message can say which paths were tried.
	proxyConfigured bool

	mu      sync.Mutex
	etag    string
	lastErr error
	// wayIndex is the route the last success came over, so the walk starts
	// where the hub was last reachable.
	wayIndex int
}

// New builds a client. apply is called for every YAML that differs from the
// one already running, and is what makes a pulled profile take effect.
func New(config Config, apply ApplyFunc) (*Client, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	client := &Client{config: config, apply: apply}
	client.dialDirect = func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, address)
	}
	client.direct = &http.Client{
		Timeout:   fetchTimeout,
		Transport: transportFor(nil),
	}

	if proxy := strings.TrimSpace(config.Proxy); proxy != "" {
		tunnel, err := newProxyDialer(proxy)
		if err != nil {
			return nil, err
		}
		client.proxyConfigured = true
		client.dialThrough = tunnel.DialContext
		client.through = &http.Client{
			Timeout:   fetchTimeout,
			Transport: transportFor(tunnel.DialContext),
		}
	}
	return client, nil
}

// ways lists the routes to the hub in the order they are tried.
//
// Direct first, deliberately. A device pulls its configuration to find out what
// it should run - including the proxy that configuration may install - so the
// first attempt must not depend on that proxy: a device whose only route out is
// the proxy it has not yet been told about would otherwise never be told. The
// direct attempt costs one connection when it works, and when the network
// resets it the proxy attempt follows.
func (c *Client) ways() []way {
	ways := []way{{name: "direct", client: c.direct, dial: c.dialDirect}}
	if c.through != nil {
		ways = append(ways, way{name: "proxy", client: c.through, dial: c.dialThrough})
	}
	return ways
}

// way is one route to the hub: the client the pull goes through and the dialer
// the socket uses, which have to agree or the two halves would take different
// paths.
type way struct {
	name   string
	client *http.Client
	dial   func(ctx context.Context, network, address string) (net.Conn, error)
}

// Start runs the channel until ctx is done: a pull first, then the socket with
// the poll beside it so a socket that cannot be held still converges.
func (c *Client) Start(ctx context.Context) {
	// The device has to be running something before it can be kept up to
	// date, and pulling first is also what puts the local file in place for a
	// caller that reads it.
	if err := c.Pull(ctx); err != nil {
		log.Warnln("[Profile] the first pull failed, running what is on disk: %s", err.Error())
	}
	go c.pollLoop(ctx)
	go c.watchLoop(ctx)
}

// pollLoop re-reads the profile on an interval. Every read sends the ETag it
// holds, so an unchanged profile costs a 304 and no body.
func (c *Client) pollLoop(ctx context.Context) {
	ticker := time.NewTicker(c.config.pollInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.Pull(ctx); err != nil {
				log.Debugln("[Profile] poll failed: %s", err.Error())
			}
		}
	}
}

// watchLoop holds the hub's socket and reapplies whatever it hands over,
// backing off when it cannot be held.
//
// The routes are walked in the same order the pull uses, so a device whose
// socket cannot be held one way still hears its pushes the other.
func (c *Client) watchLoop(ctx context.Context) {
	backoff := retryFloor
	for {
		if ctx.Err() != nil {
			return
		}
		err := c.watchAllWays(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			c.setErr(err)
			log.Debugln("[Profile] watch ended: %s (retrying in %s)", err.Error(), backoff)
			// Grow the wait only while the socket keeps failing: one that
			// worked and then dropped should come back quickly.
			backoff *= 2
			if backoff > retryCeiling {
				backoff = retryCeiling
			}
		} else {
			backoff = retryFloor
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

// watchAllWays holds the socket over whichever route can carry it.
func (c *Client) watchAllWays(ctx context.Context) error {
	ways := c.ways()
	start := c.preferredWay()
	var lastErr error
	for i := 0; i < len(ways); i++ {
		index := (start + i) % len(ways)
		err := c.watch(ctx, ways[index])
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			c.rememberWay(index)
			return nil
		}
		lastErr = err
		if len(ways) > 1 {
			log.Debugln("[Profile] watch over %s ended: %s", ways[index].name, err.Error())
		}
	}
	return lastErr
}

// watch is one connection's lifetime: dial, read messages, apply each one.
func (c *Client) watch(ctx context.Context, attempt way) error {
	target, err := c.watchURL()
	if err != nil {
		return err
	}
	header := ws.HandshakeHeaderHTTP(http.Header{
		"Authorization": []string{"Bearer " + c.config.Token},
	})
	// The core's own dialer, or the tunnel, so reaching the hub does not
	// depend on the tunnel the configuration being fetched would build.
	conn, _, _, err := ws.Dialer{Header: header, NetDial: attempt.dial}.Dial(ctx, target)
	if err != nil {
		return fmt.Errorf("profile: watch dial %s over %s: %w", target, attempt.name, err)
	}
	defer func() {
		_ = conn.Close()
	}()

	if err := conn.SetReadDeadline(time.Now().Add(watchReadDeadline)); err != nil {
		return err
	}
	c.clearErr()
	log.Infoln("[Profile] watching %s (over %s)", target, attempt.name)

	for {
		if ctx.Err() != nil {
			return nil
		}
		data, op, err := wsutil.ReadServerData(conn)
		if err != nil {
			return err
		}
		// Keep the deadline ahead of a hub that sends pings but no profile.
		_ = conn.SetReadDeadline(time.Now().Add(watchReadDeadline))
		if op != ws.OpText && op != ws.OpBinary {
			continue
		}
		if err := c.handleMessage(data); err != nil {
			log.Warnln("[Profile] %s", err.Error())
		}
	}
}

// handleMessage applies a pushed profile. The hub sends one JSON object per
// change; anything else is ignored rather than fatal, so a hub that grows a new
// message type does not stop the devices it already serves.
func (c *Client) handleMessage(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	var message struct {
		Type      string `json:"type"`
		YAML      string `json:"yaml"`
		ETag      string `json:"etag"`
		UpdatedAt int64  `json:"updatedAt"`
	}
	if err := json.Unmarshal(data, &message); err != nil {
		return fmt.Errorf("a watch message could not be read: %w", err)
	}
	if message.Type != "profile" || strings.TrimSpace(message.YAML) == "" {
		return nil
	}
	c.mu.Lock()
	same := message.ETag != "" && message.ETag == c.etag
	if !same {
		c.etag = message.ETag
	}
	c.mu.Unlock()
	if same {
		return nil
	}
	if err := c.applyYAML([]byte(message.YAML)); err != nil {
		return err
	}
	c.clearErr()
	log.Infoln("[Profile] applied the profile the hub pushed (etag %s)", message.ETag)
	return nil
}

// Pull reads the profile once and applies it when it differs from the running
// one. A 304 is a success with nothing to do.
//
// Both ways to the hub are tried in turn, so one route being down does not take
// the profile away. The attempt that succeeds is remembered, and the next pull
// starts there: a device on a network that only reaches the proxy should not
// pay a failed direct attempt on every poll.
func (c *Client) Pull(ctx context.Context) error {
	target, err := c.profileURL()
	if err != nil {
		return err
	}
	ways := c.ways()
	start := c.preferredWay()
	var lastErr error
	for i := 0; i < len(ways); i++ {
		attempt := ways[(start+i)%len(ways)]
		err := c.pullVia(ctx, attempt, target)
		if err == nil {
			c.rememberWay((start + i) % len(ways))
			return nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
		// An answer from the hub is not a route problem: the other way would
		// ask the same question and be told the same thing.
		var answered wayAnswered
		if errors.As(err, &answered) {
			break
		}
		if len(ways) > 1 {
			log.Debugln("[Profile] pull over %s failed: %s", attempt.name, err.Error())
		}
	}
	c.setErr(lastErr)
	return lastErr
}

// pullVia is one attempt over one route.
func (c *Client) pullVia(ctx context.Context, attempt way, target string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.config.Token)
	c.mu.Lock()
	etag := c.etag
	c.mu.Unlock()
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}

	response, err := attempt.client.Do(request)
	if err != nil {
		return fmt.Errorf("profile: pull %s over %s: %w", target, attempt.name, err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	switch response.StatusCode {
	case http.StatusNotModified:
		return nil
	case http.StatusNotFound:
		return fmt.Errorf("profile: the hub holds no profile for id %q", c.config.ID)
	case http.StatusOK:
	default:
		// The hub answered, so this route works: a status is not a reason to
		// try the other one, which would only repeat the same answer.
		return wayAnswered{err: fmt.Errorf("profile: pull %s over %s: the hub answered %s", target, attempt.name, response.Status)}
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxProfileLen+1))
	if err != nil {
		return fmt.Errorf("profile: pull %s over %s: %w", target, attempt.name, err)
	}
	if len(body) > maxProfileLen {
		return wayAnswered{err: fmt.Errorf("profile: the pulled profile is larger than %d bytes", maxProfileLen)}
	}

	responseEtag := strings.TrimSpace(response.Header.Get("ETag"))
	c.mu.Lock()
	same := responseEtag != "" && responseEtag == c.etag
	if !same {
		c.etag = responseEtag
	}
	c.mu.Unlock()
	if same {
		return nil
	}
	if err := c.applyYAML(body); err != nil {
		return wayAnswered{err: err}
	}
	log.Infoln("[Profile] applied the profile pulled over %s (etag %s)", attempt.name, responseEtag)
	return nil
}

// wayAnswered marks a failure that came from the hub's own answer rather than
// from the route. Trying the other way would only produce the same answer -
// the hub would refuse the credential again, or hold no profile again - so
// these stop the walk, while a route that cannot be reached does not.
type wayAnswered struct{ err error }

func (w wayAnswered) Error() string { return w.err.Error() }
func (w wayAnswered) Unwrap() error { return w.err }

// preferredWay is the route the last success came over.
func (c *Client) preferredWay() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wayIndex
}

func (c *Client) rememberWay(index int) {
	c.mu.Lock()
	c.wayIndex = index
	c.lastErr = nil
	c.mu.Unlock()
}

// applyYAML merges the device's own identity in, writes the result beside the
// running configuration, and hands it to the applier.
//
// The write comes first so a device that restarts comes back on the profile it
// was running, rather than on whatever it was started with.
func (c *Client) applyYAML(body []byte) error {
	merged := c.merge(body)
	path := c.config.filePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("profile: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, merged, 0o600); err != nil {
		return fmt.Errorf("profile: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("profile: %w", err)
	}
	if c.apply == nil {
		return nil
	}
	return c.apply(merged)
}

// merge puts the device's own identity back over the pulled YAML.
//
// The hub stores one profile and every device pulls it, so the fields that say
// which device this is cannot live there: they are merged after, and the
// device's own values win. A key may name a nested field with dots, so one
// field can be pinned without replacing the block around it.
//
// A pull that cannot be read as a mapping is returned as it came: the core
// then reports the problem where a bad profile should surface, instead of this
// layer inventing an error of its own.
func (c *Client) merge(body []byte) []byte {
	if len(c.config.Keep) == 0 {
		return body
	}
	pulled := map[string]any{}
	if err := yaml.Unmarshal(body, &pulled); err != nil {
		return body
	}
	for key, value := range c.config.Keep {
		mergeKey(pulled, key, value)
	}
	merged, err := yaml.Marshal(pulled)
	if err != nil {
		return body
	}
	return merged
}

// mergeKey overlays one key, descending into maps so a single field can be
// pinned without replacing the block around it.
func mergeKey(target map[string]any, key string, value any) {
	segments := strings.Split(key, ".")
	current := target
	for _, segment := range segments[:len(segments)-1] {
		next, ok := current[segment].(map[string]any)
		if !ok {
			next = map[string]any{}
			current[segment] = next
		}
		current = next
	}
	last := segments[len(segments)-1]
	if incoming, ok := value.(map[string]any); ok {
		if existing, ok := current[last].(map[string]any); ok {
			for k, v := range incoming {
				existing[k] = v
			}
			return
		}
	}
	current[last] = value
}

// profileURL is the endpoint a device pulls its own YAML from.
func (c *Client) profileURL() (string, error) {
	base := strings.TrimRight(strings.TrimSpace(c.config.URL), "/")
	parsed, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("profile: url %q: %w", base, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("profile: url %q must be http or https", base)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("profile: url %q names no host", base)
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/profile"
	query := parsed.Query()
	query.Set("id", c.config.ID)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

// watchURL is the socket the same endpoint publishes changes on. The scheme
// follows the hub's: a hub reached over plain http on a LAN answers on ws.
func (c *Client) watchURL() (string, error) {
	base, err := c.profileURL()
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	switch parsed.Scheme {
	case "https":
		parsed.Scheme = "wss"
	case "http":
		parsed.Scheme = "ws"
	default:
		return "", fmt.Errorf("profile: cannot watch %q", base)
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/watch"
	return parsed.String(), nil
}

// transportFor builds the transport a request goes over, dialling with the
// given function. The dialer is passed in rather than chosen here so the pull
// and the watch socket can be given the same route.
func transportFor(dial func(ctx context.Context, network, address string) (net.Conn, error)) *http.Transport {
	if dial == nil {
		dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		}
	}
	return &http.Transport{
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true,
		DialContext:           dial,
	}
}

func (c *Client) setErr(err error) {
	c.mu.Lock()
	c.lastErr = err
	c.mu.Unlock()
}

func (c *Client) clearErr() {
	c.mu.Lock()
	c.lastErr = nil
	c.mu.Unlock()
}

// LastError is why the device is not converging, or nil when it is.
func (c *Client) LastError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastErr
}

// sanitize keeps an id usable as a file name. The hub constrains ids to
// [A-Za-z0-9._-] already; this is the local half of the same rule, so a
// hand-written block cannot escape the home directory.
func sanitize(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), ".")
	if out == "" {
		return "device"
	}
	return out
}
