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

// Validate reports whether the block can be used, before anything is dialled:
// a device that names no hub has nothing to pull from, and one that names no
// id has no record to be given.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.URL) == "" {
		return errors.New("profile: url is required, the hub this device takes its configuration from")
	}
	if strings.TrimSpace(c.Token) == "" {
		return errors.New("profile: token is required, the credential the hub accepts")
	}
	if strings.TrimSpace(c.ID) == "" {
		return errors.New("profile: id is required, the record this device answers to")
	}
	return nil
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
	client *http.Client

	mu      sync.Mutex
	etag    string
	lastErr error
}

// New builds a client. apply is called for every YAML that differs from the
// one already running, and is what makes a pulled profile take effect.
func New(config Config, apply ApplyFunc) (*Client, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	transport, err := transportFor(config.Proxy)
	if err != nil {
		return nil, err
	}
	return &Client{
		config: config,
		apply:  apply,
		client: &http.Client{Timeout: fetchTimeout, Transport: transport},
	}, nil
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
func (c *Client) watchLoop(ctx context.Context) {
	backoff := retryFloor
	for {
		if ctx.Err() != nil {
			return
		}
		err := c.watch(ctx)
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

// watch is one connection's lifetime: dial, read messages, apply each one.
func (c *Client) watch(ctx context.Context) error {
	target, err := c.watchURL()
	if err != nil {
		return err
	}
	header := ws.HandshakeHeaderHTTP(http.Header{
		"Authorization": []string{"Bearer " + c.config.Token},
	})
	// The core's own dialer, so reaching the hub does not depend on the tunnel
	// the configuration being fetched would build.
	conn, _, _, err := ws.Dialer{Header: header, NetDial: c.dialContext}.Dial(ctx, target)
	if err != nil {
		return fmt.Errorf("profile: watch dial %s: %w", target, err)
	}
	defer func() {
		_ = conn.Close()
	}()

	if err := conn.SetReadDeadline(time.Now().Add(watchReadDeadline)); err != nil {
		return err
	}
	c.clearErr()
	log.Infoln("[Profile] watching %s", target)

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
func (c *Client) Pull(ctx context.Context) error {
	target, err := c.profileURL()
	if err != nil {
		return err
	}
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

	response, err := c.client.Do(request)
	if err != nil {
		c.setErr(err)
		return fmt.Errorf("profile: pull %s: %w", target, err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	switch response.StatusCode {
	case http.StatusNotModified:
		c.clearErr()
		return nil
	case http.StatusNotFound:
		err := fmt.Errorf("profile: the hub holds no profile for id %q", c.config.ID)
		c.setErr(err)
		return err
	case http.StatusOK:
	default:
		err := fmt.Errorf("profile: pull %s: the hub answered %s", target, response.Status)
		c.setErr(err)
		return err
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxProfileLen+1))
	if err != nil {
		c.setErr(err)
		return err
	}
	if len(body) > maxProfileLen {
		err := fmt.Errorf("profile: the pulled profile is larger than %d bytes", maxProfileLen)
		c.setErr(err)
		return err
	}

	responseEtag := strings.TrimSpace(response.Header.Get("ETag"))
	c.mu.Lock()
	same := responseEtag != "" && responseEtag == c.etag
	if !same {
		c.etag = responseEtag
	}
	c.mu.Unlock()
	if same {
		c.clearErr()
		return nil
	}
	if err := c.applyYAML(body); err != nil {
		c.setErr(err)
		return err
	}
	c.clearErr()
	log.Infoln("[Profile] applied the profile pulled from the hub (etag %s)", responseEtag)
	return nil
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

// dialContext uses the core's dialer, so a hub that is only reachable through
// the tunnel is still reachable, and a configuration fetched from it cannot
// depend on the configuration it would install.
func (c *Client) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return dialer.DialContext(ctx, network, address)
}

// transportFor builds the transport the pull goes through, optionally by way
// of a proxy for a network that resets the direct connection.
func transportFor(rawProxy string) (*http.Transport, error) {
	transport := &http.Transport{
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
	}
	rawProxy = strings.TrimSpace(rawProxy)
	if rawProxy == "" {
		return transport, nil
	}
	parsed, err := url.Parse(rawProxy)
	if err != nil {
		return nil, fmt.Errorf("profile: invalid proxy url %q: %w", rawProxy, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("profile: proxy url %q must be http or https", rawProxy)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("profile: proxy url %q names no host", rawProxy)
	}
	transport.Proxy = http.ProxyURL(parsed)
	return transport, nil
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
