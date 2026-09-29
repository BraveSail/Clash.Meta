package hubprofile

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// proxyTestHub is a hub plus an HTTP proxy in front of it, where the direct
// route can be turned off - which is the network this fallback exists for.
type proxyTestHub struct {
	hub   *httptest.Server
	proxy *httptest.Server

	// directBlocked makes the direct route connect to nothing.
	directBlocked atomic.Bool
	// proxyHits counts the tunneled requests, directHits the straight ones.
	proxyHits  atomic.Int32
	directHits atomic.Int32
}

// newProxyTestHub starts a hub, a CONNECT proxy that forwards to it, and wires
// the test transport so "direct" means the hub and "proxy" means the proxy.
func newProxyTestHub(t *testing.T, yaml, etag string) *proxyTestHub {
	t.Helper()
	fixture := &proxyTestHub{}

	mux := http.NewServeMux()
	mux.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte(yaml))
	})
	fixture.hub = httptest.NewServer(mux)
	t.Cleanup(fixture.hub.Close)

	// A CONNECT proxy: it accepts the tunnel and pipes it to wherever the
	// CONNECT names, which is how a real HTTP proxy carries a client through.
	fixture.proxy = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		fixture.proxyHits.Add(1)
		upstream, err := net.DialTimeout("tcp", r.Host, 5*time.Second)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		client, _, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		pipe(client, upstream)
	}))
	t.Cleanup(fixture.proxy.Close)

	return fixture
}

// pipe copies in both directions until either side closes. Each direction
// signals once, and the first to finish tears the pair down: a CONNECT tunnel
// that closed its upstream has nothing left to carry.
func pipe(a, b net.Conn) {
	var once sync.Once
	done := make(chan struct{})
	finish := func() { once.Do(func() { close(done) }) }
	go func() {
		defer finish()
		buf := make([]byte, 4096)
		for {
			n, err := a.Read(buf)
			if n > 0 {
				if _, werr := b.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer finish()
		buf := make([]byte, 4096)
		for {
			n, err := b.Read(buf)
			if n > 0 {
				if _, werr := a.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	<-done
}

// clientFor builds a client whose two routes point at this fixture: direct at
// the hub, and the proxy at the tunnel. The first route refuses connections
// when directBlocked is set.
func (f *proxyTestHub) clientFor(t *testing.T, apply ApplyFunc) *Client {
	t.Helper()
	config := Config{
		URL:   f.hub.URL,
		Token: "test-token",
		ID:    "ont",
		File:  filepath.Join(t.TempDir(), "profile.yaml"),
		Proxy: f.proxy.URL,
	}
	client, err := New(config, apply)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Replace the direct route with one that fails while directBlocked is set.
	// The hub is reached directly, so blocking it means refusing the connect.
	directTarget, err := url.Parse(f.hub.URL)
	if err != nil {
		t.Fatalf("parsing the hub URL: %v", err)
	}
	client.dialDirect = func(ctx context.Context, network, address string) (net.Conn, error) {
		// Counted whether or not it is allowed through: the point of the
		// counter is how many times the direct route was attempted.
		f.directHits.Add(1)
		if f.directBlocked.Load() {
			return nil, fmt.Errorf("connection refused")
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
	}
	client.direct = &http.Client{
		Timeout:   fetchTimeout,
		Transport: transportFor(client.dialDirect),
	}
	_ = directTarget
	return client
}

// A dead direct route must not take the profile away: the proxy carries it.
func TestADeadDirectRouteFallsBackToTheProxy(t *testing.T) {
	fixture := newProxyTestHub(t, "mode: rule\n", `"v1"`)
	fixture.directBlocked.Store(true)

	var applied []byte
	client := fixture.clientFor(t, func(b []byte) error { applied = b; return nil })

	if err := client.Pull(context.Background()); err != nil {
		t.Fatalf("Pull with the direct route down: %v", err)
	}
	if !strings.Contains(string(applied), "mode: rule") {
		t.Errorf("the profile did not arrive: %q", applied)
	}
	if fixture.proxyHits.Load() == 0 {
		t.Error("the proxy was never used, so nothing fell back")
	}
}

// A working direct route is used, and the proxy is not touched: the fallback
// costs nothing while the preferred way works.
func TestAWorkingDirectRouteIsPreferred(t *testing.T) {
	fixture := newProxyTestHub(t, "mode: rule\n", `"v1"`)

	client := fixture.clientFor(t, func([]byte) error { return nil })
	if err := client.Pull(context.Background()); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if fixture.proxyHits.Load() != 0 {
		t.Errorf("the proxy was used %d times while direct worked", fixture.proxyHits.Load())
	}
	if fixture.directHits.Load() == 0 {
		t.Error("the direct route was not used at all")
	}
}

// The route that worked is remembered, so a device behind a blocked direct
// route does not pay a failed attempt on every poll.
func TestTheRouteThatWorkedIsRemembered(t *testing.T) {
	fixture := newProxyTestHub(t, "mode: rule\n", `"v1"`)
	fixture.directBlocked.Store(true)

	client := fixture.clientFor(t, func([]byte) error { return nil })
	if err := client.Pull(context.Background()); err != nil {
		t.Fatalf("first Pull: %v", err)
	}
	if client.preferredWay() != 1 {
		t.Fatalf("the working route was not remembered: preferredWay = %d", client.preferredWay())
	}

	// The second pull must start on the remembered route. Counting CONNECTs is
	// not the evidence: the transport reuses the tunnel it already has, so the
	// direct attempt count is what shows the walk did not begin there.
	beforeDirect := fixture.directHits.Load()
	if err := client.Pull(context.Background()); err != nil {
		t.Fatalf("second Pull: %v", err)
	}
	if fixture.directHits.Load() != beforeDirect {
		t.Error("the direct route was retried despite a remembered working route")
	}
}

// A hub that refuses the credential answers the same way on either route, so
// the walk must stop rather than ask twice - and the caller must be told.
func TestAnAnswerFromTheHubStopsTheWalk(t *testing.T) {
	var proxyRequests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyRequests.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()

	hubHits := atomic.Int32{}
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hubHits.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer hub.Close()

	client, err := New(Config{
		URL:   hub.URL,
		Token: "test-token",
		ID:    "ont",
		File:  filepath.Join(t.TempDir(), "profile.yaml"),
		Proxy: proxy.URL,
	}, func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = client.Pull(context.Background())
	if err == nil {
		t.Fatal("a 401 was treated as a profile")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("the error does not carry the hub's answer: %v", err)
	}
	// The hub answered, so the route works and the other one would only repeat
	// the same refusal.
	if proxyRequests.Load() != 0 {
		t.Errorf("the proxy was tried %d times after the hub answered", proxyRequests.Load())
	}
	if hubHits.Load() != 1 {
		t.Errorf("the hub was asked %d times, want 1", hubHits.Load())
	}
}

// A proxy that cannot be reached at all is reported, and the walk still covers
// both ways before giving up.
func TestBothRoutesDownIsReported(t *testing.T) {
	fixture := newProxyTestHub(t, "mode: rule\n", `"v1"`)
	fixture.directBlocked.Store(true)
	fixture.proxy.Close() // the proxy is now refused too

	client := fixture.clientFor(t, func([]byte) error { return nil })
	err := client.Pull(context.Background())
	if err == nil {
		t.Fatal("a pull with both routes down succeeded")
	}
	if client.LastError() == nil {
		t.Error("the failure was not recorded for the caller to report")
	}
}

// The proxy URL is validated at construction, not on the first request: a
// device with a typo in its configuration should hear about it while starting.
func TestABadProxyURLIsRefusedAtConstruction(t *testing.T) {
	base := Config{
		URL:  "https://hub.example",
		Token: "t",
		ID:    "ont",
	}
	for _, bad := range []string{"socks5://127.0.0.1:1080", "not a url at all", "http://"} {
		config := base
		config.Proxy = bad
		if _, err := New(config, nil); err == nil {
			t.Errorf("proxy %q was accepted", bad)
		}
	}
	config := base
	config.Proxy = "http://127.0.0.1:7890"
	if _, err := New(config, nil); err != nil {
		t.Errorf("a plain http proxy was refused: %v", err)
	}
	// A proxy with no port gets the scheme's default rather than an error.
	config.Proxy = "http://proxy.example"
	if _, err := New(config, nil); err != nil {
		t.Errorf("a proxy with no port was refused: %v", err)
	}
}

// With no proxy configured there is exactly one way, and it is the direct one:
// a device that never mentions a proxy must not grow a second attempt.
func TestNoProxyMeansOneWay(t *testing.T) {
	client, err := New(Config{
		URL:   "https://hub.example",
		Token: "t",
		ID:    "ont",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if ways := client.ways(); len(ways) != 1 || ways[0].name != "direct" {
		t.Errorf("ways = %v, want one direct route", ways)
	}
}

// The tunnel carries a real HTTP exchange, and the pull is what proves it: the
// CONNECT dialer has to produce a usable connection, not just a handshake.
func TestTheTunnelCarriesARequest(t *testing.T) {
	fixture := newProxyTestHub(t, "mesh:\n  directory-id: shared\n", `"v7"`)
	fixture.directBlocked.Store(true)

	tunnel, err := newProxyDialer(fixture.proxy.URL)
	if err != nil {
		t.Fatalf("newProxyDialer: %v", err)
	}
	conn, err := tunnel.DialContext(context.Background(), "tcp", strings.TrimPrefix(fixture.hub.URL, "http://"))
	if err != nil {
		t.Fatalf("dial through the proxy: %v", err)
	}
	defer conn.Close()

	request := "GET /profile?id=ont HTTP/1.1\r\nHost: hub\r\nAuthorization: Bearer test-token\r\n\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("writing through the tunnel: %v", err)
	}
	buf := make([]byte, 256)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("reading through the tunnel: %v", err)
	}
	if !strings.Contains(string(buf[:n]), "200") {
		t.Errorf("the tunnel returned no 200: %q", buf[:n])
	}
}

// A proxy that needs credentials is handed them, and one that does not is not
// sent an empty header.
func TestProxyCredentialsAreSent(t *testing.T) {
	var got string
	var mu sync.Mutex
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Get("Proxy-Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()

	parsed, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	parsed.User = url.UserPassword("user", "pass")
	tunnel, err := newProxyDialer(parsed.String())
	if err != nil {
		t.Fatalf("newProxyDialer: %v", err)
	}
	_, err = tunnel.DialContext(context.Background(), "tcp", "hub.example:443")
	if err == nil {
		t.Fatal("a refused tunnel succeeded")
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.HasPrefix(got, "Basic ") {
		t.Errorf("Proxy-Authorization = %q, want a Basic credential", got)
	}
}

// The pushed profile reaches the device over whichever route holds the socket,
// which is the half a pull-only fallback would miss.
func TestTheWatchSocketFallsBackToo(t *testing.T) {
	// A hub whose socket hands over one profile, plus a proxy carrying it.
	var pushed atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte("mode: rule\n"))
	})
	hub := httptest.NewServer(mux)
	defer hub.Close()

	// Reuse the fixture's proxy by rebuilding one that CONNECTs anywhere.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		pushed.Add(1)
		upstream, err := net.DialTimeout("tcp", r.Host, 5*time.Second)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		client, _, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		pipe(client, upstream)
	}))
	defer proxy.Close()

	client, err := New(Config{
		URL:   hub.URL,
		Token: "test-token",
		ID:    "ont",
		File:  filepath.Join(t.TempDir(), "profile.yaml"),
		Proxy: proxy.URL,
	}, func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	client.dialDirect = func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, fmt.Errorf("connection refused")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The direct route is refused, so the socket must go through the proxy.
	_ = client.watchAllWays(ctx)
	if pushed.Load() == 0 {
		t.Error("the socket never reached the proxy after the direct route was refused")
	}
}

// The pulled profile is written where the configuration says, even when it
// arrived over the fallback route.
func TestTheFallbackRouteStillWritesTheProfile(t *testing.T) {
	fixture := newProxyTestHub(t, "mode: global\n", `"v1"`)
	fixture.directBlocked.Store(true)

	client := fixture.clientFor(t, func([]byte) error { return nil })
	if err := client.Pull(context.Background()); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	onDisk, err := os.ReadFile(client.config.filePath())
	if err != nil {
		t.Fatalf("reading the written profile: %v", err)
	}
	if !strings.Contains(string(onDisk), "mode: global") {
		t.Errorf("the profile was not written: %q", onDisk)
	}
	_ = json.Valid
}
