package hubprofile

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
)

// proxyDialer reaches a host through an HTTP proxy's CONNECT tunnel.
//
// The core has no such dialer of its own - its outbound HTTP proxy is built on
// http.Transport, which the socket dial cannot use (the websocket dialer takes
// a net.Conn, not a transport). The hub channel needs both halves to share one
// route, or a network that only reaches the proxy could pull its profile and
// never hear a push.
//
// The tunnel is established with the core's own dialer, so reaching the proxy
// never depends on the proxy.
type proxyDialer struct {
	// proxy is the parsed proxy URL, with user info when the proxy needs one.
	proxy *url.URL
	// direct dials the proxy itself.
	direct func(ctx context.Context, network, address string) (net.Conn, error)
}

// newProxyDialer builds a dialer for an http or https proxy URL. The proxy
// itself is reached with the core's dialer; only the tunneled leg goes through
// it.
func newProxyDialer(rawProxyURL string) (*proxyDialer, error) {
	raw := strings.TrimSpace(rawProxyURL)
	if raw == "" {
		return nil, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("profile: invalid proxy url %q: %w", raw, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("profile: proxy url %q must be http or https", raw)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("profile: proxy url %q names no host", raw)
	}
	if !strings.Contains(parsed.Host, ":") {
		port := "80"
		if parsed.Scheme == "https" {
			port = "443"
		}
		parsed.Host = net.JoinHostPort(parsed.Host, port)
	}
	return &proxyDialer{
		proxy: parsed,
		direct: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
	}, nil
}

// DialContext opens a tunnel to address through the proxy.
//
// Only TCP is supported: an HTTP proxy's CONNECT carries a byte stream, which
// is what both the profile pull and the watch socket need.
func (p *proxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("profile: a proxy tunnel carries tcp, not %s", network)
	}
	conn, err := p.direct(ctx, "tcp", p.proxy.Host)
	if err != nil {
		return nil, fmt.Errorf("profile: dial proxy %s: %w", p.proxy.Host, err)
	}
	if p.proxy.Scheme == "https" {
		conn = tlsClient(conn, proxyHostname(p.proxy))
	}
	if err := p.establish(ctx, conn, address); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// establish writes the CONNECT request and reads the proxy's answer.
func (p *proxyDialer) establish(ctx context.Context, conn net.Conn, address string) error {
	var request strings.Builder
	request.WriteString("CONNECT " + address + " HTTP/1.1\r\n")
	request.WriteString("Host: " + address + "\r\n")
	if user := p.proxy.User; user != nil {
		password, _ := user.Password()
		credentials := user.Username() + ":" + password
		request.WriteString(
			"Proxy-Authorization: Basic " +
				base64.StdEncoding.EncodeToString([]byte(credentials)) + "\r\n",
		)
	}
	request.WriteString("Proxy-Connection: keep-alive\r\n")
	request.WriteString("\r\n")

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
		defer func() {
			_ = conn.SetDeadline(timeZero)
		}()
	}
	if _, err := conn.Write([]byte(request.String())); err != nil {
		return fmt.Errorf("profile: proxy CONNECT to %s: %w", address, err)
	}

	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return fmt.Errorf("profile: proxy answer for %s: %w", address, err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("profile: proxy refused %s: %s", address, response.Status)
	}
	return nil
}

// proxyHostname is the name to verify a TLS proxy's certificate against, with
// the port stripped.
func proxyHostname(proxy *url.URL) string {
	host, _, err := net.SplitHostPort(proxy.Host)
	if err != nil {
		return proxy.Host
	}
	return host
}

// tlsClient wraps a connection to a TLS proxy. The proxy's own certificate is
// verified against its hostname: a proxy worth reaching over TLS is one whose
// identity matters, and skipping the check would make the scheme decorative.
func tlsClient(conn net.Conn, hostname string) net.Conn {
	return tls.Client(conn, &tls.Config{ServerName: hostname})
}

// timeZero clears a deadline set for an operation that is over.
var timeZero = time.Time{}
