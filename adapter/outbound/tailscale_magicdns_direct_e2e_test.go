//go:build with_gvisor && !no_tailscale && tailscale_magicdns_direct_e2e

package outbound

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/iface"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/tailscale/net/netns"
	"github.com/metacubex/tailscale/net/stun/stuntest"
	"github.com/metacubex/tailscale/tailcfg"
	"github.com/metacubex/tailscale/tstest/integration/testcontrol"
	"github.com/metacubex/tailscale/types/nettype"
	D "github.com/miekg/dns"
)

func TestTailscaleMagicDNSDirectE2E(t *testing.T) {
	oldHome := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() { C.SetHomeDir(oldHome) })

	controlURL := startMagicDNSDirectControl(t)
	server, err := NewTailscale(TailscaleOption{
		Name:       "md-server",
		Hostname:   "md-server",
		ControlURL: controlURL,
		StateDir:   filepath.Join("tailscale-magicdns-direct-e2e", "server"),
		Ephemeral:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	client, err := NewTailscale(TailscaleOption{
		Name:       "md-client",
		Hostname:   "md-client",
		ControlURL: controlURL,
		StateDir:   filepath.Join("tailscale-magicdns-direct-e2e", "client"),
		Ephemeral:  true,
		MagicDNS:   true,
		MagicDNSDirect: TailscaleMagicDNSDirectOption{
			Enabled:      true,
			ProbeTimeout: 2_000,
			CacheTTL:     1,
			AnswerTTL:    2,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	if err := server.ensureStarted(ctx); err != nil {
		t.Fatal(err)
	}
	if err := client.ensureStarted(ctx); err != nil {
		t.Fatal(err)
	}

	var serverIPv4 netip.Addr
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		serverIPv4, _ = server.server.TailscaleIPs()
		if serverIPv4.IsValid() {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	if !serverIPv4.IsValid() {
		t.Fatal("server did not receive a Tailnet IPv4 address within 30s")
	}
	serverName := "md-server.tail-scale.ts.net."

	internalTransport := tailscaleDNSTransport{tailscale: client}
	internalIP, err := queryMagicDNSDirectA(ctx, internalTransport, serverName)
	if err != nil {
		t.Fatal(err)
	}
	if internalIP != serverIPv4 {
		t.Fatalf("internal Tailscale DNS returned %s, want Tailnet IP %s", internalIP, serverIPv4)
	}

	externalTransport := tailscaleDNSTransport{tailscale: client, allowDirect: true}
	var directIP netip.Addr
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		directIP, err = queryMagicDNSDirectA(ctx, externalTransport, serverName)
		if err == nil && directIP.IsValid() && directIP != serverIPv4 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Second):
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	if !directIP.IsValid() || directIP == serverIPv4 {
		status, statusErr := client.TailnetStatus(ctx)
		probedIP, probeErr := client.magicDNSDirect.probeEndpoint(ctx, serverIPv4)
		var validationErr error
		if probeErr == nil {
			validationErr = client.magicDNSDirect.validateDirectAddr(probedIP)
		}
		client.magicDNSDirect.mu.RLock()
		peerCount := len(client.magicDNSDirect.peerAddrs)
		cacheEntry := client.magicDNSDirect.cache[serverIPv4]
		client.magicDNSDirect.mu.RUnlock()
		t.Fatalf("MagicDNS did not select a direct address; last answer=%s statusErr=%v status=%s peerAddrs=%d cache=%+v probe=%s probeErr=%v validationErr=%v", directIP, statusErr, status.Text(), peerCount, cacheEntry, probedIP, probeErr, validationErr)
	}
	if err := client.magicDNSDirect.validateDirectAddr(directIP); err != nil {
		t.Fatalf("rewritten address %s is not connected: %v", directIP, err)
	}

	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	payload := []byte("mihomo-magicdns-direct-ok")
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write(payload)
	}()

	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", netip.AddrPortFrom(directIP, port).String())
	if err != nil {
		t.Fatalf("raw TCP dial to rewritten address %s failed: %v", directIP, err)
	}
	defer conn.Close()
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, received); err != nil {
		t.Fatal(err)
	}
	if string(received) != string(payload) {
		t.Fatalf("raw TCP payload = %q, want %q", received, payload)
	}
	t.Logf("MagicDNS selected connected endpoint %s and raw TCP succeeded", directIP)
}

func queryMagicDNSDirectA(ctx context.Context, transport tailscaleDNSTransport, name string) (netip.Addr, error) {
	request := new(D.Msg)
	request.SetQuestion(name, D.TypeA)
	response, err := transport.ExchangeContext(ctx, request)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, answer := range response.Answer {
		if record, ok := answer.(*D.A); ok {
			if addr, ok := netip.AddrFromSlice(record.A); ok {
				return addr.Unmap(), nil
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("no A answer for %s", name)
}

func startMagicDNSDirectControl(t *testing.T) string {
	t.Helper()
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })

	stunIP := magicDNSDirectTestIPv4(t)
	stunAddr, stunCleanup := stuntest.ServeWithPacketListener(t, magicDNSDirectPacketListener{addr: stunIP})
	t.Cleanup(stunCleanup)
	derpMap := &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
		1: {
			RegionID:   1,
			RegionCode: "test",
			Nodes: []*tailcfg.DERPNode{{
				Name:             "t1",
				RegionID:         1,
				HostName:         stunIP.String(),
				IPv4:             stunIP.String(),
				IPv6:             "none",
				STUNPort:         stunAddr.Port,
				DERPPort:         9,
				InsecureForTests: true,
				STUNTestIP:       stunIP.String(),
			}},
		},
	}}
	control := &testcontrol.Server{
		DERPMap: derpMap,
		DNSConfig: &tailcfg.DNSConfig{
			Proxied: true,
		},
		MagicDNSDomain: "tail-scale.ts.net",
		Logf:           t.Logf,
		AllOnline:      true,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	return control.HTTPTestServer.URL
}

type magicDNSDirectPacketListener struct {
	addr netip.Addr
}

func (l magicDNSDirectPacketListener) ListenPacket(ctx context.Context, network, _ string) (net.PacketConn, error) {
	var config net.ListenConfig
	return config.ListenPacket(ctx, network, net.JoinHostPort(l.addr.String(), "0"))
}

func magicDNSDirectTestIPv4(t *testing.T) netip.Addr {
	t.Helper()
	interfaces, err := iface.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(interfaces))
	for name := range interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		localInterface := interfaces[name]
		if localInterface.Flags&net.FlagUp == 0 || localInterface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
			continue
		}
		for _, prefix := range localInterface.Addresses {
			addr := prefix.Addr().Unmap()
			if addr.Is4() && prefix.Bits() < addr.BitLen() {
				return addr
			}
		}
	}
	t.Fatal("test requires a connected non-loopback IPv4 interface")
	return netip.Addr{}
}

var _ nettype.PacketListener = magicDNSDirectPacketListener{}
