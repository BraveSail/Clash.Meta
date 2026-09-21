package adapter

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
)

// hostRelay records the metadata a tailnet-peer is handed when it dials, so a
// test can see what the outbound knows about the connection it serves.
type hostRelay struct {
	received chan *C.Metadata
}

func (h *hostRelay) DialContext(_ context.Context, metadata *C.Metadata) (C.Conn, error) {
	select {
	case h.received <- metadata:
	default:
	}
	server, client := net.Pipe()
	_ = server.Close()
	return outbound.NewConn(client, h), nil
}

func (h *hostRelay) ListenPacketContext(context.Context, *C.Metadata) (C.PacketConn, error) {
	return nil, errors.New("unsupported in this stub")
}
func (h *hostRelay) SupportUDP() bool                      { return false }
func (h *hostRelay) SupportUOT() bool                      { return false }
func (h *hostRelay) IsL3Protocol(*C.Metadata) bool         { return false }
func (h *hostRelay) Unwrap(*C.Metadata, bool) C.Proxy      { return nil }
func (h *hostRelay) Addr() string                          { return "" }
func (h *hostRelay) MarshalJSON() ([]byte, error)          { return []byte(`{}`), nil }
func (h *hostRelay) Type() C.AdapterType                   { return C.Direct }
func (h *hostRelay) Name() string                          { return "relay" }
func (h *hostRelay) StreamConn(net.Conn) (net.Conn, error) { return nil, errors.New("stub") }
func (h *hostRelay) PacketConn(net.PacketConn) (C.PacketConn, error) {
	return nil, errors.New("stub")
}
func (h *hostRelay) DialContextWithDialer(context.Context, C.Dialer, *C.Metadata) (C.Conn, error) {
	return nil, errors.New("stub")
}
func (h *hostRelay) ListenPacketContextWithDialer(context.Context, C.Dialer, *C.Metadata) (C.PacketConn, error) {
	return nil, errors.New("stub")
}
func (h *hostRelay) Alive() bool  { return true }
func (h *hostRelay) Close() error { return nil }
func (h *hostRelay) ProxyInfo() C.ProxyInfo {
	return C.ProxyInfo{ProviderName: ""}
}

// A rule that points at the mesh has to be answered by the device the requested
// name belongs to. The outbound itself is chosen by the rule before anything
// knows which device was asked for, so the name can only travel on the
// connection's metadata; this pins that it is still there when the inner proxy
// is dialled.
func TestTailnetPeerDialCarriesTheRequestedHost(t *testing.T) {
	relay := &hostRelay{received: make(chan *C.Metadata, 1)}

	// A directory that answers with a peer which is not this node: the dial
	// then goes through the inner proxy, which is where the metadata lands.
	stub := &stubDirectory{ownID: "this-device", peerID: "pc", peerAddr: "127.0.0.1"}
	server := stub.serve()
	t.Cleanup(server.Close)

	peer := newTestPeer(t, TailnetPeerOption{
		Name:           "mesh",
		Peer:           "pc",
		Port:           23333,
		Proxy:          map[string]any{"type": "direct", "name": "inner"},
		DirectoryURL:   server.URL,
		DirectoryToken: "secret",
		DirectoryID:    "this-device",
	})
	peer.inner = NewProxy(relay)
	peer.innerHost = "127.0.0.1"

	go func() {
		conn, err := peer.DialContext(context.Background(), &C.Metadata{
			NetWork: C.TCP,
			Host:    "pc.lan",
			DstIP:   netip.MustParseAddr("7.0.0.1"),
			DstPort: 23333,
			DNSMode: C.DNSFakeIP,
		})
		if err == nil && conn != nil {
			_ = conn.Close()
		}
	}()

	select {
	case metadata := <-relay.received:
		if metadata.Host != "pc.lan" {
			t.Fatalf("the inner proxy was handed host %q, want the requested name", metadata.Host)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the dial never reached the inner proxy")
	}
}

// The name a connection asks for is not what the outbound resolves by today:
// it asks the directory about its own configured peer. This is the behaviour a
// by-name rule needs to change, so it is pinned here rather than assumed.
func TestTailnetPeerResolvesByItsConfiguredName(t *testing.T) {
	stub := &stubDirectory{ownID: "this-device", peerID: "pc", peerAddr: "2409:895a::1"}
	server := stub.serve()
	t.Cleanup(server.Close)

	peer := newTestPeer(t, TailnetPeerOption{
		Name:           "mesh",
		Peer:           "pc",
		Port:           23333,
		Proxy:          map[string]any{"type": "direct", "name": "inner"},
		DirectoryURL:   server.URL,
		DirectoryToken: "secret",
		DirectoryID:    "this-device",
	})

	host, self, err := peer.resolve(context.Background())
	if err != nil || self {
		t.Fatalf("resolve = %q self=%v err=%v", host, self, err)
	}
	if host != "2409:895a::1" {
		t.Fatalf("resolve = %q, want the peer's recorded address", host)
	}
}
