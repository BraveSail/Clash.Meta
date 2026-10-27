package config

import (
	"net"
	"strconv"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener"
)

// The listener a derived mesh produces has to bind. VLESS refuses to serve
// without a certificate, a reality configuration or an encryption key - the
// check that rejected the derived listener - and a configuration that parses
// but cannot bind leaves the device unable to reach any peer.
//
// This exercises the path the app takes - parse, then Listen - rather than the
// parse alone, because the two disagreed: the parse succeeded while the bind
// failed, and nothing in the parse tests would have said so.
func TestDerivedMeshListenerBinds(t *testing.T) {
	rawCfg := &RawConfig{
		Mesh: &RawMesh{
			DirectoryURL:      "https://hub.example",
			DirectoryToken:    "secret",
			DirectoryID:       "this-device",
			Devices:           []RawMeshDevice{{Name: "pc", ID: "aaaa1111"}},
			DirectoryResolved: true,
		},
	}
	if err := expandMesh(rawCfg); err != nil {
		t.Fatal(err)
	}
	if len(rawCfg.Listeners) != 1 {
		t.Fatalf("expanded %d listeners, want the one this device serves", len(rawCfg.Listeners))
	}

	// A port nothing else holds, so a failure is the listener's own.
	port := freePort(t)
	mapping := rawCfg.Listeners[0]
	mapping["port"] = port
	mapping["listen"] = "127.0.0.1"

	bound, err := listener.ParseListener(mapping)
	if err != nil {
		t.Fatalf("the derived listener did not parse: %v", err)
	}
	if err := bound.Listen(nopTunnel{}); err != nil {
		t.Fatalf("the derived listener did not bind: %v", err)
	}
	defer func() { _ = bound.Close() }()

	// Bound and answering: the port accepts a connection.
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		t.Fatalf("the derived listener bound but does not accept: %v", err)
	}
	_ = conn.Close()
}

// A written listener keeps its own options: the derivation only fills a block
// that wrote neither half.
func TestWrittenListenerKeepsItsOptions(t *testing.T) {
	written := map[string]any{
		"type":       "vless",
		"users":      []any{map[string]any{"uuid": "11111111-2222-3333-4444-555555555555"}},
		"decryption": "mlkem768x25519plus.native.600s.somebody-elses-key",
	}
	rawCfg := &RawConfig{
		Mesh: &RawMesh{
			DirectoryURL:   "https://hub.example",
			DirectoryToken: "secret",
			DirectoryID:    "this-device",
			Listener:       written,
			Proxy:          map[string]any{"type": "vless", "uuid": "x"},
			Devices:        []RawMeshDevice{{Name: "pc"}},
		},
	}
	if err := expandMesh(rawCfg); err != nil {
		t.Fatal(err)
	}
	decryption, _ := meshEncryptionKeys("secret")
	if got := rawCfg.Listeners[0]["decryption"]; got == decryption {
		t.Fatal("a written listener had its decryption replaced by the derived one")
	}
}

// The client half the outbounds carry has to be the one the listener's server
// half answers, or two devices of one mesh could not complete a handshake.
func TestDerivedMeshEncryptionPairMatches(t *testing.T) {
	rawCfg := &RawConfig{
		Mesh: &RawMesh{
			DirectoryURL:      "https://hub.example",
			DirectoryToken:    "secret",
			DirectoryID:       "this-device",
			Devices:           []RawMeshDevice{{Name: "pc", ID: "aaaa1111"}},
			DirectoryResolved: true,
		},
	}
	if err := expandMesh(rawCfg); err != nil {
		t.Fatal(err)
	}
	decryption, _ := meshEncryptionKeys("secret")
	if got := rawCfg.Listeners[0]["decryption"]; got != decryption {
		t.Fatalf("listener decryption = %v, want the derived server half", got)
	}
	derived, ok := rawCfg.Proxy[0]["proxy"].(map[string]any)
	if !ok {
		t.Fatal("the expanded outbound carries no proxy mapping")
	}
	_, encryptionValue := meshEncryptionKeys("secret")
	if got := derived["encryption"]; got != encryptionValue {
		t.Fatalf("outbound encryption = %v, want the derived client half", got)
	}
}

// nopTunnel satisfies the tunnel interface the listener needs to start; this
// test only asks whether the listener binds, so nothing routes through it.
type nopTunnel struct{}

func (nopTunnel) HandleTCPConn(net.Conn, *C.Metadata)      {}
func (nopTunnel) HandleUDPPacket(C.UDPPacket, *C.Metadata) {}
func (nopTunnel) NatTable() C.NatTable                     { return nil }

func freePort(t *testing.T) int {
	t.Helper()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	return port
}
