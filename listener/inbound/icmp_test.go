package inbound

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/icmptunnel"
)

// The responder is the far end of a carried echo: an envelope arrives over UDP
// and a real echo has to leave for the address inside it. 223.5.5.5 is a public
// resolver that answers ICMP, so the test fails when the path is broken rather
// than when the network is.
func TestResponderAnswersWithARealEcho(t *testing.T) {
	// The option carries the port that was configured, so the port is claimed
	// first and handed to the listener.
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()

	listener, err := NewICMPResponder(&ICMPResponderOption{
		BaseOption: BaseOption{Listen: "127.0.0.1", Port: strconv.Itoa(port)},
		Timeout:    3,
	})
	if err != nil {
		t.Fatalf("NewICMPResponder: %v", err)
	}
	if err := listener.Listen(nil); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	address := listener.Address()
	if address == "" {
		t.Fatalf("the responder did not report a usable address: %q", address)
	}

	request := make([]byte, 8+len("peer-directory"))
	request[0] = 8 // echo request
	binary.BigEndian.PutUint16(request[4:6], 0x1234)
	binary.BigEndian.PutUint16(request[6:8], 7)
	copy(request[8:], "peer-directory")
	envelope, err := icmptunnel.Encode(netip.MustParseAddr("223.5.5.5"), request)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	conn, err := net.Dial("udp", address)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(envelope); err != nil {
		t.Fatalf("Write: %v", err)
	}

	buffer := make([]byte, 2048)
	length, err := conn.Read(buffer)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	target, reply, err := icmptunnel.Decode(buffer[:length])
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if target != netip.MustParseAddr("223.5.5.5") {
		t.Fatalf("answer names %s", target)
	}
	if len(reply) != len(request) {
		t.Fatalf("answer is %d bytes, want %d", len(reply), len(request))
	}
	if reply[0] != 0 {
		t.Fatalf("answer type is %d, want an echo reply", reply[0])
	}
	if binary.BigEndian.Uint16(reply[4:6]) != 0x1234 || binary.BigEndian.Uint16(reply[6:8]) != 7 {
		t.Fatalf("answer carries identifier %#x sequence %d",
			binary.BigEndian.Uint16(reply[4:6]), binary.BigEndian.Uint16(reply[6:8]))
	}
	if string(reply[8:]) != "peer-directory" {
		t.Fatalf("answer payload is %q", reply[8:])
	}
}
