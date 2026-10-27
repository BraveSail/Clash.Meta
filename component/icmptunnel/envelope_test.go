package icmptunnel

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	for _, target := range []netip.Addr{netip.MustParseAddr("223.5.5.5"), netip.MustParseAddr("2400:3200::1")} {
		message := echoRequestMessage(target, 0x1234, 5, []byte("payload"))
		envelope, err := Encode(target, message)
		if err != nil {
			t.Fatal(err)
		}
		gotTarget, gotMessage, err := Decode(envelope)
		if err != nil {
			t.Fatal(err)
		}
		if gotTarget != target || string(gotMessage) != string(message) {
			t.Fatalf("decoded %s % x, want %s % x", gotTarget, gotMessage, target, message)
		}
	}
}

func TestDecodeRefusesWhatIsNotAnEnvelope(t *testing.T) {
	if _, _, err := Decode([]byte("nope")); err == nil {
		t.Fatal("a short packet was accepted")
	}
	if _, _, err := Decode([]byte("PDXX\x01\x06")); err == nil {
		t.Fatal("a packet without the magic was accepted")
	}
	if _, _, err := Decode([]byte("PDIC\x02\x06")); err == nil {
		t.Fatal("an unknown version was accepted")
	}
}

// The responder puts a real echo on the wire; this is the same code path, so a
// reachable target has to answer with an echo reply that carries the identifier
// and payload the caller used.
func TestExchangeAnswersFromARealTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("needs the network")
	}
	for _, target := range []netip.Addr{netip.MustParseAddr("223.5.5.5"), netip.MustParseAddr("2400:3200::1")} {
		request := echoRequestMessage(target, 0xbeef, 11, []byte("peer-directory"))
		start := time.Now()
		reply, err := Exchange(context.Background(), target, request, 3*time.Second)
		if err != nil {
			t.Skipf("no ICMP answer from %s here: %v", target, err)
		}
		if len(reply) < messageHeaderLength {
			t.Fatalf("%s: reply is %d bytes", target, len(reply))
		}
		wantType := byte(0)
		if target.Is6() {
			wantType = 129
		}
		if reply[0] != wantType {
			t.Fatalf("%s: reply type = %d, want %d", target, reply[0], wantType)
		}
		if id := binary.BigEndian.Uint16(reply[4:6]); id != 0xbeef {
			t.Fatalf("%s: reply identifier = %#x, want the caller's", target, id)
		}
		if sequence := binary.BigEndian.Uint16(reply[6:8]); sequence != 11 {
			t.Fatalf("%s: reply sequence = %d, want the caller's", target, sequence)
		}
		if payload := string(reply[messageHeaderLength:]); payload != "peer-directory" {
			t.Fatalf("%s: reply payload = %q", target, payload)
		}
		t.Logf("%s answered in %s", target, time.Since(start).Round(time.Millisecond))
	}
}

func echoRequestMessage(target netip.Addr, id uint16, sequence uint16, payload []byte) []byte {
	message := make([]byte, messageHeaderLength+len(payload))
	if target.Is4() {
		message[0] = 8
	} else {
		message[0] = 128
	}
	binary.BigEndian.PutUint16(message[4:6], id)
	binary.BigEndian.PutUint16(message[6:8], sequence)
	copy(message[messageHeaderLength:], payload)
	return message
}
