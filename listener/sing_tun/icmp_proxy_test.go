package sing_tun

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// A ping tool sends an IPv6 echo request; the destination must hand the ICMP
// message to the outbound untouched and write a reply that the tool accepts.
func TestParseEchoKeepsTheMessageAndBuildsTheReply(t *testing.T) {
	request := echoRequest(128, 0x1234, 7, []byte("payload"))
	packet := ipv6Packet(netip.MustParseAddr("fd7a:115c:a1e0::1"), netip.MustParseAddr("2409:8a55::1"), request)

	message, build, err := parseEcho(packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(message) != len(request) ||
		binary.BigEndian.Uint16(message[4:6]) != 0x1234 ||
		binary.BigEndian.Uint16(message[6:8]) != 7 {
		t.Fatalf("message = % x, want the original echo request", message)
	}

	reply := echoRequest(129, 0x1234, 7, []byte("payload"))
	answer, err := build(reply)
	if err != nil {
		t.Fatal(err)
	}
	// Source and destination swap, the payload survives and the checksum is
	// recomputed for the tuple this packet is written into.
	source := netip.AddrFrom16([16]byte(answer[8:24]))
	destination := netip.AddrFrom16([16]byte(answer[24:40]))
	if source.String() != "2409:8a55::1" || destination.String() != "fd7a:115c:a1e0::1" {
		t.Fatalf("reply addresses = %s -> %s", source, destination)
	}
	if answer[40] != 129 {
		t.Fatalf("reply type = %d, want an echo reply", answer[40])
	}
	if got := answer[48:]; string(got) != "payload" {
		t.Fatalf("reply payload = %q", got)
	}
	if sum := icmpv6Checksum(source, destination, answer[40:]); sum != 0 {
		t.Fatalf("ICMPv6 checksum does not verify: %#x", sum)
	}
}

func TestParseEchoIPv4(t *testing.T) {
	request := echoRequest(8, 0xbeef, 1, []byte("x"))
	source := netip.MustParseAddr("172.19.0.1")
	destination := netip.MustParseAddr("223.5.5.5")
	packet := ipv4Packet(source, destination, request)

	message, build, err := parseEcho(packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(message) != len(request) {
		t.Fatalf("message = % x", message)
	}
	reply := echoRequest(0, 0xbeef, 1, []byte("x"))
	answer, err := build(reply)
	if err != nil {
		t.Fatal(err)
	}
	if answer[12+0] != 223 || answer[12+3] != 5 || answer[16+0] != 172 {
		t.Fatalf("reply addresses = %v -> %v", answer[12:16], answer[16:20])
	}
	if sum := checksum(answer[:20]); sum != 0 {
		t.Fatalf("IPv4 header checksum does not verify: %#x", sum)
	}
	if sum := checksum(answer[20:]); sum != 0 {
		t.Fatalf("ICMPv4 checksum does not verify: %#x", sum)
	}
}

func TestParseEchoRejectsWhatItCannotAnswer(t *testing.T) {
	if _, _, err := parseEcho(nil); err == nil {
		t.Fatal("an empty packet was accepted")
	}
	// An echo *reply* is not a request and must not be answered again.
	reply := ipv6Packet(netip.MustParseAddr("2409::1"), netip.MustParseAddr("fd7a::1"), echoRequest(129, 1, 1, nil))
	if _, _, err := parseEcho(reply); err == nil {
		t.Fatal("an echo reply was accepted as a request")
	}
}

// An echo that cannot be put on the wire is answered the way a router answers:
// the tool is told the destination cannot be reached, and its own packet
// travels inside the error so it can match the two.
func TestUnreachableReplyQuotesThePacket(t *testing.T) {
	request := echoRequest(8, 0x1234, 7, []byte("payload"))
	packet := ipv4Packet(netip.MustParseAddr("7.0.0.0"), netip.MustParseAddr("7.0.0.4"), request)
	answer, err := unreachableReply(packet)
	if err != nil {
		t.Fatalf("unreachableReply: %v", err)
	}
	if answer[20] != 3 || answer[21] != 1 {
		t.Fatalf("error type %d code %d, want destination unreachable/host", answer[20], answer[21])
	}
	if got := netip.AddrFrom4([4]byte(answer[12:16])); got.String() != "7.0.0.4" {
		t.Fatalf("error comes from %s, want the address that was pinged", got)
	}
	if got := answer[28:]; string(got) != string(packet[:28]) {
		t.Fatal("the packet that could not be delivered is not quoted in the error")
	}
	if sum := checksum(answer[:20]); sum != 0 {
		t.Fatalf("IPv4 header checksum does not verify: %#x", sum)
	}
	if sum := checksum(answer[20:]); sum != 0 {
		t.Fatalf("ICMPv4 checksum does not verify: %#x", sum)
	}

	packet6 := ipv6Packet(netip.MustParseAddr("fd7a:115c:a1e0::1"), netip.MustParseAddr("2001::fdfe:dcba:9876:4"), echoRequest(128, 1, 1, nil))
	answer6, err := unreachableReply(packet6)
	if err != nil {
		t.Fatalf("unreachableReply: %v", err)
	}
	if answer6[40] != 1 || answer6[41] != 0 {
		t.Fatalf("error type %d code %d, want destination unreachable/no route", answer6[40], answer6[41])
	}
	if got := answer6[48:]; string(got) != string(packet6[:48]) {
		t.Fatal("the packet that could not be delivered is not quoted in the error")
	}
	source := netip.AddrFrom16([16]byte(answer6[8:24]))
	destination := netip.AddrFrom16([16]byte(answer6[24:40]))
	if sum := icmpv6Checksum(source, destination, answer6[40:]); sum != 0 {
		t.Fatalf("ICMPv6 checksum does not verify: %#x", sum)
	}
}

// A flow that was pinged as a placeholder travels to the address the name
// stands for, and its answer comes back as the placeholder: both are the same
// bytes with one address changed, and the checksums that cover that address are
// recomputed.
func TestReaddressedPacketsKeepTheirChecksums(t *testing.T) {
	real := netip.MustParseAddr("123.56.139.83")
	packet := ipv4Packet(netip.MustParseAddr("7.0.0.0"), netip.MustParseAddr("7.0.0.4"), echoRequest(8, 1, 1, []byte("x")))
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))

	out := readdress(packet, real, false)
	if got := netip.AddrFrom4([4]byte(out[16:20])); got != real {
		t.Fatalf("request destination = %s", got)
	}
	if sum := checksum(out[:20]); sum != 0 {
		t.Fatalf("IPv4 header checksum does not verify: %#x", sum)
	}
	if got := netip.AddrFrom4([4]byte(packet[16:20])); got == real || got.String() != "7.0.0.4" {
		t.Fatal("the packet handed in was modified")
	}

	answer := ipv4Packet(real, netip.MustParseAddr("7.0.0.0"), echoRequest(0, 1, 1, []byte("x")))
	binary.BigEndian.PutUint16(answer[10:12], checksum(answer[:20]))
	back := readdress(answer, netip.MustParseAddr("7.0.0.4"), true)
	if got := netip.AddrFrom4([4]byte(back[12:16])); got.String() != "7.0.0.4" {
		t.Fatalf("answer source = %s", got)
	}
	if sum := checksum(back[:20]); sum != 0 {
		t.Fatalf("IPv4 header checksum does not verify: %#x", sum)
	}

	packet6 := ipv6Packet(netip.MustParseAddr("fdfe:dcba:9876::1"), netip.MustParseAddr("2001::fdfe:dcba:9876:4"), echoRequest(128, 2, 2, nil))
	real6 := netip.MustParseAddr("2400:3200::1")
	out6 := readdress(packet6, real6, false)
	if got := netip.AddrFrom16([16]byte(out6[24:40])); got != real6 {
		t.Fatalf("IPv6 request destination = %s", got)
	}
	answer6 := ipv6Packet(real6, netip.MustParseAddr("fdfe:dcba:9876::1"), echoRequest(129, 2, 2, nil))
	back6 := readdress(answer6, netip.MustParseAddr("2001::fdfe:dcba:9876:4"), true)
	source := netip.AddrFrom16([16]byte(back6[8:24]))
	destination := netip.AddrFrom16([16]byte(back6[24:40]))
	if source.String() != "2001::fdfe:dcba:9876:4" {
		t.Fatalf("IPv6 answer source = %s", source)
	}
	if sum := icmpv6Checksum(source, destination, back6[40:]); sum != 0 {
		t.Fatalf("ICMPv6 checksum does not verify: %#x", sum)
	}
}

// echoRequest builds an ICMP echo message: type, code, checksum, id, sequence.
func echoRequest(kind byte, id uint16, sequence uint16, payload []byte) []byte {
	message := make([]byte, 8+len(payload))
	message[0] = kind
	binary.BigEndian.PutUint16(message[4:6], id)
	binary.BigEndian.PutUint16(message[6:8], sequence)
	copy(message[8:], payload)
	return message
}

func ipv6Packet(source, destination netip.Addr, payload []byte) []byte {
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	packet[6] = 58
	packet[7] = 64
	source16, destination16 := source.As16(), destination.As16()
	copy(packet[8:24], source16[:])
	copy(packet[24:40], destination16[:])
	copy(packet[40:], payload)
	return packet
}

func ipv4Packet(source, destination netip.Addr, payload []byte) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 1
	source4, destination4 := source.As4(), destination.As4()
	copy(packet[12:16], source4[:])
	copy(packet[16:20], destination4[:])
	copy(packet[20:], payload)
	return packet
}
