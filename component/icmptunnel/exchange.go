package icmptunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
)

// An ICMP echo request/reply pair is eight bytes of header (type, code,
// checksum, identifier, sequence) followed by whatever the sender put in.
const messageHeaderLength = 8

var (
	ErrNotEchoRequest = errors.New("icmp tunnel: not an echo request")
	// ErrLocalPath says the outbound the rules picked cannot carry this echo
	// because it is this very node: a real echo from here would enter this
	// node's own rules again, so the flow has to keep the direct path it would
	// have had without an ICMP carrier.
	ErrLocalPath = errors.New("icmp tunnel: this node carries the echo")
)

// EchoRequest describes the message a responder has to put on the wire.
type EchoRequest struct {
	Target     netip.Addr
	Identifier uint16
	Sequence   uint16
	Payload    []byte
	// ReplyType is what the answer should look like: 0 for ICMPv4, 129 for
	// ICMPv6. It is kept so a reply can be rebuilt even on platforms whose echo
	// API hands back the payload only.
	ReplyType   byte
	RequestType byte
}

// ParseEchoRequest reads an echo request message.
func ParseEchoRequest(target netip.Addr, message []byte) (EchoRequest, error) {
	if len(message) < messageHeaderLength {
		return EchoRequest{}, ErrShort
	}
	request := EchoRequest{
		Target:     target,
		Identifier: binary.BigEndian.Uint16(message[4:6]),
		Sequence:   binary.BigEndian.Uint16(message[6:8]),
		Payload:    append([]byte(nil), message[messageHeaderLength:]...),
	}
	if target.Is4() {
		if message[0] != 8 {
			return EchoRequest{}, ErrNotEchoRequest
		}
		request.RequestType, request.ReplyType = 8, 0
	} else {
		if message[0] != 128 {
			return EchoRequest{}, ErrNotEchoRequest
		}
		request.RequestType, request.ReplyType = 128, 129
	}
	return request, nil
}

// BuildReply assembles the echo reply message for a request, which is what the
// caller's ping tool is waiting for: same identifier, same sequence, same
// payload, with the checkum recomputed for the tuple it will be written into.
func BuildReply(request EchoRequest, source, destination netip.Addr) []byte {
	reply := make([]byte, messageHeaderLength+len(request.Payload))
	reply[0] = request.ReplyType
	binary.BigEndian.PutUint16(reply[4:6], request.Identifier)
	binary.BigEndian.PutUint16(reply[6:8], request.Sequence)
	copy(reply[messageHeaderLength:], request.Payload)
	if source.Is4() {
		binary.BigEndian.PutUint16(reply[2:4], checksum(reply))
	} else {
		binary.BigEndian.PutUint16(reply[2:4], icmpv6Checksum(source, destination, reply))
	}
	return reply
}

// Exchange sends one real echo to [target] and answers with the reply message,
// or an error when nothing came back in time. The message is rebuilt from the
// request and whatever the platform's echo API returned, which keeps the
// identifier and sequence the caller used.
func Exchange(ctx context.Context, target netip.Addr, request []byte, timeout time.Duration) ([]byte, error) {
	parsed, err := ParseEchoRequest(target, request)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	payload, source, err := sendEcho(ctx, parsed, timeout)
	if err != nil {
		return nil, err
	}
	if len(payload) > 0 {
		// What came back is what the target echoed; the platform API is the one
		// that saw it, so it wins over the copy we sent.
		parsed.Payload = payload
	}
	if !source.IsValid() {
		source = target
	}
	return BuildReply(parsed, source, netip.Addr{}), nil
}

// LocalReply answers an echo that was aimed at this very node: nothing has to
// travel, because this stack is the target. The checksum is the plain one - the
// side that writes the packet rewrites it for its own tuple, and for ICMPv6
// that tuple is the only thing the pseudo header needs.
func LocalReply(request []byte, target netip.Addr) ([]byte, error) {
	parsed, err := ParseEchoRequest(target, request)
	if err != nil {
		return nil, err
	}
	return BuildReply(parsed, target, netip.Addr{}), nil
}

func checksum(data []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(data); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[index : index+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func icmpv6Checksum(source, destination netip.Addr, message []byte) uint16 {
	pseudo := make([]byte, 40)
	if source.Is6() {
		source16 := source.As16()
		copy(pseudo[0:16], source16[:])
	}
	if destination.Is6() {
		destination16 := destination.As16()
		copy(pseudo[16:32], destination16[:])
	}
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(message)))
	pseudo[39] = 58
	return checksum(append(pseudo, message...))
}
