//go:build !windows

package icmptunnel

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
)

// sendEcho puts one real echo on the wire and returns the payload and the
// address that answered.
//
// The socket is unprivileged: "udp4"/"udp6" here mean an ICMP datagram socket
// (the ping socket Linux and Android hand to applications), not a raw socket,
// so a responder needs no capabilities at all. The kernel owns the identifier
// on such a socket, which is why only the payload travels back: the caller puts
// the identifier the originator used into the reply.
func sendEcho(ctx context.Context, request EchoRequest, timeout time.Duration) ([]byte, netip.Addr, error) {
	network := "udp4"
	if request.Target.Is6() {
		network = "udp6"
	}
	conn, err := icmp.ListenPacket(network, "")
	if err != nil {
		return nil, netip.Addr{}, err
	}
	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, netip.Addr{}, err
	}

	message := requestMessage(request)
	destination := &net.IPAddr{IP: net.IP(request.Target.AsSlice())}
	if _, err := conn.WriteTo(message, destination); err != nil {
		return nil, netip.Addr{}, err
	}

	buffer := make([]byte, 1500)
	for {
		length, from, err := conn.ReadFrom(buffer)
		if err != nil {
			return nil, netip.Addr{}, err
		}
		if length < messageHeaderLength {
			continue
		}
		reply := buffer[:length]
		if request.Target.Is4() {
			if reply[0] != 0 { // echo reply
				continue
			}
		} else if reply[0] != 129 {
			continue
		}
		answered, _ := netip.AddrFromSlice(from.(*net.IPAddr).IP)
		return append([]byte(nil), reply[messageHeaderLength:]...), answered.Unmap(), nil
	}
}

// requestMessage rebuilds the echo request the socket sends: the identifier is
// the kernel's business on an unprivileged socket, so a fixed one is fine.
func requestMessage(request EchoRequest) []byte {
	message := make([]byte, messageHeaderLength+len(request.Payload))
	message[0] = request.RequestType
	binary.BigEndian.PutUint16(message[4:6], request.Identifier)
	binary.BigEndian.PutUint16(message[6:8], request.Sequence)
	copy(message[messageHeaderLength:], request.Payload)
	binary.BigEndian.PutUint16(message[2:4], checksum(message))
	return message
}
