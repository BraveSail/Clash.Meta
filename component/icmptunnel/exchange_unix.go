//go:build !windows

package icmptunnel

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"time"
)

// sendEcho puts one real echo on the wire and returns the payload and the
// address that answered.
//
// The socket is unprivileged: a datagram socket whose protocol is ICMP - the
// ping socket Linux and Android hand to applications - not a raw socket, so an
// echo needs no capabilities at all, and the kernel owns the identifier on it.
// It is opened the way the rest of mihomo opens sockets, through the dialer's
// control hook, because that is what protects it from this node's own tunnel on
// Android and what binds it to the carrying interface elsewhere.
func sendEcho(ctx context.Context, request EchoRequest, timeout time.Duration) ([]byte, netip.Addr, error) {
	conn, err := listenEchoSocket(request.Target)
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
		return append([]byte(nil), reply[messageHeaderLength:]...), echoSource(from), nil
	}
}

// echoSource reads the address an echo came from, which either socket flavour
// reports in its own type.
func echoSource(from net.Addr) netip.Addr {
	switch addr := from.(type) {
	case *net.IPAddr:
		answered, _ := netip.AddrFromSlice(addr.IP)
		return answered.Unmap()
	case *net.UDPAddr:
		return addr.AddrPort().Addr().Unmap()
	default:
		return netip.Addr{}
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
