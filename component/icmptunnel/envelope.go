// Package icmptunnel carries an ICMP echo across a tunnel that cannot speak
// ICMP: the message and the address it should reach travel as one datagram,
// and the peer that receives it puts a real echo on the wire.
package icmptunnel

import (
	"errors"
	"net/netip"
)

// Magic marks an envelope, so a datagram that is not ours is refused instead of
// parsed. Version lets the shape change later without guessing.
const (
	Magic   = "PDIC"
	Version = 1
)

const headerLength = 4 + 1 + 1

var (
	ErrShort     = errors.New("icmp tunnel: packet is too short")
	ErrNotOurs   = errors.New("icmp tunnel: not an envelope")
	ErrVersion   = errors.New("icmp tunnel: unknown version")
	ErrBadFamily = errors.New("icmp tunnel: unsupported address family")
)

// Encode wraps [message] (an ICMP message, no IP header) with the address the
// peer should send it to.
func Encode(target netip.Addr, message []byte) ([]byte, error) {
	target = target.Unmap()
	var address []byte
	family := byte(6)
	if target.Is4() {
		family = 4
		address4 := target.As4()
		address = address4[:]
	} else if target.Is6() {
		address16 := target.As16()
		address = address16[:]
	} else {
		return nil, ErrBadFamily
	}
	packet := make([]byte, 0, headerLength+len(address)+len(message))
	packet = append(packet, Magic...)
	packet = append(packet, Version, family)
	packet = append(packet, address...)
	packet = append(packet, message...)
	return packet, nil
}

// Decode reads an envelope back into the address to reach and the message to
// send there.
func Decode(packet []byte) (netip.Addr, []byte, error) {
	if len(packet) < headerLength {
		return netip.Addr{}, nil, ErrShort
	}
	if string(packet[:4]) != Magic {
		return netip.Addr{}, nil, ErrNotOurs
	}
	if packet[4] != Version {
		return netip.Addr{}, nil, ErrVersion
	}
	var size int
	switch packet[5] {
	case 4:
		size = 4
	case 6:
		size = 16
	default:
		return netip.Addr{}, nil, ErrBadFamily
	}
	if len(packet) < headerLength+size {
		return netip.Addr{}, nil, ErrShort
	}
	target, ok := netip.AddrFromSlice(packet[headerLength : headerLength+size])
	if !ok {
		return netip.Addr{}, nil, ErrBadFamily
	}
	// The caller's buffer is usually reused by the next read, so the message is
	// copied out before it is handed on.
	message := append([]byte(nil), packet[headerLength+size:]...)
	if len(message) == 0 {
		return netip.Addr{}, nil, ErrShort
	}
	return target.Unmap(), message, nil
}
