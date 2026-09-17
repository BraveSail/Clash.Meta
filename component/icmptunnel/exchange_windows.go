//go:build windows

package icmptunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"time"
	"unsafe"
)

// Windows does not hand ICMP to applications as a socket unless they are
// elevated, so the echo goes out through the API the system ping uses
// (iphlpapi's IcmpSendEcho2 / Icmp6SendEcho2). It needs no administrator, and
// it reports the answering address and the round trip itself.
var (
	iphlpapi        = syscall.NewLazyDLL("iphlpapi.dll")
	icmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	icmp6CreateFile = iphlpapi.NewProc("Icmp6CreateFile")
	icmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	icmpSendEcho2   = iphlpapi.NewProc("IcmpSendEcho2")
	icmp6SendEcho2  = iphlpapi.NewProc("Icmp6SendEcho2")
)

type sockaddrIn6 struct {
	Family   uint16
	Port     uint16
	FlowInfo uint32
	Address  [16]byte
	ScopeID  uint32
}

// The reply structures are read by offset instead of with a Go struct: the
// Windows headers pack them to four bytes, so ICMPV6_ECHO_REPLY's pointer sits
// at offset 40 rather than the 48 a Go struct would place it at, and reading it
// from the wrong place hands back a pointer nobody wrote.
const (
	echoReply4Status   = 4
	echoReply4DataSize = 12
	echoReply4Data     = 16

	echoReply6Status = 28
	// ICMPV6_ECHO_REPLY carries the payload inline instead of behind a pointer:
	// the sockaddr the answer came from is 28 bytes, then status, then the round
	// trip time, then the data itself.
	echoReply6Data = 36
)

func replyField(reply []byte, offset int, size int) uint64 {
	if len(reply) < offset+size {
		return 0
	}
	switch size {
	case 2:
		return uint64(binary.LittleEndian.Uint16(reply[offset : offset+2]))
	case 4:
		return uint64(binary.LittleEndian.Uint32(reply[offset : offset+4]))
	default:
		return binary.LittleEndian.Uint64(reply[offset : offset+8])
	}
}

const replyBufferSize = 1500

func sendEcho(ctx context.Context, request EchoRequest, timeout time.Duration) ([]byte, netip.Addr, error) {
	// IPv6 needs the handle its own API opens; an ICMPv4 handle is refused with
	// "the parameter is incorrect".
	open := icmpCreateFile
	if request.Target.Is6() {
		open = icmp6CreateFile
	}
	handle, _, err := open.Call()
	if handle == 0 || handle == uintptr(syscall.InvalidHandle) {
		return nil, netip.Addr{}, fmt.Errorf("icmptunnel: IcmpCreateFile: %w", err)
	}
	defer func() { _, _, _ = icmpCloseHandle.Call(handle) }()

	milliseconds := uint32(timeout / time.Millisecond)
	if ctxDeadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(ctxDeadline); remaining < timeout {
			milliseconds = uint32(remaining / time.Millisecond)
		}
	}
	if milliseconds == 0 {
		milliseconds = 1000
	}

	if request.Target.Is4() {
		return sendEcho4(handle, request, milliseconds)
	}
	return sendEcho6(handle, request, milliseconds)
}

func sendEcho4(handle uintptr, request EchoRequest, timeoutMS uint32) ([]byte, netip.Addr, error) {
	target4 := request.Target.As4()
	destination := binary.LittleEndian.Uint32(target4[:])
	payload := request.Payload
	reply := make([]byte, replyBufferSize)
	result, _, callErr := icmpSendEcho2.Call(
		handle,
		0, // no event: the call waits for the answer
		0,
		0,
		uintptr(destination),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(uint16(len(payload))),
		0,
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(uint32(len(reply))),
		uintptr(timeoutMS),
	)
	if result == 0 {
		return nil, netip.Addr{}, fmt.Errorf("icmptunnel: IcmpSendEcho2: %w", callErr)
	}
	if status := replyField(reply, echoReply4Status, 4); status != 0 {
		return nil, netip.Addr{}, fmt.Errorf("icmptunnel: echo status %d", status)
	}
	address := uint32(replyField(reply, 0, 4))
	answered := netip.AddrFrom4([4]byte{byte(address), byte(address >> 8), byte(address >> 16), byte(address >> 24)})
	return copyReplyData(reply, uintptr(replyField(reply, echoReply4Data, 8)), int(replyField(reply, echoReply4DataSize, 2))), answered, nil
}

func sendEcho6(handle uintptr, request EchoRequest, timeoutMS uint32) ([]byte, netip.Addr, error) {
	var source sockaddrIn6
	source.Family = syscall.AF_INET6
	destination := sockaddrIn6{Family: syscall.AF_INET6}
	destination.Address = request.Target.As16()
	payload := request.Payload
	reply := make([]byte, replyBufferSize)
	result, _, callErr := icmp6SendEcho2.Call(
		handle,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&source)),
		uintptr(unsafe.Pointer(&destination)),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(uint16(len(payload))),
		0,
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(uint32(len(reply))),
		uintptr(timeoutMS),
	)
	if result == 0 {
		return nil, netip.Addr{}, fmt.Errorf("icmptunnel: Icmp6SendEcho2: %w", callErr)
	}
	if status := replyField(reply, echoReply6Status, 4); status != 0 {
		return nil, netip.Addr{}, fmt.Errorf("icmptunnel: echo status %d", status)
	}
	// The answering address is not read from this buffer: the caller already
	// knows the address it pinged, and the reply it writes carries that as the
	// source anyway.
	end := echoReply6Data + len(request.Payload)
	if len(reply) < end {
		return nil, netip.Addr{}, errors.New("icmptunnel: short echo reply")
	}
	return append([]byte(nil), reply[echoReply6Data:end]...), request.Target, nil
}

// copyReplyData reads the payload the API pointed at. The pointer names a spot
// inside the reply buffer that was handed to the call, so the bytes are taken
// from the Go slice itself rather than dereferenced.
func copyReplyData(reply []byte, pointer uintptr, size int) []byte {
	if pointer == 0 || size <= 0 || len(reply) == 0 {
		return nil
	}
	base := uintptr(unsafe.Pointer(&reply[0]))
	if pointer < base {
		return nil
	}
	offset := int(pointer - base)
	if offset+size > len(reply) {
		return nil
	}
	return append([]byte(nil), reply[offset:offset+size]...)
}
