package adapter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/icmptunnel"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

var ipv4Loopback = netip.MustParseAddr("127.0.0.1")

// ExchangeICMP carries one echo to the peer and brings the reply back.
//
// ICMP cannot ride the inner protocol (VLESS has no field for it), so the
// message travels as a UDP datagram through the tunnel to the peer's responder,
// which puts a real echo on the wire. The target is the peer itself when the
// flow was aimed at its name - answered on the peer's loopback, which is a real
// answer from that node - and the address that was dialled otherwise, which is
// how a node whose carrier only gives it IPv6 can still ping an IPv4 address
// through a peer that has both.
func (t *TailnetPeer) ExchangeICMP(ctx context.Context, metadata *C.Metadata, request []byte) ([]byte, error) {
	host, self, err := t.resolve(ctx)
	if err != nil {
		return nil, err
	}
	if self {
		if t.destinationIsThePeer(metadata) {
			// The flow points at this node: this stack is the target, so answer
			// it here instead of asking anybody.
			log.Debugln("[ICMP] %s %s answered locally", t.Name(), metadata.RemoteAddress())
			return icmptunnel.LocalReply(request, metadata.DstIP)
		}
		// The rules sent an echo that is not aimed at this node through this
		// node's own entry. Making the echo here would put it back into these
		// rules, so the tunnel side is told to use the direct path instead.
		log.Debugln("[ICMP] %s %s is this node: using DIRECT", t.Name(), metadata.RemoteAddress())
		return nil, icmptunnel.ErrLocalPath
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return nil, fmt.Errorf("tailnet-peer: peer %q is not an address: %w", host, err)
	}
	target, err := t.echoTarget(ctx, metadata, request)
	if err != nil {
		return nil, err
	}
	envelope, err := icmptunnel.Encode(target, request)
	if err != nil {
		return nil, err
	}
	proxy, err := t.proxyForDial(ctx)
	if err != nil {
		return nil, err
	}
	port := t.option.ICMPPort
	if port <= 0 {
		port = t.option.Port + 1
	}
	// The responder lives on the peer's loopback, so the only way in is the
	// peer's own rule engine - that is, a tunnel this node opened. Nothing of
	// the responder is reachable from the internet.
	packetConn, err := proxy.ListenPacketContext(ctx, &C.Metadata{
		NetWork: C.UDP,
		DstIP:   ipv4Loopback,
		DstPort: uint16(port),
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = packetConn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = packetConn.SetDeadline(deadline)
	} else {
		_ = packetConn.SetDeadline(time.Now().Add(5 * time.Second))
	}
	destination := &net.UDPAddr{IP: net.IP(ipv4Loopback.AsSlice()), Port: port}
	if _, err := packetConn.WriteTo(envelope, destination); err != nil {
		return nil, err
	}
	buffer := make([]byte, 2048)
	length, _, err := packetConn.ReadFrom(buffer)
	if err != nil {
		return nil, err
	}
	_, reply, err := icmptunnel.Decode(buffer[:length])
	if err != nil {
		return nil, err
	}
	log.Debugln("[ICMP] %s %s answered by %s", t.Name(), metadata.RemoteAddress(), target)
	return reply, nil
}

// echoTarget is the address the peer has to put the echo on the wire for: the
// peer's own loopback when the flow was aimed at the peer, otherwise the
// address the flow named - resolved for real when the flow only carries a
// fake-ip placeholder, which is what a ping to a name looks like here.
func (t *TailnetPeer) echoTarget(ctx context.Context, metadata *C.Metadata, request []byte) (netip.Addr, error) {
	ipv6 := isIPv6Echo(request)
	if t.destinationIsThePeer(metadata) {
		if ipv6 {
			return netip.IPv6Loopback(), nil
		}
		return ipv4Loopback, nil
	}
	target := metadata.DstIP
	if resolver.IsFakeIP(target) && metadata.Host != "" {
		resolved, err := echoAddress(ctx, metadata.Host, ipv6)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("tailnet-peer: %s has no address this echo can reach: %w", metadata.Host, err)
		}
		target = resolved
	}
	if !target.IsValid() {
		return netip.Addr{}, errors.New("tailnet-peer: the flow names no address to ping")
	}
	// The message and the address have to be of one family: the peer sends the
	// echo with the API for the address, and only an echo of that family can be
	// written back into the packet this side is waiting on.
	if target.Is6() != ipv6 {
		return netip.Addr{}, fmt.Errorf("tailnet-peer: %s is not an address this %s echo can reach", target, familyName(ipv6))
	}
	return target, nil
}

func echoAddress(ctx context.Context, host string, ipv6 bool) (netip.Addr, error) {
	if ipv6 {
		return resolver.ResolveIPv6(ctx, host)
	}
	return resolver.ResolveIPv4(ctx, host)
}

func isIPv6Echo(request []byte) bool {
	return len(request) > 0 && request[0] == 128
}

func familyName(ipv6 bool) string {
	if ipv6 {
		return "IPv6"
	}
	return "IPv4"
}

// destinationIsThePeer reports whether the flow was aimed at this outbound's
// peer by name ("pc.lan", "pc", "pc.tailnet.ts.net") rather than at some other
// address the rules happen to send through it.
func (t *TailnetPeer) destinationIsThePeer(metadata *C.Metadata) bool {
	host := strings.ToLower(strings.TrimSuffix(metadata.Host, "."))
	if host == "" {
		return false
	}
	for _, name := range []string{t.option.Peer, t.directoryNameKey()} {
		if name == "" {
			continue
		}
		name = strings.ToLower(name)
		if host == name || strings.HasPrefix(host, name+".") {
			return true
		}
	}
	return false
}
