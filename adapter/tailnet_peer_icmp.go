package adapter

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/icmptunnel"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

var ipv4Loopback = netip.MustParseAddr("127.0.0.1")

// tailnetEchoTimeout bounds one echo this node makes for a ping that is aimed
// at the peer.
const tailnetEchoTimeout = 3 * time.Second

// ICMPDestination answers with the address an echo aimed at this outbound has to
// travel to: the address the directory publishes for the peer. The tunnel side
// keeps the tool's own message and sends it there, so nothing is wrapped, no
// message is re-typed and the measured time is the path that was asked about.
//
// No address means this node is the one that answers, and the tunnel side asks
// the carrier to do it. An error means the echo cannot be put on the wire as it
// stands - the tool asked in another family than the peer's address, or a rule
// asked this peer to answer for an address that is not its own - and the tunnel
// side answers with the error a router would send.
func (t *TailnetPeer) ICMPDestination(ctx context.Context, metadata *C.Metadata) (netip.Addr, error) {
	host, self, err := t.resolve(ctx)
	if err != nil {
		return netip.Addr{}, err
	}
	if self {
		if t.destinationIsThePeer(metadata) {
			// The flow points at this node: this stack is the target, and
			// ExchangeICMP answers it here.
			return netip.Addr{}, nil
		}
		// The rules sent an echo that is not aimed at this node through this
		// node's own entry: it keeps the direct path instead.
		return netip.Addr{}, icmptunnel.ErrLocalPath
	}
	peerAddr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("tailnet-peer: peer %q is not an address: %w", host, err)
	}
	if !t.destinationIsThePeer(metadata) {
		// The rules asked this peer to emit an echo from its own network. That
		// is the one thing this outbound does not do: only the peer can answer
		// for itself.
		log.Debugln("[ICMP] %s %s is not %s: unreachable", t.Name(), metadata.RemoteAddress(), t.Name())
		return netip.Addr{}, icmptunnel.ErrUnreachable
	}
	if peerAddr.Is6() != metadata.DstIP.Is6() {
		// The tool asked in the other family - an IPv4 echo for a peer that only
		// has an IPv6 address. Re-typing it would be inventing a packet the tool
		// never sent.
		log.Debugln("[ICMP] %s %s is %s and the echo is not: unreachable",
			t.Name(), metadata.RemoteAddress(), familyName(peerAddr.Is6()))
		return netip.Addr{}, icmptunnel.ErrUnreachable
	}
	return peerAddr, nil
}

// ExchangeICMP answers an echo that is aimed at this very node: the tool's
// message describes a packet this stack would have answered itself, so it is
// answered here. Anything else is refused, because this outbound moves no echo.
func (t *TailnetPeer) ExchangeICMP(ctx context.Context, metadata *C.Metadata, request []byte) ([]byte, error) {
	_, self, err := t.resolve(ctx)
	if err != nil {
		return nil, err
	}
	if !self {
		return nil, icmptunnel.ErrUnreachable
	}
	if !t.destinationIsThePeer(metadata) {
		return nil, icmptunnel.ErrLocalPath
	}
	log.Debugln("[ICMP] %s %s answered locally", t.Name(), metadata.RemoteAddress())
	return icmptunnel.LocalReply(request, metadata.DstIP)
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
