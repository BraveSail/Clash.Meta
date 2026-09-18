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

// ExchangeICMP answers an echo with the peer, and only by asking the peer.
//
// An echo aimed at the peer itself is sent to the address the directory
// publishes for it: the peer's own stack answers, exactly as it would if the
// two nodes shared a network, and the tool's message is the message that
// travels - no header is added, no address is rewritten and no message is
// re-typed, so what the tool measures is the path it asked about.
//
// An echo this node cannot put on the wire honestly is refused: a message of
// another family than the peer's address, or a rule that asks the peer to emit
// an echo on this node's behalf. The tunnel side turns that into the error a
// router would send, so ping reports a network failure instead of waiting for
// an answer that cannot come.
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
	peerAddr, err := netip.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("tailnet-peer: peer %q is not an address: %w", host, err)
	}
	if !t.destinationIsThePeer(metadata) {
		// The rules asked this peer to emit the echo from its own network. That
		// is the one thing this outbound does not do: only the peer can answer
		// for itself.
		log.Debugln("[ICMP] %s %s is not %s: unreachable", t.Name(), metadata.RemoteAddress(), t.Name())
		return nil, icmptunnel.ErrUnreachable
	}
	if !echoSpeaksFor(peerAddr, request) {
		// The tool asked in the other family - an IPv4 echo for a peer that only
		// has an IPv6 address. Re-typing it would be inventing a packet the tool
		// never sent, so the answer is the truth: that destination cannot be
		// reached with this message.
		log.Debugln("[ICMP] %s %s is %s and the echo is not: unreachable",
			t.Name(), metadata.RemoteAddress(), familyName(peerAddr.Is6()))
		return nil, icmptunnel.ErrUnreachable
	}
	log.Debugln("[ICMP] %s %s sent to %s as it is", t.Name(), metadata.RemoteAddress(), peerAddr)
	return directEcho(ctx, peerAddr, request)
}

// directEcho asks the peer's own stack for the answer: the echo goes to the
// address the directory publishes for the peer, which is the packet the tool
// would have sent if the two nodes shared a network. The bytes are the tool's
// own echo message; nothing is re-typed, re-addressed or wrapped.
func directEcho(ctx context.Context, peer netip.Addr, request []byte) ([]byte, error) {
	timeout := tailnetEchoTimeout
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}
	return icmptunnel.Exchange(ctx, peer, request, timeout)
}

// echoSpeaksFor reports whether an echo message belongs to the family of the
// address it would be sent to: an ICMPv4 message cannot travel over an IPv6
// path, and re-typing it would be inventing a packet the tool never sent.
func echoSpeaksFor(peer netip.Addr, request []byte) bool {
	if !peer.IsValid() || len(request) == 0 {
		return false
	}
	if peer.Is6() {
		return request[0] == 128
	}
	return request[0] == 8
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
