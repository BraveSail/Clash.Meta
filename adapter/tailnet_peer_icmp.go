package adapter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/icmptunnel"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

var ipv4Loopback = netip.MustParseAddr("127.0.0.1")

// tailnetEchoIdle is how long a session may sit unused before it is closed: a
// ping in progress keeps it warm, and a burst that takes a longer break pays
// one handshake again rather than holding a connection open forever.
const tailnetEchoIdle = 2 * time.Minute

// tailnetEchoTimeout bounds one echo the outbound makes itself.
const tailnetEchoTimeout = 3 * time.Second

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

// tailnetEchoSession is the tunnel session carried echoes share. Opening one
// costs a connection to the peer, which is worth paying once for a burst of
// pings rather than once for every echo - the difference between a round trip
// and a handshake plus a round trip, on the path where it is most visible.
type tailnetEchoSession struct {
	conn  C.PacketConn
	inner C.Proxy
	key   string
	at    time.Time
}

// ExchangeICMP answers an echo with the peer, in one of two shapes.
//
// An echo aimed at the peer itself is sent straight to the address the
// directory publishes for it: the peer's own stack answers, exactly as it would
// if the two nodes shared a network, and nothing about the packet changes but
// the family it is asked in. When the peer cannot be reached that way - it
// blocks inbound ICMP, or the address is not routable from here - the outbound
// can be configured to carry the echo instead (see TailnetPeerOption.ICMP).
//
// An echo aimed anywhere else cannot be answered by this node, because the
// answer has to come from the peer's network: ICMP cannot ride the inner
// protocol (VLESS has no field for it), so the message travels as a UDP
// datagram through the tunnel to the peer's responder, which puts a real echo
// on the wire. That is how a node whose carrier only gives it IPv6 pings an
// IPv4 address through a peer that holds both.
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
	if t.destinationIsThePeer(metadata) && t.option.icmpDirect() {
		if echoSpeaksFor(peerAddr, request) {
			log.Debugln("[ICMP] %s %s sent to %s as it is", t.Name(), metadata.RemoteAddress(), peerAddr)
			return directEcho(ctx, peerAddr, request)
		}
		// The tool asked in the other family - an IPv4 echo for a peer that only
		// has an IPv6 address. Nothing can be passed through unchanged there, so
		// the message is carried instead (see the envelope below).
		log.Debugln("[ICMP] %s %s is %s, the echo is not - carrying it instead",
			t.Name(), metadata.RemoteAddress(), familyName(peerAddr.Is6()))
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
	t.echoMu.Lock()
	defer t.echoMu.Unlock()
	// The responder lives on the peer's loopback, so the only way in is the
	// peer's own rule engine - that is, a tunnel this node opened. Nothing of
	// the responder is reachable from the internet.
	packetConn, err := t.echoConnection(ctx, proxy, host, port)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = packetConn.SetDeadline(deadline)
	} else {
		_ = packetConn.SetDeadline(time.Now().Add(5 * time.Second))
	}
	reply, err := t.echoOnce(packetConn, envelope, port, target, request)
	if err != nil {
		// A session that went stale - the peer restarted, the path moved - is
		// worth one more try on a fresh one before the echo is called lost.
		t.dropEcho(packetConn)
		packetConn, err = t.echoConnection(ctx, proxy, host, port)
		if err != nil {
			return nil, err
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = packetConn.SetDeadline(deadline)
		}
		if reply, err = t.echoOnce(packetConn, envelope, port, target, request); err != nil {
			t.dropEcho(packetConn)
			return nil, err
		}
	}
	log.Debugln("[ICMP] %s %s answered by %s", t.Name(), metadata.RemoteAddress(), target)
	return reply, nil
}

// echoOnce sends one envelope over [conn] and waits for its answer.
func (t *TailnetPeer) echoOnce(conn C.PacketConn, envelope []byte, port int, target netip.Addr, request []byte) ([]byte, error) {
	destination := &net.UDPAddr{IP: net.IP(ipv4Loopback.AsSlice()), Port: port}
	if _, err := conn.WriteTo(envelope, destination); err != nil {
		return nil, err
	}
	return t.readEcho(conn, target, request)
}

// echoConnection answers with the session this peer's echoes share, opening one
// when there is none, it belongs to another tunnel, or it has been idle.
func (t *TailnetPeer) echoConnection(ctx context.Context, proxy C.Proxy, host string, port int) (C.PacketConn, error) {
	key := host + ":" + strconv.Itoa(port)
	t.mu.Lock()
	session := t.echo
	if session != nil && session.inner == proxy && session.key == key && time.Since(session.at) < tailnetEchoIdle {
		session.at = time.Now()
		t.mu.Unlock()
		return session.conn, nil
	}
	t.mu.Unlock()
	if session != nil {
		t.dropEcho(session.conn)
	}
	conn, err := proxy.ListenPacketContext(ctx, &C.Metadata{
		NetWork: C.UDP,
		DstIP:   ipv4Loopback,
		DstPort: uint16(port),
	})
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	t.echo = &tailnetEchoSession{conn: conn, inner: proxy, key: key, at: time.Now()}
	t.mu.Unlock()
	return conn, nil
}

// readEcho waits for the answer to this echo. The session may still hold a late
// answer to an echo that timed out, and each envelope names the address it was
// made for, so anything that is not this echo is skipped rather than handed to
// the caller.
func (t *TailnetPeer) readEcho(conn C.PacketConn, target netip.Addr, request []byte) ([]byte, error) {
	buffer := make([]byte, 2048)
	for {
		length, _, err := conn.ReadFrom(buffer)
		if err != nil {
			t.dropEcho(conn)
			return nil, err
		}
		answered, reply, err := icmptunnel.Decode(buffer[:length])
		if err != nil {
			continue
		}
		if answered != target || !sameEcho(request, reply) {
			continue
		}
		return reply, nil
	}
}

// sameEcho reports whether a message carries the identifier and sequence of the
// request it answers, which is how the tool that sent it matches the two.
func sameEcho(request, reply []byte) bool {
	if len(request) < 8 || len(reply) < 8 {
		return true
	}
	return request[4] == reply[4] && request[5] == reply[5] &&
		request[6] == reply[6] && request[7] == reply[7]
}

// dropEcho lets go of a session that failed: the next echo opens a new one.
func (t *TailnetPeer) dropEcho(conn C.PacketConn) {
	t.mu.Lock()
	if t.echo != nil && t.echo.conn == conn {
		t.echo = nil
	}
	t.mu.Unlock()
	_ = conn.Close()
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
