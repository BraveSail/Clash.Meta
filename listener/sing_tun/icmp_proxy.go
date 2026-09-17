package sing_tun

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"

	"github.com/metacubex/mihomo/component/icmptunnel"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
)

// icmpProxyDestination carries an echo through the outbound the rules selected.
//
// sing-tun hands every echo request here as a whole IP packet and expects the
// reply through the route context; the outbound does the rest (see
// C.ICMPProxy). The identifier and sequence number travel untouched, so the
// tool that sent the ping matches the answer, and the checksums are recomputed
// for the packet this side finally writes.
type icmpProxyDestination struct {
	ctx         context.Context
	cancel      context.CancelFunc
	back        tun.DirectRouteContext
	proxy       C.ICMPProxy
	metadata    *C.Metadata
	source      M.Socksaddr
	destination M.Socksaddr
	timeout     time.Duration

	mu     sync.Mutex
	closed bool
}

func newICMPProxyDestination(
	parent context.Context,
	back tun.DirectRouteContext,
	proxy C.ICMPProxy,
	metadata *C.Metadata,
	source M.Socksaddr,
	destination M.Socksaddr,
	timeout time.Duration,
) *icmpProxyDestination {
	ctx, cancel := context.WithCancel(parent)
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &icmpProxyDestination{
		ctx:         ctx,
		cancel:      cancel,
		back:        back,
		proxy:       proxy,
		metadata:    metadata,
		source:      source,
		destination: destination,
		timeout:     timeout,
	}
}

// prepareICMPProxy asks the rules which outbound this echo would use and hands
// the packet over when that outbound can carry it. A nil answer means "not this
// way": the caller keeps its DIRECT socket or its fake echo.
func (h *ListenerHandler) prepareICMPProxy(
	parent context.Context,
	source M.Socksaddr,
	destination M.Socksaddr,
	routeContext tun.DirectRouteContext,
	timeout time.Duration,
) tun.DirectRouteDestination {
	if !destination.Addr.IsValid() {
		return nil
	}
	metadata := &C.Metadata{
		NetWork: C.ICMP,
		SrcIP:   source.Addr,
		DstIP:   destination.Addr,
	}
	// A fake-ip (or a host entry) still names the flow: the rules match on the
	// name, and the outbound that carries ICMP needs it to find the peer.
	if host, ok := resolver.FindHostByIP(destination.Addr); ok {
		metadata.Host = host
	}
	proxy, err := tunnel.MatchProxy(metadata)
	if err != nil {
		log.Debugln("[ICMP] %s: %s", destination.Addr, err)
		return nil
	}
	if proxy == nil {
		log.Debugln("[ICMP] %s matched no outbound", destination.Addr)
		return nil
	}
	carrier, carrierName := icmpCarrier(proxy, metadata)
	if carrier == nil {
		log.Debugln("[ICMP] %s matches %s, which cannot carry an echo", destination.Addr, proxy.Name())
		return nil
	}
	log.Debugln("[ICMP] %s host=%q matches %s", destination.Addr, metadata.Host, carrierName)
	log.Infoln("[ICMP] %s %s --> %s using %s", metadata.NetWork.String(), source, destination, carrierName)
	return newICMPProxyDestination(parent, routeContext, carrier, metadata, source, destination, timeout)
}

// icmpCarrier finds the outbound that would carry the echo. A rule may name a
// group, and what a group dials is what it would have carried this echo with:
// the selection is read without touching it, the same way TCP and UDP follow
// it, so a peer that is currently selected can answer a ping. A decorator
// around the outbound - the one that closes it when the config is replaced -
// embeds the adapter interface and hides everything else, so the adapter
// underneath is asked too.
func icmpCarrier(proxy C.Proxy, metadata *C.Metadata) (C.ICMPProxy, string) {
	for depth := 0; proxy != nil && depth < 8; depth++ {
		if carrier, ok := C.ICMPCarrierOf(proxy.Adapter()); ok {
			return carrier, proxy.Name()
		}
		proxy = proxy.Unwrap(metadata, false)
	}
	return nil, ""
}

func (d *icmpProxyDestination) WritePacket(packet *buf.Buffer) error {
	raw := append([]byte(nil), packet.Bytes()...)
	packet.Release()

	request, reply, err := parseEcho(raw)
	if err != nil {
		log.Debugln("[ICMP] %s: %s", d.metadata.RemoteAddress(), err)
		return nil // a packet this destination cannot answer is simply not for it
	}
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()
	if closed {
		return nil
	}
	go d.exchange(request, reply, raw, ipVersion(raw) == 6)
	return nil
}

// exchange asks the outbound for the reply and writes it back into the tunnel.
// It runs in its own goroutine so a slow peer never blocks the packet loop.
func (d *icmpProxyDestination) exchange(request []byte, builder replyBuilder, raw []byte, ipv6 bool) {
	ctx, cancel := context.WithTimeout(d.ctx, d.timeout)
	defer cancel()
	reply, err := d.proxy.ExchangeICMP(ctx, d.metadata, request)
	if err != nil {
		if errors.Is(err, icmptunnel.ErrLocalPath) {
			// The outbound is this node: the echo has to take the direct path,
			// which is built here because only this side holds the route
			// context that keeps it from entering the rules again.
			d.writeViaDirect(ctx, raw, ipv6)
			return
		}
		log.Debugln("[ICMP] %s %s: %s", d.metadata.SourceDetail(), d.metadata.RemoteAddress(), err)
		return
	}
	packet, err := builder(reply)
	if err != nil {
		log.Warnln("[ICMP] %s answer is unusable: %s", d.metadata.RemoteAddress(), err)
		return
	}
	if err := d.back.WritePacket(packet); err != nil {
		log.Debugln("[ICMP] write answer for %s: %s", d.metadata.RemoteAddress(), err)
	}
}

// writeViaDirect sends the echo down the path sing-tun uses when no outbound
// carries ICMP. A destination that is only a placeholder is resolved first, so
// a ping to a name still reaches the name instead of the placeholder.
func (d *icmpProxyDestination) writeViaDirect(ctx context.Context, raw []byte, ipv6 bool) {
	destination := d.destination
	if resolver.IsFakeIP(destination.Addr) && d.metadata.Host != "" {
		var resolved netip.Addr
		var err error
		if ipv6 {
			resolved, err = resolver.ResolveIPv6(ctx, d.metadata.Host)
		} else {
			resolved, err = resolver.ResolveIPv4(ctx, d.metadata.Host)
		}
		if err != nil {
			log.Debugln("[ICMP] %s: %s", d.metadata.RemoteAddress(), err)
			return
		}
		destination.Addr = resolved
	}
	direct, err := directICMPDestination(destination, d.back, d.timeout)
	if err != nil {
		log.Warnln("[ICMP] %s DIRECT: %s", d.metadata.RemoteAddress(), err)
		return
	}
	log.Debugln("[ICMP] %s %s DIRECT", d.metadata.RemoteAddress(), destination)
	if err := direct.WritePacket(buf.As(raw).ToOwned()); err != nil {
		log.Debugln("[ICMP] %s DIRECT: %s", d.metadata.RemoteAddress(), err)
	}
}

// ipVersion reads the family the packet was written for.
func ipVersion(packet []byte) int {
	if len(packet) == 0 {
		return 0
	}
	return int(packet[0] >> 4)
}

func (d *icmpProxyDestination) Close() error {
	d.mu.Lock()
	alreadyClosed := d.closed
	d.closed = true
	d.mu.Unlock()
	if !alreadyClosed {
		d.cancel()
	}
	return nil
}

func (d *icmpProxyDestination) IsClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed
}

// replyBuilder turns the ICMP message an outbound returned into the whole IP
// packet the tunnel has to receive, with the addresses swapped.
type replyBuilder func(reply []byte) ([]byte, error)

// parseEcho reads one echo request out of a whole IP packet and prepares the
// builder that will wrap the answer.
func parseEcho(packet []byte) ([]byte, replyBuilder, error) {
	if len(packet) < 1 {
		return nil, nil, errors.New("empty packet")
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return nil, nil, errors.New("truncated IPv4 header")
		}
		headerLength := int(packet[0]&0x0f) * 4
		if headerLength < 20 || len(packet) < headerLength {
			return nil, nil, errors.New("invalid IPv4 header length")
		}
		source, ok := netip.AddrFromSlice(packet[12:16])
		if !ok {
			return nil, nil, errors.New("invalid IPv4 source")
		}
		destination, ok := netip.AddrFromSlice(packet[16:20])
		if !ok {
			return nil, nil, errors.New("invalid IPv4 destination")
		}
		message := packet[headerLength:]
		if len(message) < 8 || message[0] != 8 { // echo request
			return nil, nil, errors.New("not an ICMPv4 echo request")
		}
		return append([]byte(nil), message...), func(reply []byte) ([]byte, error) {
			return buildIPv4Reply(source, destination, reply)
		}, nil
	case 6:
		if len(packet) < 40 {
			return nil, nil, errors.New("truncated IPv6 header")
		}
		source, ok := netip.AddrFromSlice(packet[8:24])
		if !ok {
			return nil, nil, errors.New("invalid IPv6 source")
		}
		destination, ok := netip.AddrFromSlice(packet[24:40])
		if !ok {
			return nil, nil, errors.New("invalid IPv6 destination")
		}
		message := packet[40:]
		if len(message) < 8 || message[0] != 128 { // echo request
			return nil, nil, errors.New("not an ICMPv6 echo request")
		}
		return append([]byte(nil), message...), func(reply []byte) ([]byte, error) {
			return buildIPv6Reply(source, destination, reply)
		}, nil
	default:
		return nil, nil, errors.New("not an IP packet")
	}
}

// buildIPv4Reply writes source -> destination with the answer as its payload.
func buildIPv4Reply(source, destination netip.Addr, reply []byte) ([]byte, error) {
	if len(reply) < 8 {
		return nil, errors.New("answer is too short")
	}
	packet := make([]byte, 20+len(reply))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64 // ttl
	packet[9] = 1  // icmp
	source4, destination4 := source.As4(), destination.As4()
	copy(packet[12:16], destination4[:])
	copy(packet[16:20], source4[:])
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20])) // header checksum
	copy(packet[20:], reply)
	// The answer keeps whatever the far end produced (an echo reply, or the
	// error that came back instead); its checksum covers the message alone.
	binary.BigEndian.PutUint16(packet[22:24], 0)
	binary.BigEndian.PutUint16(packet[22:24], checksum(packet[20:]))
	return packet, nil
}

// buildIPv6Reply writes source -> destination with the answer as its payload.
// The ICMPv6 checksum covers a pseudo header, and the addresses changed, so it
// is recomputed here rather than trusted from the peer.
func buildIPv6Reply(source, destination netip.Addr, reply []byte) ([]byte, error) {
	if len(reply) < 8 {
		return nil, errors.New("answer is too short")
	}
	packet := make([]byte, 40+len(reply))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(reply)))
	packet[6] = 58 // icmpv6
	packet[7] = 64 // hop limit
	source16, destination16 := source.As16(), destination.As16()
	copy(packet[8:24], destination16[:])
	copy(packet[24:40], source16[:])
	copy(packet[40:], reply)
	binary.BigEndian.PutUint16(packet[42:44], 0)
	binary.BigEndian.PutUint16(packet[42:44], icmpv6Checksum(destination, source, packet[40:]))
	return packet, nil
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

// icmpv6Checksum computes the checksum over the ICMPv6 pseudo header plus the
// message, which is what the receiver of this packet will verify.
func icmpv6Checksum(source, destination netip.Addr, message []byte) uint16 {
	pseudo := make([]byte, 40)
	source16, destination16 := source.As16(), destination.As16()
	copy(pseudo[0:16], source16[:])
	copy(pseudo[16:32], destination16[:])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(message)))
	pseudo[39] = 58
	return checksum(append(pseudo, message...))
}
