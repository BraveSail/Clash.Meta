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
	ctx      context.Context
	cancel   context.CancelFunc
	back     tun.DirectRouteContext
	proxy    C.ICMPProxy
	metadata *C.Metadata
	timeout  time.Duration

	mu     sync.Mutex
	closed bool
}

func newICMPProxyDestination(
	parent context.Context,
	back tun.DirectRouteContext,
	proxy C.ICMPProxy,
	metadata *C.Metadata,
	timeout time.Duration,
) *icmpProxyDestination {
	ctx, cancel := context.WithCancel(parent)
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &icmpProxyDestination{
		ctx:      ctx,
		cancel:   cancel,
		back:     back,
		proxy:    proxy,
		metadata: metadata,
		timeout:  timeout,
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
	adapter, carrierName := icmpAdapter(proxy, metadata)
	if adapter != nil {
		// A carrier that knows the address the echo should travel to hands the
		// flow to the direct path: the tool's own message is what leaves, and
		// the answer comes back as the address the tool pinged.
		if redirect, ok := C.ICMPRedirectOf(adapter); ok {
			address, err := redirect.ICMPDestination(parent, metadata)
			switch {
			case err == nil && address.IsValid():
				log.Infoln("[ICMP] %s %s --> %s using %s", metadata.NetWork.String(), source, destination, carrierName)
				log.Debugln("[ICMP] %s sent to %s as it is", destination.Addr, address)
				return newICMPDirectDestination(parent, routeContext, metadata, destination.Addr, address, timeout)
			case err == nil:
				// No address: the flow points at this node, so this node answers
				// it here. Answering it here also keeps the verdict the carrier
				// just gave: asking it again later could disagree.
				log.Debugln("[ICMP] %s host=%q is %s itself: answering here", destination.Addr, metadata.Host, carrierName)
				log.Infoln("[ICMP] %s %s --> %s using %s", metadata.NetWork.String(), source, destination, carrierName)
				return newICMPProxyDestination(parent, routeContext, localAnswerCarrier{}, metadata, timeout)
			case errors.Is(err, icmptunnel.ErrLocalPath):
				// The rules picked this node itself: it answers its own flows,
				// so the echo keeps the path it would have had without a carrier.
				log.Debugln("[ICMP] %s is this node: answering it here", destination.Addr)
			default:
				log.Debugln("[ICMP] %s: %s", destination.Addr, err)
				if errors.Is(err, icmptunnel.ErrUnreachable) {
					return newICMPProxyDestination(parent, routeContext, unreachableCarrier{}, metadata, timeout)
				}
				// The flow could not be placed at all - a name with no address,
				// a peer the directory does not know yet. Nothing answers, and
				// the tool times out, which is what a path that is not there
				// looks like; a routing error would be a lie about a peer that
				// exists.
				return newICMPProxyDestination(parent, routeContext, silentCarrier{}, metadata, timeout)
			}
		} else if carrier, ok := C.ICMPCarrierOf(adapter); ok {
			log.Debugln("[ICMP] %s host=%q matches %s", destination.Addr, metadata.Host, carrierName)
			log.Infoln("[ICMP] %s %s --> %s using %s", metadata.NetWork.String(), source, destination, carrierName)
			return newICMPProxyDestination(parent, routeContext, carrier, metadata, timeout)
		}
	} else {
		log.Debugln("[ICMP] %s matches %s, which cannot move an echo", destination.Addr, proxy.Name())
	}
	if metadata.Host == "" {
		return nil
	}
	// The flow names a host, so it deserves a real answer rather than the
	// stack's fake reply: resolve the name and let the tool's own echo travel
	// to the address it stands for.
	address, err := resolveForEcho(parent, metadata.Host, destination.Addr.Is6())
	if err != nil {
		log.Debugln("[ICMP] %s: %s", metadata.Host, err)
		return newICMPProxyDestination(parent, routeContext, silentCarrier{}, metadata, timeout)
	}
	log.Infoln("[ICMP] %s %s --> %s using %s", metadata.NetWork.String(), source, destination, proxy.Name())
	log.Debugln("[ICMP] %s sent to %s as it is", destination.Addr, address)
	return newICMPDirectDestination(parent, routeContext, metadata, destination.Addr, address, timeout)
}

// unreachableCarrier stands in for "this echo cannot be put on the wire as it
// stands": the tunnel side answers with the error a router would send.
type unreachableCarrier struct{}

func (unreachableCarrier) ExchangeICMP(context.Context, *C.Metadata, []byte) ([]byte, error) {
	return nil, icmptunnel.ErrUnreachable
}

// localAnswerCarrier answers an echo this node is the target of: the message
// describes a packet this stack would have answered itself.
type localAnswerCarrier struct{}

func (localAnswerCarrier) ExchangeICMP(_ context.Context, metadata *C.Metadata, request []byte) ([]byte, error) {
	return icmptunnel.LocalReply(request, metadata.DstIP)
}

// silentCarrier stands in for "this echo cannot be placed right now": it is
// dropped, so the tool times out rather than being told a route does not exist.
type silentCarrier struct{}

func (silentCarrier) ExchangeICMP(context.Context, *C.Metadata, []byte) ([]byte, error) {
	return nil, errEchoNotPlaced
}

var errEchoNotPlaced = errors.New("icmp: the flow could not be placed")

// icmpCarrier finds the outbound that would carry the echo. A rule may name a
// group, and what a group dials is what it would have carried this echo with:
// the selection is read without touching it, the same way TCP and UDP follow
// it, so a peer that is currently selected can answer a ping. A decorator
// around the outbound - the one that closes it when the config is replaced -
// embeds the adapter interface and hides everything else, so the adapter
// underneath is asked too.
func icmpAdapter(proxy C.Proxy, metadata *C.Metadata) (C.ProxyAdapter, string) {
	for depth := 0; proxy != nil && depth < 8; depth++ {
		adapter := proxy.Adapter()
		if _, ok := C.ICMPCarrierOf(adapter); ok {
			return adapter, proxy.Name()
		}
		if _, ok := C.ICMPRedirectOf(adapter); ok {
			return adapter, proxy.Name()
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
	go d.exchange(request, reply, raw)
	return nil
}

// exchange asks the outbound for the reply and writes it back into the tunnel.
// It runs in its own goroutine so a slow peer never blocks the packet loop.
func (d *icmpProxyDestination) exchange(request []byte, builder replyBuilder, raw []byte) {
	ctx, cancel := context.WithTimeout(d.ctx, d.timeout)
	defer cancel()
	reply, err := d.proxy.ExchangeICMP(ctx, d.metadata, request)
	if err != nil {
		if errors.Is(err, icmptunnel.ErrUnreachable) {
			// The echo cannot be put on the wire as it stands: answer with the
			// error a router would send, so the tool reports a network failure
			// instead of waiting for an answer that cannot come.
			d.writeUnreachable(raw, err)
			return
		}
		log.Debugln("[ICMP] %s %s: %s", d.metadata.SourceDetail(), d.metadata.RemoteAddress(), err)
		return
	}
	d.writeAnswer(builder, reply)
}

// writeUnreachable answers an echo that cannot be delivered with the error a
// router would send: the packet that could not be delivered plus the first
// eight bytes of its message, which is what the tool matches its own request
// with.
func (d *icmpProxyDestination) writeUnreachable(raw []byte, reason error) {
	packet, err := unreachableReply(raw)
	if err != nil {
		log.Debugln("[ICMP] %s: %s", d.metadata.RemoteAddress(), err)
		return
	}
	log.Debugln("[ICMP] %s cannot be reached as it stands: answering unreachable (%s)", d.metadata.RemoteAddress(), reason)
	if err := d.back.WritePacket(packet); err != nil {
		log.Debugln("[ICMP] unreachable answer for %s: %s", d.metadata.RemoteAddress(), err)
	}
}

// unreachableReply builds the ICMP error for a packet this node will not put
// on the wire: source and destination swap, the error type says the destination
// cannot be reached, and the original header and message travel inside it.
func unreachableReply(raw []byte) ([]byte, error) {
	switch ipVersion(raw) {
	case 4:
		if len(raw) < 20 {
			return nil, errors.New("truncated IPv4 packet")
		}
		headerLength := int(raw[0]&0x0f) * 4
		if headerLength < 20 || len(raw) < headerLength+8 {
			return nil, errors.New("invalid IPv4 header length")
		}
		embed := raw[:headerLength+8]
		packet := make([]byte, 20+8+len(embed))
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		packet[8] = 64 // ttl
		packet[9] = 1  // icmp
		copy(packet[12:16], raw[16:20])
		copy(packet[16:20], raw[12:16])
		binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
		packet[20] = 3 // destination unreachable
		packet[21] = 1 // host unreachable
		copy(packet[28:], embed)
		binary.BigEndian.PutUint16(packet[22:24], checksum(packet[20:]))
		return packet, nil
	case 6:
		if len(raw) < 40+8 {
			return nil, errors.New("truncated IPv6 packet")
		}
		embed := raw[:40+8]
		packet := make([]byte, 40+8+len(embed))
		packet[0] = 0x60
		binary.BigEndian.PutUint16(packet[4:6], uint16(8+len(embed)))
		packet[6] = 58 // icmpv6
		packet[7] = 64 // hop limit
		copy(packet[8:24], raw[24:40])
		copy(packet[24:40], raw[8:24])
		packet[40] = 1 // destination unreachable
		packet[41] = 0 // no route to destination
		copy(packet[48:], embed)
		source := netip.AddrFrom16([16]byte(packet[8:24]))
		destination := netip.AddrFrom16([16]byte(packet[24:40]))
		binary.BigEndian.PutUint16(packet[42:44], icmpv6Checksum(source, destination, packet[40:]))
		return packet, nil
	default:
		return nil, errors.New("not an IP packet")
	}
}

// writeAnswer hands the message an outbound returned to the packet builder and
// writes the packet into the tunnel.
func (d *icmpProxyDestination) writeAnswer(builder replyBuilder, reply []byte) {
	packet, err := builder(reply)
	if err != nil {
		log.Warnln("[ICMP] %s answer is unusable: %s", d.metadata.RemoteAddress(), err)
		return
	}
	if err := d.back.WritePacket(packet); err != nil {
		log.Debugln("[ICMP] write answer for %s: %s", d.metadata.RemoteAddress(), err)
	}
}

// resolveForEcho answers with an address the given family can reach.
func resolveForEcho(ctx context.Context, host string, ipv6 bool) (netip.Addr, error) {
	if ipv6 {
		return resolver.ResolveIPv6(ctx, host)
	}
	return resolver.ResolveIPv4(ctx, host)
}

// icmpDirectDestination sends the tool's own echo to the address the flow
// really means and writes the answer back as the address the tool pinged.
//
// A name is pinged as the placeholder the resolver handed out, and a peer is
// pinged as its name; in both cases the message is already the right one, and
// only the address on the wire has to be the real one. So the packet keeps its
// bytes, the direct path carries it - the same one a raw address takes - and
// the answer is readdressed to the placeholder before it is written into the
// tunnel, because a tool drops an answer from an address it did not ping.
type icmpDirectDestination struct {
	ctx      context.Context
	cancel   context.CancelFunc
	back     tun.DirectRouteContext
	metadata *C.Metadata
	pinged   netip.Addr
	real     netip.Addr
	timeout  time.Duration

	mu     sync.Mutex
	closed bool
	direct tun.DirectRouteDestination
}

func newICMPDirectDestination(
	parent context.Context,
	back tun.DirectRouteContext,
	metadata *C.Metadata,
	pinged netip.Addr,
	real netip.Addr,
	timeout time.Duration,
) *icmpDirectDestination {
	ctx, cancel := context.WithCancel(parent)
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &icmpDirectDestination{
		ctx:      ctx,
		cancel:   cancel,
		back:     back,
		metadata: metadata,
		pinged:   pinged,
		real:     real,
		timeout:  timeout,
	}
}

func (d *icmpDirectDestination) WritePacket(packet *buf.Buffer) error {
	raw := append([]byte(nil), packet.Bytes()...)
	packet.Release()
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()
	if closed {
		return nil
	}
	direct, err := d.destination()
	if err != nil {
		log.Warnln("[ICMP] %s: %s", d.metadata.RemoteAddress(), err)
		return nil
	}
	if err := direct.WritePacket(buf.As(readdress(raw, d.real, false)).ToOwned()); err != nil {
		log.Debugln("[ICMP] %s: %s", d.metadata.RemoteAddress(), err)
	}
	return nil
}

// destination keeps the direct socket for as long as the flow lives: it holds
// the requests it sent and the source their answers come back to, so a fresh
// one per echo would mean a fresh answer table per echo.
func (d *icmpDirectDestination) destination() (tun.DirectRouteDestination, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.direct != nil && !d.direct.IsClosed() {
		return d.direct, nil
	}
	direct, err := directICMPDestination(
		M.SocksaddrFrom(d.real, 0),
		readdressedRoute{back: d.back, source: d.pinged},
		d.timeout,
	)
	if err != nil {
		return nil, err
	}
	d.direct = direct
	return direct, nil
}

func (d *icmpDirectDestination) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	direct := d.direct
	d.direct = nil
	d.mu.Unlock()
	d.cancel()
	if direct != nil {
		return direct.Close()
	}
	return nil
}

func (d *icmpDirectDestination) IsClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed
}

// readdressedRoute writes every answer back as the address the tool pinged.
type readdressedRoute struct {
	back   tun.DirectRouteContext
	source netip.Addr
}

func (r readdressedRoute) WritePacket(packet []byte) error {
	return r.back.WritePacket(readdress(packet, r.source, true))
}

// readdress writes [address] into one end of a packet: the destination when the
// packet is a request on its way out, the source when it is the answer coming
// back. The checksums that cover an address are recomputed - the IPv4 header's
// always, and ICMPv6's, whose pseudo header names both ends.
func readdress(packet []byte, address netip.Addr, asSource bool) []byte {
	switch ipVersion(packet) {
	case 4:
		if len(packet) < 20 || !address.Is4() {
			return packet
		}
		out := append([]byte(nil), packet...)
		offset := 16
		if asSource {
			offset = 12
		}
		copy(out[offset:offset+4], address.AsSlice())
		out[10], out[11] = 0, 0
		binary.BigEndian.PutUint16(out[10:12], checksum(out[:20]))
		return out
	case 6:
		if len(packet) < 40+8 || !address.Is6() {
			return packet
		}
		out := append([]byte(nil), packet...)
		offset := 24
		if asSource {
			offset = 8
		}
		address16 := address.As16()
		copy(out[offset:offset+16], address16[:])
		source := netip.AddrFrom16([16]byte(out[8:24]))
		destination := netip.AddrFrom16([16]byte(out[24:40]))
		binary.BigEndian.PutUint16(out[42:44], 0)
		binary.BigEndian.PutUint16(out[42:44], icmpv6Checksum(source, destination, out[40:]))
		return out
	default:
		return packet
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
