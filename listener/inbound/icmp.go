package inbound

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/icmptunnel"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// An ICMP responder is the far end of the tunnel's echo support: a peer sends
// an envelope holding the address to reach and the ICMP message to send there,
// and this puts a real echo on the wire - through the operating system's own
// echo API on Windows and an unprivileged ICMP socket elsewhere - then sends
// the answer back the way it came. It exists so `ping` can leave through a node
// that is itself running mihomo, without a raw socket, a second tool or any
// administrator rights.
type ICMPResponderOption struct {
	BaseOption
	// Timeout is how long one echo may take before the caller is told nothing
	// came back, in seconds.
	Timeout int64 `inbound:"timeout,omitempty"`
}

func (o ICMPResponderOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type ICMPResponder struct {
	*Base
	config *ICMPResponderOption

	mu    sync.Mutex
	conns []net.PacketConn
}

func NewICMPResponder(options *ICMPResponderOption) (*ICMPResponder, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &ICMPResponder{Base: base, config: options}, nil
}

// Config implements constant.InboundListener
func (r *ICMPResponder) Config() C.InboundConfig {
	return r.config
}

// Address implements constant.InboundListener
func (r *ICMPResponder) Address() string {
	return r.RawAddress()
}

// Listen implements constant.InboundListener
func (r *ICMPResponder) Listen(C.Tunnel) error {
	for _, addr := range strings.Split(r.RawAddress(), ",") {
		conn, err := net.ListenPacket("udp", addr)
		if err != nil {
			return err
		}
		r.mu.Lock()
		r.conns = append(r.conns, conn)
		r.mu.Unlock()
		go r.serve(conn)
	}
	log.Infoln("ICMPResponder[%s] listening at: %s", r.Name(), r.Address())
	return nil
}

func (r *ICMPResponder) serve(conn net.PacketConn) {
	timeout := time.Duration(r.config.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	buffer := make([]byte, 2048)
	for {
		length, from, err := conn.ReadFrom(buffer)
		if err != nil {
			return // the listener is closing
		}
		target, message, err := icmptunnel.Decode(buffer[:length])
		if err != nil {
			log.Debugln("[ICMP] responder: %s", err)
			continue
		}
		go r.answer(conn, from, target, message, timeout)
	}
}

// answer performs one echo and returns the envelope with the reply in it.
func (r *ICMPResponder) answer(
	conn net.PacketConn,
	from net.Addr,
	target netip.Addr,
	message []byte,
	timeout time.Duration,
) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout+time.Second)
	defer cancel()
	reply, err := icmptunnel.Exchange(ctx, target, message, timeout)
	if err != nil {
		// A target that does not answer is reported to the caller by silence:
		// its ping times out, which is the truth.
		log.Debugln("[ICMP] responder: %s: %s", target, err)
		return
	}
	envelope, err := icmptunnel.Encode(target, reply)
	if err != nil {
		return
	}
	if _, err := conn.WriteTo(envelope, from); err != nil {
		log.Debugln("[ICMP] responder: write answer for %s: %s", target, err)
	}
}

// Close implements constant.InboundListener
func (r *ICMPResponder) Close() error {
	r.mu.Lock()
	conns := r.conns
	r.conns = nil
	r.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	return nil
}

var _ C.InboundListener = (*ICMPResponder)(nil)
