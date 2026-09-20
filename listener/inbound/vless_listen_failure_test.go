package inbound_test

import (
	"net"
	"strconv"
	"testing"

	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/vless/encryption"
	"github.com/stretchr/testify/assert"
)

// A listener whose port is already taken must surface the bind error instead
// of crashing in the decryption cleanup of its named return value.
func TestInboundVless_ListenFailureDoesNotPanic(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	defer blocker.Close()

	privateKeyBase64, _, _, err := encryption.GenX25519("")
	if !assert.NoError(t, err) {
		return
	}

	inboundOptions := inbound.VlessOption{
		BaseOption: inbound.BaseOption{
			NameStr: "vless_inbound",
			Listen:  "127.0.0.1",
			Port:    strconv.Itoa(blocker.Addr().(*net.TCPAddr).Port),
		},
		Decryption: "mlkem768x25519plus.native.600s." + privateKeyBase64,
	}
	in, err := inbound.NewVless(&inboundOptions)
	if !assert.NoError(t, err) {
		return
	}

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	assert.Error(t, in.Listen(tunnel))
}
