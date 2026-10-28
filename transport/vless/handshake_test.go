package vless

import (
	"net"
	"testing"
	"time"
)

// TestHandshakeSendsTheRequestBeforeAnyPayload pins the behaviour a mesh peer
// depends on: the destination must reach the server even when the client has
// nothing to send yet. A server-speaks-first protocol replies the moment the
// request arrives, and a request folded into the first payload never arrives at
// all - the listener accepts TCP and reads zero bytes.
func TestHandshakeSendsTheRequestBeforeAnyPayload(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	instance, err := NewClient("8b7a6c2d-2f5f-4d23-9a2b-5f6b1c3d4e5f", nil)
	if err != nil {
		t.Fatal(err)
	}
	dst := &DstAddr{Port: 9527, AddrType: AtypIPv4, Addr: net.IPv4(127, 0, 0, 1).To4()}
	conn, err := instance.StreamConn(client, dst)
	if err != nil {
		t.Fatal(err)
	}

	got := make(chan []byte, 1)
	go func() {
		buffer := make([]byte, 128)
		n, _ := server.Read(buffer)
		got <- buffer[:n]
	}()

	handshaker, ok := conn.(interface{ Handshake() error })
	if !ok {
		t.Fatal("a vless connection must be able to send its request on its own")
	}
	if err := handshaker.Handshake(); err != nil {
		t.Fatal(err)
	}

	select {
	case request := <-got:
		if len(request) == 0 {
			t.Fatal("the request was empty")
		}
		if request[0] != Version {
			t.Fatalf("version = %d, want %d", request[0], Version)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("nothing was sent before a payload was written")
	}
}
