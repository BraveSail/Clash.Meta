package hubprofile

// The socket the hub pushes profiles over: whatever arrives in the same TCP
// segment as the 101 handshake response must still be read. The hub sends the
// first profile from inside its upgrade handler, so on a low-latency path the
// frame and the handshake travel together - a client that drops the reader
// ws.Dialer.Dial returns loses those bytes, reading from the middle of a
// frame or missing the push entirely.

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"
)

func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h[:])
}

// textFrame is one unmasked (server side) text frame holding payload.
func textFrame(payload string) []byte {
	n := len(payload)
	frame := []byte{0x81}
	switch {
	case n < 126:
		frame = append(frame, byte(n))
	case n < 65536:
		frame = append(frame, 126, byte(n>>8), byte(n))
	default:
		frame = append(frame, 127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return append(frame, payload...)
}

// watchFramePayload is what a fake hub pushes.
const watchFramePayload = `{"type":"profile","yaml":"mode: global\nrules:\n  - MATCH,DIRECT\n","etag":"\u0022v9\u0022"}`

// serveWatchAnswers accepts one socket and writes the 101 answer and the frame
// as two writes split at splitAt (0 = frame arrives with the handshake as one
// write, -1 = frame arrives after a pause, giving it its own segment).
func serveWatchAnswers(t *testing.T, splitAt int) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				var key string
				// Read the upgrade request's headers to answer its nonce.
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if strings.HasPrefix(strings.ToLower(line), "sec-websocket-key:") {
						key = strings.TrimSpace(line[len("sec-websocket-key:"):])
					}
					if line == "\r\n" {
						break
					}
				}
				resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + wsAccept(key) + "\r\n\r\n"
				frame := textFrame(watchFramePayload)
				switch {
				case splitAt > 0:
					// Handshake and the first part of the frame together.
					_, _ = c.Write(append([]byte(resp), frame[:splitAt]...))
					time.Sleep(30 * time.Millisecond)
					_, _ = c.Write(frame[splitAt:])
				case splitAt == 0:
					// Handshake and the whole frame in one write.
					_, _ = c.Write(append([]byte(resp), frame...))
				default:
					// The frame gets a segment of its own.
					_, _ = c.Write([]byte(resp))
					time.Sleep(40 * time.Millisecond)
					_, _ = c.Write(frame)
				}
				time.Sleep(3 * time.Second)
			}(c)
		}
	}()
	return ln
}

// watchOnce builds a client against the listener and reports whether the
// pushed profile was applied within wait.
func watchOnce(t *testing.T, splitAt int, wait time.Duration) bool {
	t.Helper()
	ln := serveWatchAnswers(t, splitAt)

	applied := make(chan struct{}, 1)
	client, err := New(Config{
		URL:   "http://" + ln.Addr().String(),
		Token: "test-token",
		ID:    "probe",
		File:  t.TempDir() + "/profile.yaml",
	}, func([]byte) error {
		select {
		case applied <- struct{}{}:
		default:
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Dial the stub directly; the mihomo dialer state is irrelevant here.
	client.dialDirect = (&net.Dialer{Timeout: 2 * time.Second}).DialContext

	ctx, cancel := context.WithTimeout(context.Background(), wait+time.Second)
	defer cancel()
	go func() { _ = client.watch(ctx, way{name: "direct", dial: client.dialDirect}) }()

	select {
	case <-applied:
		return true
	case <-time.After(wait):
		return false
	}
}

// The frame that travelled with the handshake must still be applied.
func TestWatchReadsTheFrameSentWithTheHandshake(t *testing.T) {
	if !watchOnce(t, 0, 2500*time.Millisecond) {
		t.Error("the frame sent with the handshake was not applied - the handshake's buffered bytes were dropped")
	}
}

// A frame straddling the handshake boundary must not desynchronise the stream.
func TestWatchReadsAPartialFrameSentWithTheHandshake(t *testing.T) {
	if !watchOnce(t, 40, 2500*time.Millisecond) {
		t.Error("the frame straddling the handshake was not applied - the stream is desynchronised")
	}
}

// Control: a frame in its own segment was always read, before and after the fix.
func TestWatchReadsAFrameSentAfterTheHandshake(t *testing.T) {
	if !watchOnce(t, -1, 2500*time.Millisecond) {
		t.Error("the frame sent after the handshake was not applied")
	}
}
