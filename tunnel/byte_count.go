package tunnel

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// byteCounter counts what actually crossed a connection, so "the tunnel was
// open" and "the tunnel carried something" stop being the same sentence.
type byteCounter struct {
	net.Conn
	n *int64
}

func newByteCounter(conn net.Conn) *byteCounter {
	return &byteCounter{Conn: conn, n: new(int64)}
}

func (c *byteCounter) value() int64 {
	return atomic.LoadInt64(c.n)
}

func (c *byteCounter) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		atomic.AddInt64(c.n, int64(n))
	}
	return n, err
}

func (c *byteCounter) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		atomic.AddInt64(c.n, int64(n))
	}
	return n, err
}

// noteBytesToDisk writes the byte counts of a finished stream when one side
// carried nothing: that is the shape of a stream that opened, said nothing and
// timed out, and it is invisible in every other log line.
func noteBytesToDisk(downstream, upstream int64) {
	if downstream != 0 && upstream != 0 {
		return
	}
	home := strings.TrimSpace(C.Path.HomeDir())
	if home == "" {
		return
	}
	line := fmt.Sprintf("%s  bytes downstream=%d upstream=%d\n",
		time.Now().Format(time.RFC3339), downstream, upstream)
	file, err := os.OpenFile(filepath.Join(home, "mesh-dial.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	_, _ = file.WriteString(line)
	_ = file.Close()
}
