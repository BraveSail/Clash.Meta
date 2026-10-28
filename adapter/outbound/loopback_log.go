package outbound

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// loopbackDialLog records what became of a dial to this device's own loopback.
//
// A mesh peer is asked for its service, not for its name, so the destination
// that arrives at the far end is 127.0.0.1 and the port. If that dial never
// happens - or fails - the peer that asked sees a connection that opens and
// then says nothing, which is indistinguishable from a service that is down.
// The app shows the core's log only while it is open, so the outcome is also
// written next to the profile.
func loopbackDialLog(metadata *C.Metadata, err error) {
	if metadata == nil || !isLoopbackTarget(metadata) {
		return
	}
	home := strings.TrimSpace(C.Path.HomeDir())
	if home == "" {
		return
	}
	outcome := "ok"
	if err != nil {
		outcome = err.Error()
	}
	line := fmt.Sprintf("%s  direct %s  %s\n", time.Now().Format(time.RFC3339), metadata.RemoteAddress(), outcome)
	file, openErr := os.OpenFile(filepath.Join(home, "mesh-dial.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if openErr != nil {
		return
	}
	_, _ = file.WriteString(line)
	_ = file.Close()
}

func isLoopbackTarget(metadata *C.Metadata) bool {
	if host := strings.TrimSpace(metadata.Host); host == "localhost" {
		return true
	}
	if metadata.DstIP.IsValid() {
		return metadata.DstIP.IsLoopback()
	}
	if addr, err := netip.ParseAddr(strings.TrimSpace(metadata.Host)); err == nil {
		return addr.IsLoopback()
	}
	return false
}
