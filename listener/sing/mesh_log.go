package sing

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// noteIncomingToDisk records what an inbound stream asked this device to open.
//
// The receiving half of the mesh has no readable log: the app shows the core's
// output while it is open and forgets it when it closes, and a stream that is
// accepted and then says nothing leaves no trace anywhere. Writing the request
// down turns "it hangs" into "it asked for this and was answered with nothing".
func noteIncomingToDisk(asked string, metadata *C.Metadata) {
	home := strings.TrimSpace(C.Path.HomeDir())
	if home == "" || metadata == nil {
		return
	}
	line := fmt.Sprintf("%s  in  asked=%s  host=%q  dstip=%v  port=%d  type=%v\n",
		time.Now().Format(time.RFC3339), asked, metadata.Host, metadata.DstIP, metadata.DstPort, metadata.Type)
	file, err := os.OpenFile(filepath.Join(home, "mesh-dial.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	_, _ = file.WriteString(line)
	_ = file.Close()
}
