package tunnel

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// noteStageToDisk writes where a proxied connection has got to.
//
// A CONNECT that answers 200 and then says nothing has already been dialled and
// already been forwarded, or it has not: those two look identical from the
// client, and one of them is a bug in the peer while the other is a bug here.
// Writing each stage down tells them apart.
func noteStageToDisk(stage string, metadata *C.Metadata) {
	home := strings.TrimSpace(C.Path.HomeDir())
	if home == "" || metadata == nil {
		return
	}
	line := fmt.Sprintf("%s  stage %s  dst=%s  type=%v\n",
		time.Now().Format(time.RFC3339), stage, metadata.RemoteAddress(), metadata.Type)
	file, err := os.OpenFile(filepath.Join(home, "mesh-dial.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	_, _ = file.WriteString(line)
	_ = file.Close()
}
