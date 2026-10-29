package listener

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// noteCoreEvent writes what the core opens and closes to a file beside the
// profile.
//
// The app shows the core's log only while its window is open, and the symptom
// worth chasing here - a proxy that stops listening while the process and the
// tunnel are still up - happens exactly when nobody is looking. A line per
// listener, with the time, is the difference between "it stopped" and "the app
// closed this port at 09:41".
func noteCoreEvent(format string, args ...any) {
	home := strings.TrimSpace(C.Path.HomeDir())
	if home == "" {
		return
	}
	line := time.Now().Format(time.RFC3339) + "  " + fmt.Sprintf(format, args...) + "\n"
	file, err := os.OpenFile(filepath.Join(home, "core-events.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	_, _ = file.WriteString(line)
	_ = file.Close()
}
