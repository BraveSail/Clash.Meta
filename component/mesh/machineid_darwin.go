//go:build darwin && !ios

package mesh

import (
	"os/exec"
	"strings"
)

func platformOSName() string {
	out, err := exec.Command("sw_vers", "-productVersion").Output()
	version := strings.TrimSpace(string(out))
	if err != nil || version == "" {
		return "macOS"
	}
	return "macOS " + version
}