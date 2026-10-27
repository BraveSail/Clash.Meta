//go:build darwin && !ios

package mesh

import (
	"os/exec"
	"strings"
)

// platformMachineID reads the platform UUID out of ioreg. macOS has no
// machine-id file; IOPlatformUUID is the identifier that survives reboots and
// is unique to the machine.
func platformMachineID() string {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "IOPlatformUUID") {
			continue
		}
		_, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		return strings.Trim(strings.TrimSpace(value), `"`)
	}
	return ""
}

// platformOSName is "macOS 14.5", from the system itself.
func platformOSName() string {
	out, err := exec.Command("sw_vers", "-productVersion").Output()
	version := strings.TrimSpace(string(out))
	if err != nil || version == "" {
		return "macOS"
	}
	return "macOS " + version
}
