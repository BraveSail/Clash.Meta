package mesh

import (
	"os"
	"strings"
)

// platformMachineID reads the systemd/dbus machine id: the value a Linux
// installation keeps for its whole life. The two files hold the same id; the
// second is the older location and is still all some systems have.
func platformMachineID() string {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if id := strings.TrimSpace(string(data)); id != "" {
			return id
		}
	}
	return ""
}

// platformOSName takes the distribution's own pretty name, e.g. "Ubuntu 24.04
// LTS" - the string a person recognises, rather than the kernel's.
func platformOSName() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "Linux"
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "PRETTY_NAME" {
			continue
		}
		name := strings.Trim(strings.TrimSpace(value), `"`)
		if name != "" {
			return name
		}
	}
	return "Linux"
}
