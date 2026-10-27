//go:build linux && !android

package mesh

import (
	"os"
	"strings"
)

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