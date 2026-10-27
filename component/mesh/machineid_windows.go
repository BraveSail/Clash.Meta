package mesh

import (
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

// platformMachineID reads the machine's own id: SQMClient\MachineId, the value
// this deployment has always reported under.
//
// That key, not Cryptography\MachineGuid, is what the app read before the
// derivation moved here, so the ids already recorded on the hub are hashes of
// it - reading the other one would re-register every Windows device as new.
// The GUID is the fallback for a system with no SQMClient key.
//
// WOW64_64KEY is asked for explicitly: a 32-bit build would otherwise be
// redirected to the WOW6432Node view, which does not hold these keys.
func platformMachineID() string {
	for _, probe := range []struct{ path, value string }{
		{`SOFTWARE\Microsoft\SQMClient`, "MachineId"},
		{`SOFTWARE\Microsoft\Cryptography`, "MachineGuid"},
	} {
		key, err := registry.OpenKey(
			registry.LOCAL_MACHINE,
			probe.path,
			registry.QUERY_VALUE|registry.WOW64_64KEY,
		)
		if err != nil {
			continue
		}
		value, _, err := key.GetStringValue(probe.value)
		key.Close()
		if err != nil {
			continue
		}
		// Taken verbatim, braces included: the hash on the hub was computed
		// over exactly this string.
		if id := strings.TrimSpace(value); id != "" {
			return id
		}
	}
	return ""
}

// platformOSName is "Windows 11 Pro 23H2"-ish: the product name and the
// display version, which is what a person recognises in the dashboard.
func platformOSName() string {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		registry.QUERY_VALUE|registry.WOW64_64KEY,
	)
	if err != nil {
		return "Windows"
	}
	defer key.Close()
	product, _, _ := key.GetStringValue("ProductName")
	display, _, _ := key.GetStringValue("DisplayVersion")
	parts := make([]string, 0, 2)
	if product = strings.TrimSpace(product); product != "" {
		parts = append(parts, product)
	}
	if display = strings.TrimSpace(display); display != "" {
		parts = append(parts, display)
	}
	if len(parts) == 0 {
		return "Windows"
	}
	return strings.Join(parts, " ")
}

var _ = syscall.Errno(0)
