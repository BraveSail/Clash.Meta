package mesh

import (
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

// platformMachineID reads the machine's own GUID, the same value the app used
// to send: HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid. It survives
// reinstalls and reboots and is unique per Windows installation.
//
// WOW64_64KEY is asked for explicitly: a 32-bit build would otherwise be
// redirected to the WOW6432Node view, which does not hold this key, and the
// device would come up with no id at all.
func platformMachineID() string {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`,
		registry.QUERY_VALUE|registry.WOW64_64KEY,
	)
	if err != nil {
		return ""
	}
	defer key.Close()
	value, _, err := key.GetStringValue("MachineGuid")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(value)
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
