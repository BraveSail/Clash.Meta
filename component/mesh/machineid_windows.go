package mesh

import (
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

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