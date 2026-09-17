//go:build windows

package outbound

import (
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Windows tunnel adapter is a wintun device: IF_TYPE_PROP_VIRTUAL, named
// after the application that created it ("FlClash", "Meta"), so a name-prefix
// check cannot spot it. The tailscale fork hit exactly this and classified
// adapters by type and description instead; so does this.
const (
	ifTypeSoftwareLoopback = 24
	ifTypePropVirtual      = 53
	ifTypeTunnel           = 131
)

// isVirtualInterfaceName reports whether name belongs to an adapter that
// cannot be the physical NIC carrying traffic.
func isVirtualInterfaceName(name string) bool {
	if name == "" {
		return true
	}
	if isTunnelInterface(name) {
		return true
	}
	adapters, err := adapterAddresses()
	if err != nil {
		return false
	}
	for _, adapter := range adapters {
		if strings.EqualFold(windows.UTF16PtrToString(adapter.FriendlyName), name) {
			return isVirtualAdapter(adapter)
		}
	}
	return false
}

// isVirtualAdapter reports whether adapter is a loopback, virtual or tunnel
// adapter rather than a physical NIC.
func isVirtualAdapter(adapter *windows.IpAdapterAddresses) bool {
	switch adapter.IfType {
	case ifTypeSoftwareLoopback, ifTypePropVirtual, ifTypeTunnel:
		return true
	}
	description := strings.ToLower(windows.UTF16PtrToString(adapter.Description))
	for _, marker := range []string{"wintun", "sing-tun", "tailscale", "wireguard", "tap-windows", "openvpn", "tunnel", "vpn"} {
		if strings.Contains(description, marker) {
			return true
		}
	}
	return false
}

// adapterAddresses lists every adapter, including ones that are down or
// virtual, because the caller classifies them.
func adapterAddresses() ([]*windows.IpAdapterAddresses, error) {
	var buffer []byte
	size := uint32(15000)
	for {
		buffer = make([]byte, size)
		const flags = windows.GAA_FLAG_INCLUDE_PREFIX | windows.GAA_FLAG_INCLUDE_GATEWAYS
		err := windows.GetAdaptersAddresses(syscall.AF_UNSPEC, flags, 0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0])), &size)
		if err == nil {
			break
		}
		if err.(syscall.Errno) != syscall.ERROR_BUFFER_OVERFLOW || size <= uint32(len(buffer)) {
			return nil, os.NewSyscallError("getadaptersaddresses", err)
		}
	}
	var adapters []*windows.IpAdapterAddresses
	for adapter := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0])); adapter != nil; adapter = adapter.Next {
		adapters = append(adapters, adapter)
	}
	return adapters, nil
}

// underlyingDefaultInterface names the physical NIC that carries traffic while
// this app's tun owns the system default route.
//
// The fork ran a winipcfg metric comparison over the route table; that API is
// not in x/sys, and mihomo already keeps the same knowledge in its interface
// finder (sing-tun's monitor excludes the tun), so the platform strategy covers
// it. What is left here is the classification the fork needed: an up, non-
// virtual adapter that has a gateway, which is the one carrying traffic when
// the metric comparison is unavailable.
func underlyingDefaultInterface() (string, string, error) {
	adapters, err := adapterAddresses()
	if err != nil {
		return "", "", err
	}
	for _, adapter := range adapters {
		if adapter.OperStatus != windows.IfOperStatusUp || adapter.FirstGatewayAddress == nil {
			continue
		}
		if isVirtualAdapter(adapter) {
			continue
		}
		return windows.UTF16PtrToString(adapter.FriendlyName), "winipcfg-gateway", nil
	}
	return "", "", errNoUnderlyingInterface
}
