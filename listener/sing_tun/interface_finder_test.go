package sing_tun

import (
	"net"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/iface"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/control"
	"github.com/metacubex/sing/common/x/list"
)

type stubDefaultInterfaceMonitor struct {
	current *control.Interface
}

func (m *stubDefaultInterfaceMonitor) Start() error { return nil }

func (m *stubDefaultInterfaceMonitor) Close() error { return nil }

func (m *stubDefaultInterfaceMonitor) DefaultInterface() *control.Interface {
	return m.current
}

func (m *stubDefaultInterfaceMonitor) OverrideAndroidVPN() bool { return false }

func (m *stubDefaultInterfaceMonitor) AndroidVPNEnabled() bool { return false }

func (m *stubDefaultInterfaceMonitor) RegisterCallback(
	callback tun.DefaultInterfaceUpdateCallback,
) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	return nil
}

func (m *stubDefaultInterfaceMonitor) UnregisterCallback(
	element *list.Element[tun.DefaultInterfaceUpdateCallback],
) {
}

func TestDialerInterfaceFinderKeepsLastKnownInterface(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(interfaces) == 0 {
		t.Skip("no network interfaces")
	}
	name := interfaces[0].Name
	if _, err := iface.ResolveInterface(name); err != nil {
		t.Skipf("interface %q is not visible to the interface cache: %v", name, err)
	}

	monitor := &stubDefaultInterfaceMonitor{
		current: &control.Interface{
			Index:        interfaces[0].Index,
			MTU:          interfaces[0].MTU,
			Name:         interfaces[0].Name,
			HardwareAddr: interfaces[0].HardwareAddr,
			Flags:        interfaces[0].Flags,
		},
	}
	finder := &cDialerInterfaceFinder{
		tunName:                 "Meta",
		defaultInterfaceMonitor: monitor,
	}
	// TEST-NET-3 never matches a local prefix, so the finder has to use the
	// monitor and its fallback.
	destination := netip.MustParseAddr("203.0.113.1")

	if got := finder.DefaultInterfaceName(destination); got != name {
		t.Fatalf("DefaultInterfaceName = %q, want %q", got, name)
	}

	monitor.current = nil
	if got := finder.DefaultInterfaceName(destination); got != name {
		t.Fatalf("fallback after the monitor lost the interface = %q, want %q", got, name)
	}

	finder.lastKnownName.Store("definitely-not-an-interface")
	if got := finder.DefaultInterfaceName(destination); got != "" {
		t.Fatalf("missing interface = %q, want an empty name", got)
	}
}
