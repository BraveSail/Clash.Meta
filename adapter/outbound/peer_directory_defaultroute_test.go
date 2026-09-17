package outbound

import (
	"errors"
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// stubStrategy rewrites the decision layer's inputs for one test: the order it
// asks them in, and what each answers, is the whole point.
func stubStrategy(t *testing.T, platform string, underlying string, underlyingHow string, socket string) {
	t.Helper()
	previousPlatform, previousUnderlying, previousSocket := platformDefaultInterface, underlyingInterfaceName, socketProbeDefaultInterface
	platformDefaultInterface = func() string { return platform }
	underlyingInterfaceName = func() (string, string, error) {
		if underlying == "" {
			return "", "", errors.New("stub: nothing underlying")
		}
		return underlying, underlyingHow, nil
	}
	socketProbeDefaultInterface = func() (string, error) {
		if socket == "" {
			return "", errors.New("stub: no socket answer")
		}
		return socket, nil
	}
	t.Cleanup(func() {
		platformDefaultInterface, underlyingInterfaceName, socketProbeDefaultInterface = previousPlatform, previousUnderlying, previousSocket
	})
}

func testCandidates() map[string][]netip.Addr {
	return map[string][]netip.Addr{
		"以太网":         {netip.MustParseAddr("2409:8a55:d0a4:5500::a38e"), netip.MustParseAddr("fe80::1")},
		"rmnet_data0": {netip.MustParseAddr("2409:815a:d214:2446::27f7")},
		"tun0":        {netip.MustParseAddr("fd7a:115c:a1e0::1"), netip.MustParseAddr("2001:db8::1")},
	}
}

func testDirectory(t *testing.T) *PeerDirectory {
	t.Helper()
	// A real one needs a context and a client; the decision layer only reads the
	// name and the stored underlay answer.
	return &PeerDirectory{
		Base:   NewBase(BaseOption{Name: "test", Addr: "https://example.invalid", Type: C.PeerDirectory}),
		cancel: func() {},
	}
}

// The protected probe answers with the exact source address the system would
// use, so it leads, and it never has to ask anything else.
func TestChooseReportAddressPrefersTheProtectedProbe(t *testing.T) {
	stubStrategy(t, "以太网", "以太网", "winipcfg-gateway", "rmnet_data0")
	directory := testDirectory(t)
	directory.storeUnderlay(netip.MustParseAddr("2409:815a:d214:2446::27f7"), "rmnet_data0")

	addr, ifaceName, how := directory.chooseReportAddress(testCandidates())
	if addr != "2409:815a:d214:2446::27f7" || ifaceName != "rmnet_data0" || how != "protected-probe" {
		t.Fatalf("chooseReportAddress = %q iface=%q how=%q, want the protected probe's answer", addr, ifaceName, how)
	}
}

// A strategy that names a tunnel is rejected: on Windows the OS default-route
// lookup answers with this app's own wintun adapter, and publishing the
// tunnel's own address makes the node unreachable.
func TestChooseReportAddressRejectsVirtualAnswers(t *testing.T) {
	stubStrategy(t, "tun0", "rmnet_data0", "uid-route", "tun0")
	directory := testDirectory(t)

	addr, ifaceName, how := directory.chooseReportAddress(testCandidates())
	if addr != "2409:815a:d214:2446::27f7" || ifaceName != "rmnet_data0" || how != "uid-route" {
		t.Fatalf("chooseReportAddress = %q iface=%q how=%q, want the underlying answer after the tunnel was refused",
			addr, ifaceName, how)
	}
}

// When nothing can name the carrying interface the decision keeps the physical
// NIC addresses instead of publishing nothing at all: the fork learned that
// lesson as "kept 0 of 3".
func TestChooseReportAddressFailsOpen(t *testing.T) {
	stubStrategy(t, "tun0", "", "", "tun0")
	directory := testDirectory(t)

	addr, ifaceName, how := directory.chooseReportAddress(testCandidates())
	if how != "interface-scan" {
		t.Fatalf("how = %q, want the interface scan", how)
	}
	if ifaceName != "" {
		t.Fatalf("iface = %q, want no interface named by a scan", ifaceName)
	}
	if addr != "2409:815a:d214:2446::27f7" && addr != "2409:8a55:d0a4:5500::a38e" {
		t.Fatalf("addr = %q, want a physical NIC address", addr)
	}
}

// Every candidate belongs to a tunnel: there is nothing to publish, and saying
// so is better than publishing the tunnel's address.
func TestChooseReportAddressWithOnlyVirtualCandidates(t *testing.T) {
	stubStrategy(t, "tun0", "", "", "tun0")
	directory := testDirectory(t)
	candidates := map[string][]netip.Addr{"tun0": {netip.MustParseAddr("fd7a:115c:a1e0::1")}}

	addr, _, how := directory.chooseReportAddress(candidates)
	if addr != "" || how != "none" {
		t.Fatalf("chooseReportAddress = %q how=%q, want nothing to publish", addr, how)
	}
}
