//go:build with_gvisor && !no_tailscale && linux && tailscale_kernel_host_forward_e2e

package outbound_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/tailscale/net/netns"
	"github.com/metacubex/tailscale/net/stun/stuntest"
	"github.com/metacubex/tailscale/tailcfg"
	"github.com/metacubex/tailscale/tstest/integration/testcontrol"
	"github.com/metacubex/tailscale/types/nettype"
)

func TestTailscaleKernelHostForwardRuntimeConfigureE2E(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel host-forward runtime e2e requires root or CAP_NET_ADMIN")
	}

	oldHome := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() { C.SetHomeDir(oldHome) })

	controlURL := startKernelRuntimeControl(t)
	device := fmt.Sprintf("mtsr%06d", os.Getpid()%1000000)
	proxy, err := outbound.NewTailscale(outbound.TailscaleOption{
		Name:       "kernel-runtime",
		Hostname:   "kernel-runtime",
		ControlURL: controlURL,
		StateDir:   filepath.Join("tailscale-kernel-runtime-e2e", "server"),
		Ephemeral:  true,
		HostForward: outbound.TailscaleHostForwardOption{
			Enabled: true,
			Mode:    "kernel",
			Device:  device,
			MTU:     1280,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })

	var lastStatus, lastAddr, lastRoute string
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		status, err := proxy.TailnetStatus(ctx)
		cancel()
		if err != nil {
			lastStatus = "status error: " + err.Error()
		} else {
			lastStatus = fmt.Sprintf("backend=%s ips=%v peers=%d", status.BackendState, status.TailscaleIPs, len(status.Peers))
		}

		lastAddr = kernelRuntimeCommandOutput("ip", "-4", "addr", "show", "dev", device)
		lastRoute = kernelRuntimeCommandOutput("ip", "route", "show", "100.64.0.0/10", "dev", device)
		if strings.Contains(lastStatus, "backend=Running") &&
			strings.Contains(lastAddr, "100.") &&
			strings.Contains(lastRoute, "100.64.0.0/10") {
			t.Logf("kernel host-forward configured: %s", lastStatus)
			return
		}
		time.Sleep(250 * time.Millisecond)
	}

	lastLink := kernelRuntimeCommandOutput("ip", "-br", "link", "show", "dev", device)
	t.Fatalf("kernel host-forward never configured: %s link=%q addr=%q route=%q",
		lastStatus, strings.TrimSpace(lastLink), strings.TrimSpace(lastAddr), strings.TrimSpace(lastRoute))
}

func startKernelRuntimeControl(t *testing.T) string {
	t.Helper()
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })

	capMap := tailcfg.NodeCapMap{
		tailcfg.CapabilityHTTPS:                           []tailcfg.RawMessage{},
		tailcfg.NodeAttrFunnel:                            []tailcfg.RawMessage{},
		tailcfg.CapabilityFileSharing:                     []tailcfg.RawMessage{},
		tailcfg.CapabilityFunnelPorts + "?ports=8080,443": []tailcfg.RawMessage{},
		// The forked local test-control fixture can panic while setting up
		// peer-relay state on custom-TUN nodes before traffic starts.
		tailcfg.NodeAttrDisableRelayClient: []tailcfg.RawMessage{},
	}
	control := &testcontrol.Server{
		DERPMap: kernelRuntimeLocalDERPMap(t, "127.0.0.1"),
		DNSConfig: &tailcfg.DNSConfig{
			Proxied: true,
		},
		MagicDNSDomain:          "tail-scale.ts.net",
		DefaultNodeCapabilities: &capMap,
		Logf:                    t.Logf,
		AllOnline:               true,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	return control.HTTPTestServer.URL
}

func kernelRuntimeLocalDERPMap(t *testing.T, ipAddress string) *tailcfg.DERPMap {
	t.Helper()

	stunAddr, stunCleanup := stuntest.ServeWithPacketListener(t, nettype.Std{})
	t.Cleanup(func() { stunCleanup() })

	return &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:             "t1",
						RegionID:         1,
						HostName:         ipAddress,
						IPv4:             ipAddress,
						IPv6:             "none",
						STUNPort:         stunAddr.Port,
						DERPPort:         9,
						InsecureForTests: true,
						STUNTestIP:       ipAddress,
					},
				},
			},
		},
	}
}

func kernelRuntimeCommandOutput(name string, args ...string) string {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Sprintf("%v: %s", err, out)
	}
	return string(out)
}
