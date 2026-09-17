package tailnet

import (
	"context"
	"net/netip"
	"testing"
)

type stubProvider struct {
	status Status
}

func (s stubProvider) TailnetStatus(context.Context) (Status, error) {
	return s.status, nil
}

func TestResolvePeerFindsSelfAndPeers(t *testing.T) {
	provider := &stubProvider{status: Status{
		Self: &NodeStatus{Name: "me.tailnet.ts.net.", HostName: "me"},
		Peers: []NodeStatus{
			{Name: "pc.tailnet.ts.net.", HostName: "pc", TailscaleIPs: []string{"100.64.0.5"}},
		},
	}}
	RegisterStatusProvider("ts", provider)
	t.Cleanup(func() { UnregisterStatusProvider("ts", provider) })

	if peer, self, found := ResolvePeer(context.Background(), "pc"); !found || self || peer.HostName != "pc" {
		t.Fatalf("ResolvePeer(pc) = %+v self=%v found=%v", peer, self, found)
	}
	if _, self, found := ResolvePeer(context.Background(), "me.tailnet.ts.net"); !found || !self {
		t.Fatalf("ResolvePeer(self) self=%v found=%v, want self", self, found)
	}
	if peer, self, found := ResolvePeer(context.Background(), "100.64.0.5"); !found || self || peer.HostName != "pc" {
		t.Fatalf("ResolvePeer(ip) = %+v self=%v found=%v", peer, self, found)
	}
	if _, _, found := ResolvePeer(context.Background(), "missing"); found {
		t.Fatal("ResolvePeer(missing) found an unknown peer")
	}
}

func TestUnregisterKeepsTheReplacement(t *testing.T) {
	previous := &stubProvider{status: Status{Peers: []NodeStatus{{Name: "old"}}}}
	replacement := &stubProvider{status: Status{Peers: []NodeStatus{{Name: "new"}}}}
	RegisterStatusProvider("ts", previous)
	RegisterStatusProvider("ts", replacement)
	t.Cleanup(func() { UnregisterStatusProvider("ts", replacement) })

	UnregisterStatusProvider("ts", previous)

	if count := RegisteredProviderCount(); count != 1 {
		t.Fatalf("providers after the old outbound stopped = %d, want the replacement", count)
	}
	if _, _, found := ResolvePeer(context.Background(), "new"); !found {
		t.Fatal("the replacement provider is gone")
	}
}

func TestOrderPeerAddressesPrefersVerifiedThenSameLan(t *testing.T) {
	prefix := netip.MustParsePrefix("2409:8a55:d0a4:5500::/64")
	ordered := OrderPeerAddresses(NodeStatus{
		DirectVerified: true,
		CurAddr:        "[2409:8a55:aaaa::1]:41641",
		Addrs: []string{
			"192.168.1.5:41641",
			"[2409:8a55:d0a4:5500:1:2:3:4]:41641",
			"[2409:8a55:ffff::9]:41641",
			"[::1]:41641",
		},
	}, []netip.Prefix{prefix})

	want := []string{
		"2409:8a55:aaaa::1",
		"2409:8a55:d0a4:5500:1:2:3:4",
		"2409:8a55:ffff::9",
		"192.168.1.5",
	}
	if len(ordered) != len(want) {
		t.Fatalf("OrderPeerAddresses = %v, want %v", ordered, want)
	}
	for i, addr := range ordered {
		if addr.String() != want[i] {
			t.Fatalf("OrderPeerAddresses[%d] = %v, want %v", i, addr, want[i])
		}
	}
}

func TestOrderPeerAddressesIgnoresUnverifiedPath(t *testing.T) {
	ordered := OrderPeerAddresses(NodeStatus{
		CurAddr: "[2409:8a55:aaaa::1]:41641",
		Addrs:   []string{"[2409:8a55:ffff::9]:41641"},
	}, nil)
	if len(ordered) != 1 || ordered[0].String() != "2409:8a55:ffff::9" {
		t.Fatalf("OrderPeerAddresses = %v, want only the advertised address", ordered)
	}
}
