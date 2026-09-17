//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/tailnet"

	"github.com/metacubex/tailscale/tailcfg"
)

type stubPeerLookup struct {
	nodes map[tailcfg.NodeID]*tailcfg.Node
	err   error
}

func (s stubPeerLookup) PeerByID(_ context.Context, id tailcfg.NodeID) (*tailcfg.Node, error) {
	if s.err != nil {
		return nil, s.err
	}
	node, ok := s.nodes[id]
	if !ok {
		return nil, errors.New("unknown peer")
	}
	return node, nil
}

func TestFillPeerEndpoints(t *testing.T) {
	pc := tailcfg.NodeID(1)
	gt7 := tailcfg.NodeID(2)
	status := tailnet.Status{Peers: []tailnet.NodeStatus{
		{ID: int64(pc), Name: "pc"},
		{ID: int64(gt7), Name: "gt7", Addrs: []string{"[2409:1::2]:1"}},
		{Name: "no-id"},
	}}
	lookup := stubPeerLookup{nodes: map[tailcfg.NodeID]*tailcfg.Node{
		pc: {Endpoints: []netip.AddrPort{
			netip.MustParseAddrPort("[2409:8a55::1]:54031"),
			netip.MustParseAddrPort("[2409:8a55::2]:54031"),
		}},
		gt7: {Endpoints: []netip.AddrPort{netip.MustParseAddrPort("[2409:895a::1]:43327")}},
	}}

	fillPeerEndpoints(context.Background(), lookup, &status)

	if got := status.Peers[0].Addrs; len(got) != 2 || got[0] != "[2409:8a55::1]:54031" {
		t.Fatalf("pc endpoints = %v", got)
	}
	if got := status.Peers[1].Addrs; len(got) != 1 || got[0] != "[2409:1::2]:1" {
		t.Fatalf("existing endpoints were replaced: %v", got)
	}
	if got := status.Peers[2].Addrs; got != nil {
		t.Fatalf("peer without an id got endpoints: %v", got)
	}
}

func TestFillPeerEndpointsKeepsStatusOnLookupFailure(t *testing.T) {
	status := tailnet.Status{Peers: []tailnet.NodeStatus{{ID: 7, Name: "pc"}}}

	fillPeerEndpoints(context.Background(), stubPeerLookup{err: errors.New("backend stopped")}, &status)

	if got := status.Peers[0].Addrs; got != nil {
		t.Fatalf("failure produced endpoints: %v", got)
	}
}
