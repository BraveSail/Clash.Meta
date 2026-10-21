package outbound

import (
	"net/netip"
	"testing"
)

// The mesh reports an address so its peers can dial it. An address that is not
// reachable from the public internet must never be reported, or the peers end up
// dialling something that only exists inside one network.
func TestDialableReportAddress(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		// Public addresses, both families: the point of the change.
		{"106.55.177.19", true},
		{"1.1.1.1", true},
		{"8.8.8.8", true},
		{"2408:8256:d284:f972::1", true},
		{"2606:4700:4700::1111", true},

		// Private IPv4 (RFC 1918).
		{"10.0.0.1", false},
		{"10.255.255.255", false},
		{"172.16.0.1", false},
		{"172.31.255.254", false},
		{"192.168.1.1", false},

		// Not routable on the public internet, and missed by IsPrivate.
		{"100.64.0.1", false},     // carrier-grade NAT
		{"100.127.255.255", false}, // carrier-grade NAT, top of range
		{"169.254.1.1", false},    // link local
		{"192.0.0.1", false},      // IETF protocol assignments
		{"192.0.2.5", false},      // documentation
		{"198.18.0.1", false},     // benchmarking
		{"198.19.255.255", false}, // benchmarking, top of range
		{"198.51.100.7", false},   // documentation
		{"203.0.113.9", false},    // documentation
		{"224.0.0.1", false},      // multicast
		{"240.0.0.1", false},      // reserved
		{"255.255.255.255", false}, // broadcast

		// Loopback and the unspecified address.
		{"127.0.0.1", false},
		{"0.0.0.0", false},

		// Just outside a reserved block: these are dialable.
		{"100.63.255.255", true},
		{"100.128.0.1", true},
		{"172.15.255.255", true},
		{"172.32.0.1", true},
		{"198.17.255.255", true},
		{"198.20.0.1", true},
		{"223.255.255.255", true},

		// IPv6: unique local and documentation are not dialable.
		{"fd76:1::1", false},          // unique local
		{"fc00::1", false},            // unique local
		{"2001:db8::1", false},        // documentation
		{"fe80::1", false},            // link local
		{"::1", false},                // loopback
		{"::ffff:10.0.0.1", false},    // IPv4-mapped private
		{"::ffff:106.55.177.19", true}, // IPv4-mapped public
	}

	for _, c := range cases {
		t.Run(c.addr, func(t *testing.T) {
			addr, err := netip.ParseAddr(c.addr)
			if err != nil {
				t.Fatalf("ParseAddr(%q): %v", c.addr, err)
			}
			if got := dialableReportAddress(addr); got != c.want {
				t.Errorf("dialableReportAddress(%s) = %v, want %v", c.addr, got, c.want)
			}
		})
	}
}
