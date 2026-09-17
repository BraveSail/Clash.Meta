//go:build !android

package outbound

// The underlay probe is Android-only: its sandbox refuses the routing lookups
// that every other platform answers directly, so those platforms keep the
// interface scan (see peer_directory_underlay_other.go for the default route
// readers). Reporting from an interface scan is not the same as reporting from
// the interface carrying traffic, which is why Android cannot use it.
func (d *PeerDirectory) startUnderlayWatch() {}

func (d *PeerDirectory) refreshUnderlayInterface(string) bool { return false }
