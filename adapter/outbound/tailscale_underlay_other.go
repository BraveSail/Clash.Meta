//go:build with_gvisor && !no_tailscale && !android

package outbound

// watchUnderlayInterface is a no-op outside Android: other platforms let
// netmon read the routing table directly, and protected-socket probing is
// an Android-specific workaround for its sandbox restrictions.
func (t *Tailscale) watchUnderlayInterface() {}

// refreshUnderlayInterface is a no-op outside Android: those platforms keep
// netmon's view of the default route current through their own change
// notifications, so a host event only has to wake the monitor.
func (t *Tailscale) refreshUnderlayInterface() bool { return false }
