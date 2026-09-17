//go:build !android && !windows

package outbound

// underlyingDefaultInterface is Android's and Windows' job (their default route
// sits under a tun that the platform will not step around). Anywhere else the
// platform strategy answers or the socket probe does.
func underlyingDefaultInterface() (string, string, error) {
	return "", "", errNoUnderlyingInterface
}
