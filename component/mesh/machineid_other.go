//go:build !linux && !darwin && !windows && !android

package mesh

import "runtime"

// platformOSName is the system this build runs on, for platforms without a
// prettier answer than Go's own name.
func platformOSName() string {
	return runtime.GOOS
}
