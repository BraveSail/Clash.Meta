//go:build !windows && !linux && !darwin && !android

package mesh

import "runtime"

// platformMachineID has no portable answer on this platform. The identity is
// then empty, and the directory shows the device by the name it reports; a
// made-up id would be worse, because two machines would eventually make up the
// same one.
func platformMachineID() string {
	return ""
}

func platformOSName() string {
	return runtime.GOOS
}
