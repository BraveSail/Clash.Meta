package mesh

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"runtime"
	"strings"
	"sync"
)

// Identity is what this device reports to the peer directory: the id the
// directory knows it under, the name it is shown by, and the system it runs.
//
// It is derived here rather than taken from the profile. A profile runs on
// every device of the mesh, so anything per-device written into it is either
// wrong for all but one of them or has to be rewritten by each device before
// use - and the app rewriting it is what put half of the mesh's logic on the
// app side in the first place.
type Identity struct {
	ID   string
	Name string
	OS   string
}

// deviceIDLength is how much of the hash a directory id keeps: a DNS label, so
// a rule and a lookup can carry it.
const deviceIDLength = 12

var (
	identityOnce    sync.Once
	identityMachine string
	identityOS      string
)

// SetHostIdentity records what only the platform layer can answer, on the
// systems where the machine id is not reachable from Go.
//
// Android is the case: ANDROID_ID lives behind a Java API, so the JNI bridge
// reads it and hands it over before any configuration is parsed. Anything set
// here wins over the probe; an empty value leaves the probe in charge.
func SetHostIdentity(machineID, osName string) {
	identityMachine = strings.TrimSpace(machineID)
	identityOS = strings.TrimSpace(osName)
}

// Derive answers this device's identity.
//
// The id is a hash of the platform and the machine id, truncated to a DNS
// label: stable across restarts, different between devices, and carrying none
// of the raw machine id. A platform that reports no machine id yields an empty
// id rather than a random one - a device that cannot prove which one it is
// must not claim to be some other.
func Derive() Identity {
	machineID, osName := hostIdentity()
	return Identity{
		ID:   deviceID(runtime.GOOS, machineID),
		Name: deviceName(),
		OS:   osName,
	}
}

// DeriveOn answers the identity a given platform and machine id produce, so the
// derivation can be pinned by a test without depending on the machine running
// it.
func DeriveOn(platform, machineID string) Identity {
	return Identity{ID: deviceID(platform, machineID)}
}

func deviceID(platform, machineID string) string {
	machineID = strings.TrimSpace(machineID)
	if machineID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(platform + ":" + machineID))
	return hex.EncodeToString(sum[:])[:deviceIDLength]
}

// deviceName is the machine's own host name. A phone reports "localhost",
// which is why the profile may name one instead; an empty answer here simply
// leaves the field out and the directory falls back to the id.
func deviceName() string {
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(name)
}

func hostIdentity() (string, string) {
	identityOnce.Do(func() {
		if identityMachine == "" {
			identityMachine = platformMachineID()
		}
		if identityOS == "" {
			identityOS = platformOSName()
		}
	})
	return identityMachine, identityOS
}

// ResetHostIdentity drops the memo. It exists for tests, the way the rest of
// this package's seams do - nothing in production has a reason to call it.
func ResetHostIdentity() {
	identityOnce = sync.Once{}
	identityMachine = ""
	identityOS = ""
}
