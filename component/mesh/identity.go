package mesh

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
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

// Derive answers this device's identity: the name its key makes, the host name
// the system reports, and the system it runs.
//
// The id comes from the key and from nothing else. A machine id - ANDROID_ID,
// MachineGuid, /etc/machine-id - is a name the system gives itself: anything on
// the host can read it, it says nothing about who is asking, and it is exactly
// what a clone copies. The key never leaves the device, and the id derived from
// it is the thing the signature already proves, so the name and the proof are
// one fact rather than two that can disagree.
func Derive() Identity {
	return Identity{
		ID:   keyedID(),
		Name: deviceName(),
		OS:   platformOSName(),
	}
}

// keyedID is the name a device answers to when the machine cannot tell it what
// it is: derived from the public half of the key it keeps, and therefore
// different for every device and stable across restarts.
func keyedID() string {
	keys, err := LoadOrCreateKeys("")
	if err != nil {
		return ""
	}
	return DeriveOn(keys.Signing)
}

// DeriveOn answers the id a given signing seed produces, so the derivation can
// be pinned by a test without depending on the key stored on this machine.
func DeriveOn(seed []byte) string {
	if len(seed) != ed25519.SeedSize {
		return ""
	}
	public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	sum := sha256.Sum256(append([]byte("key:"), public...))
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

