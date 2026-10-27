package main

import (
	meshident "github.com/metacubex/mihomo/component/mesh"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/component/hubprofile"
	"github.com/metacubex/mihomo/log"
)

// builtInHub is the hub this build was linked against, if any.
//
// The mesh belongs to the core, not to the program that starts it: a build
// carrying a hub address pulls its own configuration from that hub and keeps
// it current, so the thing around it - an app, a launcher, a shell script -
// needs no address, no token and no notion that a mesh exists. A box running
// only this binary joins the mesh from a configuration that never mentions it.
//
// The identity is the device's own, derived from the machine it runs on: the
// hub learns which device this is from the key that signs the request, never
// from a name the configuration chose.
func builtInHub() *hubprofile.Config {
	if C.HubURL == "" {
		return nil
	}
	identity := meshident.Derive()
	if identity.ID == "" {
		log.Warnln("[Profile] this build belongs to %s but the machine has no identity to answer with", C.HubURL)
		return nil
	}
	return &hubprofile.Config{
		URL: C.HubURL,
		ID:  identity.ID,
		Keep: map[string]any{
			"mesh.directory-id": identity.ID,
			"mesh.device-name":  identity.Name,
			"mesh.device-os":    identity.OS,
		},
	}
}
