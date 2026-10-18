package mesh

import "sync"

// The running node's status registry, published process-wide so the control
// API can answer for the mesh without holding a reference to the outbound that
// built it.
//
// It is a single slot rather than a map: one running configuration owns one
// mesh, and a reload installs the replacement before the previous outbound
// stops. Publishing by identity (not by name) is what keeps a reload from
// having the outgoing mesh erase the incoming one's registry, which is the
// same trap the directory registry hit.
var (
	runningMu       sync.Mutex
	runningRegistry *StatusRegistry
	// holders counts the live outbounds sharing [runningRegistry]. Without it,
	// the first entry to be closed would withdraw the registry while its
	// siblings were still running, and the control API would answer "no mesh"
	// on a node that has one.
	holders int
)

// Publish makes [registry] the one the control API answers from.
func Publish(registry *StatusRegistry) {
	runningMu.Lock()
	runningRegistry = registry
	holders = 1
	runningMu.Unlock()
}

// PublishIfAbsent installs a registry for this node if none is running, and
// answers whichever one is now published. Every call is a claim on the
// registry, so every caller must release it with Withdraw.
//
// A mesh block expands into one outbound per device, all of them describing the
// same node, so the first one to be constructed installs the registry and the
// rest adopt it. Publishing unconditionally would have each entry replace the
// previous one's counters, so the live connection count would only ever show
// the connections opened through whichever outbound was built last.
func PublishIfAbsent(id string, port int, directoryURL string) *StatusRegistry {
	runningMu.Lock()
	defer runningMu.Unlock()
	if runningRegistry != nil {
		holders++
		return runningRegistry
	}
	registry := NewStatusRegistry(nil, directoryURL)
	registry.SetIdentity(id, "", port)
	runningRegistry = registry
	holders = 1
	return registry
}

// Withdraw releases one claim on [registry], and clears it only when the last
// holder lets go.
//
// A reload installs the replacement before the previous outbound stops, so a
// holder of the outgoing registry must not be able to clear the incoming one:
// the registry is matched by identity, not by name.
func Withdraw(registry *StatusRegistry) {
	runningMu.Lock()
	defer runningMu.Unlock()
	if runningRegistry != registry {
		return
	}
	if holders > 1 {
		holders--
		return
	}
	runningRegistry = nil
	holders = 0
}

// Running answers the published registry, or nil when no mesh is running. A
// reader must treat nil as "this node has no mesh", not as an error: a profile
// without a mesh block is a normal configuration.
func Running() *StatusRegistry {
	runningMu.Lock()
	defer runningMu.Unlock()
	return runningRegistry
}
