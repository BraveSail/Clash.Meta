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
)

// Publish makes [registry] the one the control API answers from.
func Publish(registry *StatusRegistry) {
	runningMu.Lock()
	runningRegistry = registry
	runningMu.Unlock()
}

// PublishIfAbsent installs a registry for this node if none is running, and
// answers whichever one is now published.
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
		return runningRegistry
	}
	registry := NewStatusRegistry(nil, directoryURL)
	registry.SetIdentity(id, "", port)
	runningRegistry = registry
	return registry
}

// Withdraw removes [registry] only if it is still the published one.
func Withdraw(registry *StatusRegistry) {
	runningMu.Lock()
	if runningRegistry == registry {
		runningRegistry = nil
	}
	runningMu.Unlock()
}

// Running answers the published registry, or nil when no mesh is running. A
// reader must treat nil as "this node has no mesh", not as an error: a profile
// without a mesh block is a normal configuration.
func Running() *StatusRegistry {
	runningMu.Lock()
	defer runningMu.Unlock()
	return runningRegistry
}
