// Package peerdirectory connects an outbound that needs a peer's current
// address with the directory outbound that knows it. The directory publishes
// itself here on construction and removes itself on Close; consumers resolve a
// peer through it instead of importing the outbound.
package peerdirectory

import (
	"context"
	"fmt"
	"reflect"
	"sync"
)

var (
	registryMu  sync.Mutex
	directories = map[string]DirectoryProvider{}
)

// DirectoryProvider answers where a peer is right now, from a directory such as
// the worker in BraveSail/peer-directory. Unlike a status snapshot it owns the
// node's own id, so it can also answer "that peer is this node".
type DirectoryProvider interface {
	PeerAddress(ctx context.Context, id string) (addr string, port int, self bool, err error)
}

// NetworkChangeInjector is implemented by a directory that can act on a network
// change the host observed instead of waiting for its own polling.
type NetworkChangeInjector interface {
	InjectNetworkChange()
}

func Register(name string, provider DirectoryProvider) {
	if name == "" || provider == nil {
		return
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	directories[name] = provider
}

// Unregister removes [provider] only if it is still the one registered under
// [name]: a config reload builds the replacement before the previous outbound
// stops, and removing by name alone would drop the new one.
func Unregister(name string, provider DirectoryProvider) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if current, ok := directories[name]; ok && sameIdentity(current, provider) {
		delete(directories, name)
	}
}

// Lookup asks [directory] where the peer [id] is. The port the directory
// reports is informational: the profile keeps owning the port it dials, which
// is what the peer's listener is configured with.
func Lookup(ctx context.Context, directory, id string) (addr string, port int, self bool, err error) {
	registryMu.Lock()
	provider, ok := directories[directory]
	registryMu.Unlock()
	if !ok {
		return "", 0, false, fmt.Errorf("peer directory %q is not configured", directory)
	}
	return provider.PeerAddress(ctx, id)
}

// InjectNetworkChange tells every registered directory that the host saw the
// network change - an interface switch, a reconnected VPN, a connectivity
// callback - so it republishes the address it has now rather than on its next
// pass.
func InjectNetworkChange() {
	registryMu.Lock()
	providers := make([]DirectoryProvider, 0, len(directories))
	for _, provider := range directories {
		providers = append(providers, provider)
	}
	registryMu.Unlock()
	for _, provider := range providers {
		if injector, ok := provider.(NetworkChangeInjector); ok {
			injector.InjectNetworkChange()
		}
	}
}

func registeredCount() int {
	registryMu.Lock()
	defer registryMu.Unlock()
	return len(directories)
}

// sameIdentity compares two interface values without assuming the dynamic type
// is comparable: a provider backed by a slice or map would panic on ==.
func sameIdentity(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	kind := reflect.TypeOf(a)
	if kind != reflect.TypeOf(b) || !kind.Comparable() {
		return false
	}
	return a == b
}
