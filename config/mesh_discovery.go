package config

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/log"
)

// meshDiscoveryTimeout bounds the one request a mesh makes to its peer
// directory: a device that cannot reach the directory has to say so rather than
// hang the start.
const meshDiscoveryTimeout = 8 * time.Second

// meshDiscovery is the directory's answer for a mesh block that lists no
// device, read before the configuration is parsed.
//
// It is carried on the block itself because the expansion runs on the apply
// path: the core is about to rebuild every outbound, and a request made there
// holds that switch up - and with it every live connection - for as long as the
// directory takes to answer. The expansion therefore reads this answer instead
// of asking again.
type meshDiscovery struct {
	devices []RawMeshDevice
	// err is why the directory could not be read. It is kept rather than
	// dropped so the expansion warns once, where it has always warned, instead
	// of making the same request a second time inside the parse.
	err error
}

// meshDiscoveryNeeded says whether a block takes its devices from the directory:
// it lists none, the app has not resolved them, and it names a directory with a
// token to read it with. Every other block is left alone, so a request is only
// ever made for a block that asks for one.
func meshDiscoveryNeeded(mesh *RawMesh) bool {
	return mesh != nil && !mesh.DirectoryResolved && meshDiscoveryConfigured(mesh)
}

// DiscoverMeshDevices reads the device list a mesh takes from its peer directory
// and answers it in the shape a profile carries: the name a device is reached
// by, the id the directory knows it under, the port it serves on and the name a
// connection uses to reach it.
//
// The request is exported so a caller can make it before the configuration is
// parsed, which is where it belongs. Reading the list is the caller's step
// because the parse runs on the apply path, and a request made there blocks the
// switch to the new configuration while the connections the old one held are
// still up. A caller that reads the list first parses a block that needs no
// network at all; the core's own hub path does exactly that.
//
// The devices come back ordered by id, so every device of the mesh expands the
// same set in the same order, with the same name handed to the same record.
func DiscoverMeshDevices(ctx context.Context, mesh *RawMesh) ([]RawMeshDevice, error) {
	if ctx == nil {
		// A caller with no context of its own still gets the bound below.
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, meshDiscoveryTimeout)
	defer cancel()
	nodes, err := discoverMeshNodes(ctx, mesh.DirectoryURL, mesh.DirectoryToken, meshDiscoveryTimeout)
	if err != nil {
		return nil, fmt.Errorf("mesh: cannot read the devices from the directory %s: %w", mesh.DirectoryURL, err)
	}
	return meshDevicesFromNodes(mesh, nodes), nil
}

// meshDevicesFromNodes turns the directory's answer into the device list a
// profile carries: the names and ids a rule and a lookup can use, and the ports
// the devices serve on.
//
// A record the mesh cannot use costs the mesh that device, not the
// configuration: the profile is shared, so refusing it over one odd record -
// a name somebody typed with a space in it, a port a device once reported and
// no longer serves - would take every device down.
func meshDevicesFromNodes(mesh *RawMesh, nodes []outbound.DirectoryNode) []RawMeshDevice {
	// Sorted by id so every device of the mesh expands the same set in the
	// same order: a profile that has to fall back from a name to an id has to
	// make the same choice everywhere, or the devices would disagree about
	// which name belongs to whom.
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	devices := make([]RawMeshDevice, 0, len(nodes))
	seenName := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		name := strings.TrimSpace(node.Name)
		if !meshDeviceNamePattern.MatchString(name) {
			// A name a profile cannot write is no name to reach a device by;
			// the id always is one.
			name = node.ID
		}
		if seenName[name] {
			// Two devices cannot answer to one name: the id is unique, so the
			// one that came later is reached by that instead.
			name = node.ID
		}
		if !meshDeviceNamePattern.MatchString(name) || seenName[name] {
			log.Warnln("[Mesh] skipping device %q: its name %q cannot be used and its id cannot stand in for it", node.ID, node.Name)
			continue
		}
		seenName[name] = true

		port := node.Port
		if port < 1 || port > 65535 {
			port = meshDefaultPort
		}
		domain := strings.ToLower(strings.TrimSpace(node.Domain))
		if domain != "" && !meshDomainPattern.MatchString(domain) {
			// Same as a device written in the profile: an odd domain costs
			// the device its name, not the whole mesh.
			log.Warnln("[Mesh] device %q carries domain %q, which is not a dns name; it will not be reached by that name", name, node.Domain)
			domain = ""
		}
		devices = append(devices, RawMeshDevice{Name: name, ID: node.ID, Port: port, Domain: domain})
	}
	if len(devices) == 0 {
		log.Warnln("[Mesh] the directory %s holds no device yet; the profile's rules will not find one", mesh.DirectoryURL)
	}
	return devices
}

// ResolveMeshDiscovery reads the devices a mesh block takes from its peer
// directory, before the configuration that carries the block is parsed.
//
// A caller that reads the list first gets a parse that touches no network, which
// is what a pushed profile needs: the hub hands a whole configuration over, and
// the parse runs on the apply path, so a request made during it holds the switch
// to the new configuration up - and every connection the old one held with it -
// for as long as the directory takes to answer.
//
// A block that lists its devices, or one the app already resolved, is left
// alone: neither asks the directory for anything.
//
// A directory that cannot be read is recorded, not treated as fatal: the same
// file loads a moment later when the reset stops happening, and refusing it
// took the whole device down over one lost packet. The parse then warns and
// expands with no device, exactly as it did when it made the request itself.
// The error is returned so the caller can report it; ignoring it costs the mesh
// its devices for this parse, not the configuration.
func ResolveMeshDiscovery(ctx context.Context, rawCfg *RawConfig) error {
	if rawCfg == nil || !meshDiscoveryNeeded(rawCfg.Mesh) {
		return nil
	}
	mesh := rawCfg.Mesh
	devices, err := DiscoverMeshDevices(ctx, mesh)
	// Recorded even on failure: the answer, or the reason there is none, is
	// what the expansion reads, so the request is made once and not again
	// inside the parse.
	mesh.discovery = &meshDiscovery{devices: devices, err: err}
	return err
}

// ParseWithMeshDiscovery parses a configuration the way Parse does, having first
// read the peer directory for a mesh block that lists no device.
//
// It is the entry a caller holding a whole configuration - the hub path above
// all - uses in place of Parse, so the one request a mesh needs is made before
// the parse rather than during it.
func ParseWithMeshDiscovery(ctx context.Context, buf []byte) (*Config, error) {
	rawCfg, err := UnmarshalRawConfig(buf)
	if err != nil {
		return nil, err
	}
	if err := ResolveMeshDiscovery(ctx, rawCfg); err != nil {
		// Not fatal, and deliberately not warned about here: the expansion
		// warns where it always has - as it proceeds with no device - so the
		// message is written in one place and reads the same either way.
		log.Debugln("[Mesh] %v", err)
	}
	return ParseRawConfig(rawCfg)
}
