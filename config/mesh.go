package config

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/log"
)

// meshDefaultPort is the port a device listens on - and is dialled at - when
// its entry in the mesh does not name one.
const meshDefaultPort = 8443

// meshDiscoveryTimeout bounds the one request the mesh makes while the
// configuration is parsed: a device that cannot reach the directory has to say
// so rather than hang the start.
const meshDiscoveryTimeout = 8 * time.Second

// discoverMeshNodes reads the device list from the peer directory. It is a
// variable so a test can describe the devices it wants the expansion to see.
var discoverMeshNodes = outbound.FetchDirectoryNodes

// meshDeviceNamePattern is what a device name may be: the agent resolves it
// through the name that device was given, and it becomes a DNS label a peer is
// reached by.
var meshDeviceNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,63}$`)

// RawMeshDevice is one device of a mesh: the name it is reached by and the
// port its service listens on. Nothing here names the device the profile runs
// on: the core reports under an id it carries, and the directory maps that id
// to these names.
type RawMeshDevice struct {
	Name string `yaml:"name" json:"name"`
	// Port is the port this device serves on and is dialled at. Every device
	// takes the same value - a device reports one port to the directory - so
	// writing it on the entries that differ from the default is enough.
	Port int `yaml:"port,omitempty" json:"port,omitempty"`
}

// RawMesh describes the devices that reach one another through a peer
// directory. It is sugar over the outbounds and the listener a profile may
// write by hand: the shared half is written once, and the block expands before
// the proxies are parsed.
type RawMesh struct {
	DirectoryURL   string `yaml:"directory-url,omitempty" json:"directory-url,omitempty"`
	DirectoryToken string `yaml:"directory-token,omitempty" json:"directory-token,omitempty"`
	// DirectoryID is the id this device reports under. One profile runs on
	// every device, so the app computes it per device from what the machine
	// itself carries. The platform is not part of the profile: each device
	// detects its own and reports it to the directory.
	DirectoryID string `yaml:"directory-id,omitempty" json:"directory-id,omitempty"`
	// Heartbeat is how often this device reports even when nothing changed,
	// in seconds; every device takes the same value.
	Heartbeat int `yaml:"heartbeat,omitempty" json:"heartbeat,omitempty"`
	// Proxy is the protocol this device dials a peer with, and Listener is
	// the protocol a peer dials this device with: the same service seen from
	// the two ends.
	Proxy    map[string]any `yaml:"proxy,omitempty" json:"proxy,omitempty"`
	Listener map[string]any `yaml:"listener,omitempty" json:"listener,omitempty"`
	// Devices lists the devices by hand. A mesh that lists none takes them
	// from the directory instead: the directory is what knows every device
	// that reported, so a profile running on all of them does not have to
	// name them.
	Devices []RawMeshDevice `yaml:"devices" json:"devices"`
}

// meshPeer is one device of a mesh as the expansion needs it: the name the
// profile and its rules reach it by, and the id the directory knows it under,
// which is what a lookup asks for.
type meshPeer struct {
	Name string
	// ID is the directory record this peer resolves to; it is empty for a
	// device the block lists by hand, where the name is all there is.
	ID   string
	Port int
}

// expandMesh turns the mesh block into the listener this device serves and one
// tailnet-peer outbound per device, and appends them to the listener and proxy
// lists. The devices are the ones the block lists, or - when it lists none -
// the ones the directory holds, read while the configuration is parsed.
func expandMesh(rawCfg *RawConfig) error {
	mesh := rawCfg.Mesh
	if mesh == nil || (len(mesh.Devices) == 0 && !meshDiscoveryConfigured(mesh)) {
		return nil
	}
	if strings.TrimSpace(mesh.DirectoryURL) == "" {
		return errors.New("mesh: directory-url is required, the peer directory the devices report to")
	}
	if len(mesh.Proxy) == 0 {
		return errors.New("mesh: proxy is required, the protocol this device dials a peer with")
	}
	port, err := meshPort(mesh)
	if err != nil {
		return err
	}

	peers, discovered, err := meshPeers(mesh, port)
	if err != nil {
		return err
	}

	// The listener half is optional: a profile that writes its listeners by
	// hand keeps doing that, and a profile written before this half existed
	// keeps loading.
	if meshListenerDefined(mesh) {
		rawCfg.Listeners = append(rawCfg.Listeners, buildMeshListener(mesh.Listener, port))
	}

	for _, peer := range peers {
		mapping := map[string]any{
			"name":          peer.Name,
			"type":          "tailnet-peer",
			"peer":          peer.Name,
			"port":          peer.Port,
			"directory-url": mesh.DirectoryURL,
			"proxy":         mesh.Proxy,
		}
		if peer.ID != "" {
			// The name is what the profile reads and its rules point at; the
			// id is what the directory is asked for, so a device renamed on
			// the dashboard still resolves to the same machine everywhere.
			mapping["directory-peer"] = peer.ID
		}
		if mesh.DirectoryToken != "" {
			mapping["directory-token"] = mesh.DirectoryToken
		}
		if mesh.DirectoryID != "" {
			mapping["directory-id"] = mesh.DirectoryID
		}
		if mesh.Heartbeat > 0 {
			mapping["heartbeat"] = mesh.Heartbeat
		}
		rawCfg.Proxy = append(rawCfg.Proxy, mapping)
	}
	switch {
	case discovered && meshListenerDefined(mesh):
		log.Infoln("[Mesh] discovered %d device(s) from the directory; this device listens on port %d and dials them there", len(peers), port)
	case discovered:
		log.Infoln("[Mesh] discovered %d device(s) from the directory into tailnet-peer outbounds", len(peers))
	case meshListenerDefined(mesh):
		log.Infoln("[Mesh] %d device(s) expanded; this device listens on port %d and dials them there", len(peers), port)
	default:
		log.Infoln("[Mesh] %d device(s) expanded into tailnet-peer outbounds", len(peers))
	}
	return nil
}

// meshDiscoveryConfigured says whether a mesh that lists no device takes its
// devices from the directory: the directory has to be named, reachable with a
// token, and there has to be a protocol to dial them with. A block without
// these is left alone, the way it was before the directory could answer.
func meshDiscoveryConfigured(mesh *RawMesh) bool {
	return len(mesh.Devices) == 0 &&
		strings.TrimSpace(mesh.DirectoryURL) != "" &&
		strings.TrimSpace(mesh.DirectoryToken) != "" &&
		len(mesh.Proxy) > 0
}

// meshPeers answers the devices of a mesh: the ones the block lists by hand -
// they keep the port the block settles on - or the ones the directory holds.
func meshPeers(mesh *RawMesh, port int) (peers []meshPeer, discovered bool, err error) {
	if len(mesh.Devices) > 0 {
		seenName := make(map[string]bool, len(mesh.Devices))
		for index, device := range mesh.Devices {
			name := strings.TrimSpace(device.Name)
			if !meshDeviceNamePattern.MatchString(name) {
				return nil, false, fmt.Errorf("mesh device %d: name %q is not a valid device name (letters, digits, . _ -, up to 63)", index, device.Name)
			}
			if seenName[name] {
				return nil, false, fmt.Errorf("mesh device %d: duplicate name %q", index, name)
			}
			seenName[name] = true
			peers = append(peers, meshPeer{Name: name, Port: port})
		}
		return peers, false, nil
	}
	peers, err = discoverMeshPeers(mesh)
	if err != nil {
		return nil, true, err
	}
	return peers, true, nil
}

// discoverMeshPeers reads the device list from the directory and turns it into
// the peers to expand. A directory that cannot be read is an error rather than
// an empty mesh: the profile is shared, so an unreachable directory would
// silently leave every rule that names a device pointing at nothing.
func discoverMeshPeers(mesh *RawMesh) ([]meshPeer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), meshDiscoveryTimeout)
	defer cancel()
	nodes, err := discoverMeshNodes(ctx, mesh.DirectoryURL, mesh.DirectoryToken, meshDiscoveryTimeout)
	if err != nil {
		return nil, fmt.Errorf("mesh: cannot read the devices from the directory %s: %w", mesh.DirectoryURL, err)
	}
	// Sorted by id so every device of the mesh expands the same set in the
	// same order: a profile that has to fall back from a name to an id has to
	// make the same choice everywhere, or the devices would disagree about
	// which name belongs to whom.
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	peers := make([]meshPeer, 0, len(nodes))
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
		peers = append(peers, meshPeer{Name: name, ID: node.ID, Port: port})
	}
	if len(peers) == 0 {
		log.Warnln("[Mesh] the directory %s holds no device yet; the profile's rules will not find one", mesh.DirectoryURL)
	}
	return peers, nil
}

// meshListenerDefined says whether the block carries the listener half too:
// with it, the mesh serves the service its peers dial; without it, the profile
// keeps writing its listeners by hand.
func meshListenerDefined(mesh *RawMesh) bool {
	return len(mesh.Listener) > 0
}

// buildMeshListener completes the listener block with what every device of a
// mesh serves: the same service, on the same port.
func buildMeshListener(source map[string]any, port int) map[string]any {
	listener := make(map[string]any, len(source)+3)
	for key, value := range source {
		listener[key] = value
	}
	if _, ok := listener["name"]; !ok {
		listener["name"] = "mesh-in"
	}
	if _, ok := listener["listen"]; !ok {
		listener["listen"] = "::"
	}
	listener["port"] = port
	return listener
}

// meshPort reads the port from the device entries: the port is written on the
// device it belongs to, one port for all of them, and it is both the port this
// device serves on and the port every peer is dialled at.
func meshPort(mesh *RawMesh) (int, error) {
	if _, ok := mesh.Listener["port"]; ok {
		return 0, errors.New("mesh: put the port on the device entries, not on the listener")
	}
	port := 0
	for index, device := range mesh.Devices {
		if device.Port == 0 {
			continue
		}
		if device.Port < 1 || device.Port > 65535 {
			return 0, fmt.Errorf("mesh device %d: invalid port %d", index, device.Port)
		}
		if port != 0 && device.Port != port {
			return 0, fmt.Errorf("mesh device %d: port %d differs from the other devices' port %d; a device reports one port to the directory", index, device.Port, port)
		}
		port = device.Port
	}
	if port == 0 {
		port = meshDefaultPort
	}
	return port, nil
}
