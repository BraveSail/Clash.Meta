package config

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/metacubex/mihomo/log"
)

// meshDefaultPort is the port a device listens on - and is dialled at - when
// its entry in the mesh does not name one.
const meshDefaultPort = 8443

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
	Proxy    map[string]any  `yaml:"proxy,omitempty" json:"proxy,omitempty"`
	Listener map[string]any  `yaml:"listener,omitempty" json:"listener,omitempty"`
	Devices  []RawMeshDevice `yaml:"devices" json:"devices"`
}

// expandMesh turns the mesh block into the listener this device serves and one
// tailnet-peer outbound per listed device, and appends them to the listener
// and proxy lists.
func expandMesh(rawCfg *RawConfig) error {
	mesh := rawCfg.Mesh
	if mesh == nil || len(mesh.Devices) == 0 {
		return nil
	}
	if strings.TrimSpace(mesh.DirectoryURL) == "" {
		return errors.New("mesh: directory-url is required, the peer directory the devices report to")
	}
	if len(mesh.Proxy) == 0 {
		return errors.New("mesh: proxy is required, the protocol this device dials a peer with")
	}

	seenName := make(map[string]bool, len(mesh.Devices))
	for index, device := range mesh.Devices {
		name := strings.TrimSpace(device.Name)
		if !meshDeviceNamePattern.MatchString(name) {
			return fmt.Errorf("mesh device %d: name %q is not a valid device name (letters, digits, . _ -, up to 63)", index, device.Name)
		}
		if seenName[name] {
			return fmt.Errorf("mesh device %d: duplicate name %q", index, name)
		}
		seenName[name] = true
	}
	port, err := meshPort(mesh)
	if err != nil {
		return err
	}

	// The listener half is optional: a profile that writes its listeners by
	// hand keeps doing that, and a profile written before this half existed
	// keeps loading.
	if meshListenerDefined(mesh) {
		rawCfg.Listeners = append(rawCfg.Listeners, buildMeshListener(mesh.Listener, port))
	}

	for _, device := range mesh.Devices {
		name := strings.TrimSpace(device.Name)
		mapping := map[string]any{
			"name":          name,
			"type":          "tailnet-peer",
			"peer":          name,
			"port":          port,
			"directory-url": mesh.DirectoryURL,
			"proxy":         mesh.Proxy,
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
	if meshListenerDefined(mesh) {
		log.Infoln("[Mesh] %d device(s) expanded; this device listens on port %d and dials them there", len(mesh.Devices), port)
	} else {
		log.Infoln("[Mesh] %d device(s) expanded into tailnet-peer outbounds", len(mesh.Devices))
	}
	return nil
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
