package config

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/metacubex/mihomo/log"
)

// meshDefaultPort is the port a device's service listens on when the device
// does not name one. It matches the peer directory's own default.
const meshDefaultPort = 8443

// meshDeviceNamePattern is what a device name may be. The name travels as the
// directory id and as the DNS label a peer pings, so it keeps the directory's
// restricted set.
var meshDeviceNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,63}$`)

// RawMeshDevice is one device of a mesh: the name it is known by everywhere
// (directory id, DNS label, rule target) and the port its service listens on.
type RawMeshDevice struct {
	Name string `yaml:"name" json:"name"`
	Port int    `yaml:"port,omitempty" json:"port,omitempty"`
}

// RawMesh describes a set of devices that reach one another through a peer
// directory. It is sugar: what every device shares is written once, and each
// device adds only its own name and port. The block expands to one
// tailnet-peer outbound per device before the proxies are parsed, so nothing
// downstream has to know about it.
type RawMesh struct {
	DirectoryURL   string `yaml:"directory-url,omitempty" json:"directory-url,omitempty"`
	DirectoryToken string `yaml:"directory-token,omitempty" json:"directory-token,omitempty"`
	// DirectoryID is the name this device reports under. One profile runs on
	// every device, so the app fills it per device. The platform is not part of
	// the profile: each device detects its own and reports it to the directory.
	DirectoryID string `yaml:"directory-id,omitempty" json:"directory-id,omitempty"`
	// Heartbeat is how often this device reports even when nothing changed,
	// in seconds; every device takes the same value.
	Heartbeat int             `yaml:"heartbeat,omitempty" json:"heartbeat,omitempty"`
	Proxy     map[string]any  `yaml:"proxy,omitempty" json:"proxy,omitempty"`
	Devices   []RawMeshDevice `yaml:"devices" json:"devices"`
}

// expandMesh turns the mesh block into the per-device tailnet-peer outbounds
// it stands for and appends them to the proxy list.
func expandMesh(rawCfg *RawConfig) error {
	mesh := rawCfg.Mesh
	if mesh == nil || len(mesh.Devices) == 0 {
		return nil
	}
	if strings.TrimSpace(mesh.DirectoryURL) == "" {
		return errors.New("mesh: directory-url is required, the peer directory the devices report to")
	}
	if len(mesh.Proxy) == 0 {
		return errors.New("mesh: proxy is required, the protocol the devices speak")
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
		if device.Port < 0 || device.Port > 65535 {
			return fmt.Errorf("mesh device %d: invalid port %d", index, device.Port)
		}
	}

	for _, device := range mesh.Devices {
		name := strings.TrimSpace(device.Name)
		port := device.Port
		if port == 0 {
			port = meshDefaultPort
		}
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
	log.Infoln("[Mesh] %d device(s) expanded into tailnet-peer outbounds", len(mesh.Devices))
	return nil
}
