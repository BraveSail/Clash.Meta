package config

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/vless/encryption"
)

// meshDefaultPort is the port a device listens on - and is dialled at - when
// its entry in the mesh does not name one.
const meshDefaultPort = 8443

// meshDerivedProtocol is what a mesh speaks when the block does not say: the
// same protocol every device of it can both serve and dial.
const meshDerivedProtocol = "vless"

// meshEncryptionPrefix is the VLESS Encryption scheme both halves of a derived
// mesh key are written under; only the mode and the key that follow it differ
// between the server and the client.
const meshEncryptionPrefix = "mlkem768x25519plus.native"

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

// meshDomainPattern is what a device's mesh domain may be: a lower-case DNS
// name a rule can carry, e.g. "pc.lan". It is matched exactly in a rule, so
// the pattern is the DNS one rather than the id one - a domain is looked up at
// connection time and a name spelled two ways must not become two devices.
var meshDomainPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// RawMeshDevice is one device of a mesh: the name it is reached by and the
// port its service listens on. Nothing here names the device the profile runs
// on: the core reports under an id it carries, and the directory maps that id
// to these names.
type RawMeshDevice struct {
	Name string `yaml:"name" json:"name"`
	// ID is the record this device answers to in the directory. The app
	// resolves the directory while it builds the configuration and writes
	// what it found next to the name, so the runtime asks by id and a device
	// renamed on the dashboard still resolves to the same machine. Empty for
	// a device written down by hand.
	ID string `yaml:"id,omitempty" json:"id,omitempty"`
	// Domain is the name a connection uses to reach this device, e.g.
	// "pc.lan". The core writes one rule per domain pointing at the mesh
	// entry, so a profile names no device at all and renaming one on the
	// dashboard cannot break a shared configuration. Empty for a device that
	// is only reachable by its own outbound.
	Domain string `yaml:"domain,omitempty" json:"domain,omitempty"`
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
	// DirectoryResolved says the app already read the device list and wrote
	// it into Devices. The list is then taken as it stands - even when it is
	// empty - and nothing is read while the configuration is parsed, which is
	// what lets a device whose network blocks the directory over a direct
	// connection still start.
	DirectoryResolved bool `yaml:"directory-resolved,omitempty" json:"directory-resolved,omitempty"`
	// DirectoryProxy is an HTTP proxy URL that runtime requests to the
	// directory go through, so a directory a direct connection cannot reach
	// stays readable and reportable. Empty keeps them off the tunnel, the way
	// they have always gone.
	DirectoryProxy string `yaml:"directory-proxy,omitempty" json:"directory-proxy,omitempty"`
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
	// Domain is the name a connection uses to reach this device, when one was
	// chosen for it. The mesh entry holds the mapping from these to their
	// records, which is how a rule can point at the mesh alone.
	Domain string
}

// meshEntryName is the name of the single outbound every mesh rule points at.
// A profile therefore names no device: the rule says "this name goes to the
// mesh" and the entry decides which device serves it from the domain the
// connection asked for. Writing a name that cannot collide with a device's own
// name is the point - a device renamed on the dashboard cannot break a profile
// that never spelled it.
const meshEntryName = "mesh"

// expandMesh turns the mesh block into the listener this device serves and one
// tailnet-peer outbound per device, and appends them to the listener and proxy
// lists. The devices are the ones the block lists, or - when it lists none -
// the ones the directory holds, read while the configuration is parsed.
func expandMesh(rawCfg *RawConfig) error {
	mesh := rawCfg.Mesh
	if mesh == nil {
		return nil
	}
	// A resolved block carries its list already, even when that list is
	// empty; an unresolved one has to be worth reading from the directory.
	if len(mesh.Devices) == 0 && !mesh.DirectoryResolved && !meshDiscoveryConfigured(mesh) {
		return nil
	}
	if strings.TrimSpace(mesh.DirectoryURL) == "" {
		return errors.New("mesh: directory-url is required, the peer directory the devices report to")
	}
	// A block that writes neither half speaks the protocol the core derives
	// from the directory token: nothing between two devices has to be written
	// down, and every device derives the same one. Writing either half opts
	// the whole block out of the derivation.
	if derivedProxy, derivedListener := meshDerivedProtocols(mesh); derivedProxy != nil {
		mesh.Proxy = derivedProxy
		mesh.Listener = derivedListener
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
		if mesh.DirectoryProxy != "" {
			mapping["directory-proxy"] = mesh.DirectoryProxy
		}
		rawCfg.Proxy = append(rawCfg.Proxy, mapping)
	}

	// One entry the domain rules point at, holding the mapping from the name a
	// connection asked for to the device that serves it. Without it every rule
	// would have to name a device, and a device renamed on the dashboard would
	// leave the profile pointing at nothing.
	domains := make(map[string]string, len(peers))
	for _, peer := range peers {
		if peer.Domain == "" || peer.ID == "" {
			continue
		}
		domains[peer.Domain] = peer.ID
	}
	if len(domains) > 0 {
		rawCfg.Proxy = append(rawCfg.Proxy, buildMeshEntry(mesh, domains))
		// The rules go first so a domain the user also wrote by hand - a
		// geosite entry, a catch-all - cannot shadow the mesh.
		rawCfg.Rule = append(buildMeshDomainRules(domains), rawCfg.Rule...)
	}
	if mesh.DirectoryResolved && len(mesh.Devices) == 0 {
		log.Warnln("[Mesh] the app resolved no device from the directory %s; the profile's rules will not find one", mesh.DirectoryURL)
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
	if len(domains) > 0 {
		log.Infoln("[Mesh] %d domain(s) added; rules for them point at %q", len(domains), meshEntryName)
	}
	return nil
}

// buildMeshEntry is the outbound a profile's mesh rules point at: it answers
// whichever device the requested name belongs to, so one rule covers every
// device and no device has to be named in the profile.
func buildMeshEntry(mesh *RawMesh, domains map[string]string) map[string]any {
	mapping := map[string]any{
		"name":          meshEntryName,
		"type":          "tailnet-peer",
		"port":          meshDefaultPort,
		"directory-url": mesh.DirectoryURL,
		"proxy":         mesh.Proxy,
		"domains":       domains,
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
	if mesh.DirectoryProxy != "" {
		mapping["directory-proxy"] = mesh.DirectoryProxy
	}
	return mapping
}

// buildMeshDomainRules is one rule per domain, pointing at the mesh entry. The
// name is matched exactly rather than by suffix: a rule written by hand for the
// same suffix must keep working, and a device is reached by the name it was
// given, not by everything that ends the same way.
func buildMeshDomainRules(domains map[string]string) []string {
	names := make([]string, 0, len(domains))
	for domain := range domains {
		names = append(names, domain)
	}
	sort.Strings(names)
	rules := make([]string, 0, len(names))
	for _, domain := range names {
		rules = append(rules, "DOMAIN,"+domain+","+meshEntryName)
	}
	return rules
}

// meshDiscoveryConfigured says whether a mesh that lists no device takes its
// devices from the directory: the directory has to be named, reachable with a
// token, and there has to be a protocol to dial them with. A block without
// these is left alone, the way it was before the directory could answer.
func meshDiscoveryConfigured(mesh *RawMesh) bool {
	return len(mesh.Devices) == 0 &&
		strings.TrimSpace(mesh.DirectoryURL) != "" &&
		strings.TrimSpace(mesh.DirectoryToken) != ""
}

// meshUUID is the user a mesh speaks under, derived from its directory token:
// every device of a mesh holds the same token, so every device derives the
// same user without anyone writing one down. The derivation has to be stable
// across builds and platforms - it is an identity, not a hash table slot.
func meshUUID(token string) string {
	sum := sha256.Sum256([]byte("mesh:" + token))
	// Formatted as a UUID so the field reads like every other vless user.
	return fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

// meshDerivedProtocols is what a mesh speaks when the block writes neither
// half: one protocol, served by every device and dialled by every device. A
// block that writes either half is left alone - mixing a derived half with a
// written one would pair a listener nobody dials.
//
// The protocol carries its own encryption - VLESS Encryption, which is
// TCP-only and needs no certificate - so what travels between two devices is
// confidential without anyone fetching a certificate for a machine that may
// not even have a name. The keys are derived from the directory token the same
// way the user is: every device holds that token, so every device arrives at
// the same server key and the same client key, and any two of them can talk.
func meshDerivedProtocols(mesh *RawMesh) (proxy, listener map[string]any) {
	if len(mesh.Proxy) > 0 || meshListenerDefined(mesh) {
		return nil, nil
	}
	uuid := meshUUID(mesh.DirectoryToken)
	decryption, encryption := meshEncryptionKeys(mesh.DirectoryToken)
	return map[string]any{
			"type":       meshDerivedProtocol,
			"uuid":       uuid,
			"udp":        true,
			"encryption": encryption,
		}, map[string]any{
			"type":       meshDerivedProtocol,
			"users":      []any{map[string]any{"uuid": uuid}},
			"decryption": decryption,
		}
}

// meshEncryptionKeys derives the VLESS Encryption pair every device of a mesh
// shares: the server half goes on the listener, the client half on the
// outbounds. Both are read from one X25519 key whose private half is the
// directory token's digest, so the pair is stable across builds and platforms
// and every device of a mesh arrives at the same one without anyone writing a
// key down. A device that never holds the token cannot derive either half, and
// neither half is useful without a matching peer.
func meshEncryptionKeys(token string) (decryption, encryptionValue string) {
	// The digest is the private key: X25519 takes 32 bytes, which sha256 is.
	sum := sha256.Sum256([]byte("mesh-encryption:" + token))
	seed := base64.RawURLEncoding.EncodeToString(sum[:])
	privateKey, password, _, err := encryption.GenX25519(seed)
	if err != nil {
		// The seed is always the right length, so this is unreachable; a
		// mesh without keys would be one nobody can join, which is worse than
		// a value that fails to authenticate.
		log.Errorln("[Mesh] cannot derive the encryption keys from the directory token: %v", err)
		return "", ""
	}
	return meshDecryptionValue(privateKey), meshEncryptionValue(password)
}

// meshDecryptionValue is the server half as the listener reads it: the X25519
// private key under a padding scheme and a lifetime the clients must fall
// inside.
func meshDecryptionValue(privateKey string) string {
	return meshEncryptionPrefix + ".600s." + privateKey
}

// meshEncryptionValue is the client half as the outbound reads it: the public
// key the server's private half corresponds to, under the same scheme.
func meshEncryptionValue(password string) string {
	return meshEncryptionPrefix + ".0rtt." + password
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
			id := strings.TrimSpace(device.ID)
			if id != "" && !meshDeviceNamePattern.MatchString(id) {
				return nil, false, fmt.Errorf("mesh device %d: id %q is not a valid directory id (letters, digits, . _ -, up to 63)", index, device.ID)
			}
			domain := strings.ToLower(strings.TrimSpace(device.Domain))
			if domain != "" && !meshDomainPattern.MatchString(domain) {
				// A domain is set on the dashboard and only decides which
				// device a name reaches: a bad one costs this device its
				// domain rule, not the profile - refusing the configuration
				// would take the whole mesh down over one odd record.
				log.Warnln("[Mesh] device %q carries domain %q, which is not a dns name; it will not be reached by that name", name, device.Domain)
				domain = ""
			}
			peers = append(peers, meshPeer{Name: name, ID: id, Port: port, Domain: domain})
		}
		return peers, false, nil
	}
	if mesh.DirectoryResolved {
		// The app read the directory and it held no device: there is nothing
		// to dial yet, and asking here would block the start on the same
		// network that could not answer.
		return nil, false, nil
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
		domain := strings.ToLower(strings.TrimSpace(node.Domain))
		if domain != "" && !meshDomainPattern.MatchString(domain) {
			// Same as a device written in the profile: an odd domain costs
			// the device its name, not the whole mesh.
			log.Warnln("[Mesh] device %q carries domain %q, which is not a dns name; it will not be reached by that name", name, node.Domain)
			domain = ""
		}
		peers = append(peers, meshPeer{Name: name, ID: node.ID, Port: port, Domain: domain})
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
