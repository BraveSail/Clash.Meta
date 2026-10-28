package config

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/adapter/outbound"
	meshident "github.com/metacubex/mihomo/component/mesh"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/vless/encryption"
)

// meshDirectoryProxy answers the proxy the directory's own requests go through.
//
// An explicit URL wins. Otherwise the block may ask for this node's mixed-port
// inbound, and the URL is built from the port and credentials the configuration
// already carries: the app used to construct it and write it into the profile,
// which meant it had to know how the core addresses its own listener.
func meshDirectoryProxy(block *RawMesh, rawCfg *RawConfig) string {
	if block.DirectoryProxy != "" {
		return block.DirectoryProxy
	}
	if !block.DirectoryViaProxy || rawCfg == nil || rawCfg.MixedPort <= 0 {
		return ""
	}
	userinfo := ""
	if len(rawCfg.Authentication) > 0 {
		name, secret, hasSecret := strings.Cut(rawCfg.Authentication[0], ":")
		switch {
		case hasSecret:
			userinfo = url.UserPassword(name, secret).String() + "@"
		case name != "":
			userinfo = url.User(name).String() + "@"
		}
	}
	return "http://" + userinfo + "127.0.0.1:" + strconv.Itoa(rawCfg.MixedPort)
}

// meshIdentityFields is what this device reports itself as: the id the
// directory knows it under, the name it is shown by, and the system it runs.
//
// A profile that names them wins - an operator overriding a name from the
// dashboard is a deliberate act. What is left empty is derived from the machine
// itself, because one profile runs on every device of the mesh: a value written
// into the file would be one device's id claimed by all of them, which is why
// the app used to compute and inject these fields on every start.
func meshIdentityFields(block *RawMesh) map[string]any {
	id := strings.TrimSpace(block.DirectoryID)
	name := strings.TrimSpace(block.DeviceName)
	osName := strings.TrimSpace(block.DeviceOS)
	if id == "" || name == "" || osName == "" {
		derived := meshident.Derive()
		if id == "" {
			id = derived.ID
		}
		if name == "" {
			name = derived.Name
		}
		if osName == "" {
			osName = derived.OS
		}
	}
	fields := make(map[string]any, 3)
	if id != "" {
		fields["directory-id"] = id
	}
	if name != "" {
		fields["hostname"] = name
	}
	if osName != "" {
		fields["os"] = osName
	}
	return fields
}

// meshDefaultPort is the port a device listens on - and is dialled at - when
// its entry in the mesh does not name one.
const meshDefaultPort = 23333

// meshDerivedProtocol is what a mesh speaks when the block does not say: the
// same protocol every device of it can both serve and dial.
const meshDerivedProtocol = "vless"

// meshEncryptionPrefix is the VLESS Encryption scheme both halves of a derived
// mesh key are written under; only the mode and the key that follow it differ
// between the server and the client.
const meshEncryptionPrefix = "mlkem768x25519plus.native"

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
	// UUID is the transport user this device listens as, read from the
	// directory. The listener accepts exactly these, so a mesh with a key per
	// device still lets its own peers in.
	UUID string `yaml:"uuid,omitempty" json:"uuid,omitempty"`
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
	// DeviceName is the name this device reports to the directory. Like the
	// id it is computed per device by the app: a phone's own host name is
	// "localhost", which an app cannot change, so the name its owner typed
	// travels here instead. Empty keeps the system host name.
	DeviceName string `yaml:"device-name,omitempty" json:"device-name,omitempty"`
	// DeviceOS is the system this device runs with its version, e.g.
	// "Android 14", written per device by the app and shown by the directory.
	DeviceOS string `yaml:"device-os,omitempty" json:"device-os,omitempty"`
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
	// DirectoryViaProxy asks for that proxy to be this node's own mixed-port
	// inbound, so the core builds the URL from the port and credentials it
	// already runs with. It exists so a caller states the intent - "route the
	// directory through my proxy" - without having to know or duplicate how
	// that proxy is addressed, which is what the app used to do.
	DirectoryViaProxy bool `yaml:"directory-via-proxy,omitempty" json:"directory-via-proxy,omitempty"`
	// discovery is the directory's answer for a block that lists no device,
	// read before the configuration was parsed by ResolveMeshDiscovery.
	//
	// It is unexported and therefore never read from a profile: the answer
	// belongs to the parse, not to the file, and a profile that spelled it out
	// would be claiming a list the directory never gave it.
	discovery *meshDiscovery
}

// meshPeer is one device of a mesh as the expansion needs it: the name the
// profile and its rules reach it by, and the id the directory knows it under,
// which is what a lookup asks for.
//
// It carries no port: the port a peer is dialled at is the one its own
// directory record reports, read when the connection is made. A port read here
// would be the one the profile happened to write, which is this device's own
// and says nothing about where the peer listens.
type meshPeer struct {
	Name string
	// ID is the directory record this peer resolves to; it is empty for a
	// device the block lists by hand, where the name is all there is.
	ID string
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
// the ones the directory held when the block was resolved, read before the
// configuration was parsed.
//
// A caller that parsed without resolving the block first still gets its devices:
// the expansion reads the directory itself, exactly as it always did. That is
// the fallback, not the path the core takes - the parse runs on the apply path,
// and a request made there holds the switch to the new configuration up for as
// long as the directory takes to answer.
func expandMesh(rawCfg *RawConfig) error {
	mesh := rawCfg.Mesh
	if mesh == nil {
		return nil
	}
	// The proxy the directory's own requests take is this node's mixed-port
	// inbound when the block asks for one; the address and the credentials are
	// properties of the running configuration, so they are resolved here rather
	// than written into a profile by whoever built it.
	mesh.DirectoryProxy = meshDirectoryProxy(mesh, rawCfg)
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

	peers, discovered, err := meshPeers(mesh)
	if err != nil {
		return err
	}

	// The listener half is optional: a profile that writes its listeners by
	// hand keeps doing that, and a profile written before this half existed
	// keeps loading.
	if meshListenerDefined(mesh) {
		rawCfg.Listeners = append(rawCfg.Listeners, buildMeshListener(mesh.Listener, port))
	}

	identityUUID, _, identityEncryption := meshTransportIdentity(mesh)
	for _, peer := range peers {
		mapping := map[string]any{
			"name":          peer.Name,
			"type":          "tailnet-peer",
			"peer":          peer.Name,
			// This entry dials the peer, but its directory half reports where
			// THIS device is: the port on the entry is the peer's, so taking
			// it here published the peer's port as this device's own and every
			// other device dialled a port this one does not bind.
			"port":          port,
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
			mapping["directory-uuid"] = identityUUID
			mapping["directory-encryption"] = identityEncryption
		}
		for key, value := range meshIdentityFields(mesh) {
			mapping[key] = value
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
		rawCfg.Proxy = append(rawCfg.Proxy, buildMeshEntry(mesh, domains, port))
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
func buildMeshEntry(mesh *RawMesh, domains map[string]string, port int) map[string]any {
	mapping := map[string]any{
		"name":          meshEntryName,
		"type":          "tailnet-peer",
		"port":          port,
		"directory-url": mesh.DirectoryURL,
		"proxy":         mesh.Proxy,
		"domains":       domains,
	}
	if mesh.DirectoryToken != "" {
		mapping["directory-token"] = mesh.DirectoryToken
	}
	identityUUID, _, identityEncryption := meshTransportIdentity(mesh)
	mapping["directory-uuid"] = identityUUID
	mapping["directory-encryption"] = identityEncryption
	for key, value := range meshIdentityFields(mesh) {
		mapping[key] = value
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
	rules := make([]string, 0, len(names)+2)
	// What a peer asks for is a service on itself, so it arrives addressed to
	// loopback. Without these, that destination falls through to the catch-all
	// rule and is sent out through a proxy - the stream then waits on a remote
	// server for a service that was local all along.
	rules = append(rules, "IPCIDR,127.0.0.0/8,DIRECT", "IPCIDR,::1/128,DIRECT")
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
// meshTransportIdentity answers the VLESS user and the encryption pair this
// device listens and dials with.
//
// A mesh that carries a token keeps the shared derivation every device has
// used: one user, one key pair, the token being the network's secret. A mesh
// with no token uses the device's own key material instead - which is the
// point of dropping the token, and why that key lives outside the profile.
func meshTransportIdentity(mesh *RawMesh) (uuid, decryption, encryption string) {
	if strings.TrimSpace(mesh.DirectoryToken) != "" {
		decryption, encryption = meshEncryptionKeys(mesh.DirectoryToken)
		return meshUUID(mesh.DirectoryToken), decryption, encryption
	}
	keys, err := meshident.LoadOrCreateKeys("")
	if err != nil {
		log.Errorln("[Mesh] cannot use the device key: %v", err)
		return "", "", ""
	}
	return keys.UUID, keys.Decryption, keys.Encryption
}

// meshListenerUsers answers who may connect to this device's listener.
//
// Under a shared token there is one user for the whole mesh, so this device's
// own uuid is the answer. With a key per device every device listens as itself,
// and a listener that accepted only its own user would refuse its peers - so it
// accepts exactly the devices the directory listed.
func meshListenerUsers(mesh *RawMesh, own string) []any {
	users := []any{map[string]any{"uuid": own}}
	if strings.TrimSpace(mesh.DirectoryToken) != "" {
		return users
	}
	seen := map[string]bool{own: true}
	for _, device := range mesh.Devices {
		user := strings.TrimSpace(device.UUID)
		if user == "" || seen[user] {
			continue
		}
		seen[user] = true
		users = append(users, map[string]any{"uuid": user})
	}
	return users
}

func meshDerivedProtocols(mesh *RawMesh) (proxy, listener map[string]any) {
	if len(mesh.Proxy) > 0 || meshListenerDefined(mesh) {
		return nil, nil
	}
	uuid, decryption, encryption := meshTransportIdentity(mesh)
	return map[string]any{
			"type":       meshDerivedProtocol,
			"uuid":       uuid,
			"udp":        true,
			"encryption": encryption,
		}, map[string]any{
			"type":       meshDerivedProtocol,
			"users":      meshListenerUsers(mesh, uuid),
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

// meshPeers answers the devices of a mesh: the ones the block lists by hand, or
// the ones the directory holds.
//
// A block that lists no device and has not been resolved asks the directory
// here, which is the fallback for a caller that parsed without resolving first.
// The core resolves before it parses, so this request is not made on its path.
func meshPeers(mesh *RawMesh) (peers []meshPeer, discovered bool, err error) {
	if len(mesh.Devices) > 0 {
		peers, err = meshPeersFromDevices(mesh.Devices)
		return peers, false, err
	}
	if mesh.DirectoryResolved {
		// The app read the directory and it held no device: there is nothing
		// to dial yet, and asking here would block the start on the same
		// network that could not answer.
		return nil, false, nil
	}
	if mesh.discovery != nil {
		// The directory was already read, before this configuration was
		// parsed: its answer is what the expansion uses, so the switch to the
		// new configuration waits on no request.
		if mesh.discovery.err != nil {
			// A directory that cannot be read is the network's answer for
			// now, not a mistake in the profile: the same file loads a moment
			// later when the reset stops happening. Refusing here took the
			// whole device down - no proxy, no direct access - over one lost
			// packet on a request the next start makes again.
			log.Warnln("[Mesh] cannot read the devices from the directory %s: %v; expanding with no device this time", mesh.DirectoryURL, mesh.discovery.err)
			return nil, true, nil
		}
		peers, err = meshPeersFromDevices(mesh.discovery.devices)
		return peers, true, err
	}
	peers, err = discoverMeshPeers(mesh)
	if err != nil {
		// A directory that cannot be read is the network's answer for now,
		// not a mistake in the profile: the same file loads a moment later
		// when the reset stops happening. Refusing here took the whole
		// device down - no proxy, no direct access - over one lost packet
		// on a request the next start makes again. The mesh stays empty
		// until a later expansion reads it, and the rules the core writes
		// from the devices' domains are simply not there while it is.
		log.Warnln("[Mesh] cannot read the devices from the directory %s: %v; expanding with no device this time", mesh.DirectoryURL, err)
		return nil, true, nil
	}
	return peers, true, nil
}

// meshPeersFromDevices turns a device list into the peers to expand: the names
// the profile and its rules reach a device by, the ids the directory knows them
// under, and the names a connection reaches them by.
//
// No port is read here: a device's own record carries the port it serves on,
// and that is what a dial uses. The port the block writes is this device's own
// (see meshPort), so it says nothing about where a peer listens.
func meshPeersFromDevices(devices []RawMeshDevice) ([]meshPeer, error) {
	peers := make([]meshPeer, 0, len(devices))
	seenName := make(map[string]bool, len(devices))
	for index, device := range devices {
		name := strings.TrimSpace(device.Name)
		if !meshDeviceNamePattern.MatchString(name) {
			return nil, fmt.Errorf("mesh device %d: name %q is not a valid device name (letters, digits, . _ -, up to 63)", index, device.Name)
		}
		if seenName[name] {
			return nil, fmt.Errorf("mesh device %d: duplicate name %q", index, name)
		}
		seenName[name] = true
		id := strings.TrimSpace(device.ID)
		if id != "" && !meshDeviceNamePattern.MatchString(id) {
			return nil, fmt.Errorf("mesh device %d: id %q is not a valid directory id (letters, digits, . _ -, up to 63)", index, device.ID)
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
		peers = append(peers, meshPeer{Name: name, ID: id, Domain: domain})
	}
	return peers, nil
}

// discoverMeshPeers reads the device list from the directory and turns it into
// the peers to expand. A directory that cannot be read is an error rather than
// an empty mesh: the profile is shared, so an unreachable directory would
// silently leave every rule that names a device pointing at nothing.
//
// It is the fallback for a caller that parsed a mesh block without resolving it
// first; see DiscoverMeshDevices for the request the core makes instead.
func discoverMeshPeers(mesh *RawMesh) ([]meshPeer, error) {
	devices, err := DiscoverMeshDevices(context.Background(), mesh)
	if err != nil {
		return nil, err
	}
	// Discovered devices carry the port they serve on in their own records,
	// which is what a dial reads; nothing here needs a port.
	return meshPeersFromDevices(devices)
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

// meshPort reads this device's port: the device entry carrying this device's
// directory id names the port it serves on, and every other entry names the
// port it is dialled at. A profile that does not say which entry is its own -
// one written before the id travelled in the block - names the port on every
// entry instead, and then they have to agree, because nothing else says which
// one is this device.
func meshPort(mesh *RawMesh) (int, error) {
	if _, ok := mesh.Listener["port"]; ok {
		return 0, errors.New("mesh: put the port on the device entries, not on the listener")
	}
	fallback := 0
	for index, device := range mesh.Devices {
		if device.Port == 0 {
			continue
		}
		if device.Port < 1 || device.Port > 65535 {
			return 0, fmt.Errorf("mesh device %d: invalid port %d", index, device.Port)
		}
		if mesh.DirectoryID != "" && device.ID == mesh.DirectoryID {
			// This entry is this device: its port is the one this device
			// serves on, and the others' are the ports it dials them at.
			return device.Port, nil
		}
		if fallback != 0 && device.Port != fallback {
			return 0, fmt.Errorf("mesh device %d: port %d differs from the other devices' port %d; put directory-id in the block to give each device its own port", index, device.Port, fallback)
		}
		fallback = device.Port
	}
	if fallback == 0 {
		fallback = meshDefaultPort
	}
	return fallback, nil
}
