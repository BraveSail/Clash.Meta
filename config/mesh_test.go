package config

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/stretchr/testify/assert"
)

func TestExpandMeshBuildsOnePeerPerDeviceAndOneListener(t *testing.T) {
	rawCfg := &RawConfig{
		Mesh: &RawMesh{
			DirectoryURL:   "https://hub.example",
			DirectoryToken: "secret",
			DirectoryID:    "this-device",
			Proxy:          map[string]any{"type": "vless", "uuid": "x", "udp": true},
			Listener:       map[string]any{"type": "vless", "users": []any{map[string]any{"uuid": "x"}}},
			Devices: []RawMeshDevice{
				{Name: "pc", Port: 9443},
				{Name: "gt7"},
			},
		},
	}

	if err := expandMesh(rawCfg); err != nil {
		t.Fatal(err)
	}
	if len(rawCfg.Proxy) != 2 {
		t.Fatalf("expanded %d proxies, want one per device", len(rawCfg.Proxy))
	}
	if len(rawCfg.Listeners) != 1 {
		t.Fatalf("expanded %d listeners, want one - the service a peer dials this device at", len(rawCfg.Listeners))
	}

	listener := rawCfg.Listeners[0]
	// The port is written on the device entries and reaches the listener from
	// there: one port, written once.
	assert.Equal(t, "mesh-in", listener["name"])
	assert.Equal(t, 9443, listener["port"])
	assert.Equal(t, "::", listener["listen"])
	// The rest of the listener block travels untouched.
	assert.Equal(t, "vless", listener["type"])
	assert.Equal(t, []any{map[string]any{"uuid": "x"}}, listener["users"])

	pc := rawCfg.Proxy[0]
	assert.Equal(t, "pc", pc["name"])
	assert.Equal(t, "tailnet-peer", pc["type"])
	assert.Equal(t, "pc", pc["peer"])
	assert.Equal(t, 9443, pc["port"])
	assert.Equal(t, "https://hub.example", pc["directory-url"])
	assert.Equal(t, "secret", pc["directory-token"])
	assert.Equal(t, "this-device", pc["directory-id"])
	assert.Equal(t, map[string]any{"type": "vless", "uuid": "x", "udp": true}, pc["proxy"])

	gt7 := rawCfg.Proxy[1]
	assert.Equal(t, "gt7", gt7["name"])
	// A device without a port takes the one the mesh settles on, 8443 when
	// nobody names one.
	assert.Equal(t, 9443, gt7["port"])
	// Every device shares the same directory identity: it is this device's own.
	assert.Equal(t, "this-device", gt7["directory-id"])
}

func TestExpandMeshDefaultsThePortWhenNobodyNamesOne(t *testing.T) {
	rawCfg := &RawConfig{
		Mesh: &RawMesh{
			DirectoryURL: "https://hub.example",
			Proxy:        map[string]any{"type": "direct"},
			Listener:     map[string]any{"type": "vless"},
			Devices:      []RawMeshDevice{{Name: "pc"}, {Name: "gt7"}},
		},
	}
	if err := expandMesh(rawCfg); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, meshDefaultPort, rawCfg.Proxy[0]["port"])
	assert.Equal(t, meshDefaultPort, rawCfg.Proxy[1]["port"])
	assert.Equal(t, meshDefaultPort, rawCfg.Listeners[0]["port"])
}

// The platform is what the client detects and reports to the directory, so
// nothing in the profile names it: only the device name and its port vary.
func TestExpandMeshWritesNoPlatformAttributes(t *testing.T) {
	rawCfg := &RawConfig{
		Mesh: &RawMesh{
			DirectoryURL: "https://hub.example",
			Proxy:        map[string]any{"type": "direct"},
			Listener:     map[string]any{"type": "vless"},
			Devices:      []RawMeshDevice{{Name: "pc"}, {Name: "gt7"}},
		},
	}
	if err := expandMesh(rawCfg); err != nil {
		t.Fatal(err)
	}
	for _, mapping := range rawCfg.Proxy {
		for _, key := range []string{"directory-id-by-platform", "platform"} {
			if mapping[key] != nil {
				t.Fatalf("mesh wrote %q: %v", key, mapping[key])
			}
		}
	}
}

func TestExpandMeshLeavesOtherProxiesAndListenersAlone(t *testing.T) {
	tagged := map[string]any{"name": "kr", "type": "ss", "server": "1.2.3.4", "port": 443}
	existing := map[string]any{"name": "api-in", "type": "http", "port": 8080}
	rawCfg := &RawConfig{
		Proxy:     []map[string]any{tagged},
		Listeners: []map[string]any{existing},
		Mesh: &RawMesh{
			DirectoryURL: "https://hub.example",
			Proxy:        map[string]any{"type": "direct"},
			Listener:     map[string]any{"type": "vless"},
			Devices:      []RawMeshDevice{{Name: "pc"}},
		},
	}
	if err := expandMesh(rawCfg); err != nil {
		t.Fatal(err)
	}
	if len(rawCfg.Proxy) != 2 {
		t.Fatalf("got %d proxies, want the tagged one plus the expanded device", len(rawCfg.Proxy))
	}
	assert.Equal(t, "kr", rawCfg.Proxy[0]["name"])
	assert.Equal(t, "pc", rawCfg.Proxy[1]["name"])
	if len(rawCfg.Listeners) != 2 {
		t.Fatalf("got %d listeners, want the existing one plus the mesh's", len(rawCfg.Listeners))
	}
	assert.Equal(t, "api-in", rawCfg.Listeners[0]["name"])
	assert.Equal(t, "mesh-in", rawCfg.Listeners[1]["name"])
}

// The listener half is optional support for profiles that write it by hand:
// the mesh still expands to one outbound per device.
func TestExpandMeshWithoutAListenerExpandsTheOutboundsOnly(t *testing.T) {
	rawCfg := &RawConfig{
		Mesh: &RawMesh{
			DirectoryURL: "https://hub.example",
			Proxy:        map[string]any{"type": "direct"},
			Devices:      []RawMeshDevice{{Name: "pc"}},
		},
	}
	if err := expandMesh(rawCfg); err != nil {
		t.Fatal(err)
	}
	if len(rawCfg.Proxy) != 1 {
		t.Fatalf("expanded %d proxies, want one per device", len(rawCfg.Proxy))
	}
	if len(rawCfg.Listeners) != 0 {
		t.Fatalf("expanded %d listeners, want none without a listener block", len(rawCfg.Listeners))
	}
}

func TestExpandMeshWithoutDevicesIsANoOp(t *testing.T) {
	for _, rawCfg := range []*RawConfig{{}, {Mesh: &RawMesh{}}} {
		if err := expandMesh(rawCfg); err != nil {
			t.Fatal(err)
		}
		if len(rawCfg.Proxy) != 0 || len(rawCfg.Listeners) != 0 {
			t.Fatalf("an empty mesh expanded to %d proxies and %d listeners", len(rawCfg.Proxy), len(rawCfg.Listeners))
		}
	}
}

func TestExpandMeshRejectsIncompleteOptions(t *testing.T) {
	device := []RawMeshDevice{{Name: "pc"}}
	proxy := map[string]any{"type": "direct"}
	listener := map[string]any{"type": "vless"}

	cases := []struct {
		testName string
		mesh     *RawMesh
	}{
		{testName: "missing directory-url", mesh: &RawMesh{Proxy: proxy, Listener: listener, Devices: device}},
		{testName: "missing proxy", mesh: &RawMesh{DirectoryURL: "https://hub.example", Listener: listener, Devices: device}},
		{testName: "invalid name", mesh: &RawMesh{DirectoryURL: "https://hub.example", Proxy: proxy, Listener: listener, Devices: []RawMeshDevice{{Name: "a b"}}}},
		{testName: "empty name", mesh: &RawMesh{DirectoryURL: "https://hub.example", Proxy: proxy, Listener: listener, Devices: []RawMeshDevice{{Port: 8443}}}},
		{testName: "duplicate name", mesh: &RawMesh{DirectoryURL: "https://hub.example", Proxy: proxy, Listener: listener, Devices: []RawMeshDevice{{Name: "pc"}, {Name: "pc"}}}},
		{testName: "invalid port", mesh: &RawMesh{DirectoryURL: "https://hub.example", Proxy: proxy, Listener: listener, Devices: []RawMeshDevice{{Name: "pc", Port: 70000}}}},
		{testName: "devices disagree on the port", mesh: &RawMesh{DirectoryURL: "https://hub.example", Proxy: proxy, Listener: listener, Devices: []RawMeshDevice{{Name: "pc", Port: 8443}, {Name: "gt7", Port: 9443}}}},
		{testName: "port written on the listener", mesh: &RawMesh{DirectoryURL: "https://hub.example", Proxy: proxy, Listener: map[string]any{"type": "vless", "port": 8443}, Devices: device}},
	}
	for _, testCase := range cases {
		t.Run(testCase.testName, func(t *testing.T) {
			rawCfg := &RawConfig{Mesh: testCase.mesh}
			assert.Error(t, expandMesh(rawCfg), testCase.testName)
		})
	}
}

// stubDiscovery replaces the directory read the mesh does while it expands,
// and answers with the devices the test is about.
func stubDiscovery(t *testing.T, nodes []outbound.DirectoryNode, err error) *int {
	t.Helper()
	calls := new(int)
	previous := discoverMeshNodes
	discoverMeshNodes = func(_ context.Context, url, token string, _ time.Duration) ([]outbound.DirectoryNode, error) {
		*calls++
		if url == "" || token == "" {
			t.Errorf("discovery was called with url %q and token %q", url, token)
		}
		return nodes, err
	}
	t.Cleanup(func() { discoverMeshNodes = previous })
	return calls
}

func discoveredMesh(devices []RawMeshDevice) *RawConfig {
	return &RawConfig{
		Mesh: &RawMesh{
			DirectoryURL:   "https://hub.example",
			DirectoryToken: "secret",
			DirectoryID:    "this-device",
			Heartbeat:      120,
			Proxy:          map[string]any{"type": "vless", "uuid": "x", "udp": true},
			Listener:       map[string]any{"type": "vless", "users": []any{map[string]any{"uuid": "x"}}},
			Devices:        devices,
		},
	}
}

// A mesh that lists no device takes them from the directory: the profile runs
// on every device, so none of them is named in it.
func TestExpandMeshDiscoversTheDevicesFromTheDirectory(t *testing.T) {
	calls := stubDiscovery(t, []outbound.DirectoryNode{
		{ID: "a1b2c3d4e5f6", Name: "PC", Addr: "2409:8a55::1", Port: 8443},
		{ID: "0f1e2d3c4b5a", Name: "gt7", Addr: "2409:895a::2", Port: 9443},
	}, nil)

	rawCfg := discoveredMesh(nil)
	if err := expandMesh(rawCfg); err != nil {
		t.Fatal(err)
	}
	if *calls != 1 {
		t.Fatalf("the directory was read %d times, want one", *calls)
	}
	if len(rawCfg.Proxy) != 2 {
		t.Fatalf("expanded %d proxies, want one per discovered device", len(rawCfg.Proxy))
	}
	if len(rawCfg.Listeners) != 1 {
		t.Fatalf("expanded %d listeners, want the one the mesh serves", len(rawCfg.Listeners))
	}
	// The mesh's own port comes from the device entries it does not have, so
	// the listener takes the default and every device is dialled at the port
	// its own record carries.
	assert.Equal(t, meshDefaultPort, rawCfg.Listeners[0]["port"])

	// The list is ordered by id, so the assertions look devices up by the id
	// they are dialled as rather than by position.
	pc := discoveredProxy(t, rawCfg, "a1b2c3d4e5f6")
	// The name is written as the directory gave it, in its own case: it is a
	// DNS label and a rule target.
	assert.Equal(t, "PC", pc["name"])
	assert.Equal(t, "tailnet-peer", pc["type"])
	assert.Equal(t, "PC", pc["peer"])
	// The lookup is by id, not by name: a device renamed on the dashboard
	// still resolves, and two devices cannot collide over a name.
	assert.Equal(t, "a1b2c3d4e5f6", pc["directory-peer"])
	assert.Equal(t, 8443, pc["port"])
	assert.Equal(t, "https://hub.example", pc["directory-url"])
	assert.Equal(t, "secret", pc["directory-token"])
	assert.Equal(t, "this-device", pc["directory-id"])
	assert.Equal(t, 120, pc["heartbeat"])
	assert.Equal(t, map[string]any{"type": "vless", "uuid": "x", "udp": true}, pc["proxy"])

	gt7 := discoveredProxy(t, rawCfg, "0f1e2d3c4b5a")
	assert.Equal(t, "gt7", gt7["name"])
	assert.Equal(t, "0f1e2d3c4b5a", gt7["directory-peer"])
	// The port is the device's own: a mesh that discovers its devices takes
	// each one as the directory recorded it.
	assert.Equal(t, 9443, gt7["port"])
}

// discoveredProxy answers the outbound expanded for one directory record.
func discoveredProxy(t *testing.T, rawCfg *RawConfig, id string) map[string]any {
	t.Helper()
	for _, mapping := range rawCfg.Proxy {
		if mapping["directory-peer"] == id {
			return mapping
		}
	}
	t.Fatalf("no outbound was expanded for device %q: %v", id, rawCfg.Proxy)
	return nil
}

// The device this profile runs on is one of the devices in the directory, and
// its rules may name it: it is expanded like any other, and the runtime - which
// knows this device's id - hands that name back to itself.
func TestExpandMeshIncludesTheDeviceItRunsOn(t *testing.T) {
	stubDiscovery(t, []outbound.DirectoryNode{
		{ID: "this-device", Name: "pc", Port: 8443},
		{ID: "0f1e2d3c4b5a", Name: "gt7", Port: 8443},
	}, nil)

	rawCfg := discoveredMesh(nil)
	if err := expandMesh(rawCfg); err != nil {
		t.Fatal(err)
	}
	if len(rawCfg.Proxy) != 2 {
		t.Fatalf("expanded %d proxies, want the self record among them", len(rawCfg.Proxy))
	}
	found := false
	for _, mapping := range rawCfg.Proxy {
		if mapping["directory-peer"] == "this-device" {
			found = true
			assert.Equal(t, "pc", mapping["name"])
		}
	}
	if !found {
		t.Fatalf("the record of the device this profile runs on was left out: %v", rawCfg.Proxy)
	}
}

// Every device of the mesh reads the same directory, and two of them may carry
// the same display name - one is not renamed yet, or two people picked the same
// one. The id is unique, so the later record is reached by that.
func TestExpandMeshFallsBackToTheIDWhenTwoDevicesShareAName(t *testing.T) {
	stubDiscovery(t, []outbound.DirectoryNode{
		{ID: "aaaa1111", Name: "pc", Port: 8443},
		{ID: "bbbb2222", Name: "pc", Port: 8443},
		// The third one's host name is the id the second fell back to, so it
		// falls back too rather than sharing a name with it.
		{ID: "cccc3333", Name: "bbbb2222", Port: 8443},
	}, nil)

	rawCfg := discoveredMesh(nil)
	if err := expandMesh(rawCfg); err != nil {
		t.Fatal(err)
	}
	if len(rawCfg.Proxy) != 3 {
		t.Fatalf("expanded %d proxies, want one per record", len(rawCfg.Proxy))
	}
	want := []struct{ name, id string }{
		{"pc", "aaaa1111"},
		{"bbbb2222", "bbbb2222"},
		{"cccc3333", "cccc3333"},
	}
	for index, expected := range want {
		assert.Equal(t, expected.name, rawCfg.Proxy[index]["name"])
		assert.Equal(t, expected.id, rawCfg.Proxy[index]["directory-peer"])
	}
}

// A name the profile could not write is not one it can point a rule at: the id
// stands in, for both the name and the lookup.
func TestExpandMeshFallsBackToTheIDForAnUnusableName(t *testing.T) {
	stubDiscovery(t, []outbound.DirectoryNode{
		{ID: "aaaa1111", Name: "pc ", Port: 8443},
		{ID: "bbbb2222", Name: "a b", Port: 8443},
		{ID: "cccc3333", Name: "", Port: 8443},
	}, nil)

	rawCfg := discoveredMesh(nil)
	if err := expandMesh(rawCfg); err != nil {
		t.Fatal(err)
	}
	for index, want := range []string{"pc", "bbbb2222", "cccc3333"} {
		assert.Equal(t, want, rawCfg.Proxy[index]["name"])
		assert.Equal(t, want, rawCfg.Proxy[index]["peer"])
	}
	assert.Equal(t, "bbbb2222", rawCfg.Proxy[1]["directory-peer"])
	assert.Equal(t, "cccc3333", rawCfg.Proxy[2]["directory-peer"])
}

// Every device of the mesh reads the same list, so the list has to expand the
// same way everywhere: it is ordered by id, and the names are handed out in
// that order.
func TestExpandMeshExpandsDiscoveredDevicesInIDOrder(t *testing.T) {
	stubDiscovery(t, []outbound.DirectoryNode{
		{ID: "cccc3333", Name: "pc", Port: 8443},
		{ID: "aaaa1111", Name: "pc", Port: 8443},
		{ID: "bbbb2222", Name: "hub", Port: 8443},
	}, nil)

	rawCfg := discoveredMesh(nil)
	if err := expandMesh(rawCfg); err != nil {
		t.Fatal(err)
	}
	want := []struct{ name, id string }{
		{"pc", "aaaa1111"},
		{"hub", "bbbb2222"},
		{"cccc3333", "cccc3333"},
	}
	for index, expected := range want {
		assert.Equal(t, expected.name, rawCfg.Proxy[index]["name"])
		assert.Equal(t, expected.id, rawCfg.Proxy[index]["directory-peer"])
	}
}

// A directory that cannot be read is the reason the profile does not load:
// rules naming a device would otherwise be left pointing at nothing.
func TestExpandMeshFailsWhenTheDirectoryCannotBeRead(t *testing.T) {
	stubDiscovery(t, nil, errors.New("directory answered 401: unauthorized"))

	rawCfg := discoveredMesh(nil)
	err := expandMesh(rawCfg)
	if err == nil {
		t.Fatal("an unreachable directory was accepted")
	}
	assert.Contains(t, err.Error(), "https://hub.example")
	if len(rawCfg.Proxy) != 0 || len(rawCfg.Listeners) != 0 {
		t.Fatalf("a failed discovery still expanded %d proxies and %d listeners", len(rawCfg.Proxy), len(rawCfg.Listeners))
	}
}

// A profile that lists its devices by hand keeps dialling them by name: the
// directory is not read behind its back.
func TestExpandMeshKeepsListedDevicesOffTheDirectory(t *testing.T) {
	calls := stubDiscovery(t, []outbound.DirectoryNode{{ID: "aaaa1111", Name: "discovered"}}, nil)

	rawCfg := discoveredMesh([]RawMeshDevice{{Name: "pc", Port: 9443}})
	if err := expandMesh(rawCfg); err != nil {
		t.Fatal(err)
	}
	if *calls != 0 {
		t.Fatalf("a mesh with listed devices read the directory %d times", *calls)
	}
	if len(rawCfg.Proxy) != 1 {
		t.Fatalf("expanded %d proxies, want the listed one", len(rawCfg.Proxy))
	}
	assert.Equal(t, "pc", rawCfg.Proxy[0]["name"])
	assert.Equal(t, 9443, rawCfg.Proxy[0]["port"])
	// A listed device is asked for by the name the block wrote.
	assert.Nil(t, rawCfg.Proxy[0]["directory-peer"])
}

// Reading the directory needs somewhere to read it from: a mesh without the
// url or the token is left alone rather than discovered from nothing. A block
// that names both speaks the protocol the core derives, so it is no longer
// part of this bunch.
func TestExpandMeshWithoutADirectoryStaysANoOp(t *testing.T) {
	calls := stubDiscovery(t, []outbound.DirectoryNode{{ID: "aaaa1111", Name: "pc"}}, nil)

	for _, rawCfg := range []*RawConfig{
		{Mesh: &RawMesh{DirectoryURL: "https://hub.example", Proxy: map[string]any{"type": "direct"}}},
		{Mesh: &RawMesh{DirectoryToken: "secret", Proxy: map[string]any{"type": "direct"}}},
		{Mesh: &RawMesh{Proxy: map[string]any{"type": "direct"}}},
	} {
		if err := expandMesh(rawCfg); err != nil {
			t.Fatal(err)
		}
		if len(rawCfg.Proxy) != 0 || len(rawCfg.Listeners) != 0 {
			t.Fatalf("a mesh without a directory expanded to %d proxies and %d listeners", len(rawCfg.Proxy), len(rawCfg.Listeners))
		}
	}
	if *calls != 0 {
		t.Fatalf("the directory was read %d times by a mesh without one", *calls)
	}
}

// The block someone writes on the dashboard names the directory and nothing
// else: the protocol between the devices is derived, so a mesh with both
// halves of the directory and no protocol still reaches its devices.
func TestExpandMeshDerivesTheProtocolWhenNoneIsWritten(t *testing.T) {
	stubDiscovery(t, []outbound.DirectoryNode{
		{ID: "aaaa1111", Name: "pc"},
		{ID: "bbbb2222", Name: "gt7"},
	}, nil)

	rawCfg := &RawConfig{
		Mesh: &RawMesh{
			DirectoryURL:   "https://hub.example",
			DirectoryToken: "secret",
			DirectoryID:    "this-device",
		},
	}
	if err := expandMesh(rawCfg); err != nil {
		t.Fatal(err)
	}
	if len(rawCfg.Proxy) != 2 {
		t.Fatalf("expanded %d proxies, want one per device", len(rawCfg.Proxy))
	}
	if len(rawCfg.Listeners) != 1 {
		t.Fatalf("expanded %d listeners, want the one peers dial this device at", len(rawCfg.Listeners))
	}

	uuid := meshUUID("secret")
	derived := rawCfg.Proxy[0]["proxy"].(map[string]any)
	assert.Equal(t, meshDerivedProtocol, derived["type"])
	assert.Equal(t, uuid, derived["uuid"])

	// The listener serves the user the outbounds dial: one derivation, both
	// ends.
	listener := rawCfg.Listeners[0]
	assert.Equal(t, meshDerivedProtocol, listener["type"])
	assert.Equal(t, []any{map[string]any{"uuid": uuid}}, listener["users"])
}

// VLESS without a certificate is refused at bind time, so the derived protocol
// has to carry the encryption that stands in for one: the server half on the
// listener, the matching client half on every outbound.
func TestExpandMeshDerivesTheEncryptionBothEndsSpeak(t *testing.T) {
	stubDiscovery(t, []outbound.DirectoryNode{{ID: "aaaa1111", Name: "pc"}}, nil)

	rawCfg := &RawConfig{
		Mesh: &RawMesh{
			DirectoryURL:   "https://hub.example",
			DirectoryToken: "secret",
			DirectoryID:    "this-device",
		},
	}
	if err := expandMesh(rawCfg); err != nil {
		t.Fatal(err)
	}

	decryption, encryptionValue := meshEncryptionKeys("secret")
	listener := rawCfg.Listeners[0]
	// Both halves have to be present, or the core refuses to bind the
	// listener: a VLESS listener without a certificate, a reality config or
	// an encryption key is not one it will serve.
	assert.Equal(t, decryption, listener["decryption"])
	derived := rawCfg.Proxy[0]["proxy"].(map[string]any)
	assert.Equal(t, encryptionValue, derived["encryption"])

	// The values have to parse as the core parses them, not merely be non
	// empty strings.
	assert.Regexp(t, `^mlkem768x25519plus\.native\.600s\.[A-Za-z0-9_-]{43}$`, decryption)
	assert.Regexp(t, `^mlkem768x25519plus\.native\.0rtt\.[A-Za-z0-9_-]{43}$`, encryptionValue)
}

// The pair is what lets two devices of one mesh talk: every device holds the
// same token, so every device derives the same two halves without anyone
// writing a key down, and two meshes do not share them.
func TestMeshEncryptionKeysAreStableAndSeparateTokens(t *testing.T) {
	decryption, encryptionValue := meshEncryptionKeys("secret")
	sameDecryption, sameEncryption := meshEncryptionKeys("secret")
	assert.Equal(t, decryption, sameDecryption)
	assert.Equal(t, encryptionValue, sameEncryption)

	otherDecryption, otherEncryption := meshEncryptionKeys("another-secret")
	assert.NotEqual(t, decryption, otherDecryption)
	assert.NotEqual(t, encryptionValue, otherEncryption)
}

// The derivation is an identity, so it cannot drift between builds or
// platforms and it cannot be the same for two meshes.
func TestMeshUUIDIsStableAndSeparatesTokens(t *testing.T) {
	first := meshUUID("secret")
	assert.Equal(t, first, meshUUID("secret"))
	assert.NotEqual(t, first, meshUUID("another-secret"))
	assert.Regexp(t, `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, first)
}

// A block that writes its protocol keeps it: the derivation only fills a
// block that wrote neither half, so a hand-written profile is untouched.
func TestExpandMeshKeepsAWrittenProtocol(t *testing.T) {
	stubDiscovery(t, []outbound.DirectoryNode{{ID: "aaaa1111", Name: "pc"}}, nil)

	written := map[string]any{"type": "vless", "uuid": "written-uuid", "udp": true}
	rawCfg := &RawConfig{
		Mesh: &RawMesh{
			DirectoryURL:   "https://hub.example",
			DirectoryToken: "secret",
			Proxy:          written,
		},
	}
	if err := expandMesh(rawCfg); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, written, rawCfg.Proxy[0]["proxy"])
	// Nothing was derived, so no listener was invented either.
	assert.Empty(t, rawCfg.Listeners)
}

// A device need not serve on the default port: the port its record carries is
// the one it is dialled at, and a record without one takes the default.
func TestExpandMeshUsesEachDiscoveredDevicePort(t *testing.T) {
	stubDiscovery(t, []outbound.DirectoryNode{
		{ID: "aaaa1111", Name: "pc", Port: 9443},
		{ID: "bbbb2222", Name: "gt7"},
		{ID: "cccc3333", Name: "old", Port: 70000},
	}, nil)

	rawCfg := discoveredMesh(nil)
	if err := expandMesh(rawCfg); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 9443, rawCfg.Proxy[0]["port"])
	assert.Equal(t, meshDefaultPort, rawCfg.Proxy[1]["port"])
	assert.Equal(t, meshDefaultPort, rawCfg.Proxy[2]["port"])
	// The listener this device serves takes the default: the mesh no longer
	// settles on one port for everyone.
	assert.Equal(t, meshDefaultPort, rawCfg.Listeners[0]["port"])
}

// The app reads the directory while it builds the configuration - the core
// cannot, because a block reachable only through the tunnel is not up yet by
// the time the block is parsed - and writes what it found beside each name.
// The runtime then asks by id, and the parse itself touches no network.
func TestExpandMeshTakesTheDeviceListTheAppResolved(t *testing.T) {
	calls := stubDiscovery(t, nil, errors.New("the directory must not be read during the parse"))

	rawCfg := discoveredMesh([]RawMeshDevice{
		{Name: "PC", ID: "a1b2c3d4e5f6"},
		{Name: "gt7", ID: "0f1e2d3c4b5a", Port: 9443},
	})
	rawCfg.Mesh.DirectoryResolved = true
	rawCfg.Mesh.DirectoryProxy = "http://127.0.0.1:7890"

	if err := expandMesh(rawCfg); err != nil {
		t.Fatal(err)
	}
	if *calls != 0 {
		t.Fatalf("a resolved device list still read the directory %d times", *calls)
	}
	if len(rawCfg.Proxy) != 2 {
		t.Fatalf("expanded %d proxies, want one per resolved device", len(rawCfg.Proxy))
	}

	pc := rawCfg.Proxy[0]
	assert.Equal(t, "PC", pc["name"])
	assert.Equal(t, "PC", pc["peer"])
	// The id travels with the device so the runtime asks the directory about
	// the record rather than the name: a device renamed on the dashboard
	// keeps resolving.
	assert.Equal(t, "a1b2c3d4e5f6", pc["directory-peer"])
	// The proxy travels to the runtime half: reading the list and asking
	// about a peer go through the same door.
	assert.Equal(t, "http://127.0.0.1:7890", pc["directory-proxy"])

	gt7 := rawCfg.Proxy[1]
	assert.Equal(t, "0f1e2d3c4b5a", gt7["directory-peer"])
	assert.Equal(t, 9443, gt7["port"])
}

// A resolved list that came back empty is a mesh with nothing to dial yet: the
// parse takes it as it stands rather than asking the same blocked directory
// again, which is what keeps a device whose network cannot reach the directory
// from failing to start.
func TestExpandMeshAcceptsAnEmptyResolvedList(t *testing.T) {
	calls := stubDiscovery(t, nil, errors.New("the directory must not be read during the parse"))

	rawCfg := discoveredMesh(nil)
	rawCfg.Mesh.DirectoryResolved = true
	if err := expandMesh(rawCfg); err != nil {
		t.Fatalf("an empty resolved list failed the parse: %v", err)
	}
	if *calls != 0 {
		t.Fatalf("an empty resolved list read the directory %d times", *calls)
	}
	if len(rawCfg.Proxy) != 0 {
		t.Fatalf("expanded %d proxies from an empty list", len(rawCfg.Proxy))
	}
	// The listener still stands: this device serves whether or not a peer is
	// known yet, and the next list will name one.
	if len(rawCfg.Listeners) != 1 {
		t.Fatalf("expanded %d listeners, want the one this device serves", len(rawCfg.Listeners))
	}
}

// A list written by hand carries no id and no resolved flag: it is a list of
// names, and asking the directory about them would be asking about nothing.
func TestExpandMeshTakesAHandWrittenListWithoutIDs(t *testing.T) {
	calls := stubDiscovery(t, nil, errors.New("a hand-written list must not be read from the directory"))

	rawCfg := discoveredMesh([]RawMeshDevice{{Name: "pc", Port: 9443}})
	if err := expandMesh(rawCfg); err != nil {
		t.Fatal(err)
	}
	if *calls != 0 {
		t.Fatalf("a hand-written list read the directory %d times", *calls)
	}
	assert.Equal(t, "pc", rawCfg.Proxy[0]["name"])
	assert.Nil(t, rawCfg.Proxy[0]["directory-peer"])
	assert.Nil(t, rawCfg.Proxy[0]["directory-proxy"])
}

// An id that cannot be asked about is a mistake in the generated list, and the
// parse says so rather than letting the runtime ask a malformed question.
func TestExpandMeshRejectsAnInvalidResolvedID(t *testing.T) {
	stubDiscovery(t, nil, errors.New("the directory must not be read during the parse"))

	rawCfg := discoveredMesh([]RawMeshDevice{{Name: "pc", ID: "a b"}})
	rawCfg.Mesh.DirectoryResolved = true
	assert.Error(t, expandMesh(rawCfg))
}

// A mesh whose devices carry domains grows one entry the rules point at, and
// the rules for the domains point at it: the profile writes no rule per device,
// so a device renamed on the dashboard cannot leave a rule pointing at nothing.
func TestExpandMeshWritesAnEntryAndRulesForTheDevicesDomains(t *testing.T) {
	stubDiscovery(t, nil, errors.New("the directory must not be read during the parse"))

	rawCfg := discoveredMesh([]RawMeshDevice{
		{Name: "PC", ID: "a1b2c3d4e5f6", Domain: "pc.lan"},
		{Name: "gt7", ID: "0f1e2d3c4b5a", Domain: "GT7.LAN"},
		{Name: "phone", ID: "112233445566"},
	})
	rawCfg.Mesh.DirectoryResolved = true

	if err := expandMesh(rawCfg); err != nil {
		t.Fatal(err)
	}

	// One entry for every device, plus the one the rules point at.
	if len(rawCfg.Proxy) != 4 {
		t.Fatalf("expanded %d proxies, want one per device plus the mesh entry", len(rawCfg.Proxy))
	}
	entry := rawCfg.Proxy[3]
	assert.Equal(t, meshEntryName, entry["name"])
	assert.Equal(t, "tailnet-peer", entry["type"])
	// The mapping is what makes one entry serve every device: the name a
	// connection asked for decides which record is looked up.
	assert.Equal(t, map[string]string{"pc.lan": "a1b2c3d4e5f6", "gt7.lan": "0f1e2d3c4b5a"}, entry["domains"])
	assert.Equal(t, meshDefaultPort, entry["port"])

	// Sorted, so the rules read the same on every device of the mesh.
	assert.Equal(t, []string{"DOMAIN,gt7.lan,mesh", "DOMAIN,pc.lan,mesh"}, rawCfg.Rule)
	// The device without a domain is still dialled by name; only its domain
	// rule is missing.
	assert.Equal(t, "phone", rawCfg.Proxy[2]["name"])
}

// The generated rules go first: a rule the user wrote by hand for the same
// name - a catch-all, a geosite entry - must not shadow the mesh.
func TestExpandMeshPutsTheDomainRulesFirst(t *testing.T) {
	stubDiscovery(t, nil, errors.New("the directory must not be read during the parse"))

	rawCfg := discoveredMesh([]RawMeshDevice{{Name: "PC", ID: "a1b2c3d4e5f6", Domain: "pc.lan"}})
	rawCfg.Mesh.DirectoryResolved = true
	rawCfg.Rule = []string{"MATCH,DIRECT"}

	if err := expandMesh(rawCfg); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, []string{"DOMAIN,pc.lan,mesh", "MATCH,DIRECT"}, rawCfg.Rule)
}

// A device without a domain grows neither an entry nor a rule: an old profile
// that names its devices keeps expanding exactly as it did.
func TestExpandMeshWritesNothingForDevicesWithoutDomains(t *testing.T) {
	stubDiscovery(t, nil, errors.New("the directory must not be read during the parse"))

	rawCfg := discoveredMesh([]RawMeshDevice{{Name: "PC", ID: "a1b2c3d4e5f6"}})
	rawCfg.Mesh.DirectoryResolved = true

	if err := expandMesh(rawCfg); err != nil {
		t.Fatal(err)
	}
	if len(rawCfg.Proxy) != 1 {
		t.Fatalf("expanded %d proxies, want only the device", len(rawCfg.Proxy))
	}
	assert.Empty(t, rawCfg.Rule)
}

// A domain is set on the dashboard and only decides which device a name
// reaches: one that is not a dns name costs the device its domain, not the
// profile - refusing the configuration would take the whole mesh down over one
// odd record.
func TestExpandMeshDropsAnInvalidDomainRatherThanTheProfile(t *testing.T) {
	stubDiscovery(t, nil, errors.New("the directory must not be read during the parse"))

	rawCfg := discoveredMesh([]RawMeshDevice{
		{Name: "PC", ID: "a1b2c3d4e5f6", Domain: "not a domain"},
		{Name: "gt7", ID: "0f1e2d3c4b5a", Domain: "gt7.lan"},
	})
	rawCfg.Mesh.DirectoryResolved = true

	if err := expandMesh(rawCfg); err != nil {
		t.Fatalf("an odd domain failed the parse: %v", err)
	}
	// The device stays; only its rule is gone.
	assert.Equal(t, []string{"DOMAIN,gt7.lan,mesh"}, rawCfg.Rule)
	assert.Equal(t, map[string]string{"gt7.lan": "0f1e2d3c4b5a"}, rawCfg.Proxy[len(rawCfg.Proxy)-1]["domains"])
}
