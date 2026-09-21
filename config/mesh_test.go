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
// url, the token or a protocol to dial with is left alone rather than
// discovered from nothing.
func TestExpandMeshWithoutADirectoryStaysANoOp(t *testing.T) {
	calls := stubDiscovery(t, []outbound.DirectoryNode{{ID: "aaaa1111", Name: "pc"}}, nil)

	for _, rawCfg := range []*RawConfig{
		{Mesh: &RawMesh{DirectoryURL: "https://hub.example", Proxy: map[string]any{"type": "direct"}}},
		{Mesh: &RawMesh{DirectoryURL: "https://hub.example", DirectoryToken: "secret"}},
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
