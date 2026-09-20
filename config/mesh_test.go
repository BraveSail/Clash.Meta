package config

import (
	"testing"

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
