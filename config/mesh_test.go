package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExpandMeshBuildsOnePeerPerDevice(t *testing.T) {
	rawCfg := &RawConfig{
		Mesh: &RawMesh{
			DirectoryURL:   "https://hub.example",
			DirectoryToken: "secret",
			DirectoryID:    "this-device",
			Proxy:          map[string]any{"type": "vless", "uuid": "x", "udp": true},
			Devices: []RawMeshDevice{
				{Name: "pc", Port: 8443},
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

	pc := rawCfg.Proxy[0]
	assert.Equal(t, "pc", pc["name"])
	assert.Equal(t, "tailnet-peer", pc["type"])
	assert.Equal(t, "pc", pc["peer"])
	assert.Equal(t, 8443, pc["port"])
	assert.Equal(t, "https://hub.example", pc["directory-url"])
	assert.Equal(t, "secret", pc["directory-token"])
	assert.Equal(t, "this-device", pc["directory-id"])
	assert.Equal(t, map[string]any{"type": "vless", "uuid": "x", "udp": true}, pc["proxy"])

	gt7 := rawCfg.Proxy[1]
	assert.Equal(t, "gt7", gt7["name"])
	// A device without a port takes the directory's default.
	assert.Equal(t, meshDefaultPort, gt7["port"])
	// Every device shares the same directory identity: it is this device's own.
	assert.Equal(t, "this-device", gt7["directory-id"])
}

// The platform is what the client detects and reports to the directory, so
// nothing in the profile names it: only the device name and its port vary.
func TestExpandMeshWritesNoPlatformAttributes(t *testing.T) {
	rawCfg := &RawConfig{
		Mesh: &RawMesh{
			DirectoryURL: "https://hub.example",
			Proxy:        map[string]any{"type": "direct"},
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

func TestExpandMeshLeavesOtherProxiesAlone(t *testing.T) {
	tagged := map[string]any{"name": "kr", "type": "ss", "server": "1.2.3.4", "port": 443}
	rawCfg := &RawConfig{
		Proxy: []map[string]any{tagged},
		Mesh: &RawMesh{
			DirectoryURL: "https://hub.example",
			Proxy:        map[string]any{"type": "direct"},
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
}

func TestExpandMeshWithoutDevicesIsANoOp(t *testing.T) {
	for _, rawCfg := range []*RawConfig{{}, {Mesh: &RawMesh{}}} {
		if err := expandMesh(rawCfg); err != nil {
			t.Fatal(err)
		}
		if len(rawCfg.Proxy) != 0 {
			t.Fatalf("an empty mesh expanded to %d proxies", len(rawCfg.Proxy))
		}
	}
}

func TestExpandMeshRejectsIncompleteOptions(t *testing.T) {
	device := []RawMeshDevice{{Name: "pc"}}
	proxy := map[string]any{"type": "direct"}

	cases := []struct {
		testName string
		mesh     *RawMesh
	}{
		{testName: "missing directory-url", mesh: &RawMesh{Proxy: proxy, Devices: device}},
		{testName: "missing proxy", mesh: &RawMesh{DirectoryURL: "https://hub.example", Devices: device}},
		{testName: "invalid name", mesh: &RawMesh{DirectoryURL: "https://hub.example", Proxy: proxy, Devices: []RawMeshDevice{{Name: "a b"}}}},
		{testName: "empty name", mesh: &RawMesh{DirectoryURL: "https://hub.example", Proxy: proxy, Devices: []RawMeshDevice{{Port: 8443}}}},
		{testName: "duplicate name", mesh: &RawMesh{DirectoryURL: "https://hub.example", Proxy: proxy, Devices: []RawMeshDevice{{Name: "pc"}, {Name: "pc"}}}},
		{testName: "invalid port", mesh: &RawMesh{DirectoryURL: "https://hub.example", Proxy: proxy, Devices: []RawMeshDevice{{Name: "pc", Port: 70000}}}},
	}
	for _, testCase := range cases {
		t.Run(testCase.testName, func(t *testing.T) {
			rawCfg := &RawConfig{Mesh: testCase.mesh}
			assert.Error(t, expandMesh(rawCfg), testCase.testName)
		})
	}
}
