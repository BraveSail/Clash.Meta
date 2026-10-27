package adapter

import "testing"

// A shared profile may carry fields a given build does not know yet (the
// directory settings arrived this way). The decoder has to ignore them instead
// of failing the whole config, or rolling a new option out would break every
// device that has not been updated.
func TestTailnetPeerIgnoresUnknownFields(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":              "pc",
		"type":              "tailnet-peer",
		"peer":              "pc",
		"port":              8443,
		"directory-url":     "https://example.invalid",
		"directory-token":   "secret",
		"something-unknown": true,
		"proxy":             map[string]any{"type": "direct", "name": "inner"},
	})
	if err != nil {
		t.Fatalf("a config with an unknown field was rejected: %v", err)
	}
	if proxy == nil {
		t.Fatal("no proxy was built")
	}
}
