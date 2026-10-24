package outbound

import (
	"os"
	"path/filepath"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// A device with no token must end up with a key on disk: without it the
// directory cannot tell which device is asking, and every report is refused.
// The failure this pins is silent - no key, no signature, no report - so it has
// to be checked at the constructor rather than in the field.
func TestADeviceWithoutATokenLoadsItsKey(t *testing.T) {
	// Not t.TempDir: the directory keeps a cache open, and Windows refuses to
	// remove a directory whose file is still held. The key is what this test is
	// about, so the cleanup is best effort.
	home, err := os.MkdirTemp("", "mesh-home")
	if err != nil {
		t.Fatal(err)
	}
	C.SetHomeDir(home)
	t.Cleanup(func() {
		C.SetHomeDir("")
		_ = os.RemoveAll(home)
	})

	directory, err := NewPeerDirectory(PeerDirectoryOption{
		Name: "mesh",
		URL:  "https://hub.example",
		ID:   "pc",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directory.Close() }()

	if len(directory.signingSeed) == 0 {
		t.Fatal("no signing key was loaded")
	}
	if _, err := os.Stat(filepath.Join(home, "mesh-key.json")); err != nil {
		t.Fatalf("the key was not written: %v", err)
	}
	if directory.option.UUID == "" {
		t.Fatal("the device does not know the user it listens as")
	}
}

// And a device that still has a token must not grow a key: the token is the
// proof, and writing a key nobody uses would only invite confusion.
func TestADeviceWithATokenDoesNotLoadAKey(t *testing.T) {
	home := t.TempDir()
	C.SetHomeDir(home)
	t.Cleanup(func() { C.SetHomeDir("") })

	directory, err := NewPeerDirectory(PeerDirectoryOption{
		Name:  "mesh",
		URL:   "https://hub.example",
		ID:    "pc",
		Token: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directory.Close() }()

	if len(directory.signingSeed) != 0 {
		t.Fatal("a token device loaded a signing key")
	}
}
