package mesh

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A device's key must be the same on every start: a new one looks like a new
// device to the directory, which is the churn the derived identity exists to
// avoid.
func TestTheKeySurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first.UUID != second.UUID || first.Decryption != second.Decryption ||
		first.Encryption != second.Encryption || string(first.Signing) != string(second.Signing) {
		t.Fatal("the key changed between loads")
	}
}

// The key is this device's own: two devices must not come out with the same
// transport material, or one could answer for the other.
func TestTwoDevicesGetDifferentKeys(t *testing.T) {
	one, err := LoadOrCreateKeys(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	two, err := LoadOrCreateKeys(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if one.UUID == two.UUID || one.Decryption == two.Decryption || one.Encryption == two.Encryption {
		t.Fatal("two devices produced the same key material")
	}
}

// The values have to be the shape the transport and the profile expect.
func TestTheKeyHasTheShapeTheTransportExpects(t *testing.T) {
	keys, err := LoadOrCreateKeys(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(keys.Decryption, EncryptionPrefix+".600s.") {
		t.Fatalf("decryption = %q", keys.Decryption)
	}
	if !strings.HasPrefix(keys.Encryption, EncryptionPrefix+"."+ClientHandshake+".") {
		t.Fatalf("encryption = %q", keys.Encryption)
	}
	// A UUID: 8-4-4-4-12 lower-case hex.
	parts := strings.Split(keys.UUID, "-")
	if len(parts) != 5 {
		t.Fatalf("uuid = %q", keys.UUID)
	}
	for i, want := range []int{8, 4, 4, 4, 12} {
		if len(parts[i]) != want {
			t.Fatalf("uuid = %q, part %d has length %d", keys.UUID, i, len(parts[i]))
		}
	}
	if len(keys.Signing) != 32 {
		t.Fatalf("signing seed has length %d", len(keys.Signing))
	}
}

// The key file is the device's secret: it must not be world-readable.
//
// Windows has no mode bits - Go maps the 0600 request onto ACLs and reports
// 0666 - so the assertion is POSIX-only rather than a failure there.
func TestTheKeyFileIsNotWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not how Windows expresses this")
	}
	dir := t.TempDir()
	if _, err := LoadOrCreateKeys(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, keyFileName))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("key file mode = %o", perm)
	}
}

// A corrupt key file is an error, not a silent regeneration: the device would
// otherwise change identity without anyone noticing.
func TestACorruptKeyFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, keyFileName), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKeys(dir); err == nil {
		t.Fatal("expected an error for a corrupt key file")
	}
}
