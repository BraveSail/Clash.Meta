package mesh

import (
	"runtime"
	"testing"
)

func platformOfThisBuild() string { return runtime.GOOS }

// The derivation is pinned by value, not recomputed: the ids on the hub are
// hashes of this exact construction, so a changed platform name, separator or
// truncation would silently re-register every device as a new one.
func TestDeviceIDMatchesTheDirectorysExistingIds(t *testing.T) {
	cases := []struct {
		platform  string
		machineID string
		want      string
	}{
		{"windows", "4C4C4544-0042-3510-8057-B4C04F4E4E32", "95f2fe2623a9"},
		{"android", "9774d56d682e549c", "2362a31b1b50"},
		{"linux", "0123456789abcdef0123456789abcdef", "0434c62c29ad"},
	}
	for _, c := range cases {
		t.Run(c.platform, func(t *testing.T) {
			if got := DeriveOn(c.platform, c.machineID).ID; got != c.want {
				t.Fatalf("DeriveOn(%q) = %q, want %q", c.platform, got, c.want)
			}
		})
	}
}

// A machine that cannot read its id gets no id. An empty id is skipped when the
// mesh block is expanded, so the device still joins; a made-up one would let
// two devices collide in the directory.
func TestNoMachineIDMeansNoID(t *testing.T) {
	for _, machineID := range []string{"", "   "} {
		if got := DeriveOn("android", machineID).ID; got != "" {
			t.Fatalf("DeriveOn(%q) = %q, want empty", machineID, got)
		}
	}
}

// The id is a DNS label: a rule and a lookup both carry it.
func TestDerivedIDIsALabel(t *testing.T) {
	id := DeriveOn("android", "some-machine").ID
	if len(id) != deviceIDLength {
		t.Fatalf("id %q has length %d, want %d", id, len(id), deviceIDLength)
	}
	for _, r := range id {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			t.Fatalf("id %q is not a lower-case hex label", id)
		}
	}
}

// What the platform layer hands over wins over the probe, which is the whole
// point of the injection on Android: the app's bridge reads ANDROID_ID there.
func TestInjectedHostIdentityWins(t *testing.T) {
	ResetHostIdentity()
	defer ResetHostIdentity()
	SetHostIdentity("9774d56d682e549c", "Android 14")
	identity := Derive()
	if identity.OS != "Android 14" {
		t.Fatalf("OS = %q, want the injected one", identity.OS)
	}
	if identity.ID != DeriveOn(platformOfThisBuild(), "9774d56d682e549c").ID {
		t.Fatalf("ID = %q, want the id derived from the injected machine id", identity.ID)
	}
}

// The name is the host's own, and an empty one is left to the directory to
// fill in rather than replaced with a placeholder.
func TestDeriveCarriesTheHostName(t *testing.T) {
	ResetHostIdentity()
	defer ResetHostIdentity()
	SetHostIdentity("machine", "Some OS")
	if name := Derive().Name; name == "" {
		t.Fatal("expected the host name to be reported")
	}
}
