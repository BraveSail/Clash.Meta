package peerdirectory

import (
	"context"
	"errors"
	"testing"
)

type stubDirectory struct {
	addr      string
	injected  int
	lookupErr error
}

func (s *stubDirectory) PeerAddress(context.Context, string) (string, int, bool, error) {
	return s.addr, 8443, false, s.lookupErr
}

func (s *stubDirectory) InjectNetworkChange() {
	s.injected++
}

func TestLookupUsesTheRegisteredDirectory(t *testing.T) {
	directory := &stubDirectory{addr: "2409:8a55::1"}
	Register("pc-directory", directory)
	t.Cleanup(func() { Unregister("pc-directory", directory) })

	addr, port, self, err := Lookup(context.Background(), "pc-directory", "gt7")
	if err != nil || addr != "2409:8a55::1" || port != 8443 || self {
		t.Fatalf("Lookup = %q %d self=%v err=%v", addr, port, self, err)
	}

	if _, _, _, err := Lookup(context.Background(), "missing", "gt7"); err == nil {
		t.Fatal("Lookup of an unregistered directory reported success")
	}
}

func TestUnregisterKeepsTheReplacement(t *testing.T) {
	previous := &stubDirectory{addr: "old"}
	replacement := &stubDirectory{addr: "new"}
	Register("directory", previous)
	Register("directory", replacement)
	t.Cleanup(func() { Unregister("directory", replacement) })

	Unregister("directory", previous)

	if count := registeredCount(); count != 1 {
		t.Fatalf("directories after the old outbound stopped = %d, want the replacement", count)
	}
	if addr, _, _, _ := Lookup(context.Background(), "directory", "peer"); addr != "new" {
		t.Fatalf("Lookup = %q, want the replacement", addr)
	}
}

func TestInjectNetworkChangeReachesEveryDirectory(t *testing.T) {
	first := &stubDirectory{}
	second := &stubDirectory{}
	Register("first", first)
	Register("second", second)
	t.Cleanup(func() {
		Unregister("first", first)
		Unregister("second", second)
	})

	InjectNetworkChange()

	if first.injected != 1 || second.injected != 1 {
		t.Fatalf("injections = %d and %d, want one each", first.injected, second.injected)
	}
}

func TestSameIdentityHandlesUncomparableProviders(t *testing.T) {
	if sameIdentity([]string{"a"}, []string{"a"}) {
		t.Fatal("slices are never the same identity")
	}
	if !sameIdentity(nil, nil) {
		t.Fatal("two nil providers are the same identity")
	}
	directory := &stubDirectory{}
	if !sameIdentity(directory, directory) || sameIdentity(directory, &stubDirectory{}) {
		t.Fatal("pointer identity is not stable")
	}
	if sameIdentity(errors.New("a"), errors.New("a")) {
		t.Fatal("distinct pointers are not the same identity")
	}
}
