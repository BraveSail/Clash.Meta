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

func TestUnregisterKeepsTheReplacement(t *testing.T) {
	previous := &stubDirectory{addr: "old"}
	replacement := &stubDirectory{addr: "new"}
	Register("directory", previous)
	Register("directory", replacement)
	t.Cleanup(func() { Unregister("directory", replacement) })

	Unregister("directory", previous)

	// The replacement has to survive: a config reload builds it before the
	// previous outbound stops, so removing by name alone would drop the new one.
	// It is observed through InjectNetworkChange, which reaches every
	// registered directory - the registry has no reader of its own left.
	replacement.injected, previous.injected = 0, 0
	InjectNetworkChange()
	if replacement.injected != 1 {
		t.Fatalf("injections on the replacement = %d, want the replacement kept", replacement.injected)
	}
	if previous.injected != 0 {
		t.Fatalf("injections on the removed directory = %d, want it gone", previous.injected)
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
