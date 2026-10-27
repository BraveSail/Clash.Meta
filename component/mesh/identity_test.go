package mesh

import (
	"bytes"
	"testing"
)

// The id is the key's name: two seeds differ, the same seed agrees, and the
// answer is a DNS label so a rule and a lookup can carry it.
func TestTheIDIsTheKeysName(t *testing.T) {
	a := bytes.Repeat([]byte{1}, 32)
	b := bytes.Repeat([]byte{2}, 32)

	if DeriveOn(a) == "" || DeriveOn(b) == "" {
		t.Fatal("a seed produced no id")
	}
	if DeriveOn(a) != DeriveOn(a) {
		t.Fatal("the same seed produced two ids")
	}
	if DeriveOn(a) == DeriveOn(b) {
		t.Fatal("two seeds produced one id")
	}
	if got := DeriveOn(a); len(got) != deviceIDLength {
		t.Fatalf("id %q is %d chars, want %d", got, len(got), deviceIDLength)
	}
}

// A seed that is not a signing seed has no name, and a device that cannot read
// its key must not invent one: two devices inventing the same way would collide
// in the directory.
func TestAShortSeedHasNoID(t *testing.T) {
	for _, seed := range [][]byte{nil, {}, bytes.Repeat([]byte{7}, 16)} {
		if got := DeriveOn(seed); got != "" {
			t.Fatalf("DeriveOn(%d bytes) = %q, want empty", len(seed), got)
		}
	}
}

// The id must not move when nothing about the key changed: the directory knows
// devices by it, and a drifting id re-registers a device as a new one.
func TestTheIDDoesNotDependOnTheHost(t *testing.T) {
	seed := bytes.Repeat([]byte{9}, 32)
	first := DeriveOn(seed)
	for i := 0; i < 3; i++ {
		if DeriveOn(seed) != first {
			t.Fatal("the id changed between calls")
		}
	}
}
