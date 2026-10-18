package mesh

import (
	"testing"
)

// A published registry is what the control API answers from, and a node with no
// mesh publishes nothing - the endpoint has to tell those two apart, so the
// empty case is the one worth pinning first.
func TestNoRegistryIsPublishedBeforeAnyMeshRuns(t *testing.T) {
	Withdraw(Running()) // a previous test may have published one
	if running := Running(); running != nil {
		t.Fatalf("Running() = %v, want nil when no mesh has published", running)
	}
}

func TestPublishIsWhatRunningAnswers(t *testing.T) {
	registry := NewStatusRegistry(nil, "https://hub.example")
	Publish(registry)
	t.Cleanup(func() { Withdraw(registry) })

	if running := Running(); running != registry {
		t.Fatal("Running() did not answer the registry that was published")
	}
}

// A reload installs the replacement before the previous outbound stops, so the
// outgoing mesh must not be able to withdraw the incoming one's registry: that
// would leave the control API answering "no mesh" while a mesh is running, which
// is the same trap the directory registry hit.
func TestWithdrawOfAnOlderRegistryKeepsTheReplacement(t *testing.T) {
	previous := NewStatusRegistry(nil, "https://hub.example")
	replacement := NewStatusRegistry(nil, "https://hub.example")

	Publish(previous)
	Publish(replacement)
	t.Cleanup(func() { Withdraw(replacement) })

	Withdraw(previous)

	if running := Running(); running != replacement {
		t.Fatal("withdrawing the outgoing registry took the replacement's place")
	}
}

func TestWithdrawClearsTheRegistryItWasGiven(t *testing.T) {
	registry := NewStatusRegistry(nil, "https://hub.example")
	Publish(registry)

	Withdraw(registry)

	if running := Running(); running != nil {
		t.Fatal("Running() still answers after the published registry was withdrawn")
	}
}
