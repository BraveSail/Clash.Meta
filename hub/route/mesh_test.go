package route

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/component/mesh"
)

// A node whose profile has no mesh block is a normal configuration, not a
// fault: the endpoint has to say so rather than answer 404 or an empty object,
// because "no mesh" and "mesh running with nothing to report yet" are different
// states and an operator has to be able to tell them apart.
func TestMeshStatusWithoutAMeshSaysSo(t *testing.T) {
	mesh.Withdraw(mesh.Running()) // a previous test may have published one

	recorder := httptest.NewRecorder()
	meshStatus(recorder, httptest.NewRequest("GET", "/mesh/status", nil))

	if recorder.Code != 200 {
		t.Fatalf("status = %d, want 200 for a node with no mesh", recorder.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not json: %v", err)
	}
	if enabled, ok := body["enabled"].(bool); !ok || enabled {
		t.Errorf("enabled = %v, want false", body["enabled"])
	}
}

// The endpoint is what an operator reads when a session drops, so it has to
// carry the values that answer that question: where this node is, what each
// route is doing, how many connections it carries, and how many times the
// configuration has been applied.
func TestMeshStatusReportsTheLiveValues(t *testing.T) {
	registry := mesh.NewStatusRegistry(nil, "https://hub.example")
	mesh.Publish(registry)
	t.Cleanup(func() { mesh.Withdraw(registry) })

	registry.SetIdentity("self-id", "2408::1", 23333)
	registry.NoteRoute("proxy", nil)
	registry.NoteRoute("direct", errStub{})
	registry.NotePeerAnswer("pc", mesh.PeerAnswer{Addr: "2408::2", Port: 23333, Source: "directory", At: time.Now()})
	release := registry.NoteDial("pc")
	registry.NoteApply(`"v3"`)

	recorder := httptest.NewRecorder()
	meshStatus(recorder, httptest.NewRequest("GET", "/mesh/status", nil))

	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not json: %v", err)
	}
	if body["id"] != "self-id" || body["port"] != float64(23333) {
		t.Errorf("identity = %v / %v, want self-id / 23333", body["id"], body["port"])
	}

	channel, _ := body["channel"].(map[string]any)
	if channel["applies"] != float64(1) || channel["etag"] != `"v3"` {
		t.Errorf("channel = %v, want one apply at the current etag", channel)
	}

	connections, _ := body["connections"].(map[string]any)
	if connections["open"] != float64(1) {
		t.Errorf("open connections = %v, want 1 while the dial is held", connections["open"])
	}

	directory, _ := body["directory"].(map[string]any)
	peers, _ := directory["peers"].(map[string]any)
	peer, _ := peers["pc"].(map[string]any)
	if peer["address"] != "2408::2" || peer["active"] != float64(1) {
		t.Errorf("peer = %v, want the resolved address with one active connection", peer)
	}

	// The failure on the direct route is the answer to "which way is it going",
	// so it has to survive into the wire shape with the route that failed.
	routes, _ := directory["routes"].([]any)
	var sawDirectFailure bool
	for _, entry := range routes {
		route, _ := entry.(map[string]any)
		if route["name"] == "direct" && route["error"] != "" {
			sawDirectFailure = true
		}
	}
	if !sawDirectFailure {
		t.Errorf("routes = %v, want the direct route's failure reported", routes)
	}

	// Releasing the connection is what a reader watches to know a stream ended.
	release()
	recorder = httptest.NewRecorder()
	meshStatus(recorder, httptest.NewRequest("GET", "/mesh/status", nil))
	_ = json.Unmarshal(recorder.Body.Bytes(), &body)
	connections, _ = body["connections"].(map[string]any)
	if connections["open"] != float64(0) {
		t.Errorf("open connections = %v after release, want 0", connections["open"])
	}
}

type errStub struct{}

func (errStub) Error() string { return "unreachable" }
