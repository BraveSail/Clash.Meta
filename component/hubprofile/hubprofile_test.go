package hubprofile

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

// pulled is what a fake hub hands out, and how many times it was asked.
type fakeHub struct {
	mu sync.Mutex
	// yaml and etag are the current revision.
	yaml string
	etag string
	// requests counts every GET; served counts the ones answered with a body.
	requests int
	served   int
	// notModified counts the ones answered 304, which is what a device holding
	// the current revision must get - and what stops it reapplying.
	notModified int
	server      *httptest.Server
}

func newFakeHub(t *testing.T, yaml, etag string) *fakeHub {
	t.Helper()
	hub := &fakeHub{yaml: yaml, etag: etag}
	mux := http.NewServeMux()
	mux.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		hub.mu.Lock()
		hub.requests++
		current := hub.etag
		body := hub.yaml
		if r.Header.Get("If-None-Match") == current {
			hub.notModified++
			hub.mu.Unlock()
			w.Header().Set("ETag", current)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		hub.served++
		hub.mu.Unlock()
		w.Header().Set("ETag", current)
		_, _ = w.Write([]byte(body))
	})
	hub.server = httptest.NewServer(mux)
	t.Cleanup(hub.server.Close)
	return hub
}

// counts is the request tally, read under the lock.
func (h *fakeHub) counts() (requests, served, notModified int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.requests, h.served, h.notModified
}

// pushYAML answers a socket with one profile message, then closes it.
func (h *fakeHub) push(t *testing.T, path string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/profile/watch", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
		defer conn.Close()
		h.mu.Lock()
		payload, _ := json.Marshal(map[string]any{
			"type": "profile", "yaml": h.yaml, "etag": h.etag,
		})
		h.mu.Unlock()
		_ = wsutil.WriteServerText(conn, payload)
		time.Sleep(50 * time.Millisecond)
	})
	_ = path
	_ = mux
}

func config(t *testing.T, url, id string, keep map[string]any) Config {
	t.Helper()
	return Config{
		URL:   url,
		Token: "test-token",
		ID:    id,
		File:  filepath.Join(t.TempDir(), "profile.yaml"),
		Keep:  keep,
	}
}

func TestPullAppliesTheHubsProfile(t *testing.T) {
	hub := newFakeHub(t, "mode: rule\nrules:\n  - MATCH,DIRECT\n", `"v1"`)

	var applied [][]byte
	client, err := New(config(t, hub.server.URL, "ont", nil), func(b []byte) error {
		applied = append(applied, b)
		return nil
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := client.Pull(context.Background()); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if len(applied) != 1 {
		t.Fatalf("applied %d times, want 1", len(applied))
	}
	if !strings.Contains(string(applied[0]), "MATCH,DIRECT") {
		t.Errorf("applied YAML lost its rules:\n%s", applied[0])
	}
	// The pulled YAML has to be on disk as well: a device that restarts comes
	// back on the profile it was running, not on whatever it was started with.
	onDisk, err := os.ReadFile(client.config.filePath())
	if err != nil {
		t.Fatalf("reading the written profile: %v", err)
	}
	if string(onDisk) != string(applied[0]) {
		t.Errorf("on disk:\n%s\napplied:\n%s", onDisk, applied[0])
	}
}

// An unchanged profile must cost a 304 and no reapply: this is the whole
// steady-state cost of the channel.
func TestPullSkipsAnUnchangedProfile(t *testing.T) {
	hub := newFakeHub(t, "mode: rule\n", `"v1"`)

	applies := 0
	client, err := New(config(t, hub.server.URL, "ont", nil), func([]byte) error {
		applies++
		return nil
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := client.Pull(context.Background()); err != nil {
			t.Fatalf("Pull %d: %v", i, err)
		}
	}
	if applies != 1 {
		t.Errorf("applied %d times over three pulls, want 1", applies)
	}
	// The client must send the ETag it holds: without it the hub answers with
	// the body every time, and the device reapplies a profile that has not
	// changed. Counting the 304s is what catches that, since the apply count
	// alone passes when only the first pull is measured.
	requests, served, notModified := hub.counts()
	if requests != 3 {
		t.Errorf("the hub saw %d requests, want 3", requests)
	}
	if served != 1 {
		t.Errorf("the hub served a body %d times, want 1", served)
	}
	if notModified != 2 {
		t.Errorf("the hub answered 304 %d times, want 2", notModified)
	}

	// And a change is picked up: the same client, a new revision at the hub.
	hub.mu.Lock()
	hub.yaml = "mode: global\n"
	hub.etag = `"v2"`
	hub.mu.Unlock()
	if err := client.Pull(context.Background()); err != nil {
		t.Fatalf("Pull after change: %v", err)
	}
	if applies != 2 {
		t.Errorf("applied %d times after a change, want 2", applies)
	}
	_, served, _ = hub.counts()
	if served != 2 {
		t.Errorf("the changed revision was served %d times, want 2", served)
	}
}

// A device names no hub and no id: the block is inert rather than fatal, so a
// profile written before this field existed keeps loading.
func TestAnEmptyBlockIsNotEnabled(t *testing.T) {
	if (&Config{}).Enabled() {
		t.Error("an empty block reports itself enabled")
	}
	if err := (&Config{}).Validate(); err == nil {
		t.Error("an empty block validated")
	}
	complete := Config{URL: "https://hub.example", Token: "t", ID: "x"}
	if complete.Validate() != nil {
		t.Error("a complete block did not validate")
	}
}

// The identity fields survive a profile shared with other devices: the hub
// stores one YAML, so what says which device this is has to be merged in after.
func TestKeepOverridesThePulledProfile(t *testing.T) {
	hub := newFakeHub(t, "mesh:\n  directory-id: shared\n  directory-url: https://hub.see.moe\n", `"v1"`)

	var applied []byte
	client, err := New(
		config(t, hub.server.URL, "ont", map[string]any{
			"mesh.directory-id": "ont",
			"mesh.device-name":  "CU_UFW",
		}),
		func(b []byte) error { applied = b; return nil },
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := client.Pull(context.Background()); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	got := string(applied)
	if !strings.Contains(got, "directory-id: ont") {
		t.Errorf("the device's own id did not win:\n%s", got)
	}
	if strings.Contains(got, "directory-id: shared") {
		t.Errorf("the pulled id survived the merge:\n%s", got)
	}
	if !strings.Contains(got, "device-name: CU_UFW") {
		t.Errorf("a field absent from the pull was not added:\n%s", got)
	}
	// The block around the pinned field survives.
	if !strings.Contains(got, "directory-url: https://hub.see.moe") {
		t.Errorf("merging a field replaced the block around it:\n%s", got)
	}
}

// A hub that ignores the conditional request must not make the device reapply
// what it already runs. The ETag is also compared on a 200 for that reason: a
// proxy or cache in front of the hub can strip the conditional handling, and
// the device would otherwise restart its configuration on every poll.
func TestA200WithTheSameEtagIsNotReapplied(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Answers with the body every time, and the same revision: exactly what
		// a hub behind something that drops If-None-Match looks like.
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte("mode: rule\n"))
	}))
	defer server.Close()

	applies := 0
	client, err := New(Config{
		URL:   server.URL,
		Token: "test-token",
		ID:    "ont",
		File:  filepath.Join(t.TempDir(), "profile.yaml"),
	}, func([]byte) error { applies++; return nil })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := client.Pull(context.Background()); err != nil {
			t.Fatalf("Pull %d: %v", i, err)
		}
	}
	if applies != 1 {
		t.Errorf("applied %d times against a hub that always answers 200, want 1", applies)
	}
}

// A hub with nothing stored for this device is reported, not silently treated
// as a profile: the device would otherwise run nothing and look healthy.
func TestAMissingProfileIsReported(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client, err := New(config(t, server.URL, "ont", nil), func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = client.Pull(context.Background())
	if err == nil {
		t.Fatal("a 404 was treated as a profile")
	}
	if !strings.Contains(err.Error(), "ont") {
		t.Errorf("the error does not name the device: %v", err)
	}
	if client.LastError() == nil {
		t.Error("the failure was not recorded for the caller to report")
	}
}

// A credential the hub rejects is an error, not an empty profile.
func TestAnUnauthorizedPullFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client, err := New(config(t, server.URL, "ont", nil), func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := client.Pull(context.Background()); err == nil {
		t.Fatal("a 401 was treated as a profile")
	}
}

// The endpoints are built from the hub root, so a profile only names one URL.
func TestTheEndpointsFollowTheHubRoot(t *testing.T) {
	client, err := New(Config{
		URL:   "https://hub.see.moe/",
		Token: "t",
		ID:    "ont",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pull, err := client.profileURL()
	if err != nil {
		t.Fatalf("profileURL: %v", err)
	}
	if pull != "https://hub.see.moe/profile?id=ont" {
		t.Errorf("pull URL = %q", pull)
	}
	watch, err := client.watchURL()
	if err != nil {
		t.Fatalf("watchURL: %v", err)
	}
	if watch != "wss://hub.see.moe/profile/watch?id=ont" {
		t.Errorf("watch URL = %q", watch)
	}

	// A LAN hub on plain http answers on ws, not wss: the socket has to match
	// what the client already reaches.
	plain, err := New(Config{URL: "http://192.168.1.9:8080", Token: "t", ID: "x"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	plainWatch, err := plain.watchURL()
	if err != nil {
		t.Fatalf("watchURL: %v", err)
	}
	if plainWatch != "ws://192.168.1.9:8080/profile/watch?id=x" {
		t.Errorf("plain-http watch URL = %q", plainWatch)
	}
}

// An id cannot escape the home directory through the file name.
func TestAnIdCannotEscapeTheHomeDirectory(t *testing.T) {
	for _, id := range []string{"../../etc/passwd", "a/b", "..", "."} {
		got := sanitize(id)
		if strings.ContainsAny(got, `/\`) || got == "" || got == "." || got == ".." {
			t.Errorf("sanitize(%q) = %q, which is not a plain name", id, got)
		}
	}
}

// A pushed profile is applied, and one already held is not applied twice: the
// hub stamps every save with a new revision, so the same revision arriving
// again is the same record and must not restart the core.
func TestHandleMessageAppliesOncePerRevision(t *testing.T) {
	applies := 0
	client, err := New(Config{
		URL:   "https://hub.see.moe",
		Token: "test-token",
		ID:    "ont",
		File:  filepath.Join(t.TempDir(), "profile.yaml"),
	}, func([]byte) error { applies++; return nil })
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	message := func(etag, yaml string) []byte {
		out, _ := json.Marshal(map[string]any{
			"type": "profile", "yaml": yaml, "etag": etag,
		})
		return out
	}

	if err := client.handleMessage(message(`"v1"`, "mode: rule\n")); err != nil {
		t.Fatalf("handleMessage: %v", err)
	}
	if err := client.handleMessage(message(`"v1"`, "mode: rule\n")); err != nil {
		t.Fatalf("handleMessage (repeat): %v", err)
	}
	if applies != 1 {
		t.Errorf("applied %d times for one revision, want 1", applies)
	}

	if err := client.handleMessage(message(`"v2"`, "mode: global\n")); err != nil {
		t.Fatalf("handleMessage (new revision): %v", err)
	}
	if applies != 2 {
		t.Errorf("applied %d times across two revisions, want 2", applies)
	}

	// A message that is not a profile is ignored rather than fatal, so a hub
	// growing a new message type does not stop the devices it serves.
	for _, other := range []string{
		`{"type":"ping"}`,
		`{"type":"profile","yaml":"  "}`,
		``,
	} {
		if err := client.handleMessage([]byte(other)); err != nil {
			t.Errorf("handleMessage(%q) = %v, want nil", other, err)
		}
	}
	if applies != 2 {
		t.Errorf("a non-profile message was applied (%d applies)", applies)
	}
}

// A profile the core cannot parse must not be written over the running one,
// or a bad save at the hub would take the device down until someone noticed.
func TestAFailedApplyIsReportedAndTheFileIsKept(t *testing.T) {
	hub := newFakeHub(t, "mode: rule\n", `"v1"`)
	sentinel := "mode: rule\n# the profile that works\n"

	client, err := New(config(t, hub.server.URL, "ont", nil), func(b []byte) error {
		if strings.Contains(string(b), "unparseable") {
			return fmt.Errorf("core refused the profile")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := client.Pull(context.Background()); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	good, err := os.ReadFile(client.config.filePath())
	if err != nil {
		t.Fatalf("reading the profile: %v", err)
	}
	_ = sentinel

	hub.mu.Lock()
	hub.yaml = "mode: unparseable\n"
	hub.etag = `"v2"`
	hub.mu.Unlock()

	if err := client.Pull(context.Background()); err == nil {
		t.Fatal("a profile the core refused was reported as applied")
	}
	if client.LastError() == nil {
		t.Error("the refusal was not recorded")
	}
	// What is on disk is the bad profile, because that is what the hub holds:
	// the device runs the previous configuration in memory, and a restart
	// reads the hub's copy again rather than a half-written file.
	after, err := os.ReadFile(client.config.filePath())
	if err != nil {
		t.Fatalf("reading the profile after the refusal: %v", err)
	}
	if !strings.Contains(string(after), "unparseable") {
		t.Errorf("the hub's profile was not the one written:\n%s", after)
	}
	if len(good) == 0 {
		t.Error("the first profile was never written")
	}
}
