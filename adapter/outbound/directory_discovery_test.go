package outbound

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newDeviceListStub answers /api/devices the way the hub does: a bearer token
// and one JSON object holding every device record.
func newDeviceListStub(t *testing.T, body string, status int) (*httptest.Server, *int) {
	t.Helper()
	requests := new(int)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		*requests++
		if request.URL.Path != "/api/devices" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		if request.Header.Get("authorization") != "Bearer secret" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writer.Header().Set("content-type", "application/json")
		writer.WriteHeader(status)
		_, _ = writer.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server, requests
}

var deviceListBody = `{
  "now": 1774000000000,
  "ttlSeconds": 604800,
  "onlineWindowSeconds": 300,
  "nodes": [
    {"id":"a1b2c3d4e5f6","addr":"2409:8a55::1","port":8443,"updatedAt":1774000000000,"etag":"\"x\"","platform":"windows","hostname":"DESKTOP-X","alias":"PC"},
    {"id":"0f1e2d3c4b5a","addr":"2409:895a::2","port":9443,"updatedAt":1774000000000,"etag":"\"y\"","platform":"android","hostname":"Pixel-8"},
    {"id":"9876543210ab","addr":"2409:8000::3","updatedAt":1774000000000,"etag":"\"z\""}
  ]
}`

func TestFetchDirectoryNodesReadsTheDeviceList(t *testing.T) {
	server, requests := newDeviceListStub(t, deviceListBody, http.StatusOK)

	nodes, err := FetchDirectoryNodes(context.Background(), server.URL, "secret", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if *requests != 1 {
		t.Fatalf("the directory was asked %d times, want one request", *requests)
	}
	if len(nodes) != 3 {
		t.Fatalf("read %d nodes, want every record the directory holds", len(nodes))
	}
	// The name is the one the device answers to: the alias if it has one, else
	// the host name it reported, else the id.
	if nodes[0].ID != "a1b2c3d4e5f6" || nodes[0].Name != "PC" || nodes[0].Addr != "2409:8a55::1" || nodes[0].Port != 8443 {
		t.Fatalf("first node = %+v", nodes[0])
	}
	if nodes[1].Name != "Pixel-8" || nodes[1].Port != 9443 {
		t.Fatalf("second node = %+v, want the host name and its own port", nodes[1])
	}
	if nodes[2].Name != "9876543210ab" {
		t.Fatalf("third node = %+v, want the id as its name", nodes[2])
	}
}

// A record the directory holds but cannot be asked about is not a peer: the id
// is what a lookup names, and a mesh has to expand from something.
func TestFetchDirectoryNodesSkipsRecordsWithoutAnID(t *testing.T) {
	server, _ := newDeviceListStub(t, `{"nodes":[{"addr":"2409:8a55::1","port":8443},{"id":"keep","addr":"2409:8a55::2"}]}`, http.StatusOK)

	nodes, err := FetchDirectoryNodes(context.Background(), server.URL, "secret", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].ID != "keep" {
		t.Fatalf("nodes = %+v, want only the record carrying an id", nodes)
	}
}

func TestFetchDirectoryNodesRejectsAnUnreadableDirectory(t *testing.T) {
	unauthorized, _ := newDeviceListStub(t, `{"error":"unauthorized"}`, http.StatusUnauthorized)
	if _, err := FetchDirectoryNodes(context.Background(), unauthorized.URL, "secret", 5*time.Second); err == nil {
		t.Fatal("an unauthorized device list was accepted")
	}

	unreadable, _ := newDeviceListStub(t, `not json`, http.StatusOK)
	if _, err := FetchDirectoryNodes(context.Background(), unreadable.URL, "secret", 5*time.Second); err == nil {
		t.Fatal("an unreadable device list was accepted")
	}

	if _, err := FetchDirectoryNodes(context.Background(), "not-a-url", "secret", 5*time.Second); err == nil {
		t.Fatal("an invalid directory url was accepted")
	}
}

// The list is read from a mesh as well as by hand, and a directory named
// without a path answers under the same one.
func TestFetchDirectoryNodesKeepsTheDirectoryPath(t *testing.T) {
	requests := new(int)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		*requests++
		if request.URL.Path != "/hub/api/devices" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = writer.Write([]byte(`{"nodes":[]}`))
	}))
	t.Cleanup(server.Close)

	nodes, err := FetchDirectoryNodes(context.Background(), server.URL+"/hub/", "", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if *requests != 1 || len(nodes) != 0 {
		t.Fatalf("requests = %d, nodes = %+v", *requests, nodes)
	}
}
