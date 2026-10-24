package outbound

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"testing"

	meshident "github.com/metacubex/mihomo/component/mesh"
)

// The headers a tokenless directory request carries are the ones the hub
// verifies: this signs with the same key and checks the bytes the way the hub's
// Python does, so a drift on either side fails here.
func TestAuthorizeSignsForADeviceWithoutAToken(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	directory := &PeerDirectory{
		option:      PeerDirectoryOption{ID: "pc"},
		signingSeed: seed,
	}
	body := []byte(`{"id":"pc"}`)
	request, err := http.NewRequest(http.MethodPost, "https://hub.example/report", nil)
	if err != nil {
		t.Fatal(err)
	}
	directory.authorize(request, body)

	if got := request.Header.Get(meshident.IDHeader); got != "pc" {
		t.Fatalf("id header = %q", got)
	}
	signature, err := base64.RawURLEncoding.DecodeString(request.Header.Get(meshident.SignatureHeader))
	if err != nil {
		t.Fatal(err)
	}
	canonical := meshident.CanonicalRequest(request.Method, request.URL.Path, body,
		request.Header.Get(meshident.TimestampHeader), "pc")
	public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if !ed25519.Verify(public, canonical, signature) {
		t.Fatal("the directory would refuse this request")
	}
	// The id is inside the signature: a request cannot be relabelled.
	other := meshident.CanonicalRequest(request.Method, request.URL.Path, body,
		request.Header.Get(meshident.TimestampHeader), "someone-else")
	if ed25519.Verify(public, other, signature) {
		t.Fatal("a signature verified for an id it was not made for")
	}
}

// A device with a token keeps using it: the old way still works, and no key is
// consulted for it.
func TestAConfiguredTokenStillAuthorizes(t *testing.T) {
	directory := &PeerDirectory{option: PeerDirectoryOption{ID: "pc", Token: "secret"}}
	request, _ := http.NewRequest(http.MethodPost, "https://hub.example/report", nil)
	directory.authorize(request, []byte(`{"id":"pc"}`))
	if got := request.Header.Get("authorization"); got != "Bearer secret" {
		t.Fatalf("authorization = %q", got)
	}
	if request.Header.Get(meshident.SignatureHeader) != "" {
		t.Fatal("a token device signed as well")
	}
}
