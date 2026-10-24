package mesh

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"
)

// The bytes are the contract between this core and the hub: the hub verifies
// with a Python implementation, so a difference in any field - a separator, the
// digest encoding, the order - would make every request look forged. These
// values were produced by that implementation from the same inputs, so this
// test fails the moment the two drift apart.
func TestASignatureMatchesWhatTheHubVerifies(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	body := []byte(`{"id":"pc"}`)
	headers := SignRequest(seed, "POST", "/report", body, "pc", time.Unix(1700000000, 0))

	if want := "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"; PublicKeyBase64(seed) != want {
		t.Fatalf("public key = %s, want %s", PublicKeyBase64(seed), want)
	}
	signature, err := base64.RawURLEncoding.DecodeString(headers[SignatureHeader])
	if err != nil {
		t.Fatal(err)
	}
	// The hub's implementation produced these bytes for the same inputs.
	if want := "4adf6cadbe80f492d6d9f78e0f7572a5cc936b2698761475e536bb812eddcf29949c29b160c382d13101088de84974f7dcdc52e665e09bae457d4cfba88c460d"; hex.EncodeToString(signature) != want {
		t.Fatalf("signature = %s", hex.EncodeToString(signature))
	}
	if got := headers[TimestampHeader]; got != "1700000000" {
		t.Fatalf("timestamp = %s", got)
	}
	if got := headers[IDHeader]; got != "pc" {
		t.Fatalf("id = %s", got)
	}
}

// And it is a signature, not just a formatted string: it verifies against the
// key, and a changed body does not.
func TestTheSignatureCoversTheBody(t *testing.T) {
	seed := make([]byte, 32)
	body := []byte(`{"id":"pc"}`)
	now := time.Unix(1700000000, 0)
	headers := SignRequest(seed, "POST", "/report", body, "pc", now)

	signature, err := base64.RawURLEncoding.DecodeString(headers[SignatureHeader])
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if !ed25519.Verify(key, CanonicalRequest("POST", "/report", body, headers[TimestampHeader], "pc"), signature) {
		t.Fatal("the signature does not verify")
	}
	if ed25519.Verify(key, CanonicalRequest("POST", "/report", []byte(`{"id":"other"}`), headers[TimestampHeader], "pc"), signature) {
		t.Fatal("a signature verified over a body it was not made for")
	}
}
