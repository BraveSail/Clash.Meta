package mesh

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"time"
)

// Headers the directory reads a signed request from. The names are the
// contract between this core and the hub; a change here would be a change
// there, so they are pinned in a test that signs and checks the bytes.
const (
	IDHeader        = "x-mesh-id"
	SignatureHeader = "x-mesh-signature"
	TimestampHeader = "x-mesh-timestamp"
)

// CanonicalRequest is what a device signs: method, path, timestamp, the body's
// digest and the id, one per line.
//
// The digest rather than the body keeps the signed bytes small for a profile
// request; the timestamp bounds a replay; the id is inside the signature so a
// request signed by one device cannot be relabelled as another's.
func CanonicalRequest(method, path string, body []byte, timestamp, deviceID string) []byte {
	digest := sha256.Sum256(body)
	lines := []string{method, path, timestamp, hex.EncodeToString(digest[:]), deviceID}
	joined := ""
	for i, line := range lines {
		if i > 0 {
			joined += "\n"
		}
		joined += line
	}
	return []byte(joined)
}

// SignRequest answers the headers that prove this device sent this request.
func SignRequest(seed []byte, method, path string, body []byte, deviceID string, now time.Time) map[string]string {
	timestamp := strconv.FormatInt(now.Unix(), 10)
	signature := ed25519.Sign(ed25519.NewKeyFromSeed(seed), CanonicalRequest(method, path, body, timestamp, deviceID))
	return map[string]string{
		IDHeader:        deviceID,
		TimestampHeader: timestamp,
		SignatureHeader: base64.RawURLEncoding.EncodeToString(signature),
	}
}

// PublicKeyBase64 is what a device registers: the public half of its signing
// seed, in the same encoding the hub hands back to a verifier.
func PublicKeyBase64(seed []byte) string {
	public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	return base64.RawURLEncoding.EncodeToString(public)
}
