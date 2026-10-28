package mesh

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/vless/encryption"
)

// EncryptionPrefix is the VLESS encryption scheme the mesh speaks. It lives
// here so a device's own keys and a token-derived pair produce values the same
// transport accepts.
const EncryptionPrefix = "mlkem768x25519plus.native"

// ClientHandshake is the VLESS encryption handshake a mesh client performs
// before it has anything to send.
//
// It is 1-RTT on purpose. Under 0-RTT a client's first flight carries payload,
// so a client with nothing to say yet - a proxy asking a peer for a service that
// greets first - never opens the stream in a way the peer can answer: the
// listener accepts, dials, and the greeting has nowhere to go. A round trip is
// cheaper than a stream that opens and stays silent.
const ClientHandshake = "1rtt"

// ClientEncryption is the value a peer dialling this device must use: the public
// key under the scheme and handshake both halves agree on.
func ClientEncryption(password string) string {
	return EncryptionPrefix + "." + ClientHandshake + "." + password
}

// keyFileName is where this device's key material lives - in the core's own
// home, never in a profile and never in the app: one profile runs on every
// device of the mesh, and a key written into it would be everyone's key.
const keyFileName = "mesh-key.json"

// storedKeys is the on-disk shape: two seeds, nothing derived. Everything else
// is computed on load, so a future derivation change does not invalidate a key
// that a device has already been approved under.
type storedKeys struct {
	Transport string `json:"transport"`
	Signing   string `json:"signing"`
}

// DeviceKeys is what this device uses: a UUID and an encryption pair for the
// transport, and a signing seed for the directory.
type DeviceKeys struct {
	// UUID is the VLESS user this device listens as. It is public: it names a
	// user, it does not authenticate one.
	UUID string
	// Decryption is what the listener presents, Encryption what a peer dialling
	// this device must use. The second is public; the first never leaves.
	Decryption string
	Encryption string
	// Signing is the Ed25519 seed the directory's requests are signed with.
	Signing []byte
}

// LoadOrCreateKeys answers this device's key material, creating it on first
// use. An empty dir means the core's home directory.
//
// A device that cannot write its key fails rather than generating a throwaway
// one: a key that changes every start would look like a new device to the
// directory on every restart, which is exactly the identity churn this whole
// design exists to avoid.
func LoadOrCreateKeys(dir string) (DeviceKeys, error) {
	if dir == "" {
		dir = constant.Path.HomeDir()
	}
	path := filepath.Join(dir, keyFileName)
	if data, err := os.ReadFile(path); err == nil {
		var stored storedKeys
		if err := json.Unmarshal(data, &stored); err != nil {
			return DeviceKeys{}, fmt.Errorf("mesh: cannot read the device key %s: %w", path, err)
		}
		return deriveKeys(stored)
	} else if !os.IsNotExist(err) {
		return DeviceKeys{}, fmt.Errorf("mesh: cannot read the device key %s: %w", path, err)
	}

	transport := make([]byte, 32)
	signing := make([]byte, 32)
	if _, err := rand.Read(transport); err != nil {
		return DeviceKeys{}, fmt.Errorf("mesh: cannot generate the device key: %w", err)
	}
	if _, err := rand.Read(signing); err != nil {
		return DeviceKeys{}, fmt.Errorf("mesh: cannot generate the device key: %w", err)
	}
	stored := storedKeys{
		Transport: base64.RawURLEncoding.EncodeToString(transport),
		Signing:   base64.RawURLEncoding.EncodeToString(signing),
	}
	body, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return DeviceKeys{}, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return DeviceKeys{}, fmt.Errorf("mesh: cannot create %s: %w", dir, err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return DeviceKeys{}, fmt.Errorf("mesh: cannot write the device key %s: %w", path, err)
	}
	return deriveKeys(stored)
}

func deriveKeys(stored storedKeys) (DeviceKeys, error) {
	signing, err := base64.RawURLEncoding.DecodeString(stored.Signing)
	if err != nil || len(signing) == 0 {
		return DeviceKeys{}, fmt.Errorf("mesh: the stored signing key is not valid base64")
	}
	privateKey, password, _, err := encryption.GenX25519(stored.Transport)
	if err != nil {
		return DeviceKeys{}, fmt.Errorf("mesh: cannot derive the transport key: %w", err)
	}
	return DeviceKeys{
		UUID:       deviceUUID(password),
		Decryption: EncryptionPrefix + ".600s." + privateKey,
		Encryption: ClientEncryption(password),
		Signing:    signing,
	}, nil
}

// deviceUUID is the VLESS user name for a public key: a hash of it, formatted
// like every other user so a profile reads normally. Public by construction -
// the key, not this label, is what the transport authenticates.
func deviceUUID(publicKey string) string {
	sum := sha256.Sum256([]byte("mesh-device:" + publicKey))
	return fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}
