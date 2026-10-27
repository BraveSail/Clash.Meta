package outbound

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/log"
)

// The directory answers where a peer is, and a dial must never wait on it: a
// directory that is slow or unreachable would otherwise stall every connection
// that names a device, which is exactly what a mesh must not do. Two layers
// keep that from happening:
//
//   - an in-memory answer, held for peerDirectoryLookupTTL, so a burst and a
//     stream of new connections share one lookup;
//   - a persisted answer, written whenever a lookup succeeds and read back
//     when the process starts, so a node that restarts (or a directory that is
//     down) still knows where its peers were.
//
// The persisted entry is only a fallback: a fresh in-memory answer always wins,
// and an entry that a lookup refreshes is written again. A peer that moves while
// the directory is unreachable keeps its old address for this window, which is
// the same trade the in-memory cache already makes.

// peerCacheStoragePrefix namespaces this directory's persisted answers inside
// the cache file, and every key it writes is built from it. The directory
// address is part of it because one node may talk to two directories and two
// profiles share one cache file on a machine; the peer id is appended to it, so
// the answers of another directory cannot be read as this one's.
func (d *PeerDirectory) peerCacheStoragePrefix() string {
	return "peer-directory/" + cacheKeyDigest(d.option.URL) + "/"
}

// cacheKeyDigest shortens an arbitrary URL into something a bucket key can
// carry. A directory address may be long and contain characters a key should
// not, so it is hashed rather than embedded.
func cacheKeyDigest(raw string) string {
	sum := make([]byte, 0, 16)
	for _, b := range []byte(strings.TrimSpace(raw)) {
		sum = append(sum, b)
	}
	// FNV-1a over the trimmed address: short, stable, and no dependency.
	var h uint64 = 14695981039346656037
	for _, b := range sum {
		h ^= uint64(b)
		h *= 1099511628211
	}
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, 16)
	for i := 60; i >= 0; i -= 4 {
		out = append(out, hexDigits[(h>>uint(i))&0xf])
	}
	return string(out)
}

// persistedPeer is what one peer's answer looks like on disk.
type persistedPeer struct {
	Addr string `json:"addr"`
	Port int    `json:"port"`
	At   int64  `json:"at"` // unix seconds, for the log line and the staleness report
}

// loadPersistedPeers reads every answer this directory has written before, so
// the first dial after a restart does not have to wait for a lookup. A missing
// or unreadable cache is not an error: the directory is asked instead.
func (d *PeerDirectory) loadPersistedPeers() {
	cache := cachefile.Cache()
	if cache == nil {
		return
	}
	prefix := d.peerCacheStoragePrefix()
	loaded := 0
	for _, id := range d.persistedPeerIDs(cache, prefix) {
		raw := cache.GetStorage(prefix + id)
		if len(raw) == 0 {
			continue
		}
		var entry persistedPeer
		if err := json.Unmarshal(raw, &entry); err != nil || entry.Addr == "" {
			continue
		}
		// at is deliberately old: this is a fallback, and a lookup that
		// succeeds replaces it. It is not treated as fresh, so the normal
		// TTL still decides when the directory is asked again.
		d.mu.Lock()
		if _, exists := d.peers[id]; !exists {
			d.peers[id] = cachedPeer{
				addr: entry.Addr,
				port: entry.Port,
				self: false,
				at:   time.Unix(entry.At, 0),
			}
			loaded++
		}
		d.mu.Unlock()
	}
	if loaded > 0 {
		log.Infoln("[PeerDirectory](%s) restored %d peer address(es) from the cache", d.Name(), loaded)
	}
}

// persistedPeerIDs lists the ids this directory has written. bbolt has no key
// prefix scan on this interface, so the ids are tracked in a side entry: the
// set is small (one mesh's devices) and rewriting it is cheap.
func (d *PeerDirectory) persistedPeerIDs(cache *cachefile.CacheFile, prefix string) []string {
	raw := cache.GetStorage(prefix + "index")
	if len(raw) == 0 {
		return nil
	}
	var ids []string
	if err := json.Unmarshal(raw, &ids); err != nil {
		return nil
	}
	return ids
}

// storePersistedPeer writes one answer so it survives a restart. A failure to
// write is logged and ignored: the directory is still the source of truth and
// the in-memory answer is already in hand.
func (d *PeerDirectory) storePersistedPeer(id, addr string, port int) {
	cache := cachefile.Cache()
	if cache == nil || addr == "" {
		return
	}
	prefix := d.peerCacheStoragePrefix()
	entry, err := json.Marshal(persistedPeer{Addr: addr, Port: port, At: time.Now().Unix()})
	if err != nil {
		return
	}
	cache.SetStorage(prefix+id, entry)
	d.addPersistedPeerID(cache, prefix, id)
}

// addPersistedPeerID keeps the index in step with the answers written.
func (d *PeerDirectory) addPersistedPeerID(cache *cachefile.CacheFile, prefix, id string) {
	ids := d.persistedPeerIDs(cache, prefix)
	for _, existing := range ids {
		if existing == id {
			return
		}
	}
	ids = append(ids, id)
	if raw, err := json.Marshal(ids); err == nil {
		cache.SetStorage(prefix+"index", raw)
	}
}

// forgetPersistedPeer drops an answer the directory has declared unknown or
// expired, so a restart does not resurrect an address nobody serves.
func (d *PeerDirectory) forgetPersistedPeer(id string) {
	cache := cachefile.Cache()
	if cache == nil {
		return
	}
	prefix := d.peerCacheStoragePrefix()
	cache.DeleteStorage(prefix + id)
}

// stalePeerTTL bounds how old a persisted answer may be and still be used when
// the directory cannot be reached. Past this the answer is more likely wrong
// than useful: a device that moved networks has had time to move again.
const stalePeerTTL = 24 * time.Hour

// usableStalePeer reports whether a persisted entry may answer a dial while the
// directory is unreachable.
func usableStalePeer(at time.Time) bool {
	if at.IsZero() {
		return false
	}
	return time.Since(at) < stalePeerTTL
}
