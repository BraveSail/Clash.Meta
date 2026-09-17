package adapter

import (
	"sync"

	"github.com/metacubex/mihomo/adapter/outbound"
)

// One directory client per (url, token, id): a shared profile lists several
// peers of the same node, and each of them would otherwise report the same
// address separately.
var directoryClients = struct {
	sync.Mutex
	clients map[string]*sharedDirectoryClient
}{clients: map[string]*sharedDirectoryClient{}}

type sharedDirectoryClient struct {
	client *outbound.PeerDirectory
	refs   int
}

func acquireDirectoryClient(option outbound.PeerDirectoryOption) (*outbound.PeerDirectory, error) {
	key := option.URL + "\x00" + option.Token + "\x00" + option.ID + "\x00" + option.Name

	directoryClients.Lock()
	if existing, ok := directoryClients.clients[key]; ok {
		existing.refs++
		directoryClients.Unlock()
		return existing.client, nil
	}
	directoryClients.Unlock()

	client, err := outbound.NewPeerDirectory(option)
	if err != nil {
		return nil, err
	}
	directoryClients.Lock()
	directoryClients.clients[key] = &sharedDirectoryClient{client: client, refs: 1}
	directoryClients.Unlock()
	return client, nil
}

func releaseDirectoryClient(client *outbound.PeerDirectory) {
	directoryClients.Lock()
	defer directoryClients.Unlock()
	for key, entry := range directoryClients.clients {
		if entry.client != client {
			continue
		}
		entry.refs--
		if entry.refs <= 0 {
			delete(directoryClients.clients, key)
			_ = client.Close()
		}
		return
	}
}
