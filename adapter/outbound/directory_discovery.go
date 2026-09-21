package outbound

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DirectoryNode is one device the peer directory holds: the id it reports
// under, the name it is shown by, and where its service was last seen.
type DirectoryNode struct {
	ID string
	// Name is what the device is called: the alias someone set for it on the
	// dashboard, else the host name it reported, else its id.
	Name string
	Addr string
	Port int
}

// FetchDirectoryNodes asks the directory for every device it holds. A mesh is
// one profile running on every device, so nothing in the profile lists them:
// the list is read from the directory while the configuration is parsed.
//
// The request leaves the machine the way every other directory request does -
// see the dialer in peer_directory.go - so it cannot end up inside this node's
// own tunnel while it is asking which nodes exist.
func FetchDirectoryNodes(ctx context.Context, rawURL, token string, timeout time.Duration) ([]DirectoryNode, error) {
	if timeout <= 0 {
		timeout = peerDirectoryDefaultTimeout
	}
	target, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" {
		return nil, fmt.Errorf("peer-directory: invalid url %q", rawURL)
	}
	target.Path = strings.TrimSuffix(target.Path, "/") + "/api/devices"

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		request.Header.Set("authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: timeout, Transport: directoryTransport()}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("directory answered %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload struct {
		Nodes []struct {
			ID       string `json:"id"`
			Addr     string `json:"addr"`
			Port     int    `json:"port"`
			Hostname string `json:"hostname"`
			Alias    string `json:"alias"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("directory device list is not readable: %w", err)
	}
	nodes := make([]DirectoryNode, 0, len(payload.Nodes))
	for _, node := range payload.Nodes {
		id := strings.TrimSpace(node.ID)
		if id == "" {
			// An entry with no id is one no client can ask about.
			continue
		}
		nodes = append(nodes, DirectoryNode{
			ID:   id,
			Name: directoryNodeName(node.Alias, node.Hostname, id),
			Addr: strings.TrimSpace(node.Addr),
			Port: node.Port,
		})
	}
	return nodes, nil
}

// directoryNodeName is the name a device answers to: what someone chose to call
// it, else what the machine calls itself, else the id it reports under - the
// same order the directory resolves a lookup in.
func directoryNodeName(alias, hostname, id string) string {
	for _, candidate := range []string{alias, hostname} {
		if name := strings.TrimSpace(candidate); name != "" {
			return name
		}
	}
	return id
}
