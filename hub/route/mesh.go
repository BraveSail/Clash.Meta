package route

import (
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/component/mesh"

	"github.com/metacubex/chi/render"
)

// meshStatus answers what this node's mesh is doing right now, in one read.
//
// The mesh had no runtime identity before this: a `mesh:` block expanded into
// several outbounds, a listener and a directory client that found each other
// through a process-wide map, so "why did that session drop?" meant asking all
// of them and comparing three log formats. This endpoint is the answer to that
// question, and every field in it is the value or timestamp of a real event.
//
// A node whose profile has no mesh block answers with `enabled: false` rather
// than an error: that is a normal configuration, not a fault.
func meshStatus(w http.ResponseWriter, r *http.Request) {
	registry := mesh.Running()
	if registry == nil {
		render.JSON(w, r, map[string]any{
			"enabled": false,
			"reason":  "no mesh is running on this node",
		})
		return
	}
	render.JSON(w, r, meshStatusBody(registry.Status()))
}

// meshStatusBody is the wire shape, kept beside the handler so the two cannot
// drift: a field the registry grows is added here deliberately rather than
// appearing because the struct was serialized whole.
func meshStatusBody(status mesh.Status) map[string]any {
	routes := make([]map[string]any, 0, len(status.Directory.Routes))
	for _, route := range status.Directory.Routes {
		routes = append(routes, map[string]any{
			"name":     route.Name,
			"lastOk":   stamp(route.LastOK),
			"error":    route.LastError,
			"attempts": route.Attempts,
			"failures": route.Failures,
		})
	}

	peers := make(map[string]any, len(status.Directory.Peers))
	for name, peer := range status.Directory.Peers {
		peers[name] = map[string]any{
			"address":      peer.Addr,
			"port":         peer.Port,
			"self":         peer.Self,
			"source":       peer.Source,
			"lastResolved": stamp(peer.LastResolved),
			"error":        peer.LastError,
			"active":       peer.Active,
		}
	}

	return map[string]any{
		"enabled": true,
		"id":      status.ID,
		"address": status.Address,
		"port":    status.Port,
		"since":   stamp(status.Since),
		"directory": map[string]any{
			"url":      status.Directory.URL,
			"route":    status.Directory.Route,
			"routes":   routes,
			"address":  status.Directory.Address,
			"reported": stamp(status.Directory.Reported),
			"error":    status.Directory.LastError,
			"peers":    peers,
		},
		"channel": map[string]any{
			"route":     status.Channel.Route,
			"etag":      status.Channel.ETag,
			"lastApply": stamp(status.Channel.LastApply),
			"applies":   status.Channel.Applies,
			"error":     status.Channel.LastError,
		},
		"connections": map[string]any{
			"open": status.Open,
		},
	}
}

// stamp renders a time for the wire, and renders the zero time as empty rather
// than as a date: "never happened" and "happened at the epoch" are different
// answers, and a client should be able to tell them apart.
func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}
