package constant

var (
	Meta       = true
	Version    = "1.10.0"
	BuildTime  = "unknown time"
	Revision   = "unknown"
	MihomoName = "mihomo"
	// HubURL is the hub this build belongs to, set at link time:
	//
	//	-X github.com/metacubex/mihomo/constant.HubURL=https://hub.example
	//
	// A build that carries one takes its configuration from that hub without
	// being told, so the program around it - an app, a launcher, a shell script
	// - does not have to know the mesh exists at all.
	HubURL = ""
)
