package main

import (
	"context"
	"os"

	"github.com/metacubex/mihomo/common/yaml"

	"github.com/metacubex/mihomo/component/hubprofile"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/log"
)

// startHubProfile puts the hub channel into service when the configuration
// that was just loaded asks for one, and returns how to stop it.
//
// The YAML it receives is parsed and switched in through the executor, the
// same way any other configuration change is, so a pushed profile takes effect
// exactly as the app's own updates do.
func startHubProfile() func() {
	block := hubBlockFromConfig()
	if !block.Enabled() {
		return func() {}
	}
	if err := block.Validate(); err != nil {
		log.Warnln("[Profile] the hub block is incomplete, staying on the file: %s", err.Error())
		return func() {}
	}

	ctx, cancel := context.WithCancel(context.Background())
	client, err := hubprofile.New(*block, func(pulled []byte) error {
		// ParseWithMeshDiscovery, not hub.Parse: the pulled YAML is a whole
		// configuration, and hub.Parse would read it from the file this one is
		// being written beside. It reads the peer directory first, before the
		// parse: the parse runs on the apply path, and a request made there
		// holds the switch to the new configuration up - and every connection
		// the old one held with it - for as long as the directory takes to
		// answer. A profile the hub stores carries no resolved device list, so
		// this is the only place that request can be made from.
		parsed, err := config.ParseWithMeshDiscovery(ctx, pulled)
		if err != nil {
			return err
		}
		hub.ApplyConfig(parsed)
		return nil
	})
	if err != nil {
		log.Warnln("[Profile] %s", err.Error())
		cancel()
		return func() {}
	}
	log.Infoln("[Profile] this device takes its configuration from %s as %q", block.URL, block.ID)
	client.Start(ctx)
	return cancel
}

// hubBlockFromConfig reads the hub block out of the configuration the core was
// started with - from the bytes when they were given inline, and from the file
// otherwise.
//
// It is read from the raw configuration rather than the parsed one: the parsed
// configuration keeps only what the core runs, and this block describes how the
// core is to be kept up to date, which is not part of that.
func hubBlockFromConfig() *hubprofile.Config {
	if len(configBytes) != 0 {
		var raw config.RawConfig
		if err := yaml.Unmarshal(configBytes, &raw); err != nil {
			log.Debugln("[Profile] the configuration could not be read for a hub block: %s", err.Error())
			return nil
		}
		if raw.Hub != nil && raw.Hub.URL != "" {
			return raw.Hub
		}
		return builtInHub()
	}
	buf, err := os.ReadFile(C.Path.Config())
	if err != nil {
		log.Debugln("[Profile] the configuration file could not be read for a hub block: %s", err.Error())
		return nil
	}
	var raw config.RawConfig
	if err := yaml.Unmarshal(buf, &raw); err != nil {
		log.Debugln("[Profile] the configuration file could not be read for a hub block: %s", err.Error())
		return nil
	}
	if raw.Hub != nil && raw.Hub.URL != "" {
		return raw.Hub
	}
	return builtInHub()
}
