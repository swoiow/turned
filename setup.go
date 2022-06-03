package turned

import (
	"fmt"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() { plugin.Register(pluginName, setup) }

func setup(c *caddy.Controller) error {
	log.Infof("Initializing, %s: v%s", pluginName, pluginVer)

	nodes, err := parseTurned(c)
	if err != nil {
		return plugin.Error(pluginName, err)
	}

	for _, f := range nodes {
		if f.Len() > max {
			return plugin.Error(pluginName, fmt.Errorf("more than %d TOs configured: %d", max, f.Len()))
		}
	}

	app := Turned{Nodes: nodes}
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		app.Next = next
		return &app
	})

	c.OnStartup(func() error {
		return app.OnStartup()
	})

	c.OnShutdown(func() error {
		return app.OnShutdown()
	})

	return nil
}

// OnStartup starts a goroutines for all proxies.
func (app *Turned) OnStartup() (err error) {
	for _, f := range app.Nodes {
		for _, p := range f.proxies {
			p.start(f.hcInterval)
		}
	}
	return nil
}

// OnShutdown stops all configured proxies.
func (app *Turned) OnShutdown() error {
	for _, f := range app.Nodes {
		for _, p := range f.proxies {
			p.stop()
		}
	}
	return nil
}
