package turned

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/parse"
	pkgtls "github.com/coredns/coredns/plugin/pkg/tls"
	"github.com/coredns/coredns/plugin/pkg/transport"
	utils "github.com/swoiow/blocked"
	"github.com/swoiow/blocked/parsers"
)

func parseTurned(c *caddy.Controller) ([]*Forward, error) {
	var (
		f   *Forward
		err error
		// i   int
		bucket []*Forward
	)
	for c.Next() {
		f, err = parseForward(c)
		if err != nil {
			return nil, err
		}

		bucket = append(bucket, f)
	}
	return bucket, nil
}

func parseForward(c *caddy.Controller) (*Forward, error) {
	f := New()

	if !c.Args(&f.groupName) {
		return f, c.ArgErr()
	}
	origFrom := f.groupName

	zones := plugin.Host(f.groupName).NormalizeExact()
	// f.groupName = zones[0] // there can only be one here, won't work with non-octet reverse

	if len(zones) > 1 {
		log.Warningf("Unsupported CIDR notation: '%s' expands to multiple zones. Using only '%s'.", origFrom, f.groupName)
	}

	for c.NextBlock() {
		if err := parseBlock(c, f); err != nil {
			return f, err
		}
	}

	return f, nil
}

func parseBlock(c *caddy.Controller, f *Forward) error {
	switch c.Val() {

	case "except":
		ignore := c.RemainingArgs()
		if len(ignore) == 0 {
			return c.ArgErr()
		}
		for i := 0; i < len(ignore); i++ {
			f.ignored = append(f.ignored, plugin.Host(ignore[i]).NormalizeExact()...)
		}
	case "max_fails":
		if !c.NextArg() {
			return c.ArgErr()
		}
		n, err := strconv.Atoi(c.Val())
		if err != nil {
			return err
		}
		if n < 0 {
			return fmt.Errorf("max_fails can't be negative: %d", n)
		}
		f.maxfails = uint32(n)
	case "health_check":
		if !c.NextArg() {
			return c.ArgErr()
		}
		dur, err := time.ParseDuration(c.Val())
		if err != nil {
			return err
		}
		if dur < 0 {
			return fmt.Errorf("health_check can't be negative: %d", dur)
		}
		f.hcInterval = dur

		for c.NextArg() {
			switch hcOpts := c.Val(); hcOpts {
			case "no_rec":
				f.opts.hcRecursionDesired = false
			default:
				return fmt.Errorf("health_check: unknown option %s", hcOpts)
			}
		}

	case "force_tcp":
		if c.NextArg() {
			return c.ArgErr()
		}
		f.opts.forceTCP = true
	case "prefer_udp":
		if c.NextArg() {
			return c.ArgErr()
		}
		f.opts.preferUDP = true
	case "tls":
		args := c.RemainingArgs()
		if len(args) > 3 {
			return c.ArgErr()
		}

		tlsConfig, err := pkgtls.NewTLSConfigFromArgs(args...)
		if err != nil {
			return err
		}
		f.tlsConfig = tlsConfig
	case "tls_servername":
		if !c.NextArg() {
			return c.ArgErr()
		}
		f.tlsServerName = c.Val()
	case "expire":
		if !c.NextArg() {
			return c.ArgErr()
		}
		dur, err := time.ParseDuration(c.Val())
		if err != nil {
			return err
		}
		if dur < 0 {
			return fmt.Errorf("expire can't be negative: %s", dur)
		}
		f.expire = dur
	case "policy":
		if !c.NextArg() {
			return c.ArgErr()
		}
		switch x := c.Val(); x {
		case "random":
			f.p = &random{}
		case "round_robin":
			f.p = &roundRobin{}
		case "sequential":
			f.p = &sequential{}
		default:
			return c.Errf("unknown policy '%s'", x)
		}
	case "max_concurrent":
		if !c.NextArg() {
			return c.ArgErr()
		}
		n, err := strconv.Atoi(c.Val())
		if err != nil {
			return err
		}
		if n < 0 {
			return fmt.Errorf("max_concurrent can't be negative: %d", n)
		}
		f.ErrLimitExceeded = errors.New("concurrent queries exceeded maximum " + c.Val())
		f.maxConcurrent = int64(n)

	// turned part
	case "to":
		to := c.RemainingArgs()
		if len(to) == 0 {
			return c.ArgErr()
		}

		toHosts, err := parse.HostPortOrFile(to...)
		if err != nil {
			panic(err)
			// return f, err
		}

		transports := make([]string, len(toHosts))
		allowedTrans := map[string]bool{"dns": true, "tls": true}
		for i, host := range toHosts {
			trans, h := parse.Transport(host)

			if !allowedTrans[trans] {
				panic(fmt.Errorf("'%s' is not supported as a destination protocol in forward: %s", trans, host))
				// return f, fmt.Errorf("'%s' is not supported as a destination protocol in forward: %s", trans, host)
			}
			p := NewProxy(h, trans)
			f.proxies = append(f.proxies, p)
			transports[i] = trans
		}

		if f.tlsServerName != "" {
			f.tlsConfig.ServerName = f.tlsServerName
		}

		// Initialize ClientSessionCache in tls.Config. This may speed up a TLS handshake
		// in upcoming connections to the same TLS server.
		f.tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(len(f.proxies))

		for i := range f.proxies {
			// Only set this for proxies that need it.
			if transports[i] == transport.TLS {
				f.proxies[i].SetTLSConfig(f.tlsConfig)
			}
			f.proxies[i].SetExpire(f.expire)
			f.proxies[i].health.SetRecursionDesired(f.opts.hcRecursionDesired)
		}
	case "from":
		args := c.RemainingArgs()

		if len(args) == 1 {
			f.from = strings.TrimSpace(args[0])
		} else {
			bottle := bloom.NewWithEstimates(calculateSizeRate(len(args)))
			addLines2filter(parsers.LooseParser(args, parsers.DomainParser, 1), bottle)
			f.bottle = bottle
			f.from = ""
		}
		break
	case "rules":
		args := c.RemainingArgs()
		inputString := strings.TrimSpace(args[0])
		lines, _ := utils.FileToLines(inputString)

		bottle := bloom.NewWithEstimates(calculateSizeRate(len(lines)))
		addLines2filter(parsers.LooseParser(lines, parsers.DomainParser, 1), bottle)
		f.bottle = bottle
		f.from = ""
		break

	default:
		return c.Errf("unknown property '%s'", c.Val())
	}

	return nil
}

const max = 15 // Maximum number of upstreams.

func addLines2filter(lines []string, filter *bloom.BloomFilter) (int, *bloom.BloomFilter) {
	c := 0
	for _, line := range lines {
		if !filter.TestAndAddString(strings.ToLower(strings.TrimSpace(line))) {
			c += 1
		}
	}
	return c, filter
}

func calculateSizeRate(t int) (uint, float64) {
	total := t * 30
	return uint(total), 0.01
}
