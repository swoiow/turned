package turned

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/parse"
	pkgtls "github.com/coredns/coredns/plugin/pkg/tls"
	"github.com/coredns/coredns/plugin/pkg/transport"
	cuckoo "github.com/seiflotfy/cuckoofilter"
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

		mode := "-"
		count := "-"
		if f.bottle != nil {
			if f.bottle.BloomFilter != nil {
				mode = "Bloom"
				count = strconv.Itoa(int(f.bottle.BloomFilter.Count()))
			} else {
				mode = "Hash"
				count = strconv.Itoa(len(f.bottle.HashMap))
			}
		}
		log.Infof("[Settings] config node >>  name:%s mode:%s count:%s", f.groupName, mode, count)
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
			adapter := NewAdapter()
			for _, line := range parsers.LooseParser(args, parsers.DomainParser, 1) {
				adapter.mapAddString(line)
			}
			adapter.setupContainsFunc()

			f.bottle = adapter
			f.from = ""
		}
		break

	case "rules":
		args := c.RemainingArgs()
		inputString := strings.TrimSpace(args[0])
		inputStringInLow := strings.ToLower(inputString)

		if f.bottle == nil {
			bottle := cuckoo.NewFilter(200_000)

			adapter := NewAdapter()
			adapter.BloomFilter = bottle
			adapter.setupContainsFunc()

			f.bottle = adapter
		}

		switch true {
		case strings.HasPrefix(inputStringInLow, "cache+"):
			inputString = strings.TrimPrefix(inputString, "cache+")

			if strings.HasPrefix(inputString, "http://") || strings.HasPrefix(inputString, "https://") {
				filter, _ := utils.RemoteCacheLoader(inputString)
				f.bottle.BloomFilter = filter
			} else {
				filter, _ := utils.LocalCacheLoader(inputString)
				f.bottle.BloomFilter = filter
			}

		case strings.HasPrefix(inputStringInLow, "http://"),
			strings.HasPrefix(inputStringInLow, "https://"):

			err := utils.RemoteRuleLoader(inputString, f.bottle.BloomFilter)
			if err != nil {
				return err
			}

		default:
			err := utils.LocalRuleLoader(inputString, f.bottle.BloomFilter, false)
			if err != nil {
				return err
			}
		}

		f.from = ""
		break

	default:
		return c.Errf("unknown property '%s'", c.Val())
	}

	return nil
}

const max = 15 // Maximum number of upstreams.

func PureDomain(s string) string {
	return utils.PureDomain(s)
}
