package turned

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/parse"
	pkgtls "github.com/coredns/coredns/plugin/pkg/tls"
	"github.com/coredns/coredns/plugin/pkg/transport"
	"github.com/swoiow/dns_utils/loader"
	"github.com/swoiow/dns_utils/parsers"
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
		if f.bottle == nil {
			log.Infof("[doing] config node >> name:%s", f.groupName)
		} else {
			if f.bottle.BloomFilter != nil {
				mode = "Bloom"
				count = strconv.Itoa(int(f.bottle.BloomFilter.ApproximatedSize()))
			} else {
				mode = "Hash"
				count = strconv.Itoa(len(f.bottle.HashMap))
			}
			log.Infof("[doing] config node >> name:%s mode:%s count:%s", f.groupName, mode, count)
		}
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

	case "bootstrap_resolvers":
		f.bootstrapResolvers = c.RemainingArgs()
		log.Info("[doing] bootstrap_resolvers is enabled")
		break

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

	case "edns", "edns_client_subnet":
		subnets := c.RemainingArgs()
		if len(subnets) == 0 {
			return c.ArgErr()
		}

		for _, subnet := range subnets {
			if i, m := ParseEDNS0SubNet(subnet); i != nil {
				f.eDnsClientSubnet = append(f.eDnsClientSubnet, ClientSubnet{i, m})
			}
		}

		if len(f.eDnsClientSubnet) > 0 {
			f.opts.eDNS = true
		}
		log.Infof("[doing] setup edns0: %v", f.eDnsClientSubnet)
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

		if f.bottle == nil {
			bottle := bloom.NewWithEstimates(50_000, 0.001)

			adapter := NewAdapter()
			adapter.BloomFilter = bottle
			adapter.setupContainsFunc()

			f.bottle = adapter
		}

		m := loader.DetectMethods(inputString)
		bsResolvers := f.bootstrapResolvers

		switch true {
		case m.IsCache:
			isOk := false
			for _, resolver := range bsResolvers {
				m.SetupResolver(resolver)
				err := m.LoadCache(f.bottle.BloomFilter)
				if err != nil {
					log.Warningf("resolver[%s] catch err: %s", resolver, err)
					continue
				} else {
					isOk = true
					break
				}
			}
			if !isOk {
				err := m.LoadCache(f.bottle.BloomFilter)
				if err != nil {
					return err
				}
			}

			log.Infof(loadLogFmt, "cache", f.bottle.BloomFilter.ApproximatedSize(), m.RawInput)
			break

		case m.IsRules:
			var (
				isOk  = false
				rules []string
				err   error
			)

			for _, resolver := range bsResolvers {
				m.SetupResolver(resolver)
				rules, err = m.LoadRules(false)
				if err != nil {
					log.Warningf("resolver[%s] catch err: %s", resolver, err)
					continue
				} else {
					isOk = true
					break
				}
			}
			if !isOk {
				rules, err = m.LoadRules(false)
				if err != nil {
					return err
				}
			}

			c, _ := addLines2filter(rules, f.bottle.BloomFilter)
			log.Infof(loadLogFmt, "rules", c, m.RawInput)
			break

		default:
			log.Warningf("Unload anythings in `rules` with '%s'.", m.RawInput)
		}

		f.from = ""
		break

	case "{", "}":
		break

	default:
		return c.Errf("Unknown property '%s'.", c.Val())
	}

	return nil
}

const max = 15 // Maximum number of upstreams.

/*
 *   Utils
 */

func addLines2filter(lines []string, filter *bloom.BloomFilter) (int, *bloom.BloomFilter) {
	c := 0
	for _, line := range lines {
		if !filter.TestAndAddString(strings.ToLower(strings.TrimSpace(line))) {
			c += 1
		}
	}
	return c, filter
}

func ParseEDNS0SubNet(clientSubnet string) (net.IP, uint8) {
	ip := net.ParseIP(clientSubnet)
	if ip != nil {
		clientSubnet = fmt.Sprintf("%s/24", ip)
	}

	_, ipNet, err := net.ParseCIDR(clientSubnet)
	if err != nil {
		log.Errorf("unable to parse subnet: %s", clientSubnet)
		return nil, 0
	}
	netMark, _ := ipNet.Mask.Size()
	if netMark >= 32 {
		log.Errorf("%s net mark should less than 32", clientSubnet)
		return nil, 0
	}
	return ipNet.IP, uint8(netMark)
}
