package turned

import (
	"context"
	"crypto/tls"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/debug"
	"github.com/coredns/coredns/plugin/metadata"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
	ot "github.com/opentracing/opentracing-go"
	otext "github.com/opentracing/opentracing-go/ext"
)

var log = clog.NewWithPlugin(pluginName)

// New returns a new Forward.
func New() *Forward {
	var f = &Forward{
		maxfails:  2,
		tlsConfig: new(tls.Config),
		expire:    defaultExpire, p: new(random),
		groupName:  "final",
		hcInterval: hcInterval,
		opts:       options{forceTCP: false, preferUDP: false, hcRecursionDesired: true},

		from: ".",
	}
	return f
}

// SetProxy appends p to the proxy list and starts healthchecking.
func (f *Forward) SetProxy(p *Proxy) {
	f.proxies = append(f.proxies, p)
	p.start(f.hcInterval)
}

// Len returns the number of configured proxies.
func (f *Forward) Len() int { return len(f.proxies) }

// Name implements plugin.Handler.
func (app *Turned) Name() string { return pluginName }

// ServeDNS implements plugin.Handler.
func (app *Turned) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	var f *Forward
	question := r.Question[0]
	qDomain := strings.ToLower(strings.TrimSuffix(question.Name, "."))

	for _, node := range app.Nodes {
		// log.Infof("[Forward: %s] checking", node.Name())

		if node.match(qDomain) {
			f = node
			break
		}
	}

	if f == nil {
		log.Warning("next plugin \n")

		return plugin.NextOrFailure(app.Name(), app.Next, ctx, w, r)
	}

	log.Infof("[Forward: %s] matched", f.Name())

	state := request.Request{W: w, Req: r}

	if f.maxConcurrent > 0 {
		count := atomic.AddInt64(&(f.concurrent), 1)
		defer atomic.AddInt64(&(f.concurrent), -1)
		if count > f.maxConcurrent {
			MaxConcurrentRejectCount.Add(1)
			return dns.RcodeRefused, f.ErrLimitExceeded
		}
	}

	fails := 0
	var span, child ot.Span
	var upstreamErr error
	span = ot.SpanFromContext(ctx)
	i := 0
	list := f.List()
	deadline := time.Now().Add(defaultTimeout)
	start := time.Now()
	for time.Now().Before(deadline) {
		if i >= len(list) {
			// reached the end of list, reset to begin
			i = 0
			fails = 0
		}

		proxy := list[i]
		i++
		if proxy.Down(f.maxfails) {
			fails++
			if fails < len(f.proxies) {
				continue
			}
			// All upstream proxies are dead, assume healthcheck is completely broken and randomly
			// select an upstream to connect to.
			r := new(random)
			proxy = r.List(f.proxies)[0]

			HealthcheckBrokenCount.Add(1)
		}

		if span != nil {
			child = span.Tracer().StartSpan("connect", ot.ChildOf(span.Context()))
			otext.PeerAddress.Set(child, proxy.addr)
			ctx = ot.ContextWithSpan(ctx, child)
		}

		metadata.SetValueFunc(ctx, "forward/upstream", func() string {
			return proxy.addr
		})

		var (
			ret *dns.Msg
			err error
		)
		opts := f.opts
		for {
			ret, err = proxy.Connect(ctx, state, opts)
			if err == ErrCachedClosed { // Remote side closed conn, can only happen with TCP.
				continue
			}
			// Retry with TCP if truncated and prefer_udp configured.
			if ret != nil && ret.Truncated && !opts.forceTCP && opts.preferUDP {
				opts.forceTCP = true
				continue
			}
			break
		}

		if child != nil {
			child.Finish()
		}

		log.Infof("spent: %s", time.Since(start))

		upstreamErr = err

		if err != nil {
			// Kick off health check to see if *our* upstream is broken.
			if f.maxfails != 0 {
				proxy.Healthcheck()
			}

			if fails < len(f.proxies) {
				continue
			}
			break
		}

		// Check if the reply is correct; if not return FormErr.
		if !state.Match(ret) {
			debug.Hexdumpf(ret, "Wrong reply for id: %d, %s %d", ret.Id, state.QName(), state.QType())

			formerr := new(dns.Msg)
			formerr.SetRcode(state.Req, dns.RcodeFormatError)
			w.WriteMsg(formerr)
			return 0, nil
		}

		w.WriteMsg(ret)
		return 0, nil
	}

	if upstreamErr != nil {
		return dns.RcodeServerFailure, upstreamErr
	}

	return dns.RcodeServerFailure, ErrNoHealthy
}

func (f *Forward) match(d string) bool {
	switch true {
	case f.from != "":
		// log.Info("matching by from")

		if !plugin.Name(f.from).Matches(d) || !f.isAllowedDomain(d) {
			return false
		}
		return true

	case f.bottle != nil:
		// log.Info("matching by bottle")

		if f.bottle.TestString(d) {
			return true
		}
		return f.useWildMode(d)

	default:
		return false
	}
}

func GetWild(h string) []string {
	// log.Info("matching by wildcard")

	var bucket = make([]string, 5)
	firstFlag := true
	splitHost := strings.Split(h, ".")
	newHost := ""
	for i := len(splitHost) - 1; i > 0; i-- {
		if firstFlag {
			newHost = splitHost[i]
			firstFlag = false
		} else {
			newHost = splitHost[i] + "." + newHost
		}
		bucket = append(bucket, "*."+newHost)
	}
	return bucket
}

func (f *Forward) useWildMode(name string) bool {
	dnList := GetWild(name)
	for _, dn := range dnList {
		if f.bottle.TestString(dn) {
			return true
		}
	}
	return false
}

func (f *Forward) isAllowedDomain(name string) bool {
	if dns.Name(name) == dns.Name(f.from) {
		return true
	}

	for _, ignore := range f.ignored {
		if plugin.Name(ignore).Matches(name) {
			return false
		}
	}
	return true
}

func (f *Forward) Name() string { return f.groupName }

// ForceTCP returns if TCP is forced to be used even when the request comes in over UDP.
func (f *Forward) ForceTCP() bool { return f.opts.forceTCP }

// PreferUDP returns if UDP is preferred to be used even when the request comes in over TCP.
func (f *Forward) PreferUDP() bool { return f.opts.preferUDP }

// List returns a set of proxies to be used for this client depending on the policy in f.
func (f *Forward) List() []*Proxy { return f.p.List(f.proxies) }
