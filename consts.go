package turned

import (
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/coredns/coredns/plugin"
)

const (
	loadLogFmt = ">> loaded %s (num:%v) from `%s`."
)

type ClientSubnet struct {
	Addr    net.IP
	NetMark uint8
}

// Forward represents a plugin instance that can proxy requests to another (DNS) server. It has a list
// of proxies each representing one upstream proxy.
type Forward struct {
	concurrent int64 // atomic counters need to be first in struct for proper alignment

	proxies    []*Proxy
	p          Policy
	hcInterval time.Duration

	groupName string
	ignored   []string

	eDnsClientSubnet []ClientSubnet

	tlsConfig     *tls.Config
	tlsServerName string
	maxfails      uint32
	expire        time.Duration
	maxConcurrent int64

	opts options // also here for testing

	// ErrLimitExceeded indicates that a query was rejected because the number of concurrent queries has exceeded
	// the maximum allowed (maxConcurrent)
	ErrLimitExceeded error

	from   string
	bottle *bottleAdapter
}

type Turned struct {
	Nodes []*Forward
	Next  plugin.Handler
}

var (
	// ErrNoHealthy means no healthy proxies left.
	ErrNoHealthy = errors.New("no healthy proxies")
	// ErrNoForward means no forwarder defined.
	ErrNoForward = errors.New("no forwarder defined")
	// ErrCachedClosed means cached connection was closed by peer.
	ErrCachedClosed = errors.New("cached connection was closed by peer")
)

// options holds various options that can be set.
type options struct {
	forceTCP           bool
	preferUDP          bool
	hcRecursionDesired bool
	eDNS               bool
}

var defaultTimeout = 5 * time.Second
