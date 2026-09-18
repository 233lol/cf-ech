package main

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Upstream is a remote resolver that answers DNS queries over an encrypted
// transport. Implementations must be safe for concurrent use.
type Upstream interface {
	// Exchange forwards msg to the upstream resolver and returns its response.
	Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
	// String returns the upstream URL, used for logging.
	String() string
	// Close releases the resources held by the upstream.
	Close() error
}

// NewUpstream creates an Upstream from an upstream URL.
// Supported schemes:
//
//	https:// (and http://) - DNS over HTTPS, RFC 8484
//	quic:// (and doq://)   - DNS over QUIC, RFC 9250
//
// timeout bounds the time a single exchange may take.
func NewUpstream(rawURL string, timeout time.Duration) (Upstream, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse upstream %q: %w", rawURL, err)
	}

	switch strings.ToLower(u.Scheme) {
	case "https", "http":
		return newDoHUpstream(u, timeout)
	case "quic", "doq":
		return newDoQUpstream(u)
	default:
		return nil, fmt.Errorf("unsupported upstream scheme %q in %q (supported: https, quic)", u.Scheme, rawURL)
	}
}
