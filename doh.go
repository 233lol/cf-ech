package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/miekg/dns"
)

// DoHUpstream resolves queries using DNS over HTTPS (RFC 8484).
type DoHUpstream struct {
	u      *url.URL
	client *http.Client
}

func newDoHUpstream(u *url.URL, timeout time.Duration) (*DoHUpstream, error) {
	if u.Host == "" {
		return nil, fmt.Errorf("invalid DoH upstream %q: missing host", u.String())
	}
	return &DoHUpstream{
		u:      u,
		client: &http.Client{Timeout: timeout},
	}, nil
}

func (d *DoHUpstream) String() string {
	return d.u.String()
}

func (d *DoHUpstream) Close() error {
	d.client.CloseIdleConnections()
	return nil
}

// Exchange sends msg as an RFC 8484 GET request and returns the decoded response.
func (d *DoHUpstream) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	origID := msg.Id
	msg.Id = 0

	packed, err := msg.Pack()
	msg.Id = origID
	if err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}

	// Keep any parameters already present in the configured URL.
	u := *d.u
	query := u.Query()
	query.Set("dns", base64.RawURLEncoding.EncodeToString(packed))
	u.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-message")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}

	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpack: %w", err)
	}

	r.Id = origID
	return r, nil
}
