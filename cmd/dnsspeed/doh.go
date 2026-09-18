package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/miekg/dns"
)

// Request methods supported for DoH queries (RFC 8484, section 4.1).
const (
	methodGET  = "GET"
	methodPOST = "POST"
)

// maxDoHResponse limits how much of a DoH response body is read.
const maxDoHResponse = 64 << 10

// dohProber queries a server with DNS over HTTPS (RFC 8484). HTTP connections
// are reused, so only the first query pays for TCP, TLS and HTTP/2 setup.
type dohProber struct {
	url    string
	method string
	client *http.Client
}

func newDoHProber(rawURL string, opts benchOptions) (*dohProber, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w", rawURL, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid DoH URL %q: missing host", rawURL)
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   opts.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   opts.Timeout,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.InsecureSkipVerify,
		},
	}

	return &dohProber{
		url:    u.String(),
		method: opts.DoHMethod,
		client: &http.Client{Transport: transport, Timeout: opts.Timeout},
	}, nil
}

func (d *dohProber) Close() error {
	if t, ok := d.client.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
	return nil
}

// Exchange sends msg as an RFC 8484 GET or POST request and returns the
// decoded response.
func (d *dohProber) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	origID := msg.Id
	msg.Id = 0

	packed, err := msg.Pack()
	msg.Id = origID
	if err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}

	var req *http.Request
	if d.method == methodPOST {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(packed))
		if err != nil {
			return nil, fmt.Errorf("new request: %w", err)
		}
		req.Header.Set("Content-Type", "application/dns-message")
	} else {
		// Keep any parameters already present in the configured URL.
		u, err := url.Parse(d.url)
		if err != nil {
			return nil, fmt.Errorf("parse url: %w", err)
		}
		query := u.Query()
		query.Set("dns", base64.RawURLEncoding.EncodeToString(packed))
		u.RawQuery = query.Encode()

		req, err = http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, fmt.Errorf("new request: %w", err)
		}
	}
	req.Header.Set("Accept", "application/dns-message")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do: %w", requestError(err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDoHResponse))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, truncateBody(body))
	}

	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpack: %w", err)
	}

	r.Id = origID
	return r, nil
}

// truncateBody keeps error messages from DoH servers readable.
func truncateBody(body []byte) string {
	const max = 120
	if len(body) > max {
		return string(body[:max]) + "..."
	}
	return string(body)
}

// requestError unwraps the *url.Error of a failed request. Its message embeds
// the whole request URL, which contains the base64 encoded query and would
// make the failure report unreadable.
func requestError(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return uerr.Err
	}
	return err
}
