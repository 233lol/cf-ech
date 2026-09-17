package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

type Resolver struct {
	primary  string
	fallback string
	client   *http.Client
}

func NewResolver(primary, fallback string, timeout time.Duration) *Resolver {
	return &Resolver{
		primary:  primary,
		fallback: fallback,
		client:   &http.Client{Timeout: timeout},
	}
}

func dohExchange(client *http.Client, upstream string, msg *dns.Msg) (*dns.Msg, error) {
	origID := msg.Id
	msg.Id = 0

	packed, err := msg.Pack()
	if err != nil {
		msg.Id = origID
		return nil, fmt.Errorf("pack: %w", err)
	}

	b64 := base64.RawURLEncoding.EncodeToString(packed)

	req, err := http.NewRequest("GET", upstream+"?dns="+b64, nil)
	if err != nil {
		msg.Id = origID
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		msg.Id = origID
		return nil, fmt.Errorf("do: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		msg.Id = origID
		return nil, fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		msg.Id = origID
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}

	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		msg.Id = origID
		return nil, fmt.Errorf("unpack: %w", err)
	}

	r.Id = origID
	return r, nil
}

func (r *Resolver) Exchange(msg *dns.Msg) (*dns.Msg, error) {
	start := time.Now()

	resp, err := dohExchange(r.client, r.primary, msg)
	if err == nil {
		slog.Debug("upstream resolved", "rtt", time.Since(start), "answers", len(resp.Answer), "upstream", r.primary)
		return resp, nil
	}

	slog.Warn("primary upstream failed", "error", err, "upstream", r.primary)

	if r.fallback != "" {
		start = time.Now()
		resp, err = dohExchange(r.client, r.fallback, msg)
		if err == nil {
			slog.Debug("fallback resolved", "rtt", time.Since(start), "answers", len(resp.Answer), "upstream", r.fallback)
			return resp, nil
		}
		slog.Warn("fallback upstream also failed", "error", err, "upstream", r.fallback)
	}

	return nil, err
}
