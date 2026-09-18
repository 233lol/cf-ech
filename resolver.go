package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/miekg/dns"
)

// Resolver forwards queries to a primary upstream and falls back to a second
// one when the primary is unreachable.
type Resolver struct {
	primary  Upstream
	fallback Upstream
	timeout  time.Duration
}

func NewResolver(primary, fallback Upstream, timeout time.Duration) *Resolver {
	return &Resolver{
		primary:  primary,
		fallback: fallback,
		timeout:  timeout,
	}
}

// Close releases the connections held by the upstreams.
func (r *Resolver) Close() error {
	if r.primary != nil {
		_ = r.primary.Close()
	}
	if r.fallback != nil {
		_ = r.fallback.Close()
	}
	return nil
}

// Exchange resolves msg using the configured upstreams.
func (r *Resolver) Exchange(msg *dns.Msg) (*dns.Msg, error) {
	return r.ExchangeContext(context.Background(), msg)
}

// ExchangeContext is Exchange with a caller supplied context, e.g. for ECH
// refresh requests. Every upstream attempt gets its own timeout.
func (r *Resolver) ExchangeContext(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	resp, err := r.exchange(ctx, r.primary, msg)
	if err == nil {
		return resp, nil
	}

	if r.fallback == nil {
		return nil, err
	}

	slog.Warn("primary upstream failed", "error", err, "upstream", r.primary)

	resp, err = r.exchange(ctx, r.fallback, msg)
	if err == nil {
		return resp, nil
	}
	slog.Warn("fallback upstream also failed", "error", err, "upstream", r.fallback)

	return nil, err
}

func (r *Resolver) exchange(ctx context.Context, upstream Upstream, msg *dns.Msg) (*dns.Msg, error) {
	if upstream == nil {
		return nil, errors.New("no upstream configured")
	}

	if r.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.timeout)
		defer cancel()
	}

	start := time.Now()
	resp, err := upstream.Exchange(ctx, msg)
	if err != nil {
		return nil, err
	}

	slog.Debug("upstream resolved", "rtt", time.Since(start), "answers", len(resp.Answer), "upstream", upstream)
	return resp, nil
}
