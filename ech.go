package main

import (
	"context"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type ECHCache struct {
	mu       sync.RWMutex
	ech      []byte
	resolver *Resolver
	interval time.Duration
}

func NewECHCache(resolver *Resolver, interval time.Duration) *ECHCache {
	return &ECHCache{
		resolver: resolver,
		interval: interval,
	}
}

func (c *ECHCache) Start(ctx context.Context) {
	c.fetch()

	go func() {
		for {
			jitter := time.Duration(rand.Int63n(int64(30*time.Second))) - 15*time.Second
			timer := time.NewTimer(c.interval + jitter)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				c.fetch()
			}
		}
	}()
}

func (c *ECHCache) fetch() {
	msg := new(dns.Msg)
	msg.SetQuestion("cloudflare-ech.com.", dns.TypeHTTPS)
	msg.RecursionDesired = true

	r, err := c.resolver.Exchange(msg)
	if err != nil {
		slog.Error("failed to fetch ECH from upstream", "error", err)
		return
	}

	for _, rr := range r.Answer {
		https, ok := rr.(*dns.HTTPS)
		if !ok {
			continue
		}
		for _, v := range https.Value {
			if ech, ok := v.(*dns.SVCBECHConfig); ok && len(ech.ECH) > 0 {
				c.mu.Lock()
				c.ech = make([]byte, len(ech.ECH))
				copy(c.ech, ech.ECH)
				c.mu.Unlock()
				slog.Info("ECH config updated", "len", len(ech.ECH))
				return
			}
		}
	}
	slog.Warn("no ECH config found in upstream response")
}

func (c *ECHCache) InjectECH(msg *dns.Msg) {
	c.mu.RLock()
	echConfig := c.ech
	c.mu.RUnlock()

	if len(echConfig) == 0 {
		return
	}

	for _, rr := range msg.Answer {
		https, ok := rr.(*dns.HTTPS)
		if !ok {
			continue
		}

		hasECH := false
		for _, v := range https.Value {
			if _, ok := v.(*dns.SVCBECHConfig); ok {
				hasECH = true
				break
			}
		}

		if !hasECH {
			ech := &dns.SVCBECHConfig{ECH: make([]byte, len(echConfig))}
			copy(ech.ECH, echConfig)
			https.Value = append(https.Value, ech)
			slog.Debug("injected ECH", "name", https.Hdr.Name)
		}
	}
}
