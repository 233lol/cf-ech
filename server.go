package main

import (
	"log/slog"

	"github.com/miekg/dns"
)

type DNSHandler struct {
	resolver *Resolver
	echCache *ECHCache
}

func (h *DNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	slog.Debug("query received", "question", r.Question[0].Name, "type", dns.TypeToString[r.Question[0].Qtype])

	resp, err := h.resolver.Exchange(r.Copy())
	if err != nil {
		slog.Error("upstream query failed", "error", err)
		dns.HandleFailed(w, r)
		return
	}

	h.echCache.InjectECH(resp)

	w.WriteMsg(resp)
}

func StartServer(addr string, handler *DNSHandler) (*dns.Server, *dns.Server, error) {
	udpServer := &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: handler,
	}
	tcpServer := &dns.Server{
		Addr:    addr,
		Net:     "tcp",
		Handler: handler,
	}

	go func() {
		slog.Info("DNS server starting", "addr", addr, "proto", "udp")
		if err := udpServer.ListenAndServe(); err != nil {
			slog.Error("UDP server failed", "error", err)
		}
	}()

	go func() {
		slog.Info("DNS server starting", "addr", addr, "proto", "tcp")
		if err := tcpServer.ListenAndServe(); err != nil {
			slog.Error("TCP server failed", "error", err)
		}
	}()

	return udpServer, tcpServer, nil
}
