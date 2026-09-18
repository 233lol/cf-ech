package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	listen := flag.String("listen", ":5353", "DNS listen address")
	upstream := flag.String("upstream", "quic://dns.chunghwamc.com/dns-query", "Primary upstream URL (https:// for DoH, quic:// for DoQ)")
	fallback := flag.String("fallback", "https://doh.dns4all.eu/dns-query", "Fallback upstream URL (https:// for DoH, quic:// for DoQ)")
	timeout := flag.Duration("timeout", 5*time.Second, "Upstream query timeout")
	refresh := flag.Duration("refresh", 5*time.Minute, "ECH refresh interval")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	slog.Info("starting cf-ech DNS proxy",
		"listen", *listen,
		"upstream", *upstream,
		"fallback", *fallback,
		"refresh", *refresh,
	)

	primary, err := NewUpstream(*upstream, *timeout)
	if err != nil {
		slog.Error("invalid upstream", "error", err)
		os.Exit(1)
	}

	var fallbackUpstream Upstream
	if *fallback != "" {
		fallbackUpstream, err = NewUpstream(*fallback, *timeout)
		if err != nil {
			slog.Error("invalid fallback upstream", "error", err)
			os.Exit(1)
		}
	}

	resolver := NewResolver(primary, fallbackUpstream, *timeout)
	defer resolver.Close()

	echCache := NewECHCache(resolver, *refresh)
	echCache.Start(ctx)

	handler := &DNSHandler{
		resolver: resolver,
		echCache: echCache,
	}

	udpServer, tcpServer, err := StartServer(*listen, handler)
	if err != nil {
		slog.Error("failed to start server", "error", err)
		os.Exit(1)
	}

	<-ctx.Done()
	slog.Info("shutting down...")

	udpServer.Shutdown()
	tcpServer.Shutdown()

	slog.Info("stopped")
}
