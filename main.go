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
	upstream := flag.String("upstream", "https://doh.dns4all.eu/dns-query", "Primary upstream DoH URL")
	fallback := flag.String("fallback", "https://doh.dns4all.eu/dns-query", "Fallback upstream DoH URL")
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

	echCache := NewECHCache(*upstream, *refresh)
	echCache.Start(ctx)

	resolver := NewResolver(*upstream, *fallback, 5*time.Second)
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
