package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestComputeStats(t *testing.T) {
	samples := []time.Duration{
		30 * time.Millisecond,
		10 * time.Millisecond,
		20 * time.Millisecond,
		40 * time.Millisecond,
	}

	s := computeStats(samples)
	if s.N != 4 {
		t.Errorf("N = %d, want 4", s.N)
	}
	if s.Min != 10*time.Millisecond || s.Max != 40*time.Millisecond {
		t.Errorf("min/max = %v/%v, want 10ms/40ms", s.Min, s.Max)
	}
	if s.Median != 25*time.Millisecond {
		t.Errorf("median = %v, want 25ms", s.Median)
	}
	if s.Avg != 25*time.Millisecond {
		t.Errorf("avg = %v, want 25ms", s.Avg)
	}
	if s.P95 != 40*time.Millisecond {
		t.Errorf("p95 = %v, want 40ms", s.P95)
	}
	if s.Stddev < 11*time.Millisecond || s.Stddev > 11*time.Millisecond+time.Millisecond {
		t.Errorf("stddev = %v, want ~11.18ms", s.Stddev)
	}
	if want := s.Median + s.Stddev; s.Score() != want {
		t.Errorf("score = %v, want %v", s.Score(), want)
	}

	// The input must not be modified.
	if samples[0] != 30*time.Millisecond {
		t.Errorf("input was modified: %v", samples)
	}

	if got := computeStats(nil); got != (Stats{}) {
		t.Errorf("empty stats = %+v, want the zero value", got)
	}

	single := computeStats([]time.Duration{5 * time.Millisecond})
	if single.Min != single.Median || single.Median != single.P95 || single.Stddev != 0 {
		t.Errorf("single sample stats = %+v", single)
	}
}

func TestPercentile(t *testing.T) {
	samples := make([]time.Duration, 20)
	for i := range samples {
		samples[i] = time.Duration(i+1) * time.Millisecond
	}

	tests := []struct {
		p    float64
		want time.Duration
	}{
		{0.5, 10 * time.Millisecond},
		{0.95, 19 * time.Millisecond},
		{1, 20 * time.Millisecond},
		{0, time.Millisecond},
	}
	for _, tc := range tests {
		if got := percentile(samples, tc.p); got != tc.want {
			t.Errorf("percentile(%v) = %v, want %v", tc.p, got, tc.want)
		}
	}

	if got := percentile(nil, 0.95); got != 0 {
		t.Errorf("percentile of nothing = %v, want 0", got)
	}
}

func TestRank(t *testing.T) {
	results := []Result{
		{Target: Target{Proto: ProtoDoH, URL: "https://slow.example/dns-query"}, OK: true,
			Stats: Stats{Median: 50 * time.Millisecond, Avg: 10 * time.Millisecond, P95: 90 * time.Millisecond}},
		{Target: Target{Proto: ProtoDoQ, URL: "quic://dead.example:853"}, OK: false, Err: "timeout"},
		{Target: Target{Proto: ProtoDoH, URL: "https://fast.example/dns-query"}, OK: true,
			Stats: Stats{Median: 10 * time.Millisecond, Avg: 50 * time.Millisecond, P95: 20 * time.Millisecond}},
		{Target: Target{Proto: ProtoDoH, URL: "https://broken.example/dns-query"}, OK: false, Err: "dial"},
	}

	order := func(ranked []Result) []string {
		out := make([]string, 0, len(ranked))
		for _, r := range ranked {
			out = append(out, r.Target.URL)
		}
		return out
	}

	ranked := Rank(results, "median")
	want := []string{
		"https://fast.example/dns-query",
		"https://slow.example/dns-query",
		"quic://dead.example:853",
		"https://broken.example/dns-query",
	}
	if got := order(ranked); !equalStrings(got, want) {
		t.Errorf("Rank(median) = %v, want %v", got, want)
	}

	// Ranking by average reverses the two successful endpoints.
	ranked = Rank(results, "avg")
	if got := order(ranked)[0]; got != "https://slow.example/dns-query" {
		t.Errorf("Rank(avg) first = %q, want https://slow.example/dns-query", got)
	}

	// Ranking by P95 keeps the order of the successes and of the failures.
	ranked = Rank(results, "p95")
	want = []string{
		"https://fast.example/dns-query",
		"https://slow.example/dns-query",
		"quic://dead.example:853",
		"https://broken.example/dns-query",
	}
	if got := order(ranked); !equalStrings(got, want) {
		t.Errorf("Rank(p95) = %v, want %v", got, want)
	}

	// The input order must be kept in the argument slice.
	if results[0].Target.URL != "https://slow.example/dns-query" {
		t.Errorf("Rank modified the input: %v", order(results))
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// testA returns the answer record used by the test DoH and DoQ servers.
func testA(name string) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.IPv4(93, 184, 216, 34),
	}
}

// readDoHRequest decodes the DNS message of a GET or POST DoH request.
func readDoHRequest(r *http.Request) ([]byte, error) {
	switch r.Method {
	case http.MethodGet:
		raw := r.URL.Query().Get("dns")
		if raw == "" {
			return nil, fmt.Errorf("missing dns parameter")
		}
		return base64.RawURLEncoding.DecodeString(raw)
	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); ct != "application/dns-message" {
			return nil, fmt.Errorf("unexpected content type %q", ct)
		}
		return io.ReadAll(io.LimitReader(r.Body, maxDoHResponse))
	default:
		return nil, fmt.Errorf("unexpected method %s", r.Method)
	}
}

// dohHandler answers every DoH request with one A record and counts them.
func dohHandler(t *testing.T, requests *int64) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readDoHRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil {
			http.Error(w, "bad message", http.StatusBadRequest)
			return
		}
		if q.Id != 0 {
			http.Error(w, "message ID is not 0", http.StatusBadRequest)
			return
		}
		atomic.AddInt64(requests, 1)

		resp := new(dns.Msg)
		resp.SetReply(q)
		resp.Answer = append(resp.Answer, testA(q.Question[0].Name))

		out, err := resp.Pack()
		if err != nil {
			http.Error(w, "pack", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}
}

// dohReplyHandler answers with a fixed response code and optionally an answer.
func dohReplyHandler(rcode int, withAnswer bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readDoHRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil {
			http.Error(w, "bad message", http.StatusBadRequest)
			return
		}

		resp := new(dns.Msg)
		resp.SetReply(q)
		resp.Rcode = rcode
		if withAnswer {
			resp.Answer = append(resp.Answer, testA(q.Question[0].Name))
		}

		out, err := resp.Pack()
		if err != nil {
			http.Error(w, "pack", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}
}

func TestBenchmarkTargetDoH(t *testing.T) {
	for _, method := range []string{methodGET, methodPOST} {
		t.Run(method, func(t *testing.T) {
			var requests int64
			srv := httptest.NewServer(dohHandler(t, &requests))
			defer srv.Close()

			target := Target{
				Server: Server{
					Provider:  "test",
					URL:       srv.URL + "/dns-query",
					Protocols: []string{ProtoDoH},
				},
				Proto: ProtoDoH,
				URL:   srv.URL + "/dns-query",
			}
			opts := benchOptions{
				Count:     3,
				Timeout:   3 * time.Second,
				Domain:    "example.com",
				Qtype:     dns.TypeA,
				DoHMethod: method,
			}

			res := benchmarkTarget(context.Background(), target, opts)

			if !res.OK {
				t.Fatalf("benchmark failed: %s", res.Err)
			}
			if res.Succeeded() != 3 || res.Attempts != 4 || res.Failures != 0 {
				t.Errorf("succeeded %d, attempts %d, failures %d, want 3/4/0",
					res.Succeeded(), res.Attempts, res.Failures)
			}
			if res.Handshake <= 0 {
				t.Errorf("handshake = %v, want > 0", res.Handshake)
			}
			if res.Stats.N != 3 || res.Stats.Max <= 0 {
				t.Errorf("unexpected stats: %+v", res.Stats)
			}
			if got := atomic.LoadInt64(&requests); got != 4 {
				t.Errorf("the server saw %d queries, want 4", got)
			}
			if want := strings.TrimPrefix(srv.URL, "http://"); res.Target.Host() != want {
				t.Errorf("host = %q, want %q", res.Target.Host(), want)
			}
		})
	}
}

func TestBenchmarkTargetFailures(t *testing.T) {
	opts := benchOptions{Count: 2, Timeout: 2 * time.Second, Domain: "example.com", Qtype: dns.TypeA, DoHMethod: methodGET}

	tests := []struct {
		name    string
		handler http.HandlerFunc
		wantErr string
	}{
		{"empty answer", dohReplyHandler(dns.RcodeSuccess, false), "answer is empty"},
		{"servfail", dohReplyHandler(dns.RcodeServerFailure, true), "response code SERVFAIL"},
		{
			name: "http error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "nope", http.StatusInternalServerError)
			},
			wantErr: "status 500",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()

			target := Target{
				Server: Server{Provider: "test", URL: srv.URL + "/dns-query"},
				Proto:  ProtoDoH,
				URL:    srv.URL + "/dns-query",
			}

			res := benchmarkTarget(context.Background(), target, opts)
			if res.OK {
				t.Fatalf("endpoint was reported as OK: %+v", res.Stats)
			}
			if !strings.Contains(res.Err, tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", res.Err, tc.wantErr)
			}
			// The handshake probe failed, so there is nothing to time.
			if res.Attempts != 1 || res.Failures != 1 || len(res.Samples) != 0 {
				t.Errorf("attempts %d, failures %d, samples %d, want 1/1/0",
					res.Attempts, res.Failures, len(res.Samples))
			}
		})
	}
}

func TestBenchmarkTargetUnreachable(t *testing.T) {
	opts := benchOptions{Count: 2, Timeout: time.Second, Domain: "example.com", Qtype: dns.TypeA, DoHMethod: methodGET}
	target := Target{Server: Server{Provider: "dead", URL: "http://127.0.0.1:1/dns-query"}, Proto: ProtoDoH, URL: "http://127.0.0.1:1/dns-query"}

	res := benchmarkTarget(context.Background(), target, opts)
	if res.OK {
		t.Fatal("an unreachable endpoint was reported as OK")
	}
	if res.Err == "" {
		t.Error("no error was recorded")
	}
}

func TestBenchmarkTargetCancelledContext(t *testing.T) {
	var requests int64
	srv := httptest.NewServer(dohHandler(t, &requests))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	opts := benchOptions{Count: 2, Timeout: time.Second, Domain: "example.com", Qtype: dns.TypeA, DoHMethod: methodGET}
	target := Target{Server: Server{Provider: "test", URL: srv.URL + "/dns-query"}, Proto: ProtoDoH, URL: srv.URL + "/dns-query"}

	res := benchmarkTarget(ctx, target, opts)
	if res.OK {
		t.Fatalf("a cancelled benchmark was reported as OK: %+v", res.Stats)
	}
}

func TestRunBench(t *testing.T) {
	var requests int64
	srv := httptest.NewServer(dohHandler(t, &requests))
	defer srv.Close()

	targets := make([]Target, 0, 5)
	for i := 0; i < 4; i++ {
		targets = append(targets, Target{
			Server: Server{Provider: fmt.Sprintf("srv%d", i), URL: srv.URL + "/dns-query"},
			Proto:  ProtoDoH,
			URL:    srv.URL + "/dns-query",
		})
	}
	targets = append(targets, Target{
		Server: Server{Provider: "dead", URL: "http://127.0.0.1:1/dns-query"},
		Proto:  ProtoDoH,
		URL:    "http://127.0.0.1:1/dns-query",
	})

	opts := benchOptions{Count: 2, Timeout: time.Second, Domain: "example.com", Qtype: dns.TypeA, DoHMethod: methodGET}

	var reported int64
	results := RunBench(context.Background(), targets, opts, 3, func(Result) {
		atomic.AddInt64(&reported, 1)
	})

	if len(results) != len(targets) {
		t.Fatalf("got %d results, want %d", len(results), len(targets))
	}
	if got := atomic.LoadInt64(&reported); got != int64(len(targets)) {
		t.Errorf("report was called %d times, want %d", got, len(targets))
	}

	// Results keep the order of the targets, whatever order they finished in.
	for i, target := range targets {
		if results[i].Target.Server.Provider != target.Server.Provider {
			t.Errorf("result %d is %q, want %q", i, results[i].Target.Server.Provider, target.Server.Provider)
		}
	}

	ok, failed := 0, 0
	for _, r := range results {
		if r.OK {
			ok++
		} else {
			failed++
		}
	}
	if ok != 4 || failed != 1 {
		t.Errorf("%d endpoints succeeded and %d failed, want 4 and 1", ok, failed)
	}

	// 4 endpoints, 3 queries each (the failing one never reaches the server).
	if got := atomic.LoadInt64(&requests); got != 12 {
		t.Errorf("the server saw %d queries, want 12", got)
	}
}

func TestRequestError(t *testing.T) {
	inner := errors.New("connection refused")

	wrapped := &url.Error{
		Op:  "Get",
		URL: "https://dns.example.com/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE",
		Err: inner,
	}
	if got := requestError(wrapped); !errors.Is(got, inner) {
		t.Errorf("requestError = %v, want the inner error", got)
	}
	if got := requestError(inner); !errors.Is(got, inner) {
		t.Errorf("requestError = %v, want the error itself", got)
	}
}
