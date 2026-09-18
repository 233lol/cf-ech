package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParseFlagsDefaults(t *testing.T) {
	cfg, err := parseFlags(nil)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}

	if cfg.csvPath != defaultCSV {
		t.Errorf("csvPath = %q, want %q", cfg.csvPath, defaultCSV)
	}
	if !equalStrings(cfg.protos, []string{ProtoDoH, ProtoDoQ}) {
		t.Errorf("protocols = %v", cfg.protos)
	}
	if cfg.count != 5 || cfg.concurrency != 8 || cfg.timeout != 5*time.Second {
		t.Errorf("unexpected defaults: count %d, concurrency %d, timeout %v", cfg.count, cfg.concurrency, cfg.timeout)
	}
	if cfg.domain != "example.com" || cfg.qtype != dns.TypeA || cfg.qtypeName != "A" {
		t.Errorf("unexpected query defaults: %s/%s", cfg.domain, cfg.qtypeName)
	}
	if cfg.sortKey != "median" || cfg.doqPort != doqDefaultPort || cfg.dohMethod != methodGET {
		t.Errorf("unexpected defaults: sort %q, port %q, method %q", cfg.sortKey, cfg.doqPort, cfg.dohMethod)
	}
	if !cfg.bar || cfg.wide || cfg.insecure || cfg.verbose {
		t.Errorf("unexpected boolean defaults: %+v", cfg)
	}
}

func TestParseFlags(t *testing.T) {
	cfg, err := parseFlags([]string{
		"-protocol", "DOH, quic",
		"-count", "3",
		"-timeout", "2s",
		"-domain", "example.org.",
		"-qtype", "aaaa",
		"-top", "10",
		"-limit", "5",
		"-sort", "P95",
		"-filter", "(?i)adguard",
		"-concurrency", "2",
		"-report-json", "out.json",
	})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}

	if !equalStrings(cfg.protos, []string{ProtoDoH, ProtoDoQ}) {
		t.Errorf("protocols = %v", cfg.protos)
	}
	if cfg.count != 3 || cfg.timeout != 2*time.Second || cfg.concurrency != 2 || cfg.top != 10 || cfg.limit != 5 {
		t.Errorf("unexpected options: %+v", cfg)
	}
	if cfg.domain != "example.org" {
		t.Errorf("domain = %q, want example.org", cfg.domain)
	}
	if cfg.qtype != dns.TypeAAAA || cfg.qtypeName != "AAAA" {
		t.Errorf("qtype = %v / %q", cfg.qtype, cfg.qtypeName)
	}
	if cfg.sortKey != "p95" {
		t.Errorf("sortKey = %q", cfg.sortKey)
	}
	if cfg.filter == nil || !cfg.filter.MatchString("AdGuard") {
		t.Errorf("filter = %v", cfg.filter)
	}
	if cfg.reportJSON != "out.json" {
		t.Errorf("reportJSON = %q", cfg.reportJSON)
	}
}

func TestParseFlagsErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"unsupported protocol", []string{"-protocol", "dot"}},
		{"empty protocol", []string{"-protocol", " "}},
		{"zero count", []string{"-count", "0"}},
		{"zero timeout", []string{"-timeout", "0s"}},
		{"zero concurrency", []string{"-concurrency", "0"}},
		{"negative limit", []string{"-limit", "-1"}},
		{"negative top", []string{"-top", "-1"}},
		{"unknown sort key", []string{"-sort", "bogus"}},
		{"unsupported DoH method", []string{"-doh-method", "PATCH"}},
		{"unknown query type", []string{"-qtype", "BOGUS"}},
		{"empty domain", []string{"-domain", "."}},
		{"invalid filter", []string{"-filter", "("}},
		{"empty csv", []string{"-csv", " "}},
		{"unknown flag", []string{"-nope"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseFlags(tc.args); err == nil {
				t.Errorf("parseFlags(%v) succeeded, want an error", tc.args)
			}
		})
	}
}

func TestParseProtocols(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"doh", []string{ProtoDoH}},
		{"DoQ", []string{ProtoDoQ}},
		{"doh,doq", []string{ProtoDoH, ProtoDoQ}},
		{"all", []string{ProtoDoH, ProtoDoQ}},
		{"quic,https,doh", []string{ProtoDoQ, ProtoDoH}},
		{"doh,, doq ", []string{ProtoDoH, ProtoDoQ}},
	}

	for _, tc := range tests {
		got, err := parseProtocols(tc.in)
		if err != nil {
			t.Fatalf("parseProtocols(%q): %v", tc.in, err)
		}
		if !equalStrings(got, tc.want) {
			t.Errorf("parseProtocols(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}

	if _, err := parseProtocols("dot"); err == nil {
		t.Error("parseProtocols(dot) succeeded, want an error")
	}
}

// captureOutput runs fn with os.Stdout and os.Stderr redirected into temporary
// files and returns what was written to them.
func captureOutput(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()

	outFile, err := os.CreateTemp(t.TempDir(), "stdout-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer outFile.Close()

	errFile, err := os.CreateTemp(t.TempDir(), "stderr-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer errFile.Close()

	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outFile, errFile
	fn()
	os.Stdout, os.Stderr = oldOut, oldErr

	read := func(f *os.File) string {
		data, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatalf("read %s: %v", f.Name(), err)
		}
		return string(data)
	}
	return read(outFile), read(errFile)
}

// TestRunEndToEnd drives the whole tool against a local DoH server: CSV
// loading, benchmarking, ranking and both report files.
func TestRunEndToEnd(t *testing.T) {
	var requests int64
	srv := httptest.NewServer(dohHandler(t, &requests))
	defer srv.Close()

	csvPath := writeTempCSV(t, "Provider,URL,Protocols\n"+
		"Local,"+srv.URL+"/dns-query,DoH\n")

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "speed.json")
	csvOut := filepath.Join(dir, "speed.csv")

	cfg, err := parseFlags([]string{
		"-csv", csvPath,
		"-protocol", "doh",
		"-count", "2",
		"-concurrency", "1",
		"-timeout", "3s",
		"-bar=false",
		"-report-json", jsonPath,
		"-report-csv", csvOut,
	})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}

	stdout, stderr := captureOutput(t, func() {
		if err := run(cfg); err != nil {
			t.Fatalf("run: %v", err)
		}
	})

	// 2 timed queries plus the handshake probe, all of them successful.
	for _, want := range []string{"测试配置", "速度排名", "Local", "2/3", "汇总", "JSON 报告已写入", "CSV 报告已写入"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout does not contain %q:\n%s", want, stdout)
		}
	}
	if !strings.Contains(stderr, "开始测试 1 个端点") {
		t.Errorf("unexpected progress output:\n%s", stderr)
	}
	// One handshake query plus two timed queries.
	if got := atomic.LoadInt64(&requests); got != 3 {
		t.Errorf("the server saw %d queries, want 3", got)
	}

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read JSON report: %v", err)
	}
	var report jsonReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal JSON report: %v", err)
	}
	if len(report.Results) != 1 || !report.Results[0].OK || report.Results[0].Rank != 1 {
		t.Errorf("unexpected JSON report: %+v", report.Results)
	}
	if report.Options.Count != 2 || report.Options.Domain != "example.com" {
		t.Errorf("unexpected JSON options: %+v", report.Options)
	}

	csvData, err := os.ReadFile(csvOut)
	if err != nil {
		t.Fatalf("read CSV report: %v", err)
	}
	if !strings.Contains(string(csvData), "rank,protocol,provider,url") || !strings.Contains(string(csvData), "Local") {
		t.Errorf("unexpected CSV report:\n%s", csvData)
	}
}
