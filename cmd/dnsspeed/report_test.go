package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// sampleResults returns a fast endpoint, a slow endpoint with a long provider
// name and a failed endpoint.
func sampleResults() []Result {
	return []Result{
		{
			Target: Target{
				Server: Server{
					Provider:  "AdGuard",
					URL:       "https://dns.adguard-dns.com/dns-query",
					Filtering: "广告过滤",
				},
				Proto: ProtoDoH,
				URL:   "https://dns.adguard-dns.com/dns-query",
			},
			OK:        true,
			Handshake: 30 * time.Millisecond,
			Samples:   []time.Duration{10 * time.Millisecond, 12 * time.Millisecond},
			Attempts:  3,
			Stats: Stats{
				N:      2,
				Min:    10 * time.Millisecond,
				Median: 11 * time.Millisecond,
				Avg:    11 * time.Millisecond,
				P95:    12 * time.Millisecond,
				Max:    12 * time.Millisecond,
				Stddev: time.Millisecond,
			},
		},
		{
			Target: Target{
				Server: Server{Provider: "Slow Provider With A Very Long Name", URL: "https://slow.example/dns-query"},
				Proto:  ProtoDoQ,
				URL:    "quic://slow.example:853",
			},
			OK:        true,
			Handshake: 120 * time.Millisecond,
			Samples:   []time.Duration{200 * time.Millisecond},
			Attempts:  2,
			Stats: Stats{
				N:      1,
				Min:    200 * time.Millisecond,
				Median: 200 * time.Millisecond,
				Avg:    200 * time.Millisecond,
				P95:    200 * time.Millisecond,
				Max:    200 * time.Millisecond,
			},
		},
		{
			Target: Target{
				Server: Server{Provider: "Dead", URL: "https://dead.example/dns-query"},
				Proto:  ProtoDoH,
				URL:    "https://dead.example/dns-query",
			},
			Err:      "do: dial tcp 127.0.0.1:1: connection refused",
			Attempts: 1,
			Failures: 1,
		},
	}
}

func TestPrintRanking(t *testing.T) {
	ranked := Rank(sampleResults(), "median")

	var buf bytes.Buffer
	PrintRanking(&buf, ranked, reportOptions{Sort: "median", Bar: true, Wide: true})
	out := buf.String()

	for _, want := range []string{"速度排名", "首查(含握手)", "中位", "P95", "抖动", "成功", "评分", "2/3", "1/2"} {
		if !strings.Contains(out, want) {
			t.Errorf("ranking output does not contain %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "…") {
		t.Errorf("the long provider name was not truncated:\n%s", out)
	}

	fast := strings.Index(out, "dns.adguard-dns.com")
	slow := strings.Index(out, "slow.example")
	if fast < 0 || slow < 0 || fast > slow {
		t.Errorf("the fastest endpoint is not listed first:\n%s", out)
	}
	if strings.Count(out, "█") < 2 {
		t.Errorf("expected speed bars:\n%s", out)
	}

	// Top limits the table, the bar column can be turned off.
	buf.Reset()
	PrintRanking(&buf, ranked, reportOptions{Sort: "median", Top: 1})
	out = buf.String()
	if strings.Contains(out, "slow.example") {
		t.Errorf("-top 1 listed more than one endpoint:\n%s", out)
	}
	if strings.Contains(out, "█") {
		t.Errorf("bars are drawn although they were disabled:\n%s", out)
	}
}

func TestPrintRankingWithoutResults(t *testing.T) {
	var buf bytes.Buffer
	PrintRanking(&buf, []Result{{Err: "boom"}}, reportOptions{Sort: "median"})
	if !strings.Contains(buf.String(), "没有任何端点测试成功") {
		t.Errorf("unexpected output: %s", buf.String())
	}
}

func TestPrintFailures(t *testing.T) {
	ranked := Rank(sampleResults(), "median")

	var buf bytes.Buffer
	PrintFailures(&buf, ranked)
	out := buf.String()

	if !strings.Contains(out, "失败端点（1 个）") || !strings.Contains(out, "connection refused") {
		t.Errorf("unexpected failure table:\n%s", out)
	}
	if strings.Contains(out, "dns.adguard-dns.com") {
		t.Errorf("a successful endpoint is listed as failed:\n%s", out)
	}

	buf.Reset()
	PrintFailures(&buf, []Result{{OK: true}})
	if buf.Len() != 0 {
		t.Errorf("expected no output, got:\n%s", buf.String())
	}
}

func TestProgressLine(t *testing.T) {
	ok := sampleResults()[0]
	if got := ProgressLine(ok); !strings.Contains(got, "中位 11.0ms") || !strings.Contains(got, "2/3") {
		t.Errorf("ProgressLine = %q", got)
	}

	bad := sampleResults()[2]
	if got := ProgressLine(bad); !strings.Contains(got, "失败: ") || !strings.Contains(got, "connection refused") {
		t.Errorf("ProgressLine = %q", got)
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want string
	}{
		{0, "-"},
		{-time.Second, "-"},
		{500 * time.Microsecond, "500µs"},
		{12300 * time.Microsecond, "12.3ms"},
		{1500 * time.Millisecond, "1.50s"},
	}
	for _, tc := range tests {
		if got := formatDuration(tc.in); got != tc.want {
			t.Errorf("formatDuration(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSpeedBar(t *testing.T) {
	if got := speedBar(10*time.Millisecond, 10*time.Millisecond, 8); got != strings.Repeat("█", 8) {
		t.Errorf("fastest bar = %q", got)
	}
	if got := speedBar(20*time.Millisecond, 10*time.Millisecond, 8); got != strings.Repeat("█", 4) {
		t.Errorf("half speed bar = %q", got)
	}
	if got := speedBar(time.Millisecond, 10*time.Millisecond, 8); got != strings.Repeat("█", 8) {
		t.Errorf("bar must be capped: %q", got)
	}
	if got := speedBar(0, 10*time.Millisecond, 8); got != "" {
		t.Errorf("bar of a missing measurement = %q", got)
	}
}

func TestDisplayWidthAndTruncate(t *testing.T) {
	if got := displayWidth("中文abc"); got != 7 {
		t.Errorf("displayWidth = %d, want 7", got)
	}
	if got := truncate("abcdef", 4); got != "abc…" {
		t.Errorf("truncate = %q, want abc…", got)
	}
	if got := truncate("abcdef", 6); got != "abcdef" {
		t.Errorf("truncate = %q, want abcdef", got)
	}
	if got := pad("ab", 5, true); got != "   ab" {
		t.Errorf("pad right = %q", got)
	}
	if got := pad("ab", 5, false); got != "ab   " {
		t.Errorf("pad left = %q", got)
	}
	if got := pad("中文", 4, false); got != "中文" {
		t.Errorf("pad of a wide string = %q", got)
	}
}

func TestWriteJSON(t *testing.T) {
	cfg := config{
		csvPath:     defaultCSV,
		domain:      "example.com",
		qtypeName:   "A",
		protos:      []string{ProtoDoH, ProtoDoQ},
		count:       5,
		concurrency: 8,
		timeout:     5 * time.Second,
		sortKey:     "median",
	}
	ranked := Rank(sampleResults(), "median")

	path := filepath.Join(t.TempDir(), "speed.json")
	if err := WriteJSON(path, ranked, cfg); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}

	var report jsonReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if report.Tool != "dnsspeed" || report.GeneratedAt == "" {
		t.Errorf("unexpected header: %+v", report)
	}
	if len(report.Results) != 3 {
		t.Fatalf("got %d results, want 3", len(report.Results))
	}
	if report.Options.TimeoutMS != 5000 || report.Options.Sort != "median" || len(report.Options.Protocols) != 2 {
		t.Errorf("unexpected options: %+v", report.Options)
	}

	first := report.Results[0]
	if first.Rank != 1 || !first.OK || first.Provider != "AdGuard" {
		t.Errorf("unexpected first result: %+v", first)
	}
	if first.MedianMS != 11 || first.P95MS != 12 || first.HandshakeMS != 30 || first.JitterMS != 1 {
		t.Errorf("unexpected measurements: %+v", first)
	}
	if first.Succeeded != 2 || first.Attempts != 3 {
		t.Errorf("unexpected counters: %+v", first)
	}

	last := report.Results[2]
	if last.Rank != 0 || last.OK || last.Error == "" {
		t.Errorf("unexpected failed result: %+v", last)
	}
}

func TestWriteCSVReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "speed.csv")
	if err := WriteCSVReport(path, Rank(sampleResults(), "median")); err != nil {
		t.Fatalf("WriteCSVReport: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open report: %v", err)
	}
	defer f.Close()

	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if len(records) != 4 {
		t.Fatalf("got %d rows, want 4 (header + 3 endpoints)", len(records))
	}
	if records[0][0] != "rank" || records[0][8] != "median_ms" {
		t.Errorf("unexpected header: %v", records[0])
	}
	if records[1][2] != "AdGuard" || records[1][4] != "dns.adguard-dns.com" || records[1][8] != "11.000" {
		t.Errorf("unexpected first row: %v", records[1])
	}
	if records[2][4] != "slow.example:853" || records[2][12] != "200.000" {
		t.Errorf("unexpected second row: %v", records[2])
	}
	if records[3][0] != "0" || records[3][5] != "false" || records[3][6] == "" {
		t.Errorf("unexpected third row: %v", records[3])
	}
}
