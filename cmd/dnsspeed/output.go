package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// PrintConfig describes the benchmark setup.
func PrintConfig(w io.Writer, cfg config, servers int, targets []Target, doh, doq int) {
	fmt.Fprintln(w, "== 测试配置 ==")
	fmt.Fprintf(w, "  测试时间:   %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "  服务器列表: %s（%d 条记录，去重后）\n", cfg.csvPath, servers)
	fmt.Fprintf(w, "  测试域名:   %s %s\n", cfg.domain, cfg.qtypeName)
	fmt.Fprintf(w, "  协议:       %s（%d 个端点：DoH %d，DoQ %d）\n",
		strings.Join(cfg.protos, "+"), len(targets), doh, doq)
	fmt.Fprintf(w, "  每端点:     %d 次计时查询 + 1 次握手查询\n", cfg.count)
	fmt.Fprintf(w, "  超时/并发:  %s / %d\n", cfg.timeout, cfg.concurrency)
	if cfg.dohMethod != "" {
		fmt.Fprintf(w, "  DoH 请求:   %s\n", cfg.dohMethod)
	}
	if cfg.doqPort != "" {
		fmt.Fprintf(w, "  DoQ 端口:   %s\n", cfg.doqPort)
	}
	if cfg.insecure {
		fmt.Fprintln(w, "  TLS 校验:   已关闭 (-insecure)")
	}
	if cfg.filterRaw != "" {
		fmt.Fprintf(w, "  过滤条件:   %s\n", cfg.filterRaw)
	}
	fmt.Fprintln(w)
}

// jsonReport is the machine readable result document written by -report-json.
type jsonReport struct {
	Tool        string       `json:"tool"`
	GeneratedAt string       `json:"generated_at"`
	Options     jsonOptions  `json:"options"`
	Results     []jsonResult `json:"results"`
}

type jsonOptions struct {
	CSV         string   `json:"csv"`
	Domain      string   `json:"domain"`
	Qtype       string   `json:"qtype"`
	Protocols   []string `json:"protocols"`
	Count       int      `json:"count"`
	Concurrency int      `json:"concurrency"`
	TimeoutMS   float64  `json:"timeout_ms"`
	Sort        string   `json:"sort"`
}

type jsonResult struct {
	Rank        int     `json:"rank"` // 0 for endpoints that failed
	Protocol    string  `json:"protocol"`
	Provider    string  `json:"provider"`
	URL         string  `json:"url"`
	Host        string  `json:"host"`
	Filtering   string  `json:"filtering,omitempty"`
	DNSSEC      string  `json:"dnssec,omitempty"`
	NoLogging   string  `json:"no_logging,omitempty"`
	Comment     string  `json:"comment,omitempty"`
	OK          bool    `json:"ok"`
	Error       string  `json:"error,omitempty"`
	HandshakeMS float64 `json:"handshake_ms"`
	MedianMS    float64 `json:"median_ms"`
	AvgMS       float64 `json:"avg_ms"`
	P95MS       float64 `json:"p95_ms"`
	MinMS       float64 `json:"min_ms"`
	MaxMS       float64 `json:"max_ms"`
	JitterMS    float64 `json:"jitter_ms"`
	ScoreMS     float64 `json:"score_ms"`
	Succeeded   int     `json:"succeeded"`
	Attempts    int     `json:"attempts"`
}

// WriteJSON writes the full report, successful endpoints first, to a JSON file.
func WriteJSON(path string, ranked []Result, cfg config) error {
	report := jsonReport{
		Tool:        "dnsspeed",
		GeneratedAt: time.Now().Format(time.RFC3339),
		Options: jsonOptions{
			CSV:         cfg.csvPath,
			Domain:      cfg.domain,
			Qtype:       cfg.qtypeName,
			Protocols:   cfg.protos,
			Count:       cfg.count,
			Concurrency: cfg.concurrency,
			TimeoutMS:   ms(cfg.timeout),
			Sort:        cfg.sortKey,
		},
		Results: make([]jsonResult, 0, len(ranked)),
	}

	rank := 0
	for _, r := range ranked {
		if r.OK {
			rank++
		} else {
			rank = 0
		}

		report.Results = append(report.Results, jsonResult{
			Rank:        rank,
			Protocol:    r.Target.Proto,
			Provider:    r.Target.Server.Provider,
			URL:         r.Target.URL,
			Host:        r.Target.Host(),
			Filtering:   r.Target.Server.Filtering,
			DNSSEC:      r.Target.Server.DNSSEC,
			NoLogging:   r.Target.Server.NoLogging,
			Comment:     r.Target.Server.Comment,
			OK:          r.OK,
			Error:       r.Err,
			HandshakeMS: ms(r.Handshake),
			MedianMS:    ms(r.Stats.Median),
			AvgMS:       ms(r.Stats.Avg),
			P95MS:       ms(r.Stats.P95),
			MinMS:       ms(r.Stats.Min),
			MaxMS:       ms(r.Stats.Max),
			JitterMS:    ms(r.Stats.Stddev),
			ScoreMS:     ms(r.Stats.Score()),
			Succeeded:   r.Succeeded(),
			Attempts:    r.Attempts,
		})
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// WriteCSVReport writes one row per endpoint, fastest first.
func WriteCSVReport(path string, ranked []Result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	header := []string{
		"rank", "protocol", "provider", "url", "host", "ok", "error",
		"handshake_ms", "median_ms", "avg_ms", "p95_ms", "min_ms", "max_ms",
		"jitter_ms", "score_ms", "succeeded", "attempts",
	}
	if err := w.Write(header); err != nil {
		return err
	}

	rank := 0
	for _, r := range ranked {
		if r.OK {
			rank++
		} else {
			rank = 0
		}

		row := []string{
			strconv.Itoa(rank),
			r.Target.Proto,
			r.Target.Server.Provider,
			r.Target.URL,
			r.Target.Host(),
			strconv.FormatBool(r.OK),
			r.Err,
			msString(r.Handshake),
			msString(r.Stats.Median),
			msString(r.Stats.Avg),
			msString(r.Stats.P95),
			msString(r.Stats.Min),
			msString(r.Stats.Max),
			msString(r.Stats.Stddev),
			msString(r.Stats.Score()),
			strconv.Itoa(r.Succeeded()),
			strconv.Itoa(r.Attempts),
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}

	w.Flush()
	return w.Error()
}
