// Command dnsspeed benchmarks the public encrypted DNS servers listed in
// dns_over_https.csv and prints a speed ranking.
//
// Usage:
//
//	go run ./cmd/dnsspeed                        # DoH + DoQ, all servers
//	go run ./cmd/dnsspeed -protocol doh -top 20  # DoH only, 20 fastest
//	go run ./cmd/dnsspeed -report-json speed.json -report-csv speed.csv
//
// Build a standalone binary with:
//
//	go build -o dnsspeed ./cmd/dnsspeed
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// config holds the validated command line options.
type config struct {
	csvPath      string
	protocolsRaw string
	protos       []string
	count        int
	timeout      time.Duration
	domain       string
	qtypeName    string
	qtype        uint16
	concurrency  int
	limit        int
	filterRaw    string
	filter       *regexp.Regexp
	top          int
	sortKey      string
	doqPort      string
	dohMethod    string
	insecure     bool
	bar          bool
	wide         bool
	reportJSON   string
	reportCSV    string
	verbose      bool
}

// sortKeys are the supported ranking keys.
var sortKeys = map[string]bool{
	"median": true,
	"avg":    true,
	"p95":    true,
	"min":    true,
	"score":  true,
}

func main() {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "dnsspeed: "+err.Error())
		os.Exit(2)
	}

	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "dnsspeed: "+err.Error())
		os.Exit(1)
	}
}

// parseFlags reads and validates the command line.
func parseFlags(args []string) (config, error) {
	cfg := config{}
	fs := flag.NewFlagSet("dnsspeed", flag.ContinueOnError)

	fs.StringVar(&cfg.csvPath, "csv", defaultCSV, "服务器列表 CSV 文件")
	fs.StringVar(&cfg.protocolsRaw, "protocol", "doh,doq", "测试的协议：doh、doq、all，可用逗号分隔")
	fs.IntVar(&cfg.count, "count", 5, "每个端点的计时查询次数")
	fs.DurationVar(&cfg.timeout, "timeout", 5*time.Second, "单次查询超时")
	fs.StringVar(&cfg.domain, "domain", "example.com", "用于测试的域名")
	fs.StringVar(&cfg.qtypeName, "qtype", "A", "查询类型（A、AAAA、HTTPS 等）")
	fs.IntVar(&cfg.concurrency, "concurrency", 8, "并行测试的端点数")
	fs.IntVar(&cfg.limit, "limit", 0, "只测试前 N 个端点（0 表示全部）")
	fs.StringVar(&cfg.filterRaw, "filter", "", "只测试服务商或地址匹配该正则的端点")
	fs.IntVar(&cfg.top, "top", 0, "排名表只显示最快的 N 个端点（0 表示全部）")
	fs.StringVar(&cfg.sortKey, "sort", "median", "排名依据：median、avg、p95、min、score（中位延迟+抖动）")
	fs.StringVar(&cfg.doqPort, "doq-port", doqDefaultPort, "从 DoH 地址推导 DoQ 端点时使用的端口")
	fs.StringVar(&cfg.dohMethod, "doh-method", methodGET, "DoH 请求方法：GET 或 POST")
	fs.BoolVar(&cfg.insecure, "insecure", false, "跳过 TLS 证书校验")
	fs.BoolVar(&cfg.bar, "bar", true, "在排名表中绘制速度条")
	fs.BoolVar(&cfg.wide, "wide", false, "排名表中额外显示最小/最大延迟")
	fs.StringVar(&cfg.reportJSON, "report-json", "", "把完整结果写入该 JSON 文件")
	fs.StringVar(&cfg.reportCSV, "report-csv", "", "把完整结果写入该 CSV 文件")
	fs.BoolVar(&cfg.verbose, "verbose", false, "在进度信息中显示端点完整地址")

	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	return cfg.validate()
}

// validate checks the options and fills in the derived fields.
func (c config) validate() (config, error) {
	protos, err := parseProtocols(c.protocolsRaw)
	if err != nil {
		return config{}, err
	}
	c.protos = protos

	switch {
	case strings.TrimSpace(c.csvPath) == "":
		return config{}, errors.New("-csv 不能为空")
	case c.count < 1:
		return config{}, errors.New("-count 至少为 1")
	case c.timeout <= 0:
		return config{}, errors.New("-timeout 必须大于 0")
	case c.concurrency < 1:
		return config{}, errors.New("-concurrency 必须大于 0")
	case c.limit < 0:
		return config{}, errors.New("-limit 不能为负数")
	case c.top < 0:
		return config{}, errors.New("-top 不能为负数")
	}

	c.sortKey = strings.ToLower(strings.TrimSpace(c.sortKey))
	if !sortKeys[c.sortKey] {
		return config{}, fmt.Errorf("未知的排序方式 %q（支持 median、avg、p95、min、score）", c.sortKey)
	}

	c.dohMethod = strings.ToUpper(strings.TrimSpace(c.dohMethod))
	if c.dohMethod != methodGET && c.dohMethod != methodPOST {
		return config{}, fmt.Errorf("未知的 DoH 请求方法 %q（支持 GET、POST）", c.dohMethod)
	}

	c.qtypeName = strings.ToUpper(strings.TrimSpace(c.qtypeName))
	qtype, ok := dns.StringToType[c.qtypeName]
	if !ok {
		return config{}, fmt.Errorf("未知的查询类型 %q", c.qtypeName)
	}
	c.qtype = qtype

	c.domain = strings.TrimSuffix(strings.TrimSpace(c.domain), ".")
	if c.domain == "" {
		return config{}, errors.New("-domain 不能为空")
	}

	if strings.TrimSpace(c.filterRaw) != "" {
		re, err := regexp.Compile(c.filterRaw)
		if err != nil {
			return config{}, fmt.Errorf("非法的 -filter 正则表达式: %w", err)
		}
		c.filter = re
	}

	return c, nil
}

// parseProtocols maps -protocol to the canonical protocol names.
func parseProtocols(v string) ([]string, error) {
	var out []string
	add := func(p string) {
		for _, existing := range out {
			if existing == p {
				return
			}
		}
		out = append(out, p)
	}

	for _, part := range strings.Split(v, ",") {
		switch p := strings.TrimSpace(part); {
		case p == "":
			continue
		case strings.EqualFold(p, "doh"), strings.EqualFold(p, "https"), strings.EqualFold(p, "h2"):
			add(ProtoDoH)
		case strings.EqualFold(p, "doq"), strings.EqualFold(p, "quic"):
			add(ProtoDoQ)
		case strings.EqualFold(p, "all"):
			add(ProtoDoH)
			add(ProtoDoQ)
		default:
			return nil, fmt.Errorf("未知的协议 %q（支持 doh、doq、all）", p)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("-protocol 不能为空")
	}
	return out, nil
}

// run performs the benchmark and writes the ranking.
func run(cfg config) error {
	servers, err := LoadServers(cfg.csvPath)
	if err != nil {
		return err
	}

	targets := BuildTargets(servers, cfg.protos, cfg.doqPort)
	if cfg.filter != nil {
		targets = filterTargets(targets, cfg.filter)
	}
	if cfg.limit > 0 && len(targets) > cfg.limit {
		targets = targets[:cfg.limit]
	}
	if len(targets) == 0 {
		return errors.New("没有需要测试的端点，请检查 -protocol、-filter 和 -limit")
	}

	doh, doq := countProtocols(targets)
	PrintConfig(os.Stdout, cfg, len(servers), targets, doh, doq)

	opts := benchOptions{
		Count:              cfg.count,
		Timeout:            cfg.timeout,
		Domain:             cfg.domain,
		Qtype:              cfg.qtype,
		DoHMethod:          cfg.dohMethod,
		InsecureSkipVerify: cfg.insecure,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Fprintf(os.Stderr, "开始测试 %d 个端点，每个端点 %d 次计时查询...\n\n", len(targets), cfg.count)

	var mu sync.Mutex
	done := 0
	results := RunBench(ctx, targets, opts, cfg.concurrency, func(r Result) {
		mu.Lock()
		done++
		line := ProgressLine(r)
		if cfg.verbose {
			line = r.Target.URL + "  " + line
		}
		fmt.Fprintf(os.Stderr, "[%3d/%3d] %-3s %-30s %s\n", done, len(targets), r.Target.Proto, r.Target.Host(), line)
		mu.Unlock()
	})

	if ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "测试被中断，下面只显示已完成的结果。")
	}

	ranked := Rank(results, cfg.sortKey)
	PrintRanking(os.Stdout, ranked, reportOptions{
		Sort: cfg.sortKey,
		Top:  cfg.top,
		Bar:  cfg.bar,
		Wide: cfg.wide,
	})
	PrintFailures(os.Stdout, ranked)

	if cfg.reportJSON != "" {
		if err := WriteJSON(cfg.reportJSON, ranked, cfg); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "JSON 报告已写入 %s\n", cfg.reportJSON)
	}
	if cfg.reportCSV != "" {
		if err := WriteCSVReport(cfg.reportCSV, ranked); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "CSV 报告已写入 %s\n", cfg.reportCSV)
	}

	summarise(os.Stdout, ranked)
	return nil
}

// countProtocols counts the endpoints of every protocol.
func countProtocols(targets []Target) (doh, doq int) {
	for _, t := range targets {
		switch t.Proto {
		case ProtoDoH:
			doh++
		case ProtoDoQ:
			doq++
		}
	}
	return doh, doq
}

// summarise prints the final tally of the benchmark.
func summarise(w io.Writer, ranked []Result) {
	ok, failed := 0, 0
	for _, r := range ranked {
		if r.OK {
			ok++
		} else {
			failed++
		}
	}

	fmt.Fprintf(w, "== 汇总 ==\n\n  成功 %d 个端点，失败 %d 个端点\n", ok, failed)
	if ok > 0 {
		best := ranked[0]
		fmt.Fprintf(w, "  最快端点: %s（%s，中位延迟 %s）\n",
			best.Target.Host(), best.Target.Proto, formatDuration(best.Stats.Median))
	}
	fmt.Fprintln(w)
}
