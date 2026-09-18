package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// benchOptions controls how the endpoints are probed.
type benchOptions struct {
	Count              int           // timed queries per endpoint
	Timeout            time.Duration // timeout of a single query
	Domain             string        // domain to query
	Qtype              uint16        // query type
	DoHMethod          string        // DoH request method, GET or POST
	InsecureSkipVerify bool          // skip TLS certificate verification
}

// prober is a client for a single endpoint.
type prober interface {
	// Exchange sends one query and returns the response.
	Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
	// Close releases the resources held by the endpoint.
	Close() error
}

// newProber creates the client for a target endpoint.
func newProber(t Target, opts benchOptions) (prober, error) {
	switch t.Proto {
	case ProtoDoH:
		return newDoHProber(t.URL, opts)
	case ProtoDoQ:
		return newDoQProber(t.URL, opts)
	default:
		return nil, fmt.Errorf("unsupported protocol %q", t.Proto)
	}
}

// Result holds the measurements of one endpoint.
type Result struct {
	Target Target

	// OK is true when at least one timed query succeeded.
	OK bool
	// Err is the last error seen while probing the endpoint.
	Err string
	// Handshake is the duration of the first query, which includes the TCP, TLS
	// or QUIC handshake.
	Handshake time.Duration
	// Samples holds the duration of every successful timed query.
	Samples []time.Duration
	// Attempts counts all queries, including the handshake probe.
	Attempts int
	// Failures counts the queries that failed or returned no usable answer.
	Failures int
	Stats    Stats
}

// Stats summarises the successful queries of one endpoint.
type Stats struct {
	N      int
	Min    time.Duration
	Median time.Duration
	Avg    time.Duration
	P95    time.Duration
	Max    time.Duration
	Stddev time.Duration
}

// Score is the ranking value used by -sort=score: the median latency plus the
// jitter, i.e. how fast an endpoint answers usually and how steady it does so.
// Lower is better.
func (s Stats) Score() time.Duration { return s.Median + s.Stddev }

// Succeeded returns the number of successful timed queries.
func (r Result) Succeeded() int { return len(r.Samples) }

// RankKey returns the value the endpoint is ranked by.
func (r Result) RankKey(key string) time.Duration {
	switch key {
	case "avg":
		return r.Stats.Avg
	case "p95":
		return r.Stats.P95
	case "min":
		return r.Stats.Min
	case "score":
		return r.Stats.Score()
	default:
		return r.Stats.Median
	}
}

// benchmarkTarget probes one endpoint: a first query that pays for the
// connection setup, followed by opts.Count timed queries on the same
// connection.
func benchmarkTarget(ctx context.Context, t Target, opts benchOptions) Result {
	res := Result{Target: t}

	p, err := newProber(t, opts)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer p.Close()

	res.Attempts++
	start := time.Now()
	if _, err := queryOnce(ctx, p, t, opts); err != nil {
		res.Failures++
		res.Err = err.Error()
		return res
	}
	res.Handshake = time.Since(start)

	for i := 0; i < opts.Count; i++ {
		res.Attempts++
		start := time.Now()
		if _, err := queryOnce(ctx, p, t, opts); err != nil {
			res.Failures++
			res.Err = err.Error()
			continue
		}
		res.Samples = append(res.Samples, time.Since(start))
	}

	res.Stats = computeStats(res.Samples)
	res.OK = len(res.Samples) > 0
	return res
}

// queryOnce sends a single DNS query and checks that the answer is usable.
func queryOnce(ctx context.Context, p prober, t Target, opts benchOptions) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(opts.Domain), opts.Qtype)
	msg.RecursionDesired = true

	resp, err := p.Exchange(ctx, msg)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		code, ok := dns.RcodeToString[resp.Rcode]
		if !ok {
			code = strconv.Itoa(resp.Rcode)
		}
		return nil, fmt.Errorf("response code %s", code)
	}
	if len(resp.Answer) == 0 {
		return nil, errors.New("answer is empty")
	}
	return resp, nil
}

// RunBench probes all targets with at most concurrency workers. The returned
// slice keeps the order of targets; report, if set, is called for every
// endpoint as soon as it has been measured.
func RunBench(ctx context.Context, targets []Target, opts benchOptions, concurrency int, report func(Result)) []Result {
	if concurrency < 1 {
		concurrency = 1
	}

	results := make([]Result, len(targets))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t Target) {
			defer wg.Done()
			defer func() { <-sem }()

			r := benchmarkTarget(ctx, t, opts)

			mu.Lock()
			results[i] = r
			if report != nil {
				report(r)
			}
			mu.Unlock()
		}(i, t)
	}

	wg.Wait()
	return results
}

// Rank orders the results: successful endpoints first, from fastest to
// slowest, followed by the failed ones in their original order.
func Rank(results []Result, key string) []Result {
	out := make([]Result, len(results))
	copy(out, results)

	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.OK != b.OK {
			return a.OK
		}
		if !a.OK {
			return false // keep the list order for failed endpoints
		}
		return a.RankKey(key) < b.RankKey(key)
	})
	return out
}

// computeStats summarises successful query durations.
func computeStats(samples []time.Duration) Stats {
	if len(samples) == 0 {
		return Stats{}
	}

	sorted := make([]time.Duration, len(samples))
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	s := Stats{
		N:      len(sorted),
		Min:    sorted[0],
		Max:    sorted[len(sorted)-1],
		Median: median(sorted),
		P95:    percentile(sorted, 0.95),
	}

	var sum time.Duration
	for _, d := range sorted {
		sum += d
	}
	s.Avg = sum / time.Duration(len(sorted))

	mean := float64(s.Avg)
	var variance float64
	for _, d := range sorted {
		diff := float64(d) - mean
		variance += diff * diff
	}
	variance /= float64(len(sorted))
	s.Stddev = time.Duration(math.Sqrt(variance))

	return s
}

// median returns the median of sorted durations.
func median(sorted []time.Duration) time.Duration {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

// percentile returns the p-quantile of sorted (0 < p <= 1) using the
// nearest-rank method.
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(math.Ceil(p * float64(len(sorted))))
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}
