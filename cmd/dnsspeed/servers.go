package main

import (
	"encoding/csv"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Protocol names as used in the server list, e.g. "DoH, DoT, DoQ".
const (
	ProtoDoH = "DoH"
	ProtoDoQ = "DoQ"
)

// defaultCSV is the server list shipped with cf-ech.
const defaultCSV = "dns_over_https.csv"

// Server is one row of the public DNS server list.
type Server struct {
	Provider  string
	URL       string
	Protocols []string
	Filtering string
	DNSSEC    string
	NoLogging string
	Upstream  string
	Comment   string
}

// Supports reports whether the server advertises proto, e.g. "DoQ".
func (s Server) Supports(proto string) bool {
	for _, p := range s.Protocols {
		if strings.EqualFold(p, proto) {
			return true
		}
	}
	return false
}

// Host returns the host and port of the DoH URL, used for logging.
func (s Server) Host() string {
	return hostOf(s.URL)
}

// DoQURL builds the DoQ endpoint of a server from its DoH URL. DoQ uses the
// same host name on port 853 (RFC 9250, section 4.1.1) and the URL path is
// irrelevant, so the DoH URL is enough to derive it.
func (s Server) DoQURL(port string) (string, error) {
	u, err := url.Parse(s.URL)
	if err != nil {
		return "", fmt.Errorf("parse %q: %w", s.URL, err)
	}

	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("no host in %q", s.URL)
	}
	if net.ParseIP(host) != nil {
		// A quic:// URL built from an IP address would need an explicit ?sni=
		// name, which the list does not provide.
		return "", fmt.Errorf("cannot derive the DoQ server name from the IP address %q", host)
	}

	return "quic://" + net.JoinHostPort(host, port), nil
}

// Target is one endpoint to benchmark: a single protocol of a single server.
type Target struct {
	Server Server
	Proto  string
	URL    string
}

// Host returns the host and port of the endpoint URL.
func (t Target) Host() string {
	return hostOf(t.URL)
}

// String returns a short, human readable endpoint description.
func (t Target) String() string {
	return t.Proto + " " + t.Host()
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if u.Port() == "" {
		return u.Hostname()
	}
	return u.Host
}

// LoadServers reads the CSV server list. Columns are looked up by header name,
// so their order and additional columns do not matter; a UTF-8 BOM is
// tolerated. Comment rows, rows without a URL and duplicate URLs are skipped.
func LoadServers(path string) ([]Server, error) {
	resolved, err := findFile(path)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(resolved)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1 // tolerate rows with a different number of fields
	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", resolved, err)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("%s: empty file", resolved)
	}

	header := make(map[string]int, len(records[0]))
	for i, name := range records[0] {
		name = strings.TrimPrefix(strings.TrimSpace(name), "\ufeff")
		header[name] = i
	}
	for _, col := range []string{"Provider", "URL", "Protocols"} {
		if _, ok := header[col]; !ok {
			return nil, fmt.Errorf("%s: missing the %q column", resolved, col)
		}
	}

	// cell returns the trimmed value of col in rec, or "" when the row is short.
	cell := func(rec []string, col string) string {
		i, ok := header[col]
		if !ok || i >= len(rec) {
			return ""
		}
		return strings.TrimSpace(rec[i])
	}

	servers := make([]Server, 0, len(records)-1)
	seen := make(map[string]bool, len(records))
	for _, rec := range records[1:] {
		if isComment(rec) {
			continue
		}

		rawURL := cell(rec, "URL")
		if rawURL == "" || strings.HasPrefix(rawURL, "#") {
			continue
		}
		key := strings.ToLower(rawURL)
		if seen[key] {
			continue
		}
		seen[key] = true

		s := Server{
			Provider:  cell(rec, "Provider"),
			URL:       rawURL,
			Protocols: splitList(cell(rec, "Protocols")),
			Filtering: cell(rec, "Filtering"),
			DNSSEC:    cell(rec, "DNSSEC"),
			NoLogging: cell(rec, "NoLogging"),
			Upstream:  cell(rec, "Upstream"),
			Comment:   cell(rec, "Comment"),
		}
		if s.Provider == "" {
			s.Provider = hostOf(s.URL)
		}
		servers = append(servers, s)
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("%s: no usable rows", resolved)
	}

	return servers, nil
}

// isComment reports whether a row is commented out. The published list uses
// "#" for rows that should be ignored; provider names may start with "@".
func isComment(rec []string) bool {
	return len(rec) > 0 && strings.HasPrefix(strings.TrimSpace(rec[0]), "#")
}

// splitList splits a comma (or semicolon, or slash) separated CSV cell.
func splitList(v string) []string {
	parts := strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || r == ';' || r == '/'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// BuildTargets expands the server list into the endpoints of the requested
// protocols. DoQ endpoints are derived from the DoH URL of servers that
// advertise DoQ in the list.
func BuildTargets(servers []Server, protos []string, doqPort string) []Target {
	var targets []Target
	for _, s := range servers {
		for _, proto := range protos {
			switch proto {
			case ProtoDoH:
				targets = append(targets, Target{Server: s, Proto: ProtoDoH, URL: s.URL})
			case ProtoDoQ:
				if !s.Supports(ProtoDoQ) {
					continue
				}
				rawURL, err := s.DoQURL(doqPort)
				if err != nil {
					continue // no usable DoQ endpoint for this row
				}
				targets = append(targets, Target{Server: s, Proto: ProtoDoQ, URL: rawURL})
			}
		}
	}
	return targets
}

// filterTargets keeps the endpoints whose provider or host matches re.
func filterTargets(targets []Target, re *regexp.Regexp) []Target {
	out := make([]Target, 0, len(targets))
	for _, t := range targets {
		if re.MatchString(t.Server.Provider) || re.MatchString(t.URL) {
			out = append(out, t)
		}
	}
	return out
}

// findFile resolves a possibly relative file name. Besides the working
// directory it searches up to four parent directories, so the tool can be run
// from the repository root as well as from cmd/dnsspeed.
func findFile(path string) (string, error) {
	if _, err := os.Stat(path); err == nil {
		return path, nil
	} else if filepath.IsAbs(path) {
		return "", err
	}

	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for i := 0; i < 4; i++ {
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
		candidate := filepath.Join(dir, path)
		if _, statErr := os.Stat(candidate); statErr == nil {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("cannot find %q in the working directory or its parents", path)
}
