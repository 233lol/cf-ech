package main

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"
)

// writeTempCSV writes a server list to a temporary file and returns its path.
func writeTempCSV(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), defaultCSV)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write csv: %v", err)
	}
	return path
}

func TestLoadServers(t *testing.T) {
	path := writeTempCSV(t, "\ufeffProvider,URL,Protocols,Filtering,DNSSEC,NoLogging,Upstream,Comment\n"+
		"AdGuard,https://dns.adguard-dns.com/dns-query,\"DoH, DoT, DoQ\",广告过滤,Yes,未知,自有,\"广告过滤\"\n"+
		"AdGuard,https://dns.adguard-dns.com/dns-query,\"DoH, DoT, DoQ\",广告过滤,Yes,未知,自有,\"重复行\"\n"+
		"#commented,https://ignored.example/dns-query,DoH,无过滤,No,未知,自有,\n"+
		"no-url,,,,,,,\n"+
		"AliDNS,https://dns.alidns.com/dns-query,DoH,无过滤,No,未知,自有,\n")

	servers, err := LoadServers(path)
	if err != nil {
		t.Fatalf("LoadServers: %v", err)
	}
	if len(servers) != 2 {
		t.Fatalf("got %d servers, want 2: %+v", len(servers), servers)
	}

	adguard := servers[0]
	if adguard.Provider != "AdGuard" || adguard.Host() != "dns.adguard-dns.com" {
		t.Errorf("unexpected first server: %+v", adguard)
	}
	if want := []string{"DoH", "DoT", "DoQ"}; !reflect.DeepEqual(adguard.Protocols, want) {
		t.Errorf("protocols = %v, want %v", adguard.Protocols, want)
	}
	if !adguard.Supports("doq") || adguard.Supports("DNSCrypt") {
		t.Errorf("Supports() is wrong for %v", adguard.Protocols)
	}
	if adguard.Filtering != "广告过滤" || adguard.Comment != "广告过滤" || adguard.DNSSEC != "Yes" {
		t.Errorf("unexpected fields of the first server: %+v", adguard)
	}

	alidns := servers[1]
	if alidns.Provider != "AliDNS" || len(alidns.Protocols) != 1 || alidns.Supports(ProtoDoQ) {
		t.Errorf("unexpected second server: %+v", alidns)
	}
}

func TestLoadServersColumnOrderAndMissingColumns(t *testing.T) {
	// The header order must not matter, unknown columns are ignored.
	path := writeTempCSV(t, "URL,Extra,Provider,Protocols\n"+
		"https://dns.example.com/dns-query,ignored,Example,\"DoH, DoQ\"\n")

	servers, err := LoadServers(path)
	if err != nil {
		t.Fatalf("LoadServers: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("got %d servers, want 1", len(servers))
	}
	if servers[0].Provider != "Example" || !servers[0].Supports(ProtoDoQ) {
		t.Errorf("unexpected server: %+v", servers[0])
	}

	bad := writeTempCSV(t, "Provider,Protocols\nExample,DoH\n")
	if _, err := LoadServers(bad); err == nil {
		t.Fatal("expected an error for a list without a URL column")
	}

	if _, err := LoadServers(filepath.Join(t.TempDir(), "missing.csv")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestFindFileSearchesParents(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "cmd", "dnsspeed")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	want := filepath.Join(dir, defaultCSV)
	if err := os.WriteFile(want, []byte("Provider,URL,Protocols\nExample,https://dns.example.com/dns-query,DoH\n"), 0o644); err != nil {
		t.Fatalf("write csv: %v", err)
	}

	t.Chdir(sub)
	got, err := findFile(defaultCSV)
	if err != nil {
		t.Fatalf("findFile: %v", err)
	}
	if got != want {
		t.Errorf("findFile = %q, want %q", got, want)
	}
}

func TestServerDoQURL(t *testing.T) {
	tests := []struct {
		name    string
		server  Server
		port    string
		want    string
		wantErr bool
	}{
		{
			name:   "doh url",
			server: Server{URL: "https://dns.adguard-dns.com/dns-query"},
			port:   "853",
			want:   "quic://dns.adguard-dns.com:853",
		},
		{
			name:   "explicit http port is dropped",
			server: Server{URL: "https://dns.example.com:8443/dns-query"},
			port:   "853",
			want:   "quic://dns.example.com:853",
		},
		{
			name:   "custom doq port",
			server: Server{URL: "https://dns.example.com/dns-query"},
			port:   "8853",
			want:   "quic://dns.example.com:8853",
		},
		{
			name:    "ip address",
			server:  Server{URL: "https://1.1.1.1/dns-query"},
			port:    "853",
			wantErr: true,
		},
		{
			name:    "missing host",
			server:  Server{URL: "https:///dns-query"},
			port:    "853",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.server.DoQURL(tc.port)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("DoQURL = %q, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("DoQURL: %v", err)
			}
			if got != tc.want {
				t.Errorf("DoQURL = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildTargets(t *testing.T) {
	servers := []Server{
		{Provider: "AdGuard", URL: "https://dns.adguard-dns.com/dns-query", Protocols: []string{"DoH", "DoT", "DoQ"}},
		{Provider: "Cloudflare", URL: "https://cloudflare-dns.com/dns-query", Protocols: []string{"DoH"}},
		{Provider: "IPv4 only", URL: "https://1.1.1.1/dns-query", Protocols: []string{"DoH", "DoQ"}},
	}

	targets := BuildTargets(servers, []string{ProtoDoH, ProtoDoQ}, "853")
	want := []struct{ proto, url string }{
		{ProtoDoH, "https://dns.adguard-dns.com/dns-query"},
		{ProtoDoQ, "quic://dns.adguard-dns.com:853"},
		{ProtoDoH, "https://cloudflare-dns.com/dns-query"},
		{ProtoDoH, "https://1.1.1.1/dns-query"},
	}

	if len(targets) != len(want) {
		t.Fatalf("got %d targets, want %d: %+v", len(targets), len(want), targets)
	}
	for i, w := range want {
		if targets[i].Proto != w.proto || targets[i].URL != w.url {
			t.Errorf("target %d = %s %s, want %s %s", i, targets[i].Proto, targets[i].URL, w.proto, w.url)
		}
	}
	if got := targets[1].Server.Provider; got != "AdGuard" {
		t.Errorf("target 1 belongs to %q, want AdGuard", got)
	}

	if got := BuildTargets(servers, []string{ProtoDoQ}, "853"); len(got) != 1 {
		t.Errorf("DoQ only: got %d targets, want 1", len(got))
	}
}

func TestFilterTargets(t *testing.T) {
	servers := []Server{
		{Provider: "AdGuard", URL: "https://dns.adguard-dns.com/dns-query", Protocols: []string{"DoH", "DoQ"}},
		{Provider: "Cloudflare", URL: "https://cloudflare-dns.com/dns-query", Protocols: []string{"DoH"}},
	}
	targets := BuildTargets(servers, []string{ProtoDoH, ProtoDoQ}, "853")

	got := filterTargets(targets, regexp.MustCompile("(?i)adguard"))
	if len(got) != 2 {
		t.Fatalf("got %d targets, want 2", len(got))
	}
	for _, target := range got {
		if target.Server.Provider != "AdGuard" {
			t.Errorf("unexpected target: %+v", target)
		}
	}

	if got := filterTargets(targets, regexp.MustCompile("^https://cloudflare")); len(got) != 1 {
		t.Errorf("URL filter: got %d targets, want 1", len(got))
	}
	if got := filterTargets(targets, regexp.MustCompile("nothing-matches")); len(got) != 0 {
		t.Errorf("got %d targets, want 0", len(got))
	}
}
