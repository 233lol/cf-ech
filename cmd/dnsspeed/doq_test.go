package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// testDoQServer is a minimal DoQ server (RFC 9250) that counts the queries and
// connections it sees, so tests can verify connection reuse.
type testDoQServer struct {
	ln *quic.Listener

	mu          sync.Mutex
	queries     int
	connections int
}

func newTestDoQServer(t *testing.T) *testDoQServer {
	t.Helper()

	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{testCertificate(t)},
		NextProtos:   []string{doqALPN},
	}, &quic.Config{})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	s := &testDoQServer{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			s.mu.Lock()
			s.connections++
			s.mu.Unlock()
			go s.handleConn(conn)
		}
	}()

	return s
}

func (s *testDoQServer) Addr() net.Addr { return s.ln.Addr() }
func (s *testDoQServer) Close() error   { return s.ln.Close() }

func (s *testDoQServer) counts() (queries, connections int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queries, s.connections
}

func (s *testDoQServer) handleConn(conn *quic.Conn) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}

		body, err := readDoQFrame(stream)
		if err != nil {
			return
		}

		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil {
			return
		}
		if q.Id != doqMessageID {
			stream.CancelRead(quic.StreamErrorCode(doqErrorProtocol))
			return
		}

		s.mu.Lock()
		s.queries++
		s.mu.Unlock()

		resp := new(dns.Msg)
		resp.SetReply(q)
		resp.Answer = append(resp.Answer, testA(q.Question[0].Name))

		frame, err := writeDoQFrame(resp)
		if err != nil {
			return
		}
		if _, err := stream.Write(frame); err != nil {
			return
		}
		if err := stream.Close(); err != nil {
			return
		}
	}
}

func readDoQFrame(stream *quic.Stream) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		return nil, err
	}
	body := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(stream, body); err != nil {
		return nil, err
	}
	return body, nil
}

func writeDoQFrame(msg *dns.Msg) ([]byte, error) {
	packed, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 2+len(packed))
	binary.BigEndian.PutUint16(out, uint16(len(packed)))
	copy(out[2:], packed)
	return out, nil
}

// testCertificate returns a self-signed certificate for 127.0.0.1.
func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestBenchmarkTargetDoQ(t *testing.T) {
	server := newTestDoQServer(t)
	defer server.Close()

	addr := server.Addr().String()
	target := Target{
		Server: Server{
			Provider:  "test",
			URL:       "https://" + addr + "/dns-query",
			Protocols: []string{"DoH", "DoQ"},
		},
		Proto: ProtoDoQ,
		URL:   "quic://" + addr,
	}
	opts := benchOptions{
		Count:              3,
		Timeout:            3 * time.Second,
		Domain:             "example.com",
		Qtype:              dns.TypeA,
		InsecureSkipVerify: true, // the test server uses a self-signed certificate
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

	queries, connections := server.counts()
	if queries != 4 {
		t.Errorf("the server saw %d queries, want 4", queries)
	}
	// All queries must be sent on the same connection (RFC 9250, section 4.2).
	if connections != 1 {
		t.Errorf("the client opened %d connections, want 1", connections)
	}
}

func TestBenchmarkTargetDoQUnreachable(t *testing.T) {
	opts := benchOptions{
		Count:              1,
		Timeout:            time.Second,
		Domain:             "example.com",
		Qtype:              dns.TypeA,
		InsecureSkipVerify: true,
	}
	target := Target{Server: Server{Provider: "dead"}, Proto: ProtoDoQ, URL: "quic://127.0.0.1:1"}

	res := benchmarkTarget(context.Background(), target, opts)
	if res.OK {
		t.Fatal("an unreachable DoQ endpoint was reported as OK")
	}
	if res.Err == "" {
		t.Error("no error was recorded")
	}
	if res.Attempts != 1 || res.Failures != 1 {
		t.Errorf("attempts %d, failures %d, want 1/1", res.Attempts, res.Failures)
	}
}

func TestNewDoQProber(t *testing.T) {
	t.Run("default port", func(t *testing.T) {
		p, err := newDoQProber("quic://dns.adguard-dns.com", benchOptions{})
		if err != nil {
			t.Fatalf("newDoQProber: %v", err)
		}
		if p.addr != "dns.adguard-dns.com:"+doqDefaultPort {
			t.Errorf("addr = %q", p.addr)
		}
		if p.serverName != "dns.adguard-dns.com" || p.tlsConfig.ServerName != "dns.adguard-dns.com" {
			t.Errorf("server name = %q / %q", p.serverName, p.tlsConfig.ServerName)
		}
		if !reflect.DeepEqual(p.tlsConfig.NextProtos, []string{doqALPN}) {
			t.Errorf("ALPN = %v, want [%s]", p.tlsConfig.NextProtos, doqALPN)
		}
		if p.tlsConfig.MinVersion != tls.VersionTLS13 {
			t.Errorf("MinVersion = %#x, want TLS 1.3", p.tlsConfig.MinVersion)
		}
	})

	t.Run("explicit port and sni", func(t *testing.T) {
		p, err := newDoQProber("quic://1.1.1.1:8853?sni=cloudflare-dns.com", benchOptions{})
		if err != nil {
			t.Fatalf("newDoQProber: %v", err)
		}
		if p.addr != "1.1.1.1:8853" {
			t.Errorf("addr = %q", p.addr)
		}
		if p.serverName != "cloudflare-dns.com" {
			t.Errorf("server name = %q", p.serverName)
		}
	})

	t.Run("insecure", func(t *testing.T) {
		p, err := newDoQProber("quic://dns.example.com", benchOptions{InsecureSkipVerify: true})
		if err != nil {
			t.Fatalf("newDoQProber: %v", err)
		}
		if !p.tlsConfig.InsecureSkipVerify {
			t.Error("InsecureSkipVerify was not propagated")
		}
	})

	t.Run("missing host", func(t *testing.T) {
		if _, err := newDoQProber("quic://", benchOptions{}); err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestNewDoHProber(t *testing.T) {
	if _, err := newDoHProber("https://dns.example.com/dns-query", benchOptions{Timeout: time.Second}); err != nil {
		t.Fatalf("newDoHProber: %v", err)
	}
	if _, err := newDoHProber("https:///dns-query", benchOptions{Timeout: time.Second}); err == nil {
		t.Fatal("expected an error for a URL without a host")
	}
}
