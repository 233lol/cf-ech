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
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// TestDoQUpstreamExchange runs a small DoQ server and checks the client against
// it: stream framing, message IDs, reconnects and retries.
func TestDoQUpstreamExchange(t *testing.T) {
	server := newTestDoQServer(t)
	defer server.Close()

	up := &DoQUpstream{
		url:        "quic://" + server.Addr().String(),
		addr:       server.Addr().String(),
		serverName: "localhost",
		tlsConfig: &tls.Config{
			ServerName:         "localhost",
			NextProtos:         []string{doqALPN},
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true, // test server uses a self-signed certificate
		},
		quicConfig: &quic.Config{
			MaxIdleTimeout:       5 * time.Second,
			KeepAlivePeriod:      time.Second,
			HandshakeIdleTimeout: 5 * time.Second,
		},
	}
	defer up.Close()

	exchange := func(name string) (*dns.Msg, error) {
		msg := new(dns.Msg)
		msg.SetQuestion(name, dns.TypeA)
		msg.Id = 0x1234 // must be zero on the wire and restored in the response

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return up.Exchange(ctx, msg)
	}

	// The first query establishes the connection.
	r, err := exchange("first.example.")
	if err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("first exchange: got %d answers, want 1", len(r.Answer))
	}
	if r.Id != 0x1234 {
		t.Fatalf("first exchange: got message ID %#x, want 0x1234", r.Id)
	}

	// The server closed the connection, the client has to reconnect.
	time.Sleep(400 * time.Millisecond)
	if _, err := exchange("second.example."); err != nil {
		t.Fatalf("exchange after the server closed the connection: %v", err)
	}

	// The connection is closed right after the response to this query.
	if _, err := exchange("reconnect.example."); err != nil {
		t.Fatalf("reconnect exchange: %v", err)
	}
	time.Sleep(400 * time.Millisecond)
	if _, err := exchange("after-reconnect.example."); err != nil {
		t.Fatalf("exchange after reconnect: %v", err)
	}

	// A broken connection is retried exactly once.
	if _, err := exchange("flaky.example."); err == nil {
		t.Fatal("flaky.example.: expected an error")
	}
	if got := server.queryCount("flaky.example."); got != 2 {
		t.Fatalf("flaky.example. was attempted %d times, want 2", got)
	}
}

// testDoQServer is a minimal DoQ server (RFC 9250) for the test above.
type testDoQServer struct {
	ln *quic.Listener

	mu   sync.Mutex
	seen map[string]int
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

	s := &testDoQServer{ln: ln, seen: make(map[string]int)}

	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go s.handleConn(conn)
		}
	}()

	return s
}

func (s *testDoQServer) Addr() net.Addr { return s.ln.Addr() }
func (s *testDoQServer) Close() error   { return s.ln.Close() }

func (s *testDoQServer) queryCount(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen[name]
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

		name := q.Question[0].Name
		s.mu.Lock()
		s.seen[name]++
		s.mu.Unlock()

		if name == "flaky.example." {
			// Break the connection without answering.
			_ = conn.CloseWithError(doqErrorInternal, "boom")
			return
		}

		resp := new(dns.Msg)
		resp.SetReply(q)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(93, 184, 216, 34),
		})

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

		if name == "reconnect.example." {
			// Simulate a server closing an idle connection.
			go func() {
				time.Sleep(200 * time.Millisecond)
				_ = conn.CloseWithError(doqErrorNoError, "")
			}()
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
