package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

const (
	// doqALPN is the ALPN token registered for DoQ (RFC 9250, section 8.1).
	doqALPN = "doq"
	// doqDefaultPort is the port reserved for DoQ (RFC 9250, section 4.1.1).
	doqDefaultPort = "853"
	// doqMessageID is the only DNS message ID allowed on the wire
	// (RFC 9250, section 4.2.1).
	doqMessageID = 0
	// maxDoQMessageSize is the largest DNS message that fits into the 2-octet
	// length field used to frame messages (RFC 9250, section 4.6).
	maxDoQMessageSize = 65535

	// doqMaxIdleTimeout and doqKeepAlivePeriod keep the connection usable
	// between queries, so that new queries don't need a new handshake.
	doqMaxIdleTimeout  = 60 * time.Second
	doqKeepAlivePeriod = 20 * time.Second
)

// DoQ error codes (RFC 9250, section 4.3).
const (
	doqErrorProtocol         = quic.ApplicationErrorCode(0x2)
	doqErrorRequestCancelled = quic.ApplicationErrorCode(0x3)
)

// doqProber queries a server with DNS over QUIC (RFC 9250). One QUIC
// connection is reused for all queries and every query is sent on its own
// bidirectional stream, as required by RFC 9250, section 4.2.
type doqProber struct {
	url        string
	addr       string
	serverName string

	tlsConfig  *tls.Config
	quicConfig *quic.Config

	mu     sync.Mutex
	conn   *quic.Conn
	closed bool
}

// newDoQProber builds a prober for a quic:// URL. The host name is used for
// certificate validation, unless the URL carries an explicit one:
// quic://1.1.1.1:853?sni=cloudflare-dns.com
func newDoQProber(rawURL string, opts benchOptions) (*doqProber, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w", rawURL, err)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("invalid DoQ URL %q: missing host", rawURL)
	}

	port := u.Port()
	if port == "" {
		port = doqDefaultPort
	}

	serverName := host
	if sni := strings.TrimSpace(u.Query().Get("sni")); sni != "" {
		serverName = strings.TrimSuffix(sni, ".")
	}

	return &doqProber{
		url:        u.String(),
		addr:       net.JoinHostPort(host, port),
		serverName: serverName,
		tlsConfig: &tls.Config{
			ServerName:         serverName,
			NextProtos:         []string{doqALPN},
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: opts.InsecureSkipVerify,
		},
		quicConfig: &quic.Config{
			MaxIdleTimeout:  doqMaxIdleTimeout,
			KeepAlivePeriod: doqKeepAlivePeriod,
		},
	}, nil
}

func (d *doqProber) Close() error {
	d.mu.Lock()
	conn := d.conn
	d.conn = nil
	d.closed = true
	d.mu.Unlock()

	if conn != nil {
		_ = conn.CloseWithError(quic.ApplicationErrorCode(0x0), "")
	}
	return nil
}

// Exchange sends msg over DoQ and returns the response.
func (d *doqProber) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	origID := msg.Id
	msg.Id = doqMessageID
	packed, err := msg.Pack()
	msg.Id = origID
	if err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}
	if len(packed) > maxDoQMessageSize {
		return nil, fmt.Errorf("message too large for DoQ (%d bytes)", len(packed))
	}

	resp, err := d.query(ctx, packed)
	if err != nil {
		return nil, err
	}

	resp.Id = origID
	return resp, nil
}

// query runs one exchange on the (possibly cached) connection.
func (d *doqProber) query(ctx context.Context, packed []byte) (*dns.Msg, error) {
	conn, err := d.connection(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := doqExchange(ctx, conn, packed)
	if err != nil && conn.Context().Err() != nil {
		// The connection is gone, make sure the next query dials a new one.
		d.discard(conn)
	}
	return resp, err
}

// connection returns the cached QUIC connection, dialing a new one if needed.
func (d *doqProber) connection(ctx context.Context) (*quic.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil, errors.New("prober closed")
	}
	if d.conn != nil && d.conn.Context().Err() == nil {
		return d.conn, nil
	}

	conn, err := quic.DialAddr(ctx, d.addr, d.tlsConfig, d.quicConfig)
	if err != nil {
		d.conn = nil
		return nil, fmt.Errorf("dial %s: %w", d.addr, err)
	}

	d.conn = conn
	return conn, nil
}

// discard drops conn if it is still the cached one and closes it.
func (d *doqProber) discard(conn *quic.Conn) {
	d.mu.Lock()
	if d.conn == conn {
		d.conn = nil
	}
	d.mu.Unlock()

	_ = conn.CloseWithError(quic.ApplicationErrorCode(0x0), "")
}

// doqExchange sends packed on a new bidirectional stream of conn and reads the
// length-prefixed response (RFC 9250, section 4.2).
func doqExchange(ctx context.Context, conn *quic.Conn, packed []byte) (*dns.Msg, error) {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}

	// If the caller gives up, tell the server that the response is no longer
	// needed instead of leaking the stream (RFC 9250, section 4.3.1).
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			stream.CancelWrite(quic.StreamErrorCode(doqErrorRequestCancelled))
			stream.CancelRead(quic.StreamErrorCode(doqErrorRequestCancelled))
		case <-stop:
		}
	}()

	buf := make([]byte, 2+len(packed))
	binary.BigEndian.PutUint16(buf, uint16(len(packed)))
	copy(buf[2:], packed)

	if _, err := stream.Write(buf); err != nil {
		return nil, fmt.Errorf("write query: %w", err)
	}
	// Signal the end of the query (RFC 9250, section 4.2).
	if err := stream.Close(); err != nil {
		return nil, fmt.Errorf("close stream: %w", err)
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	size := int(binary.BigEndian.Uint16(lenBuf[:]))
	if size == 0 {
		stream.CancelRead(quic.StreamErrorCode(doqErrorProtocol))
		return nil, errors.New("empty response")
	}

	body := make([]byte, size)
	if _, err := io.ReadFull(stream, body); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(body); err != nil {
		stream.CancelRead(quic.StreamErrorCode(doqErrorProtocol))
		return nil, fmt.Errorf("unpack: %w", err)
	}
	if resp.Id != doqMessageID {
		stream.CancelRead(quic.StreamErrorCode(doqErrorProtocol))
		return nil, fmt.Errorf("response has message ID %d, want %d", resp.Id, doqMessageID)
	}

	return resp, nil
}
