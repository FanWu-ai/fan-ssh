// Package prototype is an intentionally loopback-only direct transport experiment.
package prototype

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const Timeout = 5 * time.Second
const maxMetadata = 4096

type Diagnostic struct {
	Code  string
	Cause error
}

func (e *Diagnostic) Error() string   { return e.Code + ": " + e.Cause.Error() }
func (e *Diagnostic) Unwrap() error   { return e.Cause }
func fail(code, message string) error { return &Diagnostic{code, errors.New(message)} }

// Identity is ephemeral test material; this package never persists credentials.
type Identity struct {
	Certificate tls.Certificate
	Pin         string
}

func NewIdentity(name string) (Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return Identity{}, err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return Identity{}, err
	}
	return Identity{tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, pin(der)}, nil
}
func pin(der []byte) string { sum := sha256.Sum256(der); return hex.EncodeToString(sum[:]) }
func config(id Identity, allowed map[string]bool, server bool) *tls.Config {
	c := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{id.Certificate}, InsecureSkipVerify: true} // Verification is replaced with exact certificate pin + validity below.
	if server {
		c.ClientAuth = tls.RequireAnyClientCert
	}
	c.VerifyConnection = func(s tls.ConnectionState) error {
		if len(s.PeerCertificates) != 1 {
			return fail("IDENTITY_REJECTED", "exactly one pinned certificate required")
		}
		cert := s.PeerCertificates[0]
		if !allowed[pin(cert.Raw)] {
			return fail("ACL_DENIED", "peer certificate not explicitly approved")
		}
		now := time.Now()
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return fail("IDENTITY_EXPIRED", "ephemeral identity expired")
		}
		return nil
	}
	return c
}

// LoopbackAddress accepts only numeric loopback literals, never DNS or wildcard binds.
func LoopbackAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fail("INVALID_ADDRESS", err.Error())
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fail("NON_LOOPBACK_DENIED", "v0 only accepts numeric loopback addresses")
	}
	p, err := net.LookupPort("tcp", port)
	if err != nil || p < 0 || p > 65535 || fmt.Sprint(p) != port {
		return fail("INVALID_PORT", "numeric TCP port required")
	}
	return nil
}
func listen(address string) (net.Listener, error) {
	if err := LoopbackAddress(address); err != nil {
		return nil, err
	}
	return net.Listen("tcp", address)
}
func dial(ctx context.Context, address string) (net.Conn, error) {
	if err := LoopbackAddress(address); err != nil {
		return nil, err
	}
	return (&net.Dialer{Timeout: Timeout}).DialContext(ctx, "tcp", address)
}

type Peer struct {
	ID        string `json:"id"`
	Address   string `json:"address"`
	Pin       string `json:"pin"`
	Transport string `json:"transport"`
}
type Coordinator struct {
	URL      string
	server   *http.Server
	listener net.Listener
}

// StartCoordinator freezes administrator-approved dev records. It has no data-plane route,
// registration API, HTTP CONNECT handler, body forwarding/storage or upstream dialer.
func StartCoordinator(id Identity, members map[string]Identity, records map[string]Peer, acl map[string]map[string]bool) (*Coordinator, error) {
	pins := map[string]bool{}
	names := map[string]string{}
	for name, m := range members {
		pins[m.Pin] = true
		names[m.Pin] = name
	}
	frozen := map[string]Peer{}
	for k, p := range records {
		if err := LoopbackAddress(p.Address); err != nil {
			return nil, err
		}
		frozen[k] = p
	}
	permissions := map[string]map[string]bool{}
	for k, v := range acl {
		permissions[k] = map[string]bool{}
		for p, b := range v {
			permissions[k][p] = b
		}
	}
	l, err := listen("127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "GET" || r.ContentLength != 0 || len(r.TransferEncoding) > 0 || r.URL.RawQuery != "" {
			http.Error(w, "metadata GET only", http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/v1/peers/") {
			http.NotFound(w, r)
			return
		}
		target := strings.TrimPrefix(r.URL.Path, "/v1/peers/")
		caller := names[pin(r.TLS.PeerCertificates[0].Raw)]
		if !permissions[caller][target] {
			http.Error(w, "ACL_DENIED", http.StatusForbidden)
			return
		}
		p, ok := frozen[target]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(p)
	})
	s := &http.Server{Handler: h, TLSConfig: config(id, pins, true), ReadHeaderTimeout: Timeout, ReadTimeout: Timeout, WriteTimeout: Timeout, IdleTimeout: Timeout, MaxHeaderBytes: 4096}
	c := &Coordinator{"https://" + l.Addr().String(), s, l}
	go s.Serve(tls.NewListener(l, s.TLSConfig))
	return c, nil
}
func (c *Coordinator) Close() { _ = c.server.Close(); _ = c.listener.Close() }
func Discover(ctx context.Context, base string, id Identity, coordinatorPin, target string) (Peer, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return Peer{}, fail("INVALID_COORDINATOR", "plain HTTPS origin required")
	}
	if err := LoopbackAddress(u.Host); err != nil {
		return Peer{}, err
	}
	tr := &http.Transport{TLSClientConfig: config(id, map[string]bool{coordinatorPin: true}, false), Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) { return dial(ctx, address) }}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect denied") }}
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/v1/peers/"+url.PathEscape(target), nil)
	if err != nil {
		return Peer{}, err
	}
	res, err := client.Do(req)
	if err != nil {
		return Peer{}, &Diagnostic{"CONTROL_UNREACHABLE", err}
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return Peer{}, fail("DISCOVERY_DENIED", res.Status)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxMetadata+1))
	if err != nil {
		return Peer{}, err
	}
	if len(data) > maxMetadata {
		return Peer{}, fail("METADATA_TOO_LARGE", "response exceeds limit")
	}
	var p Peer
	if err = json.Unmarshal(data, &p); err != nil {
		return Peer{}, err
	}
	if p.ID != target || p.Transport != "direct-tcp-tls" || len(p.Pin) != 64 {
		return Peer{}, fail("INVALID_METADATA", "unexpected peer metadata")
	}
	if err = LoopbackAddress(p.Address); err != nil {
		return Peer{}, err
	}
	return p, nil
}

type Tunnel struct {
	Address  string
	listener net.Listener
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func StartTunnel(ctx context.Context, address, target string, id Identity, approved map[string]bool) (*Tunnel, error) {
	if err := LoopbackAddress(target); err != nil {
		return nil, err
	}
	l, err := listen(address)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	context.AfterFunc(ctx, func() { l.Close() })
	immutable := map[string]bool{}
	for p, b := range approved {
		immutable[p] = b
	}
	cfg := config(id, immutable, true)
	t := &Tunnel{Address: l.Addr().String(), listener: l, cancel: cancel}
	slots := make(chan struct{}, 32)
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		for {
			raw, err := l.Accept()
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				raw.Close()
				continue
			}
			t.wg.Add(1)
			go func() {
				defer func() { <-slots }()
				defer t.wg.Done()
				defer raw.Close()
				stop := context.AfterFunc(ctx, func() { raw.Close() })
				defer stop()
				c := tls.Server(raw, cfg)
				_ = c.SetDeadline(time.Now().Add(Timeout))
				if c.HandshakeContext(ctx) != nil {
					return
				}
				_ = c.SetDeadline(time.Time{})
				up, err := dial(ctx, target)
				if err != nil {
					return
				}
				defer up.Close()
				_ = Bridge(ctx, c, up)
			}()
		}
	}()
	return t, nil
}
func (t *Tunnel) Close() { t.cancel(); _ = t.listener.Close(); t.wg.Wait() }
func Connect(ctx context.Context, p Peer, id Identity, approvedPin string) (*tls.Conn, error) {
	if p.Pin != approvedPin {
		return nil, fail("PIN_MISMATCH", "coordinator cannot change the approved destination identity")
	}
	raw, err := dial(ctx, p.Address)
	if err != nil {
		return nil, &Diagnostic{"NO_DIRECT_PATH", err}
	}
	c := tls.Client(raw, config(id, map[string]bool{approvedPin: true}, false))
	_ = c.SetDeadline(time.Now().Add(Timeout))
	if err = c.HandshakeContext(ctx); err != nil {
		c.Close()
		return nil, &Diagnostic{"PEER_AUTH_FAILED", err}
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

// Bridge has bounded copy buffers, propagates FIN/close_notify, and cancels both legs.
// Every session has an absolute 30-second deadline in this dev prototype.
func Bridge(ctx context.Context, a, b net.Conn) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { a.Close(); b.Close() })
	defer stop()
	_ = a.SetDeadline(time.Now().Add(30 * time.Second))
	_ = b.SetDeadline(time.Now().Add(30 * time.Second))
	results := make(chan error, 2)
	copyOne := func(dst, src net.Conn) {
		_, err := io.CopyBuffer(dst, src, make([]byte, 32*1024))
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		results <- err
	}
	go copyOne(a, b)
	go copyOne(b, a)
	first := <-results
	if first != nil {
		cancel()
	}
	second := <-results
	if first != nil {
		return first
	}
	return second
}
