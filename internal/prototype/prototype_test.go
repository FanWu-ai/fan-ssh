package prototype

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func identity(t *testing.T) Identity {
	t.Helper()
	i, e := NewIdentity(t.Name())
	if e != nil {
		t.Fatal(e)
	}
	return i
}
func session(t *testing.T) *Session {
	t.Helper()
	ctx := context.Background()
	target, closeTarget, e := EchoTarget(ctx)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(closeTarget)
	s, e := NewSession(ctx, target)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	return s
}
func TestLoopbackRestrictions(t *testing.T) {
	for _, a := range []string{"0.0.0.0:22", "[::]:22", "localhost:22", "example.org:22", "192.168.1.1:22", "[fe80::1%eth0]:22", "127.0.0.1:http", "127.0.0.1:-1", "127.0.0.1:65536"} {
		if LoopbackAddress(a) == nil {
			t.Errorf("accepted %q", a)
		}
	}
	for _, a := range []string{"127.0.0.1:0", "127.0.0.2:22", "[::1]:22"} {
		if e := LoopbackAddress(a); e != nil {
			t.Error(e)
		}
	}
}
func TestEndToEndConcurrentLargePayload(t *testing.T) {
	s := session(t)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, e := s.Dial(context.Background())
			if e != nil {
				t.Error(e)
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(Timeout))
			want := bytes.Repeat([]byte("SSH-shaped opaque bytes\x00\xff"), 6000)
			done := make(chan error, 1)
			go func() { _, e := c.Write(want); done <- e }()
			got := make([]byte, len(want))
			_, e = io.ReadFull(c, got)
			if e != nil {
				t.Error(e)
				return
			}
			if !bytes.Equal(got, want) {
				t.Error("payload mismatch")
			}
			if e = <-done; e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
}
func TestCoordinatorNoRelayAndDirectionalACL(t *testing.T) {
	a, b, coord := identity(t), identity(t), identity(t)
	acl := map[string]map[string]bool{"a": {"b": true}}
	records := map[string]Peer{"b": {"b", "127.0.0.1:12345", b.Pin, "direct-tcp-tls"}}
	c, e := StartCoordinator(coord, map[string]Identity{"a": a, "b": b}, records, acl)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	acl["a"]["b"] = false
	records["b"] = Peer{} // snapshot, not caller-mutable
	if _, e := Discover(context.Background(), c.URL, a, coord.Pin, "b"); e != nil {
		t.Fatal(e)
	}
	if _, e := Discover(context.Background(), c.URL, b, coord.Pin, "a"); e == nil {
		t.Fatal("reverse ACL accepted")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: config(a, map[string]bool{coord.Pin: true}, false)}, Timeout: Timeout}
	defer client.CloseIdleConnections()
	for _, method := range []string{"POST", "PUT", "CONNECT", "PATCH"} {
		req, _ := http.NewRequest(method, c.URL+"/v1/peers/b", strings.NewReader("business data"))
		res, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		if res.StatusCode == 200 {
			t.Errorf("accepted %s", method)
		}
	}
	req, _ := http.NewRequest("GET", c.URL+"/v1/peers/b", strings.NewReader("payload"))
	res, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode == 200 {
		t.Fatal("GET body accepted")
	}
	if _, e := Discover(context.Background(), c.URL, identity(t), coord.Pin, "b"); e == nil {
		t.Fatal("unapproved coordinator identity accepted")
	}
}
func TestUnauthorizedPeerCannotReachTarget(t *testing.T) {
	target, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	server, allowed, attacker := identity(t), identity(t), identity(t)
	tun, e := StartTunnel(context.Background(), "127.0.0.1:0", target.Addr().String(), server, map[string]bool{allowed.Pin: true})
	if e != nil {
		t.Fatal(e)
	}
	defer tun.Close()
	p := Peer{"target", tun.Address, server.Pin, "direct-tcp-tls"}
	c, e := Connect(context.Background(), p, attacker, server.Pin)
	if e == nil {
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		_, _ = c.Write([]byte("attack"))
		_, e = c.Read(make([]byte, 1))
		if e == nil {
			t.Fatal("unapproved peer accepted")
		}
	}
	target.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond))
	if c, e := target.Accept(); e == nil {
		c.Close()
		t.Fatal("target dialed before authorization")
	}
}
func TestPinnedPeerRejectsCoordinatorSubstitution(t *testing.T) {
	s := session(t)
	p := s.Peer
	p.Pin = identity(t).Pin
	if _, e := Connect(context.Background(), p, s.Client, s.Peer.Pin); e == nil {
		t.Fatal("substitution accepted")
	}
}
func TestWrongServerPinFailsTLS(t *testing.T) {
	s := session(t)
	wrong := identity(t).Pin
	p := s.Peer
	p.Pin = wrong
	if _, e := Connect(context.Background(), p, s.Client, wrong); e == nil {
		t.Fatal("wrong server pin accepted")
	}
}
func TestNoArbitraryDestination(t *testing.T) {
	_, e := StartTunnel(context.Background(), "127.0.0.1:0", "8.8.8.8:22", identity(t), nil)
	if e == nil {
		t.Fatal("non-loopback target accepted")
	}
	s := session(t)
	c, e := s.Dial(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	payload := []byte("CONNECT 8.8.8.8:22 HTTP/1.1\r\n\r\n")
	c.SetDeadline(time.Now().Add(Timeout))
	c.Write(payload)
	got := make([]byte, len(payload))
	if _, e = io.ReadFull(c, got); e != nil || !bytes.Equal(payload, got) {
		t.Fatalf("bytes interpreted instead of fixed-target opaque forwarding: %v", e)
	}
}
func TestHalfClosePreservesResponse(t *testing.T) {
	ctx := context.Background()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	go func() {
		c, e := l.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		p, _ := io.ReadAll(c)
		c.Write(append([]byte("response:"), p...))
	}()
	s, e := NewSession(ctx, l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	c, e := s.Dial(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(Timeout))
	c.Write([]byte("request"))
	c.(*tls.Conn).CloseWrite()
	got, e := io.ReadAll(c)
	if e != nil || string(got) != "response:request" {
		t.Fatalf("%q %v", got, e)
	}
}
func TestCancelBackpressure(t *testing.T) {
	a, client := net.Pipe()
	b, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Bridge(ctx, a, b) }()
	go client.Write(bytes.Repeat([]byte("x"), 1<<20))
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("bridge leaked under cancellation/backpressure")
	}
}
func TestTunnelCloseCancelsIncompleteHandshake(t *testing.T) {
	s := session(t)
	c, e := net.Dial("tcp", s.Tunnel.Address)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	done := make(chan struct{})
	go func() { s.Tunnel.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close did not cancel handshake")
	}
}
func TestDirectIPv6Loopback(t *testing.T) {
	l, e := net.Listen("tcp", "[::1]:0")
	if e != nil {
		t.Skipf("IPv6 unavailable: %v", e)
	}
	defer l.Close()
	go func() {
		c, e := l.Accept()
		if e == nil {
			defer c.Close()
			io.Copy(c, c)
		}
	}()
	server, client := identity(t), identity(t)
	tun, e := StartTunnel(context.Background(), "[::1]:0", l.Addr().String(), server, map[string]bool{client.Pin: true})
	if e != nil {
		t.Fatal(e)
	}
	defer tun.Close()
	p := Peer{"v6", tun.Address, server.Pin, "direct-tcp-tls"}
	c, e := Connect(context.Background(), p, client, server.Pin)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(Timeout))
	c.Write([]byte("ipv6"))
	b := make([]byte, 4)
	if _, e = io.ReadFull(c, b); e != nil || string(b) != "ipv6" {
		t.Fatal(e)
	}
}

func TestMetadataResponseBound(t *testing.T) {
	coord, client := identity(t), identity(t)
	l, e := listen("127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, strings.Repeat("x", maxMetadata+1)) })}
	defer srv.Close()
	go srv.Serve(tls.NewListener(l, config(coord, map[string]bool{client.Pin: true}, true)))
	_, e = Discover(context.Background(), "https://"+l.Addr().String(), client, coord.Pin, "target")
	if e == nil || !strings.Contains(e.Error(), "METADATA_TOO_LARGE") {
		t.Fatalf("oversized metadata not rejected: %v", e)
	}
}

func TestParentCancelClosesTunnelListener(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	i := identity(t)
	tun, e := StartTunnel(ctx, "127.0.0.1:0", "127.0.0.1:12345", i, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tun.Close()
	cancel()
	done := make(chan struct{})
	go func() { tun.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("listener not closed on context cancellation")
	}
	if c, e := net.DialTimeout("tcp", tun.Address, time.Second); e == nil {
		c.Close()
		t.Fatal("listener still open")
	}
}

func TestLocalForwardAndCancellation(t *testing.T) {
	s := session(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() { done <- s.Forward(ctx, "127.0.0.1:0", func(a string) { ready <- a }) }()
	var address string
	select {
	case address = <-ready:
	case <-time.After(time.Second):
		t.Fatal("forward did not start")
	}
	c, e := net.DialTimeout("tcp", address, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(Timeout))
	c.Write([]byte("forward"))
	b := make([]byte, 7)
	if _, e = io.ReadFull(c, b); e != nil || string(b) != "forward" {
		t.Fatalf("forward failed %q %v", b, e)
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("forward did not shut down")
	}
}
