package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDemo(t *testing.T) {
	var out, log bytes.Buffer
	if e := run([]string{"demo"}, strings.NewReader(""), &out, &log); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "PASS:") {
		t.Fatal(out.String())
	}
}
func TestProxyStdoutContainsOnlyPayload(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = ctx
	go func() {
		c, e := l.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()
	var out, log bytes.Buffer
	payload := "SSH-2.0-test\r\n"
	if e := run([]string{"proxy", "--target", l.Addr().String()}, strings.NewReader(payload), &out, &log); e != nil {
		t.Fatal(e)
	}
	if out.String() != payload {
		t.Fatalf("stdout polluted: %q", out.String())
	}
	if log.Len() == 0 {
		t.Fatal("missing stderr diagnostic")
	}
}

type failedReader struct{ err error }

func (r failedReader) Read([]byte) (int, error) { return 0, r.err }
func TestProxyInputError(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	sentinel := errors.New("input failed")
	e := proxy(context.Background(), a, failedReader{sentinel}, io.Discard)
	if !errors.Is(e, sentinel) {
		t.Fatalf("lost input error: %v", e)
	}
}
func TestProxyCancelBlockedStdout(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	out, unread := net.Pipe()
	defer out.Close()
	defer unread.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- proxy(ctx, a, strings.NewReader(""), out) }()
	go b.Write([]byte("blocked output"))
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("stdout cancellation stalled")
	}
}
