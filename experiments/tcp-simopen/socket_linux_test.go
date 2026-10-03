//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestBoundLoopbackOnly(t *testing.T) {
	for _, f := range []string{"4", "6"} {
		t.Run(f, func(t *testing.T) {
			s, e := boundSocket(f)
			if e != nil {
				if f == "6" {
					t.Skipf("IPv6 unavailable: %v", e)
				}
				t.Fatal(e)
			}
			defer syscall.Close(s.fd)
			host, _, e := net.SplitHostPort(s.text)
			if e != nil || !net.ParseIP(host).IsLoopback() {
				t.Fatalf("unsafe bind: %s", s.text)
			}
			s2, e := boundSocket(f)
			if e != nil {
				t.Fatal(e)
			}
			defer syscall.Close(s2.fd)
			if s.text == s2.text {
				t.Fatal("ports not distinct")
			}
		})
	}
	if _, e := boundSocket("external"); e == nil {
		t.Fatal("bad family accepted")
	}
}
func TestNegativeNoPeerConnect(t *testing.T) {
	a, e := boundSocket("4")
	if e != nil {
		t.Fatal(e)
	}
	defer syscall.Close(a.fd)
	b, e := boundSocket("4")
	if e != nil {
		t.Fatal(e)
	}
	defer syscall.Close(b.fd)
	ctx, c := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer c()
	conn, initial, e := connect(ctx, a, b)
	if conn != nil {
		conn.Close()
		t.Fatal("bound nonconnecting peer unexpectedly connected")
	}
	if e == nil {
		t.Fatal("expected refusal or timeout")
	}
	t.Logf("negative: initial=%s final=%v", initial, e)
}
func TestCanceledAndExpiredBeforeTrial(t *testing.T) {
	ctx, c := context.WithCancel(context.Background())
	c()
	if r := runTrial(ctx, "4"); r.Verified || !strings.Contains(r.Error, "canceled") {
		t.Fatalf("%+v", r)
	}
	ctx, c = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer c()
	if r := runTrial(ctx, "4"); r.Verified || !strings.Contains(r.Error, "deadline") {
		t.Fatalf("%+v", r)
	}
}
func TestCompletionWaitBounds(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		ctx, c := context.WithTimeout(context.Background(), 5*time.Millisecond)
		defer c()
		e := waitConnected(ctx, func() (bool, error) { return false, nil })
		if !errors.Is(e, context.DeadlineExceeded) {
			t.Fatal(e)
		}
	})
	t.Run("cancel in progress", func(t *testing.T) {
		ctx, c := context.WithCancel(context.Background())
		e := waitConnected(ctx, func() (bool, error) { c(); return false, nil })
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	})
	t.Run("error", func(t *testing.T) {
		e := waitConnected(context.Background(), func() (bool, error) { return false, syscall.ECONNREFUSED })
		if !errors.Is(e, syscall.ECONNREFUSED) {
			t.Fatal(e)
		}
	})
}
func TestPayloadTimeoutAndCancellation(t *testing.T) {
	// Pipes deliberately have unmatched readers, to exercise timeout without external blackholes.
	for _, cancelNow := range []bool{false, true} {
		a, unusedA := net.Pipe()
		b, unusedB := net.Pipe()
		ctx, c := context.WithTimeout(context.Background(), 10*time.Millisecond)
		if cancelNow {
			c()
		}
		start := time.Now()
		e := roundtrip(ctx, a, b)
		c()
		a.Close()
		b.Close()
		unusedA.Close()
		unusedB.Close()
		if e == nil {
			t.Fatal("stalled payload accepted")
		}
		if time.Since(start) > time.Second {
			t.Fatal("deadline failed")
		}
	}
}
func TestRepeatTrialsAndDescriptorCleanup(t *testing.T) {
	baseline, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		t.Fatal(e)
	}
	for _, family := range []string{"4", "6"} {
		success := 0
		for i := 0; i < 100; i++ {
			ctx, c := context.WithTimeout(context.Background(), 50*time.Millisecond)
			r := runTrial(ctx, family)
			c()
			if r.Verified {
				success++
				if r.A.Local != r.B.Remote || r.B.Local != r.A.Remote || r.A.Local == r.B.Local || r.Error != "" {
					t.Fatalf("bad successful tuple: %+v", r)
				}
			}
		}
		// Zero successes is a legitimate kernel/scheduling observation, not a test failure.
		t.Logf("family %s: verified %d/100; no listener", family, success)
	}
	after, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		t.Fatal(e)
	}
	// Go may lazily create one epoll + one eventfd for net.FileConn.
	if len(after) > len(baseline)+2 {
		t.Fatalf("descriptor growth: %d -> %d", len(baseline), len(after))
	}
}
