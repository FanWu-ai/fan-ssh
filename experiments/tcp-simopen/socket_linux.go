//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
)

type socket struct {
	fd   int
	addr syscall.Sockaddr
	text string
}

func boundSocket(family string) (*socket, error) {
	domain := syscall.AF_INET
	var addr syscall.Sockaddr = &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}
	if family == "6" {
		domain = syscall.AF_INET6
		addr = &syscall.SockaddrInet6{Addr: [16]byte{15: 1}}
	} else if family != "4" {
		return nil, fmt.Errorf("invalid family")
	}
	fd, err := syscall.Socket(domain, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*socket, error) { syscall.Close(fd); return nil, err }
	if err = syscall.Bind(fd, addr); err != nil {
		return fail(err)
	}
	actual, err := syscall.Getsockname(fd)
	if err != nil {
		return fail(err)
	}
	var text string
	var port int
	switch a := actual.(type) {
	case *syscall.SockaddrInet4:
		port = a.Port
		text = net.JoinHostPort(net.IP(a.Addr[:]).String(), fmt.Sprint(port))
	case *syscall.SockaddrInet6:
		port = a.Port
		text = net.JoinHostPort(net.IP(a.Addr[:]).String(), fmt.Sprint(port))
	default:
		return fail(fmt.Errorf("unexpected address"))
	}
	if port < 1024 {
		return fail(fmt.Errorf("refusing allocated low port %d", port))
	}
	return &socket{fd, actual, text}, nil
}

// Completion requires getpeername success, not merely SO_ERROR == 0 on a pending socket.
func waitConnected(ctx context.Context, probe func() (bool, error)) error {
	timer := time.NewTicker(time.Millisecond)
	defer timer.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		ready, err := probe()
		if err != nil {
			return err
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}
func connect(ctx context.Context, s, peer *socket) (net.Conn, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "not attempted", err
	}
	err := syscall.Connect(s.fd, peer.addr)
	initial := errText(err)
	if err != nil && !errors.Is(err, syscall.EINPROGRESS) && !errors.Is(err, syscall.EALREADY) && !errors.Is(err, syscall.EINTR) {
		return nil, initial, err
	}
	err = waitConnected(ctx, func() (bool, error) {
		code, e := syscall.GetsockoptInt(s.fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
		if e != nil {
			return false, e
		}
		if code != 0 {
			return false, syscall.Errno(code)
		}
		_, e = syscall.Getpeername(s.fd)
		if errors.Is(e, syscall.ENOTCONN) {
			return false, nil
		}
		return e == nil, e
	})
	if err != nil {
		return nil, initial, err
	}
	// FileConn duplicates fd. Close only that duplicated File here; the original is owned by runTrial.
	dup, err := syscall.Dup(s.fd)
	if err != nil {
		return nil, initial, err
	}
	syscall.CloseOnExec(dup)
	file := os.NewFile(uintptr(dup), "so-socket")
	conn, err := net.FileConn(file)
	file.Close()
	return conn, initial, err
}
func roundtrip(ctx context.Context, a, b net.Conn) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return fmt.Errorf("bounded deadline required")
	}
	if err := a.SetDeadline(deadline); err != nil {
		return err
	}
	if err := b.SetDeadline(deadline); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { a.SetDeadline(time.Now()); b.SetDeadline(time.Now()) })
	defer stop()
	payload := bytes.Repeat([]byte("SO-loopback-diagnostic-only\x00"), 128)
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, len(payload))
		_, err := io.ReadFull(b, buf)
		if err == nil && !bytes.Equal(buf, payload) {
			err = fmt.Errorf("payload mismatch")
		}
		if err == nil {
			_, err = b.Write(buf)
		}
		done <- err
	}()
	_, err := a.Write(payload)
	if err == nil {
		buf := make([]byte, len(payload))
		_, err = io.ReadFull(a, buf)
		if err == nil && !bytes.Equal(buf, payload) {
			err = fmt.Errorf("echo mismatch")
		}
	}
	if err != nil {
		a.SetDeadline(time.Now())
		b.SetDeadline(time.Now())
	}
	other := <-done
	if err != nil {
		return err
	}
	return other
}
func runTrial(ctx context.Context, family string) (r Result) {
	start := time.Now()
	r.Family = family
	defer func() { r.DurationUS = time.Since(start).Microseconds() }()
	if ctx.Err() != nil {
		r.Error = ctx.Err().Error()
		return
	}
	a, err := boundSocket(family)
	if err != nil {
		r.Error = "bind A: " + err.Error()
		return
	}
	defer syscall.Close(a.fd)
	b, err := boundSocket(family)
	if err != nil {
		r.Error = "bind B: " + err.Error()
		return
	}
	defer syscall.Close(b.fd)
	if a.text == b.text {
		r.Error = "distinct port invariant failed"
		return
	}
	r.A.Local = a.text
	r.A.Remote = b.text
	r.B.Local = b.text
	r.B.Remote = a.text
	var ready, finished sync.WaitGroup
	ready.Add(2)
	finished.Add(2)
	goNow := make(chan struct{})
	var ac, bc net.Conn
	worker := func(s, p *socket, out *Endpoint, c *net.Conn) {
		defer finished.Done()
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		ready.Done()
		<-goNow
		beg := time.Now()
		out.StartUS = beg.Sub(start).Microseconds()
		var err error
		*c, out.Initial, err = connect(ctx, s, p)
		out.DurationUS = time.Since(beg).Microseconds()
		out.Error = errText(err)
	}
	go worker(a, b, &r.A, &ac)
	go worker(b, a, &r.B, &bc)
	ready.Wait()
	close(goNow)
	finished.Wait()
	if ac != nil {
		defer ac.Close()
	}
	if bc != nil {
		defer bc.Close()
	}
	if ac == nil || bc == nil {
		r.Error = "one or both active connects failed"
		return
	}
	if ac.LocalAddr().String() != a.text || ac.RemoteAddr().String() != b.text || bc.LocalAddr().String() != b.text || bc.RemoteAddr().String() != a.text {
		r.Error = "connected tuple mismatch"
		return
	}
	err = roundtrip(ctx, ac, bc)
	r.Error = errText(err)
	r.Verified = err == nil
	return
}
