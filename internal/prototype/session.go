package prototype

import (
	"context"
	"io"
	"net"
	"sync"
)

// Session provisions two synthetic approved devices and a coordinator in memory.
// There is deliberately no persisted enrollment or real-device management API.
type Session struct {
	Client      Identity
	Peer        Peer
	Coordinator *Coordinator
	Tunnel      *Tunnel
	cancel      context.CancelFunc
}

func NewSession(ctx context.Context, target string) (*Session, error) {
	ctx, cancel := context.WithCancel(ctx)
	ok := false
	defer func() {
		if !ok {
			cancel()
		}
	}()
	client, err := NewIdentity("dev-client")
	if err != nil {
		return nil, err
	}
	server, err := NewIdentity("dev-target")
	if err != nil {
		return nil, err
	}
	coord, err := NewIdentity("dev-coordinator")
	if err != nil {
		return nil, err
	}
	tunnel, err := StartTunnel(ctx, "127.0.0.1:0", target, server, map[string]bool{client.Pin: true})
	if err != nil {
		return nil, err
	}
	record := Peer{"dev-target", tunnel.Address, server.Pin, "direct-tcp-tls"}
	c, err := StartCoordinator(coord, map[string]Identity{"dev-client": client, "dev-target": server}, map[string]Peer{"dev-target": record}, map[string]map[string]bool{"dev-client": {"dev-target": true}})
	if err != nil {
		tunnel.Close()
		return nil, err
	}
	discovered, err := Discover(ctx, c.URL, client, coord.Pin, "dev-target")
	if err != nil {
		c.Close()
		tunnel.Close()
		return nil, err
	}
	if discovered.Pin != server.Pin {
		c.Close()
		tunnel.Close()
		return nil, fail("PIN_MISMATCH", "approved local pin differs")
	}
	ok = true
	return &Session{client, discovered, c, tunnel, cancel}, nil
}
func (s *Session) Close() { s.cancel(); s.Coordinator.Close(); s.Tunnel.Close() }
func (s *Session) Dial(ctx context.Context) (net.Conn, error) {
	return Connect(ctx, s.Peer, s.Client, s.Peer.Pin)
}
func (s *Session) Forward(ctx context.Context, address string, ready func(string)) error {
	l, err := listen(address)
	if err != nil {
		return err
	}
	defer l.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	slots := make(chan struct{}, 32)
	ready(l.Addr().String())
	for {
		a, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			a.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer func() { <-slots }()
			defer wg.Done()
			defer a.Close()
			b, err := s.Dial(ctx)
			if err != nil {
				return
			}
			defer b.Close()
			_ = Bridge(ctx, a, b)
		}()
	}
}

// EchoTarget is only a test fixture, never an SSH implementation.
func EchoTarget(ctx context.Context) (string, func(), error) {
	l, err := listen("127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				stop := context.AfterFunc(ctx, func() { c.Close() })
				defer stop()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return l.Addr().String(), func() { cancel(); l.Close(); wg.Wait() }, nil
}
