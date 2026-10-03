package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"time"

	"directssh.local/prototype/internal/prototype"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string, in io.Reader, out, log io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: directssh demo | forward --target 127.0.0.1:22 --listen 127.0.0.1:2222 | proxy --target 127.0.0.1:22")
	}
	mode := args[0]
	if mode != "demo" && mode != "forward" && mode != "proxy" {
		return fmt.Errorf("unknown command %q", mode)
	}
	f := flag.NewFlagSet(mode, flag.ContinueOnError)
	f.SetOutput(log)
	target := f.String("target", "", "fixed numeric-loopback TCP target")
	bind := f.String("listen", "127.0.0.1:2222", "loopback local forward listener")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if mode == "demo" {
		if *target != "" {
			return fmt.Errorf("demo always uses its own ephemeral echo fixture")
		}
		address, closeEcho, err := prototype.EchoTarget(ctx)
		if err != nil {
			return err
		}
		defer closeEcho()
		*target = address
	} else if *target == "" {
		return fmt.Errorf("--target is required; this does not enroll or change SSH authentication")
	}
	s, err := prototype.NewSession(ctx, *target)
	if err != nil {
		return err
	}
	defer s.Close()
	fmt.Fprintln(log, "DEV ONLY: ephemeral identities; loopback direct TCP/TLS; no hole punching, no relay; 30-second session deadline")
	switch mode {
	case "demo":
		c, err := s.Dial(ctx)
		if err != nil {
			return err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(prototype.Timeout))
		payload := "direct-only encrypted loopback demo\n"
		if _, err = io.WriteString(c, payload); err != nil {
			return err
		}
		buf := make([]byte, len(payload))
		if _, err = io.ReadFull(c, buf); err != nil {
			return err
		}
		if string(buf) != payload {
			return fmt.Errorf("payload mismatch")
		}
		fmt.Fprintln(out, "PASS: coordinator-discovered, mutually authenticated direct TLS echo; no relay")
		return nil
	case "forward":
		return s.Forward(ctx, *bind, func(address string) { fmt.Fprintln(log, "Listening:", address, "-> fixed target", *target) })
	case "proxy":
		ctx, end := context.WithTimeout(ctx, 30*time.Second)
		defer end()
		c, err := s.Dial(ctx)
		if err != nil {
			return err
		}
		defer c.Close()
		return proxy(ctx, c, in, out)
	}
	return nil
}

func proxy(ctx context.Context, c net.Conn, in io.Reader, out io.Writer) error {
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	inputDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(c, in)
		inputDone <- err
		if v, ok := c.(interface{ CloseWrite() error }); ok {
			v.CloseWrite()
		}
		if err != nil {
			c.Close()
		}
	}()
	outputDone := make(chan error, 1)
	go func() { _, err := io.Copy(out, c); outputDone <- err }()
	var err error
	// Inherited stdio descriptors may be uninterruptible. Return on cancellation;
	// the CLI process then exits, terminating any blocked stdio copy goroutine.
	select {
	case err = <-outputDone:
	case <-ctx.Done():
		return ctx.Err()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	select {
	case inputErr := <-inputDone:
		if inputErr != nil {
			return fmt.Errorf("STDIN_FAILED: %w", inputErr)
		}
	default:
	}
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return fmt.Errorf("SESSION_DEADLINE: %w", err)
		}
		return err
	}
	return nil
}
