package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"
)

type Endpoint struct {
	Local      string `json:"local"`
	Remote     string `json:"remote"`
	StartUS    int64  `json:"connect_start_us"`
	DurationUS int64  `json:"connect_duration_us"`
	Initial    string `json:"initial_connect_result"`
	Error      string `json:"error,omitempty"`
}
type Result struct {
	Family     string   `json:"family"`
	Trial      int      `json:"trial"`
	A          Endpoint `json:"a"`
	B          Endpoint `json:"b"`
	Verified   bool     `json:"payload_roundtrip_verified"`
	Error      string   `json:"error,omitempty"`
	DurationUS int64    `json:"duration_us"`
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
func main() {
	n := flag.Int("trials", 50, "trials per family (1..500)")
	d := flag.Duration("timeout", 200*time.Millisecond, "per trial timeout (1ms..5s)")
	total := flag.Duration("budget", 20*time.Second, "total runtime budget (1ms..60s)")
	family := flag.String("family", "both", "4, 6, or both; loopback only")
	flag.Parse()
	if *n < 1 || *n > 500 || *d < time.Millisecond || *d > 5*time.Second || *total < time.Millisecond || *total > 60*time.Second || (*family != "4" && *family != "6" && *family != "both") || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "invalid bounded diagnostic arguments")
		os.Exit(2)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.Encode(map[string]any{"kind": "environment", "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "loopback_only": true, "listener_used": false, "nat_traversal_proven": false, "socket_options_changed": false})
	ctx, cancel := context.WithTimeout(context.Background(), *total)
	defer cancel()
	families := []string{"4", "6"}
	if *family != "both" {
		families = []string{*family}
	}
	successes, attempts := 0, 0
	for _, f := range families {
		for i := 0; i < *n && ctx.Err() == nil; i++ {
			c, stop := context.WithTimeout(ctx, *d)
			r := runTrial(c, f)
			stop()
			r.Trial = i + 1
			enc.Encode(r)
			attempts++
			if r.Verified {
				successes++
			}
		}
	}
	enc.Encode(map[string]any{"kind": "summary", "attempts": attempts, "verified": successes, "budget_error": errText(ctx.Err()), "claim": "socket feasibility only; no NAT tested"})
	if successes == 0 {
		os.Exit(1)
	}
}
