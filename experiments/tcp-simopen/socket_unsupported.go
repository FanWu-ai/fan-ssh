//go:build !linux

package main

import "context"

func runTrial(ctx context.Context, family string) Result {
	return Result{Family: family, Error: "TCP_SO_SOCKET_UNSUPPORTED: only Linux adapter implemented; cross-compilation does not validate runtime"}
}
