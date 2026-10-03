# Bounded TCP simultaneous-open diagnostic

Local socket feasibility experiment, isolated from the main fan-ssh prototype. No network address argument exists: sockets bind only `127.0.0.1` or `::1` and connect only to the other socket's allocated high port. Run as an ordinary user. No listener, accept, reuse-address/reuse-port option, firewall/sysctl change, root, packet capture, credential, deployment, NAT or external probe is used.

## Observed result (2026-10-03 UTC)

Linux 6.18.44 amd64, uid 1000; official Go 1.27.1 toolchain:

- Initial 100 trials: 14 payload-verified connects.
- Separate recorded 400-trial run: IPv4 30/200, IPv6 33/200, total 63/400 verified payload echoes.
- Other trials ended with refusal or bounded deadline. These are expected observations, not hidden retry successes.
- `go test -race -count=1 -v ./...`: passed. This independently reported 15/100 IPv4 and 9/100 IPv6 successes.
- `go test -race -count=10 ./...`: passed (2,000 additional bounded trial attempts plus controls; pass does not require any specific socket success rate).
- `go vet ./...`: passed.
- Linux, Windows and macOS amd64 builds: passed. Windows/macOS use explicit `TCP_SO_SOCKET_UNSUPPORTED` stubs; no runtime validation was performed there.

Historical observations: [test-results/history/tcp-simopen](../../test-results/history/tcp-simopen). Fresh consolidated checks are described in [VALIDATION.md](../../VALIDATION.md). The JSON lists allocated and verified peer tuples, initial connect errno, completion error, monotonic start offsets/durations, and echo result. No endpoint identification or authentication is attempted; payload is a fixed diagnostic string, never SSH data.

## What the experiment establishes

Two separate TCP sockets are prebound and held simultaneously on distinct loopback ephemeral high ports. Each pinned OS-thread worker waits at one barrier, then initiates an outbound nonblocking `connect` toward the other's exact tuple. Completion requires both `SO_ERROR == 0` and a successful `getpeername`, then matching endpoint tuples after conversion to Go connections. There is no passive listener fallback. An exact 3,584-byte payload is read and echoed byte-for-byte over a successful pair. Success therefore demonstrates the Linux local active/active socket primitive in this environment.

This is not NAT traversal, an ICE implementation, a hard-NAT capability, authenticated peer connectivity, or proof that real networks permit crossing SYNs. No packet trace was collected. In particular, no coordinator-observed mapping, same-port observation-connection coexistence, destination-dependent mapping, interface change, or cross-process ownership race was tested. Fresh ephemeral binds avoid deliberately reusing TIME_WAIT ports; reuse viability is untested.

Loopback SYN arrival is faster than typical network delay. The barrier does not force simultaneous kernel processing; one SYN can arrive before its counterpart has begun connecting and elicit refusal. Observed percentages are scheduler/environment-specific, not predicted NAT success rates. An unsuccessful bounded attempt does not prove all direct TCP approaches impossible.

## Reproduce

From this directory, with Go installed on PATH:

```sh
export GOTOOLCHAIN=local
export GOCACHE="${TMPDIR:-/tmp}/fan-ssh-go-cache"
go test -race -count=1 -v ./...
go test -race -count=10 ./...
go vet ./...
mkdir -p build
for os in linux windows darwin; do
  GOOS=$os GOARCH=amd64 go build -buildvcs=false -o build/so-diagnostic-$os-amd64 .
done
./build/so-diagnostic-linux-amd64 -trials 200 -timeout 200ms -budget 20s
```

`-family 4`, `-family 6`, or `-family both` (default); 1–500 trials per family; 1 ms–5 s per trial; 1 ms–60 s total budget. Default 50 trials per family, 200 ms each, 20 s total. Exit 0 means at least one verified local pair, not full success; inspect summary for budget exhaustion. Exit 1 means no verified local pair; exit 2 means invalid arguments. Unsupported runtime emits explicit per-trial errors and exit 1. IPv6 absence is an observed bind error; the test skips only its bind-capability subtest, and repeated diagnostic results remain failed/unverified.

No external dependencies or downloads are needed to build when Go is installed. Build outputs are ignored by Git.

## Negative and lifecycle coverage

- Bound peer that never connects: refusal or timeout; must not yield a connection.
- Invalid address-family selector: rejected before socket creation.
- Pre-canceled and pre-expired trial: rejected before bind.
- Pending-connect completion poll: deterministic synthetic not-ready probe times out or cancels; direct errno propagation checked. This is state-machine coverage, not a claim to create a real blackholed network.
- Payload timeout/cancellation: unmatched local in-memory pipes deliberately stall; bounded error required. These test I/O cancellation, not TCP behavior.
- 100 real socket attempts per family per suite: no false success tuple, no descriptor growth beyond Go's initial poller descriptors.
- Successful real pairs perform an exact payload echo. Repeat tests do not demand success under every scheduler/kernel; observations must be inspected separately.

## Definition and next research gate

RFC 6544 section 3 distinguishes active outbound-only, passive incoming, and simultaneous-open candidates. Active pairs with passive; simultaneous-open pairs with simultaneous-open. A successful listener/accept path would not validate this experiment's active/active primitive. Appendix A/B discusses limits and BSD socket considerations: https://www.rfc-editor.org/rfc/rfc6544.html#section-3

A future separately authorized campaign needs named consenting endpoints on independently routed networks, exact source/observed/peer tuples, relevant OS runtimes, controlled timing, and owner-approved NAT/firewall lab changes if any. Mapping acquisition from the intended local binding and coexistence of observation and peer sockets require separate tests; this harness deliberately does not implement permissive reuse. Evaluate verified direct stream identity before SSH, fail closed with no relay, and report each tested combination honestly.
