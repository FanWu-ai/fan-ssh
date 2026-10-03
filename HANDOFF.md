# fan-ssh development handoff

## Product goal

Build an ordinary-user, many-to-many SSH connectivity tool for Windows, macOS and Linux devices on different LANs. A peer can initiate and receive multiple concurrent sessions. Normal use must not require administrator privileges, TUN/TAP, kernel drivers, route changes or automatic firewall changes.

The central difficult requirement is **UDP blocked while both peers are behind complex NAT**. This is a research target, not a solved capability or a promise every network can be traversed. Some network policies offer no allowed direct path; report that honestly.

A public coordination service is permitted for bounded control-plane information only: enrollment, authentication, ACL decisions, candidates, observations and scheduling. **All SSH/business bytes must travel directly between the two endpoints.** No TURN, STCP, DERP, HTTP CONNECT, WebSocket data relay, third-peer forwarding or silent proxy fallback. Ordinary Internet routing/NAT is not an application relay.

Keep three independent layers explicit:

1. Device key identity and authenticated transport.
2. Directed device/service ACLs and independently checked admission.
3. Existing SSH host-key verification and OS-user authentication.

Joining the overlay does not grant an SSH login. Preserve verified host keys, use a stable HostKeyAlias, and never disable StrictHostKeyChecking or silently forward ssh-agent. An existing authorized SSH server is currently a prerequisite for real SSH use. Installing/enabling a system sshd can require administrator rights, especially on Windows; binary portability does not solve that prerequisite.

## What is implemented

The root module has a small dependency-free Go CLI named `directssh`. Every run creates ephemeral synthetic identities and a fixture coordinator in the same process. All listeners and destinations are numeric loopback only. Exact certificate pins are independently provisioned; directed ACL snapshots control discovery and the receiver checks the approved client before connecting to its fixed loopback service. It supports opaque byte transfer, bounded concurrent forwarding and clean ProxyCommand stdout. Data sessions have a fixed 30-second deadline.

There are no real enrolled devices, persistent trust store, public listener, signed tickets, live ACL updates/revocation, leases, candidate racing, reverse dialing, UDP/ICE/STUN, TCP mapping acquisition or NAT traversal in the CLI.

`experiments/tcp-simopen/` is a separate dependency-free Go module. Linux uses two outbound-only, prebound loopback TCP sockets and verifies exact tuples and payload echo without a listener/accept fallback. Windows/macOS deliberately return `TCP_SO_SOCKET_UNSUPPORTED`. This is not an authenticated transport or part of the main CLI; local successes do not establish NAT traversal. All reported success rates are environment-specific observations.

## Starting locally

Use Go 1.25+ on PATH (recorded validation used Go 1.27.1). Race tests require a supported native C toolchain. Python 3 is needed only for the Linux CLI cancellation regression. Neither module needs external Go dependencies. Read README.md, VALIDATION.md and ARCHITECTURE.md before changing the safety boundaries.

```sh
# Root module
export GOTOOLCHAIN=local
# Optional when the default cache location is not writable:
export GOCACHE="${TMPDIR:-/tmp}/fan-ssh-go-cache"
go test -race -count=3 -v ./...
go vet ./...
mkdir -p dist
CGO_ENABLED=0 go build -buildvcs=false -trimpath -o dist/directssh-linux-amd64 ./cmd/directssh
./dist/directssh-linux-amd64 demo
# Linux only; uses the binary at the path built above:
python3 scripts/test_blocked_stdout.py

# Separate module: it is NOT included by root go test ./...
(cd experiments/tcp-simopen && go test -race -count=1 -v ./... && go vet ./...)
(cd experiments/tcp-simopen && go run . -trials 50 -timeout 200ms -budget 20s)
```

The diagnostic exits 0 if at least one pair was verified and 1 if none were; both are legitimate bounded experimental observations. Inspect its JSON summary and budget field rather than treating the exit status as a general network verdict. Windows/macOS runtime use of this experiment remains unsupported.

## Recommended next work and acceptance gates

1. **Design real enrollment/admission before exposing endpoints.** Local key generation and proof of possession; operator-approved enrollment; secure user-owned key storage; explicit trust rotation; account isolation; bounded, session-bound messages; directed service ACLs. Never send private keys to the coordinator. Add negative/replay/expiry/revocation tests. This is design work first: persistent credentials and deployment need explicit authorization.
2. **Introduce transport candidates and typed diagnostics.** Direct TCP IPv4/IPv6 in both directions, bounded candidate racing, selected endpoint evidence, cancellation and backpressure. Keep candidate counts/scopes bounded to consenting peers; reject arbitrary destinations and relay paths before service bytes. Add Pion direct UDP only as an additional path, with pinned dependencies, no TURN and explicit message-to-stream framing.
3. **Develop safe platform-specific TCP socket adapters.** Preserve the current Linux diagnostic as a baseline. Test source binding and observation/peer-connection coexistence, cancellation, TIME_WAIT, port ownership and interface changes. Do not copy permissive Linux reuse flags onto Windows. A listener/accept success is not evidence of active/active simultaneous-open. Unsupported safe combinations must fail explicitly.
4. **Run an explicitly authorized two-network campaign.** Use consenting, independently routed endpoints and an approved coordinator. Collect exact local/observed/peer tuples, OS/runtime, timing, selected transport and authenticated payload evidence. Compare all nine ordered Windows/macOS/Linux pairs, UDP-blocked conditions, IPv4 NAT, filtered IPv6, double NAT/CGN and endpoint-dependent mappings. Test rate/budget limits, denials, coordinator loss, clock skew, sleep/resume and network changes. Router/firewall changes, packet capture and network labs need separate scope/permission. Do not use arbitrary public hosts for probing.
5. **Only then harden demonstrated paths.** Establish long-session lease/revocation behavior, service allowlists, shutdown and concurrency limits; test real SSH independently. If zero pre-existing sshd becomes mandatory, scope a current-user embedded server separately, without privilege escalation or arbitrary user impersonation. Interactive PTY/ConPTY compatibility is a separate project gate.

## Verification and security reminders

- Current results are Linux loopback runtime evidence. Windows/macOS and other architectures have compile evidence only; they have not passed runtime tests.
- Root code intentionally replaces default TLS CA/name validation with exact pin and certificate-validity validation. Do not remove the replacement verifier or reuse this configuration for normal HTTPS.
- Current metadata validation and fixed ACL fixtures are not a production enrollment/security protocol.
- Local-forward ports can be reached by other local processes; SSH authentication is still required. Prefer ProxyCommand for eventual user-facing operation.
- No real SSH login, two-LAN traversal, difficult-NAT success or production deployment has been demonstrated.
- No license has been selected. Preserve that decision for the repository owner.
- Keep credentials, endpoint/account inventories, raw private logs, build outputs and toolchains out of Git. The checked-in evidence uses only loopback/synthetic fixtures.
