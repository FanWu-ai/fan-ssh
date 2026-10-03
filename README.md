# fan-ssh

Direct-only SSH transport research. The current executable is named `directssh`.

A small, dependency-free Go experiment for **direct-only encrypted byte streams** with a metadata-only coordinator. It is a safe foundation, **not a working cross-LAN NAT traversal product**. The difficult requirement—UDP blocked with both endpoints behind complex NAT—remains unsolved and explicitly unimplemented here.

## What runs today

- One CLI process starts two synthetic device identities and a coordinator, all in memory, valid for one hour and never saved.
- The coordinator authenticates clients with exact-pinned TLS 1.3 certificates and returns one bounded peer record only for an explicit directed ACL edge.
- The initiator checks a separately approved destination pin before establishing mutually authenticated direct TLS.
- The receiver validates the client pin before dialing its one operator-configured, numeric-loopback TCP target. Peer bytes cannot choose another target.
- A local forward or SSH ProxyCommand can transport existing SSH unchanged. SSH still checks its own host key and authenticates the OS user. Device approval is not passwordless SSH login.
- IPv4 and IPv6 loopback direct TCP are tested. No administrator rights, virtual interfaces, firewall changes, user device operations, deployment, or real SSH keys are needed for the demo.

Every listener and destination is restricted to numeric loopback. There is no flag to disable this safety restriction. The code intentionally does not expose a public coordinator or perform Internet probes.

## Build and test

Requires Go 1.25 or newer. Only the standard library is used. With Go on PATH:

```sh
go test -race ./...
go vet ./...
go build -buildvcs=false -o directssh ./cmd/directssh
./directssh demo
```

On Windows, use `directssh.exe`. The checked implementation was tested with Go 1.27.1 on Linux amd64. macOS and Windows are compile-checked, not runtime-tested. In a read-only home environment set `GOCACHE` and `GOPATH` to writable temporary directories.

`demo` creates an ephemeral loopback echo service and verifies an opaque byte round-trip through the direct encrypted tunnel. It does not run an SSH server. Expected result:

```text
PASS: coordinator-discovered, mutually authenticated direct TLS echo; no relay
```

All identities and synthetic authorization disappear on exit. The v0 mock approval occurs within the demo process; there is no real enrollment UI, persisted trust, production enrollment code, or real-device many-to-many management.

## Optional local SSH integration, not executed by this project

If you already operate an SSH server on your own loopback port, these commands are examples for your separate local validation. They do not install/configure SSH, generate keys, or change authentication.

```sh
./directssh forward --target 127.0.0.1:22 --listen 127.0.0.1:2222
ssh -p 2222 -o HostKeyAlias=directssh-dev-local -o StrictHostKeyChecking=yes user@127.0.0.1
```

Or use ProxyCommand (adjust executable path and quoting for your shell):

```sh
ssh -o 'ProxyCommand=./directssh proxy --target 127.0.0.1:22' \
    -o HostKeyAlias=directssh-dev-local -o StrictHostKeyChecking=yes user@directssh-dev-local
```

The alias must already have the correctly verified host key in your SSH known-hosts configuration. An unknown key fails closed; do not disable host-key checks. Existing SSH key/agent/certificate authentication remains necessary for actual passwordless login. No SSH account, private key, host key, or credential has been created or installed by the prototype.

`proxy` emits **only transported bytes on stdout**; diagnostics go to stderr. Each run starts a new synthetic local session, not a remote device connection. `forward` can accept concurrent connections and stops on Ctrl-C. The fixture uses an absolute 30-second data-session deadline; it is not ready for long interactive sessions.

## Security boundaries and limitations

- Exact SHA-256 certificate pinning replaces normal CA/name verification intentionally; certificate validity and possession are verified. Pins are provisioned in memory separately from discovery. Unknown pins fail. TLS cryptography is Go's implementation, not a custom cipher.
- Coordinator APIs are GET-only metadata retrieval; POST/CONNECT/GET bodies, transfer-encoded bodies and query strings are rejected. It has no arbitrary upstream dialer or stream route. A malicious client can still send bytes to any HTTP listener; this means no supported forwarding of business data, not an information-theoretic covert-channel claim.
- Metadata is limited to 4096 bytes at the client; server header reads/writes and discovery/handshake operations are bounded to five seconds. The ProxyCommand CLI returns/exits on cancellation even if a stdio-copy goroutine is blocked; process exit terminates that goroutine. This helper is not a reusable long-lived embedded I/O service. Stream buffers are bounded; tunnel and forward handlers are capped at 32 concurrent connections each. Sessions have an absolute 30-second deadline and cancellation closes both network legs.
- The coordinator is locally provisioned and uses static immutable ACL snapshots. Real enrollment, signed session grants/leases, live revocation, persistence, account isolation and distributed lifecycle are NOT implemented. A production public listener additionally needs comprehensive rate limits, strict schemas, audit logging and abuse protection.
- Local forward ports have no local-client authentication. Any process on that same host able to connect can use the synthetic overlay session; real SSH authentication remains the final login boundary.
- A compromised approved endpoint can misuse its own authorization; no claim is made about proving Internet physical topology against malicious routing.
- Stream failures terminate the session. No automatic replay, relay fallback, TURN, HTTP CONNECT, WebSocket data tunnel, VPN, TUN or driver exists.
- TLS rejection detail may appear as a generic peer-auth/network error at the client, particularly with TLS 1.3. There is no claim of a comprehensive NAT diagnosis engine.

## Actual capability matrix

| Feature | Current status |
|---|---|
| Synthetic approved identities, directed ACL, pinned mTLS | Implemented, loopback-tested |
| Direct TCP IPv4 and IPv6 loopback | Implemented, tested when IPv6 available |
| Fixed loopback target, concurrent byte streams | Implemented, tested |
| Forward listener / clean ProxyCommand stdout | Implemented; echo integration tested |
| Real SSH login | Not executed; existing external SSH required |
| Windows/macOS ordinary-user binary | Cross-compiled only; runtime untested |
| Multi-device distributed enrollment / many-to-many UX | Roadmap only |
| Real LAN / public IPv4 / global IPv6 reachability | Not tested; blocked by v0 safety restriction |
| Reverse-direction dialing / candidate racing | Not implemented |
| TCP simultaneous-open across NAT | Not implemented; research gate |
| ICE / Pion UDP / STUN | Not implemented |
| UDP-blocked + complex NAT end-to-end | Not solved; no success claim |
| Business-data relay fallback | Intentionally forbidden |

Read [HANDOFF.md](HANDOFF.md) for the development handoff. The separate [TCP simultaneous-open experiment](experiments/tcp-simopen/README.md) demonstrates only a Linux loopback socket primitive; it does not add NAT traversal to the main CLI.

Read [ARCHITECTURE.md](ARCHITECTURE.md) for a **future** transport/security plan and sources. Proposed tickets, leases and protocols there are not current features. Read [VALIDATION.md](VALIDATION.md) for actual test/build evidence. No package release or deployment is provided.

## License

A license has not yet been selected by the owner. No license grant is included.

## Repository layout

- `cmd/directssh/`: development CLI (`demo`, `forward`, `proxy`)
- `internal/prototype/`: loopback-only transport, identities, coordinator and tests
- `experiments/tcp-simopen/`: independent Go module, Linux active/active socket diagnostic
- `scripts/`: Linux blocked-stdout CLI regression
- `test-results/`: recorded baseline and consolidated validation evidence

The nested experiment is a separate module: root `go test ./...` does not run its tests. Run both modules as described in [VALIDATION.md](VALIDATION.md).
