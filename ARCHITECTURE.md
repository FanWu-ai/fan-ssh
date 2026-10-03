# Architecture and research gates

## Implemented Python fixture

One CLI invocation builds an ephemeral CA and three one-hour leaf certificates: initiator, receiver and coordinator. The CA only provides the cryptographic validation needed by Python/OpenSSL's mutual TLS; authorization comes from independently provisioned exact leaf pins and directed ACLs. Names in these certificates are synthetic. Hostname verification is disabled because peer identity is a pinned leaf, not a DNS name; CA/signature/validity verification remains enabled (`CERT_REQUIRED`). TLS minimum version is 1.3.

`Session` freezes the operator-selected numeric-loopback target. It starts a TLS receiver with exactly the approved initiator pin, then a TLS coordinator with immutable identity/record/ACL snapshots. The initiator requests the destination metadata, rejects any destination pin different from its independent approved pin, then connects directly to the receiver. The receiver authenticates the client before making the one fixed upstream TCP connection. Business bytes flow initiator ↔ receiver ↔ receiver-local service, never through the coordinator.

The loopback gate is deliberate and cannot be disabled with a CLI flag. IPv4 and bracketed IPv6 numeric loopback are supported. DNS, scoped IPv6, wildcard, non-loopback and noncanonical ports are rejected. Port zero is allowed only for listener allocation.

### Metadata protocol

Each mutually authenticated connection carries a 4-byte unsigned network-order length followed by 1..4096 UTF-8 JSON bytes. Exactly one request is processed:

```json
{"op":"lookup","target":"target"}
```

Unknown fields/operations and invalid names are rejected. Names contain 1..64 ASCII letters, digits, underscores or hyphens. An allowed lookup returns exactly `id`, `address`, `pin`, `transport`; denied directed edges return an error. The client validates the exact response schema, expected name, lowercase 64-digit SHA-256 pin, numeric-loopback address and transport tag. Coordinator has no registration, stream forwarding, arbitrary dial, HTTP CONNECT, or redirect implementation.

### Data protocol and half-close

Transport tag: `direct-tcp-tls-framed-v1`. After exact pin checks, each direction carries 4-byte unsigned network-order lengths, with payload lengths 1..16384. Length zero marks EOF in that direction. Frames above the cap are rejected before payload read. Premature TLS/connection EOF or a truncated frame is an error; it cannot become an authenticated clean application EOF.

Python asyncio SSL streams do not implement independent `write_eof()`. Explicit framing therefore carries half-close: local stdin/TCP EOF sends zero; receiver then shuts down only the target's write half while continuing to read a delayed response. Both directions finish before bridge closure. Errors, cancellation or absolute deadlines cancel both pumps and close both legs. TLS encrypts/authenticates framing as well as payload. This is a deliberate wire change, not interoperability with the previous Go protocol.

### Resource lifecycle

A service acquires a semaphore before accepting a socket, so its 32-slot cap includes stalled TLS handshakes. Extra arrivals wait in the bounded OS listen backlog; they do not get Python handlers. Connection setup and TLS handshake each have a five-second bound. Coordinator request/response work has a five-second deadline; discovery has an outer five-second deadline. Data bridges expire after 30 seconds irrespective of trickle activity. Reads use 16 KiB chunks; `drain()` propagates backpressure. TLS shutdown is bounded to 0.5 seconds.

Each service owns its listener, accept task and active handlers. Closing first stops acceptance then cancels/gathers active tasks; bridges cancel/gather their pumps and close both writers. The CLI handles SIGINT/SIGTERM by cancelling its main task. Its raw-stdio daemon threads allow process termination when inherited pipes cannot be interrupted. Windows uses binary descriptor mode; Windows signal/SSL/event-loop behavior remains untested.

### Scope and threats

The fixture guards against unauthorized synthetic peers, tampered discovery pins, arbitrary upstream selection, unbounded framing and straightforward handler exhaustion. It does not implement production enrollment, key custody, persistent trust, tenant isolation, live revocation, signed grants, leases, distributed lifecycle or public-service abuse defense. An approved compromised endpoint can exercise its authorization. A forward port has no authentication for local callers. The existing SSH server must still authenticate the OS user and the SSH client must verify the host key.

## Product goal, not current capability

Ordinary-user, many-to-many SSH connectivity across Windows/macOS/Linux and different LANs, with no admin-only interface, route, driver or firewall installation during normal client operation. All business bytes must use a direct peer transport. A metadata-only public coordinator may exchange approved identities, ACL results, candidates, observations and schedules, but never relay business data.

The difficult research requirement is UDP blocked while both peers are behind complex NAT. No universal direct-connect guarantee is possible when network policy supplies no allowed direct path. The correct outcome then is an explicit failure, not a hidden relay. This Python rewrite does not solve or newly demonstrate that requirement.

## Next acceptance gates

1. Design real identity enrollment, proof of possession, owner approval, secure user-owned storage, trust rotation and directed service admission before any public listener. Persistent credentials and deployment require separate approval.
2. Introduce bounded direct IPv4/IPv6 candidates in both directions, cancellation, typed failure reasons and exact selected-path evidence. Keep consenting-peer and destination scopes explicit.
3. Develop platform-specific safe active/active TCP adapters. The included Linux loopback experiment is only a primitive diagnostic. Do not apply Linux socket reuse flags blindly on Windows; unsupported combinations must fail explicitly.
4. Run an explicitly authorized two-network campaign with consenting endpoints and approved coordination. Cover all ordered Windows/macOS/Linux pairs, blocked UDP, double NAT/CGN, filtered IPv6 and endpoint-dependent mappings. Capture exact local/observed/peer tuples, OS/runtime, timing and authenticated payload evidence. No arbitrary public probes or unapproved router/firewall changes.
5. Only harden paths that are demonstrated: lease/revocation policy, long-session lifetime, sleep/resume, network changes, concurrency, backpressure and real SSH. Existing authorized sshd remains a prerequisite; installing/enabling it may need admin rights. An embedded current-user SSH server and PTY/ConPTY support would be separate work.

These are planned gates, not implemented functions or protocol promises.
