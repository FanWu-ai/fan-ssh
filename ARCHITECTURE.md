> ROADMAP, NOT IMPLEMENTATION STATUS. This file proposes future production behavior. The current executable implements only synthetic in-memory enrollment, frozen local ACLs, loopback TCP/TLS and fixed loopback forwarding. Tickets, leases, revocation, externally reachable candidates, reverse dialing, NAT observation, UDP, and simultaneous-open are NOT implemented. See README.md and VALIDATION.md for verified v0 capabilities. The fixture uses self-signed exact-pinned certificates, not the proposed test CA.

# Direct-only cross-platform SSH: implementation design

## Decision and scope

Build a Go user-mode reachability engine first, with SSH as its first byte-stream service. The central research target is UDP-blocked / complex-NAT networks, not merely ordinary UDP traversal. No transport is allowed to relay business bytes. A failed direct path is a correct result, reported with evidence and uncertainty.

Use interchangeable stream transports:
1. Direct TCP + TLS 1.3, both dialing directions, IPv4 and IPv6. This covers a reachable endpoint even when the initiating SSH client cannot receive inbound connections.
2. Experimental TCP simultaneous-open, isolated behind OS-specific socket helpers. This is a real research gate, not a claim that ICE-TCP enables it automatically.
3. Pion WebRTC reliable ordered DataChannel over direct ICE/UDP for UDP-capable paths. STUN only, no TURN. Keep it as a useful path, not the acceptance criterion for difficult networks.

Expose one executable for peer operation and one coordinator service. Work is local design/prototype only: no real deployment, enrollment, credentials installed, router changes, publication, or external probes without their requested scope.

## Non-negotiable invariant

The coordinator carries only typed, bounded control messages (authentication, ACL decisions, signed tickets, candidate exchange, probe coordination, lease renewal). It has no stream-forwarding endpoint. Business bytes cannot be sent in these messages. No TURN, STCP fallback, HTTP CONNECT proxy, WebSocket byte tunnel, DERP, VPN gateway, or circuit relay. A peer endpoint that forwards traffic through another host also violates the invariant. A normal Internet router/NAT on the path is not an application relay.

Before opening a local SSH service or emitting the first SSH byte: require an authenticated peer transport, a valid session ticket/lease, target-side ACL approval, and a selected direct path. Retest the path after every change. If a direct path fails, terminate the stream; do not silently retry an SSH command or migrate to a relay. Candidate type alone is not a cryptographic proof of physical topology; describe evidence as endpoint socket/pair verification plus controlled coordinator accounting. A dishonest remote network could conceal routing from the application.

## Capability matrix

| Condition | Try | Honest outcome |
|---|---|---|
| UDP available, feasible NAT mapping/filtering | ICE UDP host/srflx/prflx | Direct Pion stream if checks succeed |
| UDP blocked, either peer has reachable TCP IPv4 endpoint | Direct TCP, reverse direction also | Direct TLS stream |
| UDP blocked, global IPv6 on both peers | Direct TCP IPv6 in both directions; optional simultaneous-open probe | Global address alone proves no reachability; host/router filters may block |
| Both behind IPv4 NAT, UDP blocked | Real TCP simultaneous-open with known/observed mappings | Experimental; requires OS/socket behavior, usable mapping and compatible NAT/firewall |
| Destination-dependent TCP mapping / randomized mapping | Compare observations, attempt only bounded consented peer pairs | An observed coordinator-facing mapping may not apply to peer; no guaranteed solution |
| Only an outbound enterprise HTTP proxy permits Internet traffic | Coordinator may be reachable, direct peer path may not exist | Report unavailable; do not tunnel business via proxy |
| Peer inbound denied and simultaneous-open denied on both sides | No path among permitted transports | Direct unavailable under present policy/network constraints |
| PCP/NAT-PMP/UPnP or manual mapping possible | Not in default implementation; separate explicit network-owner authorization | Mapping is a network change, not a privilege-free magic feature; double NAT/CGN still matters |

“UDP unavailable” should be a measured finding scoped to tested endpoints and time, not a universal conclusion from one timeout. “Complex NAT” is not a reliable single diagnosis. Report observed mapping variation, socket errors, and failed candidate pairs.

## Architecture

### Coordinator

HTTPS/TLS control API; persistent outbound control session per peer (WSS or length-bounded HTTP stream); registry of device public keys, directed service ACL edges, presence, ticket issuance, revocation and bounded probe scheduling. Separate TCP observation listener(s) and STUN endpoint(s) for tests. At least two distinct externally reachable destination addresses are needed to investigate destination-dependent mappings; ports on one address alone are insufficient to characterize address dependence. These endpoints return authenticated observations, never tunnel peer traffic.

One device can accept many sessions and initiate many sessions simultaneously. No full-mesh warm tunnels in v0. Per-session connections simplify ownership, revocation and race conditions. Add reuse/multiplexing later only after measuring costs.

### Peer

Modules: identity; coordinator control; registry/ACL cache; reachability collector; direct-TCP connector; OS-specific simultaneous-open connector; Pion direct-UDP connector; authenticated stream adapter; fixed local-service dialer; CLI diagnostics.

Foreground ordinary-user process. User-writable config/state only. No TUN/TAP, routes, privileged ports, kernel drivers, system services, firewall changes, or elevation. Transport listener uses allocated high ports; a local firewall may still block it, which is reported rather than changed. Graceful stop closes all listeners and sessions.

Local service is explicitly configured, e.g. service `ssh` maps only to `127.0.0.1:22` or `[::1]:2222`. A remote caller supplies service ID, never arbitrary destination host/port. Reject other endpoints. A target peer is not a subnet gateway.

## Three independent security layers

1. Device/transport identity: locally generated device key; public-key proof to coordinator; TLS peer certificate or signed handshake bound to device identity, session ID and role. Device IDs are hashes/IDs bound to enrolled public keys. Never share one group password as all peers' identity.
2. Authorization: coordinator signs a short-lived ticket for exact initiator device, target device, service ID, session nonce, expiry, policy revision, transport policy `direct_only`. Target independently checks local service allowlist and ticket. Membership is not an all-to-all permission grant. ACLs are directed edges or explicit groups expanded on server.
3. SSH: existing SSH client and server authenticate the OS login using their own keys/certificates and host keys. Device enrollment is not SSH login authorization. Pin the actual SSH host key under a stable device/service alias. Do not set StrictHostKeyChecking=no or ignore hostkey changes.

### Enrollment and trust

For the current prototype, local fixtures supply exact-pinned self-signed ephemeral certificates and mock enrollment. Real enrollment design: operator creates a single-use expiring enrollment code tied to an account/device scope; peer generates private key locally and proves possession; server binds ID to public key and records approval. Codes do not go into source, logs or URLs. Private keys never go to coordinator. Replacement enrollment rotates identity and requires approval rather than overriding an existing key silently.

The coordinator is trusted for membership and ACL authority, availability and address metadata. It cannot provide SSH hostkey truth independently of the initial trusted pin. Compromise can authorize malicious devices/DoS; SSH verification remains essential. For stronger endpoint identity against coordinator compromise, later add owner-signed device roster, not handwaving about E2E encryption.

### Revocation

New sessions require current coordinator authorization. Target receives revocations and closes matching active sessions. Also use renewable short-lived active-session leases (initial design: 60 seconds, renew before 30 seconds remaining); loss of coordinator connectivity ends sessions at lease expiry. This is deliberately fail-closed and means coordinator outage can interrupt otherwise direct SSH. No claim of instantaneous revocation during partition. Revocation of overlay identity does not remove independently installed SSH keys; document/revoke those separately if applicable.

## Protocol v0

All control envelopes: `{version, type, request_id, session_id?, sequence, body}`; authenticated channel; strict allowlist of fields and sizes; per-device and per-session rate limits; no opaque arbitrary bulk body. Signed objects use deterministic serialization and domain-separated signatures. Avoid custom cryptographic primitives.

Messages:
- EnrollRequest(device_public_key, enrollment_code, challenge_proof); EnrollApproved(device_id, registry_epoch).
- Authenticate(challenge, proof); Presence(capabilities, service_ids).
- ConnectRequest(target_device, service_id, requested_paths).
- ConnectGrant(ticket, peer_identity, target_presence) or Denied(reason).
- SessionOffer(ticket, signed_candidate_set, transport_parameters), SessionAnswer(...).
- ProbePrepare(probe_id, transport, local_bind_intent, peer_candidates); ProbeReady; ProbeGo(bounded_start_window); ProbeResult(outcome, timings, sanitized_error, observations).
- RenewLease(session_id, lease_serial); LeaseGranted; Revoke(device/session/service, revision); Close(reason).

Candidate messages are session-bound, expiration-bound and authenticated; only send to authorized peers. Never log ICE credentials, enrollment codes or private keys. Limit count and exclude invalid/unspecified/multicast/broadcast addresses. Default off loopback/link-local remote candidates outside test mode; private candidates only within explicitly allowed scope to avoid turning enrollment into a network scanner. Probe only enrolled consenting peer addresses and designated observation servers, with fixed retry/time budgets.

Peer handshake before service dial: validate session ticket and remote identity; exchange fresh nonces and signed session-bound proof (or use authenticated TLS identities); reject replay, wrong target, wrong service, expiry, duplicate admission and policy mismatch. Direct TCP TLS certificate key is bound to enrolled device key/approved certificate. DataChannel fingerprint/SDP is signed and session-bound; after DTLS establish, verify actual remote identity proof before forwarding.

## Real TCP simultaneous-open experiment

Keep this separate from ordinary active/passive ICE-TCP. Use ordinary TCP sockets, not raw packets or TTL tricks. Each peer chooses a dedicated local high-port binding and holds all required socket resources. Obtain TCP observed endpoints using that same binding where OS permits. Coordinate bounded concurrent connect attempts from the same local endpoint to the peer's observed endpoint; authenticate any resulting stream. An observation obtained on another local source port is not evidence of the desired mapping.

Socket lifecycle is an OS adapter, with tests for bind-to-same-port, established observation connection plus peer connect, cancellation, TIME_WAIT, cross-process port hijack resistance, IPv4/IPv6 and interface changes. Go `net.Dialer.LocalAddr` and `Control` may be enough for some paths, but cannot be assumed to make every platform combination work. Avoid copying Linux SO_REUSEADDR policy to Windows: Windows documentation explicitly warns of indeterminate delivery/socket hijacking with address reuse. For unsupported safe binding combinations return `TCP_SO_SOCKET_UNSUPPORTED`; do not weaken safety to claim success. A listener can aid active/passive path discovery, but successful active/passive accept is not proof of simultaneous-open.

Log each attempt's local/observed/remote 4-tuple, monotonic phase timing, OS version, socket error, and resulting authenticated peer. Packet traces are optional operator-supplied evidence; ordinary-user prototype cannot assume capture privileges. Mapping prediction/port sweeping is out of v0. Failed exact observed endpoint does not prove all possible direct TCP strategies impossible, only that tested path failed.

## Pion integration limits

Use a pinned reviewed Pion release, not mutable main; determine matching WebRTC/ICE module versions during implementation. Configure only approved STUN URLs; reject TURN at config load; reject relay candidates in incoming and outgoing signaling; check selected pair before and throughout data forwarding. Enable reliable, ordered channel; no partial-reliability settings. Implement explicit bounded frames `{OPEN, DATA, FIN, RESET}` with per-direction close state and flow-control/backpressure. DataChannel is message-oriented: do not assume raw io.Copy gives correct half-close semantics. DATA <=16 KiB, bounded queues and a buffer high-water mark; reject malformed frames and avoid unbounded buffering. OPEN carries ticket/session/service only; no arbitrary network destination.

Pion's current source inspected 2026-10-03 creates passive TCP candidates and active candidates when offered a passive remote; an `so` enum exists but is not proof of working simultaneous-open generation. Thus ICE-TCP support is not the difficult-network success claim. Direct TCP transport can avoid SCTP/DTLS overhead when TCP already connects.

## SSH user experience and prerequisite

Planned command (not implemented): `directssh proxy --peer DEVICE --service ssh`, stdin/stdout is pure SSH byte stream, logs exclusively stderr. Integrates with OpenSSH ProxyCommand and stable HostKeyAlias `DEVICE.ssh`. Prefer this over opening an unauthenticated loopback forwarding port. Local-forward mode is optional, binds loopback only, and documents other local users can attempt access (SSH authentication still applies).

The existing SSH server must already run and allow the requested ordinary account. Public-key login must already be authorized or separately enrolled with permission. The tool cannot grant OS access simply by connecting peers. Passwordless can mean an encrypted private key unlocked through the user's agent; do not equate it with leaving private keys unencrypted. Do not silently forward ssh-agent.

Windows/macOS/Linux binary portability does not mean their system sshd can be installed/enabled without administration. In particular Microsoft's documented Windows installation path requires an administrator. If zero pre-existing sshd is mandatory, add a separately scoped current-user embedded SSH server: execute only as the process owner, no impersonation/switch-user/elevation. Begin with explicit noninteractive command allowlist; later Unix PTY vs Windows ConPTY, shell quoting, environment handling, exit status and signal translation need independent security/compatibility work. Do not market this as arbitrary system-user SSH or a finished interactive shell.

## Implementation phases and acceptance gates

P0, first deliverable: transport interfaces, fixture coordinator, reachability report schema and direct-only invariant tests. Implement direct TCP IPv4/IPv6 both directions, socket-capability probes on all three OS adapters, and experimental exact-endpoint TCP simultaneous-open harness. UDP-blocked scenario is a named required test from the start. Emit JSON + concise human diagnosis. No production identity installed.

P1: authenticated direct TCP byte stream and ProxyCommand against a controlled local fixture sshd/service; ticket, ACL, replay, lease and revocation tests; multiple initiators to multiple targets concurrently. Add independent SSH key/hostkey integration fixtures. Data path must never be accessible through coordinator.

P2: Pion direct UDP path and DataChannel stream framing/backpressure; continue difficult-network probe work in parallel. Reuse same session admission and direct-only gates.

P3: actual external-network campaign using two independently routed LANs and user-approved endpoints, Windows/macOS/Linux as both source and target. Test all nine ordered OS pairs, IPv4 NAT, global IPv6 with filters, UDP blocked, compatible/incompatible TCP NAT, double NAT/CGN, endpoint-dependent mapping, policy-denied peers, network switches, sleep/resume and clock skew. Acceptance claims label exact combinations verified. No launch claim that all hard networks work.

P4: harden only proven paths; optional current-user embedded SSH or authorized mapping support based on explicit requirements, not before reachability evidence.

## Tests proving useful properties

- Local units/fuzz: parser bounds, signatures/session binding, ticket replay, ACL direction, service restriction, revoked key, lease expiry, cancellation/resource leaks, DATA limits/FIN races/half-close/backpressure, hostile candidates.
- Transport integration: each permitted direct path; rejected relay candidate/config; every path timeout; coordinator disconnect; selected path change; 10 concurrent sources/targets; large bidirectional payload checksum; partial close and early SSH exit.
- No relay: transfer large incompressible payload over a proven peer path and assert coordinator only sees bounded typed control events; inspect peer socket endpoints. Stop coordinator data-related test listeners while leaving permitted control as needed. All direct attempts failing must produce a nonzero exit without any service connection or successful business transfer.
- Kernel/network lab: containers/netns or controlled test routers simulate NAT/firewall only in an explicitly authorized lab. User-mode fake network can validate state-machine cases, not real kernel NAT/socket/firewall compatibility. Same-LAN/loopback success never proves cross-LAN punching.
- Cloud Linux can test parser/security logic and Linux local integration; cross-compiling Windows/macOS proves compilation only. It cannot certify those runtimes, real two-LAN NAT behavior, Windows firewall prompts, macOS local-network policy, or deployment success.

## Source basis (primary documentation inspected 2026-10-03)

- RFC 6544, especially Appendix A/B, distinguishes active/passive/simultaneous-open and socket/NAT limitations: https://www.rfc-editor.org/rfc/rfc6544.html
- RFC 5382 requires compliant NAT handling of TCP simultaneous-open, not a promise all deployed NATs comply: https://www.rfc-editor.org/rfc/rfc5382.html
- TCP specification simultaneous-open: https://www.rfc-editor.org/rfc/rfc9293.html
- Pion TCP candidate creation (mutable source, inspect pinned dependency again): https://github.com/pion/ice/blob/main/gather.go and https://github.com/pion/ice/blob/main/agent.go
- Pion DataChannel/selected-pair API: https://pkg.go.dev/github.com/pion/webrtc/v4
- Go TCP socket implementation discusses simultaneous connections: https://go.dev/src/net/tcpsock_posix.go
- Windows socket reuse hazards and options: https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse
- Linux socket reuse semantics: https://man7.org/linux/man-pages/man7/socket.7.html
- Apple archived socket option semantics (not proof for modern macOS): https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/setsockopt.2.html
- IPv6 filtering and unsolicited TCP SYN: https://www.rfc-editor.org/rfc/rfc6092.html
- Explicit PCP mapping changes: https://www.rfc-editor.org/rfc/rfc6887.html
- frp XTCP direct mode and optional STCP fallback (must remain absent if used for comparison): https://gofrp.org/en/docs/features/xtcp/
- libp2p DCUtR uses relay-based synchronization; avoid as lean first architecture, not inherently impossible to constrain control-only: https://docs.libp2p.io/concepts/hole-punching
- OpenSSH ProxyCommand/HostKeyAlias: https://man.openbsd.org/ssh_config
- Windows OpenSSH setup administrator prerequisites: https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse
