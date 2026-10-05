# Direct multi-host architecture

## Identity and service approval

`device.py` creates independent self-signed P-256 certificates and owner-private keys. Remote mode has no shared session CA. An operator approves public certificates and fixed numeric high-port candidates in `config.py`'s immutable policy: current valid canonical self-signed non-CA P-256 leaves, unique pins, maximum 64 devices, eight candidates/device and 4096 directed service edges.

TLS trusts approved leaf certificates, requires TLS 1.3 and CERT_REQUIRED, then independently verifies exact pins. Hostnames are disabled because identity is a pinned leaf. Roster membership alone does not authorize service use; directed grants and receiver-local service maps are separate checks. Existing SSH host-key/OS-user authentication remain independent.

Windows DACLs are protected and owned by the current SID; readable grants must be for that SID, SYSTEM or Administrators. Users/Everyone read access is rejected. POSIX directory/key permissions exclude other users. Identities refuse overwrite. Private temporary TLS PEMs are deleted after context loading. No encrypted keystore, unattended enrollment or hardware-backed custody exists.

## Metadata control

`control.py` processes exact-schema, length-prefixed JSON operations, maximum 4096 bytes. A pinned mTLS connection accepts at most 64 operations within 30 seconds, with a five-second operation/idle deadline. Each operation rechecks current roster membership, certificate validity and rate. TCP observation remains one held operation. Native UDP setup reuses one control connection to avoid allocating fresh TCP mappings between STUN observations and peer dialing. Connections close after admission/failure. There is no business forwarder, arbitrary dialer, CONNECT, TURN or relay operation.

`grants.py` signs domain-separated canonical JSON with the approved coordinator P-256 key. Claims bind account/revision, random session ID, both device IDs/pins, service, direction, transport, issue/expiry and serial. Initial serial zero is consumed once. Replay cache: 1024 unexpired initial tokens, rejecting overflow rather than evicting live entries. Only the receiver may renew; renewal preserves bindings and advances serial/expiry.

Limits: 240 requests/minute/device, 128 pending offers and 128 UDP answers. Expired entries are purged. Policy replacement clears pending state and observed IPs. Coordinator identity has no data candidates/ACL edges; a separate business identity may share its host with a distinct port.

`stun.py` optionally returns one 32-byte IPv4 XOR-MAPPED-ADDRESS Binding response for authenticated-control-observed source IPs, at most 60 small requests/minute/IP. No TURN/allocation/forwarding exists. Shared-NAT IP approval does not authenticate each UDP request. Metadata-only is an implementation property, not a mathematical covert-channel guarantee.

## Direct TCP

`remote.py` races at most eight approved candidates; only pinned TLS can win. Pending attempts/losing sockets are closed. OPEN carries the signed grant. The receiver checks actual caller pin, target, direction/transport, ACL, expiry, replay and configured service before dialing its fixed **loopback** target.

Reverse direct dialing exchanges a signed offer through control. The target initiates TLS to an independently approved source listener. Pins/session bindings are checked at both ends before the target opens its service. Business stays source ↔ target.

`strategies.py` selects ordered direct methods for remote CLI connections: TCP, configured reverse TCP, explicitly enabled UDP ICE, then IPv4 UDP prediction. Each has a fresh client/path/grant and a bounded deadline. Only connectivity failures permit another method. Certificate/pin, admission, configuration and permission errors are terminal. A plugin must report `relay: false` and affirmative service-readiness evidence before selection. The attempt trace is returned on success or `NO_DIRECT_PATH`.

Wire tag: `direct-tcp-tls-framed-v2`. TLS/grant admission then four-byte big-endian lengths in each direction: 1–16384 payload bytes, zero directional EOF. Oversized/truncated frames fail. Explicit EOF permits delayed replies after half-close because Python TLS streams do not support independent write_eof. The older Go wire format and original v1 loopback fixture are separate.

## Native UDP

`udp_path.py` isolates pinned aiortc 1.15.0/aioice 0.10.2 private APIs. A native connection binds one explicit approved physical IP/ephemeral UDP port; no interface enumeration/default STUN/TURN. Host and optional IPv4 server-reflexive candidates come from a primary and optional alternate explicit numeric observer on that same socket. Native IPv6 host candidates are supported but not demonstrated across the authorized hosts.

`udp_traversal.py` implements optional IPv4 prediction inspired by frp's low-TTL/range approach. It derives at most 21 neighboring high ports from at most two same-IP observations; irregular deltas or changed IPs do not expand the range. The observed stable side is preferred as receiver, otherwise the controlled ICE side is used. Warmup sends authenticated ICE Binding requests at TTL 7 and restores the original TTL synchronously before yielding. Ordinary ICE then selects and authenticates the path. This is a heuristic, not a complete NAT classification. Multi-socket/random-port traversal remains a separate control-packet diagnostic, not an automatic production method.

`ice_metadata.py` enforces exact schemas, 2048-byte metadata, at most eight UDP component-one candidates, approved numeric IPs/high ports; DNS/mDNS/relay/TCP candidates fail. ICE+DTLS+SCTP setup is bounded to 15 seconds. The selected native IP and peer IP are checked again. Peer-reflexive ports require an approved IP and independent exact DTLS fingerprint. Certificate validity is checked before setup.

DTLS uses the existing P-256 identity. Reliable ordered SCTP exposes one negotiated data channel, then the same OPEN/grant/service framing as TCP. `udp_remote.py` sends only ICE metadata through control. It reserves a 32-path limit before network awaits, rejects new paths after close and never opens the local service before pin/grant admission.

The channel has four 16-KiB application credits and bounded incoming/pending queues. Malformed/overflow messages close it. Cleanup is idempotent, cancels ICE checks and bounds each transport stop. SafeTransaction guards a due upstream retry callback from completing an already completed future. Private accesses require exact-version tests before any upgrade.

Windows explicit UDP CLI uses SelectorEventLoop after sustained bidirectional DTLS stalled on Python 3.12's proactor loop. TCP/stdio retains the platform default. The adapter does not replace an embedding application's loop automatically.

Prediction retries one connectivity setup failure using a new path and signed
grant; pin/policy failures remain terminal. NativeSCTP surfaces a disconnected
DTLS sender through its owned stream rather than leaving an upstream timer or
reconfiguration task with an unobserved exception. Expected association shutdown
is separate from active send failure; failures cannot become service readiness.

`ssh_cli.py` invokes the existing OpenSSH client with Python's actual proxy entry.
ProxyCommand precedes ProxyJump, and a real `ssh -G` preflight must report the
exact Python command. No bypass to the original alias's management network is
allowed. The alias supplies original host identity/credentials; no SSH config or
authentication change is made. Parent cancellation terminates its SSH child.

## Explicit local workstation bridge

`home_bridge.py` implements an opt-in `HomeBridge` peer with one immutable
peer/service target. Incoming grants authorize a named service on the local workstation peer;
the outgoing client obtains a separate grant for local workstation -> final peer/service.
Callers cannot supply another destination. Ordinary `Node` service validation
continues to reject anything except fixed loopback targets; only `HomeBridge`
accepts the internal `PeerService` descriptor. The coordinator is unchanged.

An anonymous socket pair composes the admitted incoming stream with an outgoing
client using the existing direct-method selector. There is no extra local
forwarding listener. Incoming readiness refers to the local workstation bridge admission;
outgoing readiness is separately logged only with affirmative direct evidence.
Full success still requires final SSH identity/login/data checks and native paths
on both legs. SSH remains end-to-end between the source and final host.

The existing 32-session cap bounds brokers; owner completion cancels a pending
outgoing attempt. Each leg renews its own grant. Either path failing or a local
policy revision closes both; a bridge policy update requires restart before new
sessions because outgoing clients retain their startup snapshot. No automatic
relay discovery/fallback or cloud business operation is added.

## Lifetimes and resources

Remote grants last 30 seconds. Receiver renews halfway through remaining lifetime; failed control/policy/expiry closes both legs. Absolute data deadline: 24 hours. Local node revision cancels sessions/offers. Invalid policy updates retain the previous snapshot; coordinator pin rotation requires restart. Clients use startup snapshots.

Services cap 32 accepted handlers including TLS handshakes; nodes cap 32 active service streams. Setup/service dials: five seconds; TLS shutdown: 0.5 seconds. Cancellation closes listeners, handlers, pumps and both legs. Selector-based accept checks cancellation before accepting and closes any socket accepted during owner cancellation, avoiding a Python 3.12 readiness/cancellation race. Proxy stdout is binary-clean; stderr carries diagnostics. One-shot daemon stdio workers permit process exit with blocked inherited pipes. Local forwards do not authenticate local callers.

## Linux NAT diagnostics

`tcp_probe.py` prebinds source-bound SO_REUSEADDR sockets, retains authenticated observation sockets for 15 seconds and compares the same local port at two approved coordinator ports. Strict active mode dials only the exact consenting peer tuple. Explicit hybrid mode also prebinds a target listener and primes outbound SYNs; results distinguish it from active/active success. No SO_REUSEPORT, raw socket, port sweep or OS changes. Windows rejects this Linux adapter.

Different observations for the same local port at different destination ports demonstrate destination-port-dependent mapping for those measurements. Missing responses cannot establish a complete NAT type. TCP connect/SSH banner alone does not prove the intended authenticated host.

## Open acceptance gate

Ordinary-user, many-to-many SSH across different LANs remains the product objective. The alternative accepted topology uses a local Windows workstation business bridge between remote LAN device A and remote LAN device B, provided both legs independently use verified native peer paths and neither Tailscale nor the cloud carries business traffic. The explicit `home-bridge` mode uses a separate peer identity and two directed service approvals; synthetic checks do not satisfy the real-network gate.

The Linux pair is unsolved, and the alternative topology is incomplete: local workstation ↔ remote LAN device B FRP reference SSH works, but local workstation ↔ remote LAN device A is unverified. Address observations alone do not pass either gate. No global native IPv6 candidate or gateway mapping interface was found on the Linux hosts. Measurements are environment-specific, not proof that every possible direct technique fails.

Next work needs new evidence: a verified local workstation ↔ remote LAN device A native path or native Linux pair, followed by complete SSH/data validation. Preserve explicit failure when the selected topology lacks a path. Deployment, SSH auth changes and network configuration require user approval. No automatic relay fallback, production service installation, roaming/sleep recovery, macOS validation or universal hard-NAT solution is claimed.
