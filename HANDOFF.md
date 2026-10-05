# Python v0.2 development handoff

Read README.md, ARCHITECTURE.md and VALIDATION.md first. The baseline is Python main at `2cd46ec7d2b6705c2f12527b6c1dc67de7ab50c4`; do not reintroduce the earlier Go draft.

## User objective and acceptance

Latest correction: **deliver the usable Python connection**, not an original-FRP
research success. The new Python `ssh` entry and native connection stack must
pass actual strict SSH/data checks before updating GitHub. The prior research PR
is a draft, not the accepted final delivery. Deployment and server network/
authentication changes still require explicit confirmation.

Ordinary-user, multi-host SSH across different LANs. The owner's latest acceptance permits either **native 3k ↔ 医院 SSH** or **3k ↔ home Windows ↔ 医院**, with both home legs independently direct over physical networks. In the alternative topology the home computer is an explicitly permitted business bridge; Tailscale and the cloud must not carry business traffic. A metadata-only cloud coordinator remains allowed. Verify both legs, the intended SSH identities and complete data transfer before counting that topology as success. One working home ↔ hospital reference is insufficient. The new explicit `home-bridge` command has synthetic validation, not complete real-topology acceptance. Do not label the project complete or publish a completed product before accepted real-network behavior and product integration pass.

The user authorized the current Windows computer, cloud host and the two Linux hosts for temporary testing. Deployment or changes to SSH authentication/network configuration need confirmation. Existing SSH is management only; use verified host keys, no ssh-agent forwarding and no authentication changes. The user requested GitHub upload after the full result is finished.

Earlier steering extended temporary tests to peers 4/5 and authorized uploading
sanitized research once any of peers 3/4/5 connects successfully. This supersedes
the original completed-product-only condition; the newest correction above now
requires the usable Python connection. Do not publish private
endpoint inventories, addresses, usernames, credentials, tokens, router details
or raw logs, including through intermediate Git commits. Permanent deployment
and network/authentication changes still require confirmation.

## Implemented work

- Independent persisted P-256 device identities, exact approved leaf trust, directed service ACLs, bounded numeric candidates and monotonic policy revisions.
- Pinned mTLS coordinator; signed short-lived account/device/service/direction/transport grants, replay admission and renewable leases.
- Peer TCP candidate racing and explicit reverse direct TCP; local-loopback service targets only.
- Ordered automatic direct-method selection in remote proxy/forward: TCP, configured reverse TCP, explicitly enabled UDP ICE and IPv4 UDP prediction. Network failures fall through; identity/admission/configuration errors stop. No relay fallback.
- Optional explicit physical-IP ICE/DTLS/SCTP transport, bounded metadata/credit queues, no relay or automatic interface gathering. Pinned aiortc/aioice private adapter, retry-race guard and idempotent teardown.
- Optional alternate STUN on the same physical socket; authenticated TTL-7 warmup at a bounded predicted high-port interval. Linux multi-socket/random-port probes remain separate diagnostics.
- Windows explicit UDP selector loop; filesystem ACL/ownership checks with privileged SYSTEM/Administrators exceptions. Certificate validity and key/pin matching checks.
- Separate Linux source-bound TCP observation/simultaneous-open/hybrid research and read-only gateway inspection. These are not automatic production fallbacks.
- Authorized temporary Linux test runner/offline wheels, multi-host campaigns and small HMAC peer-control probes. Private inventories/results are ignored under `.fan-ssh/`.
- Whitelisted bounded dual-UDP/TCP STUN reference observers, complete diagnostic Binding parsing (including MAPPED-only servers), and a strict selected-peer gate for EasyTier v2.6.4 CLI evidence. These are diagnostics, not new production transports.
- Explicit fixed-target home business bridge: incoming named service and home-to-final service require separate directed grants. Ordinary nodes retain loopback-only targets. Anonymous socket pairs compose the legs without an additional forwarding listener; cancellation/revocation closes both. The bridge is opt-in, never an automatic/cloud relay fallback. Policy revisions require a bridge restart.

The original loopback fixture remains isolated: synthetic identities, loopback restriction, 30-second session. Remote sessions use renewal and a 24-hour absolute deadline. The new remote protocols are not compatible with the old Go/v1 fixture.

## Real network findings

Cloud-bound direct TLS and a Windows → cloud existing-credential SSH login were demonstrated. They do not satisfy 3k ↔ 医院 acceptance. Both Linux routes to the other public exit use physical NICs. Neither host has a global native IPv6 address.

After the user opened UDP 22092 on cloud, each host obtained a server-reflexive tuple. ICE still timed out before DTLS/SCTP. Three controlled HMAC trials used ephemeral, fixed 22092 and fixed 3478 source ports: each host sent 40 packets/trial; no verified or unexpected peer datagrams arrived. A standard STUN-formatted authenticated fixed-3478 trial also received no peer packets. Its wire integrity/fingerprint passed independent aioice parsing. A read-only non-promiscuous 3k NIC capture confirmed 40 peer-bound packets physically transmitted, cloud observation request/reply and zero peer ingress. No arbitrary port sweep was attempted.

Three same-source-port TCP observations at two approved cloud destination ports showed mapping changes on 3k and stable mappings on 医院. This demonstrates destination-port-dependent TCP mapping for those observations, not a complete NAT classification. Strict active and explicit passive/active hybrid attempts produced no pinned peer path. Hybrid TCP connect completion without matching target accept/TLS must not count as success.

Gateway UPnP discovery returned no usable descriptors; NAT-PMP external-address-only queries received port-unreachable errors. No mapping was created. An existing public SSH port responded with a host key different from the hospital's verified key: authentication was stopped, and known_hosts was not changed. Never count that other SSH endpoint as the hospital.

## Temporary cloud rules

The user manually added a **UDP 22092, source 0.0.0.0/0** security-group rule for temporary tests. Bounded observers reused it during this authorized continuation and stopped. Confirm actual rule removal before declaring cleanup complete. All temporary observers/processes have bounded lifetimes; rules are separate from process cleanup. No configured cloud CLI credentials/RAM role were available to remove rules automatically. Do not recreate them or keep a permanent listener based on temporary approval.

The user's continuation approved **temporary UDP 22093 restricted to the two Linux exits**, with both temporary rules to be removed after testing. After the user replied “22093 已添加”, physical-IP-bound checks verified replies on **both ports from both hosts**. The earlier missing-22093 capture predates that addition and is not the current reachability state. Sanitized evidence: `test-results/dual-stun-reachability-20261004.json`.

`scripts/dual_stun_observer.py` passed actual frp 0.71.0 discovery locally. It emits compatible MAPPED/CHANGED/OTHER addresses at two ports on one IP, not a full RFC 5780 classification. An initial three-check reference and a completed six-check extended reference ran after both ports became reachable. Both hosts discovered successfully, but neither established a hole. The extended reference covered all ten paired frp mode-0 strategies (roles, receiver TTL 7/4/normal, delays and read timeouts); the observer sent 48 Binding responses. A 35-second non-promiscuous 3k capture saw four outgoing peer UDP packets, no incoming peer packet and no kernel drops. Interrupted management/control runs are not counted as completed traversal failures.

The Computer Use automatic approval check stopped browser interaction because it could not reliably identify the current browser URL. No cloud-console edit occurred. Do not retry that blocked browser action or re-request the approved second rule. Stop owned observers after each bounded trial; actual security-group rule deletion is still separate and unverified.

At this checkpoint, all owned reference/diagnostic-test processes and temporary directories were verified absent on all three servers. TCP 22090/22110 and UDP 22092/22093 test listeners were closed. The user has been asked to delete the two approved temporary UDP security-group rules; that actual deletion is not yet confirmed. Do not claim complete network-rule cleanup or silently reopen a removed rule.

## Validation workflow

```sh
python -m pip install -e '.[udp]'
python -m unittest discover -s tests -v
python -m unittest discover -s experiments/tcp-simopen -v
python -m fan_ssh demo
```

Run Linux-specific tests on the authorized Linux hosts instead of counting Windows skips as completed Linux validation. `scripts/remote_tests.py --host ALIAS --python python3.12 --udp --output .fan-ssh/host-tests.log` ships supplied offline Linux wheels, runs root/experimental suites and the demo under an ordinary uid, and removes only its validated mktemp directory. Root discovery does not run the separate experiment suite. Latest results belong in VALIDATION.md and sanitized `test-results/v0.2-*`; do not publish private endpoint inventories, credentials or ICE secrets.

The user reports that the exit gateways cannot be inspected and subsequently stated they will provide no further help. Do not repeat requests for gateway status, browser operations, screenshots or an administrator alias. Earlier assistance questions are superseded. Continue independently within temporary-test/read-only authorization; deployment, network and authentication changes still require confirmation. The 3k account has existing noninteractive sudo for read-only firewall/capture inspection; relevant host rules were checked without changes. Hospital ordinary-user requires a sudo password and has no administrator log group; never ask for passwords or change authentication to obtain access.

## Continue from evidence

### Independent continuation (2026-10-05)

**Actual Python product entry passed native peer-5 acceptance.** The corrected
`python -m fan_ssh ssh` command completed three strict SSH logins, an 8 MiB upload
hash and exact 8 MiB roundtrip hash. All five operations emitted authenticated
native UDP evidence and had corresponding Python target sessions. Both physical
routes were verified. The trace failed TCP/ordinary ICE, then selected prediction;
one fresh prediction retry was observed. No original FRP process was started for
these tests; OpenSSH performs existing user/host authentication only. See
`test-results/python-ssh-peer5-20261005.json`.

The command's ProxyCommand must precede ProxyJump (even "none"); a real `ssh -G`
preflight now rejects any inactive Python proxy. An earlier entry test bypassed
the intended proxy and is explicitly excluded. Windows SID extraction now reads
only the ASCII SID field, supporting localized account output. Enrollment checks
directory ACLs before writing keys, rejecting exFAT; use private NTFS state.
Signaling reuses a pinned control connection within one UDP setup to avoid TCP
mapping churn; each operation retains roster/certificate/rate checks. A predicted
setup may retry one connectivity failure with fresh state, never identity errors.
SCTP disconnected send callbacks close their owned stream instead of unobserved
timer exceptions. Package version is 0.3.0; deploy matching current coordinators.

Permanent deployment still needs confirmation. Tests stopped/removed their owned
processes/directories; no SSH auth or system network configuration changed.

**New native reference positive: home Windows ↔ peer-5.** Original frp 0.71.0
XTCP/IPv4/QUIC with numeric cloud STUN passed both endpoint hole logs, selected
native IP/physical-route checks, strict existing-host-key SSH login and expected
ordinary-user identity, a 1 MiB upload hash and 1 MiB roundtrip hash. No fallback,
assisted address, agent forwarding, SSH key copy or cloud business relay was used.
The new ordinary-user syscall supervisor binds the owned static Go child's IPv4
UDP sockets to a physical interface; no host routes/configuration were changed.
Generic source is in `experiments/frp-device-binding/`; private orchestrators,
profiles and raw addresses/logs stay ignored. Evidence:
`test-results/frp-home-peer5-native-20261005.json`.

Three ordinary accounts passed physical-device UDP/TCP address observation.
Peer-4's default route includes a virtual proxy interface, so it must not be
counted native without physical binding. External STUN observations varied from
numeric cloud observations; both numeric cloud UDP ports were reachable on all
three hosts. After the corrected comparison, peers 3/4 still had no verified
hole/SSH success, while peer-5 passed. Existing services were preserved.

The owner now accepts a home Windows business bridge provided both Linux hosts
connect natively to home. Focus on the remaining home ↔ 3k leg; preserve the
working hospital FRP visitor. New four-role/held-release Windows/k3 TCP comparisons
all completed MACed coordination but failed peer MAC, while four Windows local
controls passed 64 KiB/hash/half-close. Role-reversed FRP QUIC also failed, with
seven fully logged paired hole strategies and one excluded partial paired record;
physical capture saw 2082 outgoing and zero incoming peer UDP packets, no drops.
Actual home/3k EasyTier UDP/TCP comparisons obtained no selected native peer in
eight snapshots each. Both reported symmetric TCP NAT; EasyTier skips symmetric
initiators, so do not call its TCP reference a completed hard-NAT punching failure.
Evidence: `home-k3-tcp-sync-20261005.json`, `home-k3-frp-reversed-20261005.json`,
`home-k3-easytier-20261005.json`. No network/authentication configuration changed.

The new `home-bridge` command composes independently granted direct legs to one
fixed peer/service using anonymous socket pairs. Incoming readiness refers only
to the named home service; outgoing readiness is separately logged, and complete
native SSH/data acceptance is still open. Source SSH checks the final host's key
and uses its existing credentials. Policy revisions close the bridge and require
restart. Tests cover TCP, mixed TCP/UDP and two UDP legs, revocation, wrong pins,
relay-evidence denial, cancellation, full binary/half-close behavior and foreground
CLI. A deterministic before/after regression fixed socket cleanup when a broker
is cancelled before starting. Do not present these synthetic positives as real
3k traversal or a completed release.

Latest regression: both real Linux hosts passed **80 full tests + 26 TCP
diagnostics, no skips**, and demo. After replacing a fixed 50 ms cleanup assertion
with bounded actual settlement, all nine TCP bridge cases passed again on both.
Windows passed the 11 bridge cases and installed-wheel foreground CLI, but the
latest full 80-test run failed existing UDP/one-second-renewal tests (75 passed,
one failure, one error, three Linux-only skips). Do not call it clean. Isolated
renewal passed; three non-debug 1 MiB UDP controls passed, but debug-enabled UDP
stalled with pending SCTP data and a teardown background error. Installed aiortc
source matched the offline wheel; no dependency/runtime patch was made. Next
software work must investigate this Windows UDP/lease behavior without masking
the failed full run. Evidence: `test-results/home-bridge-20261005.json` and
explicitly named `home-bridge-windows-full-failed-20261005.txt`.

GitHub main was fetched directly using a command-only URL override after an
existing mirror rewrite returned repository-not-found; main remains the recorded
baseline. No permanent Git configuration changed. No GitHub completed-product
upload/release is authorized until the accepted result is complete.

After the user reported ongoing FRP downloads, read-only inspection found their
existing Windows XTCP visitor on loopback 16022 still running, with no configured
fallback. Its log records successful IPv4/QUIC hole establishment to hospital's
native public exit at 2026-10-05 06:52:01, with no assisted addresses. A new SSH
login through that existing visitor passed the existing hospital host-key alias
strictly and returned the expected marker, exit 0. No configuration/deployment
was changed or download speed remeasured. This confirms the existing Windows ↔
hospital positive and does not establish 3k ↔ hospital acceptance. Evidence:
`test-results/frp-live-windows-hospital-20261005.json`.

The TCP observer had a reproducible Python 3.12 cleanup defect: waiting for
`server.wait_closed()` before cancelling handlers delayed exit while an observed
client stayed connected. The fix stops accepting, cancels/gathers handlers and
bounds writer shutdown before waiting for the server. An actual subprocess/client
regression failed before the fix and passed afterward: authenticated observation,
controller stdin EOF with the client held open, process exit within three seconds,
client EOF and listener rebinding. Hospital uid 1005 and 3k uid 1002 each passed
all **26 TCP diagnostic tests without skips**; WSL passed all 26 too. This fixes
cleanup, not NAT traversal. Logs: `tcp-reuse-diagnostics-*-20261005.txt`; evidence:
`test-results/tcp-observer-shutdown-20261005.json`.

Four valid native TCP timing trials borrowed DCUtR's CONNECT/SYNC/half-RTT
coordination, with a startup READY barrier and both role assignments. Two held
the observation socket; two released it before peer dialing, inspired by
RustDesk. Coordination completed in all four (approximately 54–63 ms round trip),
but no peer MAC passed and hospital accepted no connection. Two WSL controls
passed exact 64 KiB/hash/half-close. These are Python research prototypes, not
actual libp2p/RustDesk binary or wire-protocol runs and not production fallbacks.
Cloud forwarded zero business bytes. Setup failures preceding the barrier/frame
ordering/Python-version fixes are excluded. Evidence:
`test-results/tcp-sync-native-20261005.json`.

A fresh physical TCP comparison used a hospital socket prelistening before its
authenticated observation. 3k TTL 2/4/7/64 probes completed handshakes in about
0.7–0.9 ms, but hospital had zero accepts and no peer identity was verified. The
non-promiscuous capture saw 37 packets and zero drops, including TTL-2 outbound
SYN and TTL-63 incoming SYN-ACK. Against the known cloud observer, TCP/UDP TTL-2
probes failed while normal-TTL authenticated observations succeeded. Hospital
exit-address ICMP also replied at TTL 2 in about 29 ms, so TTL alone cannot bound
the actual physical hop count: tunneling, rewriting or protocol-specific handling
remain possible. The combined TCP evidence is consistent with an intermediary
or handshake responder; it does not identify its device/software or explain all
UDP failures. The two gateway HTTP roots refused connections; no login attempt
or configuration change occurred. Known native SSH ports were checked without
credentials; the hospital exit's offered port-2222 key differed from the verified
hospital key, so no login was attempted. Evidence:
`test-results/tcp-path-comparison-20261005.json`.

Home ↔ 3k also failed a completed frp 0.71.0 XTCP/KCP comparison, with six
client-version/banner checks and four completed hole strategies, including two
full 38-second random-port strategies (256 home sockets, 1000 consenting-peer
ports from 3k). 3k's physical capture contained 2008 outgoing peer UDP packets,
zero peer ingress and zero kernel drops. Earlier QUIC/short-KCP runs interrupted
some long strategies and must not be counted as completed long-mode failures.
The home exit matched the fresh successful home ↔ hospital comparator. Evidence:
`test-results/home-k3-frp-reference-20261005.json`.

Read-only, physical-source-bound UPnP now returned the home router's WAN IPv4:
it is RFC1918 private, proving an upstream IPv4 layer without proving CGNAT.
The upper gateway's public HTTP page identifies HX5-9saLite but exposes a login
form, not WAN status; no login was attempted. Both Linux hosts still lack native
global IPv6/default routes. NetworkManager is `ignore` on 3k and `auto` at
hospital; these do not justify switching settings blindly. In particular,
hospital kernel `accept_ra=0` does not prove NM's userspace IPv6 handling is
disabled. Two standard link-local Router Solicitations on 3k received no RA in
eight seconds and changed no address/route snapshot. The existing hospital proxy
returned HTTP CONNECT 200 for an IPv6 destination but TLS ended with SSLEOFError;
that does not establish an IPv6 bridge. The home relay remains undeployed.
Updated evidence: `test-results/home-relay-feasibility-20261004.json`.

After this continuation, all owned test processes/directories and cloud
TCP 22090/22110 and UDP 22092/22093 observation listeners were verified absent.
Security-group rule removal remains separately unverified. Do not publish a
completed product: native Linux-to-Linux SSH is still an open acceptance gate.

### Latest TCP and home-relay continuation (2026-10-04)

The user requested evaluating their ZTE ZXHN E2633 home IPv6 router as a
replacement data relay because cloud throughput is poor. This is an additional
requested option; a home relay would not itself establish native 3k ↔ hospital
direct SSH acceptance. Confirm deployment/network/authentication changes first.
Source-bound Windows WLAN IPv6 HTTPS succeeded with the expected native source;
both Linux hosts still lack a native global IPv6 address/default route and return
`Network is unreachable` when looking up the home IPv6 destination. Do not expose
an IPv6-only relay and assume those IPv4-only hosts can use it. WAN IPv4 inbound
reachability, router software hosting, IPv6 firewall and upload bandwidth remain
unverified. A public reachable IPv4 entry, native IPv6 access at both peers or an
explicitly selected IPv4/IPv6 bridge is required. The user reports signing into
the in-app router page, but tab reads failed with a CDP deadline before command
dispatch. Do not extract browser cookies/profile files or alter router settings
to bypass this tool limitation. The later read-only UPnP result and the user's
refusal to provide assistance supersede the earlier WAN-status question.
Sanitized evidence: `test-results/home-relay-feasibility-20261004.json`.

The standalone TCP control now supports `--strategy both-listen`: both Linux
hosts prelisten and actively connect from the same source port using SO_REUSEPORT.
Only role 0 selects a MAC-verified stream, so simultaneous accepted/outbound
streams cannot lead the two peers to choose different connections. WSL verified
the complete authenticated observation, peer MAC, exact 64 KiB echo and half-close;
the old TTL control also still passed. Both real Linux hosts, ordinary uid 1002
and 1005, passed the expanded 25-test TCP diagnostic suite without skips.

Three fresh native trials plus one separately captured trial all failed peer
authentication. 3k completed an apparent outbound TCP connect in each; hospital
had zero successful connects and zero matching accepts. In the captured trial,
3k's non-promiscuous physical NIC saw nine TCP packets, including inbound SYN-ACK
and FIN, with zero kernel drops; reading the peer MAC ended at EOF with zero bytes.
This does not identify the responding device or the exact failed gateway/filter.
No SSH payload was attempted. All owned processes, test directories and cloud
observation listeners were verified absent after cleanup; security-group removal
remains separately unconfirmed. This diagnostic is not a production fallback.
Evidence: `test-results/tcp-reuse-native-20261004.json` and the two
`tcp-reuse-diagnostics-*-20261004.txt` logs.

On 2026-10-04 the user supplied earlier conversation `<private-archive-reference>`. Its 2026-09-30 turn `<private-archive-reference>` proves a historical Windows ↔ hospital **frp XTCP IPv4/QUIC** success: both peer establishment logs, existing-host-key SSH login (exit 0), and 32 MiB transfers at 9.38/4.67 MB/s. The original hospital log and Windows configuration still exist and were inspected read-only. No `fallbackTo` was configured; assisted addresses were disabled. It was not IPv6 and was not a 3k ↔ hospital acceptance run. The current Tailscale/DERP route does not invalidate it. See VALIDATION.md and `test-results/historical-frp-20260930.json`.

That successful trial switched from a failing observer to `stun.easyvoip.com:3478`. Hospital frp used receiver/mode 1, TTL 7 and a bounded 17-port predicted candidate interval; the selected Windows public port differed from its initial observations. Prediction is now implemented and locally exercised, but four native control trials (both role assignments, TTL 7/4) received zero authenticated peer packets. A fresh 3k-source frp 0.71.0 reference trial failed its external STUN discovery before punching. These results do not invalidate the historical Windows pair. Require explicitly native sockets, approved peer IPs, bounded candidate attempts and actual authenticated peer-path evidence.

A fresh 2026-10-04 Windows ↔ hospital frp IPv4/QUIC comparator now also passed strict host-key SSH, exit 0. No assisted addresses or cloud business fallback was configured. Six Linux multi-socket/random-port UDP probes (both pool assignments, TTL 7/4/normal), a Python predicted ICE handshake and four passive TCP/low-TTL SYN probes still failed. Latest real-host suites: 69/69 on both Linux hosts plus 22 experiment tests, no skips; Windows 66 passed/3 Linux skips. New sanitized evidence and regression logs are in `test-results/`; VALIDATION.md records the rebuilt wheel.

For frp QUIC comparators, send the ordinary SSH client version before passively waiting for a server banner, and then perform strict existing-host-key SSH. Passive banner reads alone did not announce a usable QUIC stream in the measured trial. Unset proxy variables only in the temporary frpc process; do not alter the hospital's proxy environment or existing provider. Keep the 3k acceptance gate separate from successful Windows evidence.

The next comparison found 3k STUN DNS answers in the benchmark/Fake-IP range, destination-dependent exits and intermittent external UDP observations; hospital's corresponding samples were more stable. Do not identify an upstream proxy or complete NAT type from those facts alone. See `test-results/stun-routing-20261004.json`.

Actual EasyTier v2.6.4 no-TUN UDP/default-TCP references also failed. Default TCP STUN supplied a different 3k exit. A final ordinary-user comparison corrected only the supervised test child's two TCP STUN destinations to already reachable cloud ports 22090/22110; the static release binary and host configuration were unchanged. Both endpoints obtained the native exits. Hospital initiated real TCP punching against 3k's native tuple, still without a direct peer. Each completed reference had eight peer snapshots with a two-hop target route and null direct peer; no SSH data was attempted. A local 64 KiB/hash/half-close positive and an advertised two-hop relay-denial negative also passed the actual CLI selected-connection gate. All 13 new diagnostic tests passed on Windows and both real Linux hosts without skips. Evidence: `test-results/easytier-native-reference-20261004.json` and `reference-diagnostics-*-20261004.txt`.

The instrumented TCP test is a reference experiment, not a production adapter. Failed static-library override and aliased-observer setup attempts are not counted as corrected native TCP references. A future EasyTier adapter must support explicit observation endpoints and preserve fan-ssh's directed signed grants, exact peer identity and direct-only data admission; a shared EasyTier network secret alone is insufficient.

The host-level adapters work in local tests. Source-bound port observations are useful diagnostics; do not predict a full NAT type from missing STUN replies or turn arbitrary public port scans into a fallback. The exit gateways cannot be inspected by the user; do not repeat that request. Router/network modifications and deployment still require user approval. Do not modify the existing frp/Tailscale setup to reproduce a temporary test.

Keep signed grant, exact peer identity and existing SSH host-key/user-auth checks at every new path. No TURN/DERP/cloud stream forwarding/TUN/driver/configuration workaround may silently satisfy the direct-only acceptance. Roaming/sleep recovery, macOS runtime, hardware key custody, production enrollment UI/service deployment and universal hard-NAT traversal remain open work.
