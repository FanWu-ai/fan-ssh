# Python validation history

Public evidence uses stable, generic remote LAN device labels A–D and a local
workstation label. These identify distinct test roles across reports, not SSH
aliases. Account UIDs, router models and personal operation history are redacted;
measured outcomes, timestamps and validation limits are retained.

The latest Python 0.3 functional entry is documented at the end of this report.
Historical failures and reference-only successes below are retained as evidence.

Validation dates: 2026-10-03–05 (Asia/Shanghai). Baseline main: `2cd46ec7d2b6705c2f12527b6c1dc67de7ab50c4`. This report concerns Python work only; no earlier Go build/race result is counted. Real-network acceptance remains **not passed**: the remaining topology targets are either native remote LAN device A ↔ remote LAN device B SSH or remote LAN device A ↔ local Windows workstation ↔ remote LAN device B with two independently verified direct legs. Tailscale and cloud business relays remain excluded; complete SSH/data transfer and product integration are still required.

## Actual regression runs

The following table is the earlier 69-test checkpoint. A subsequent home-bridge
checkpoint passed **80 full tests and 26 diagnostics on each real Linux host, no
skips**. Windows passed the 11 bridge cases, but that checkpoint's full 80-test run
was **not a clean pass**: one UDP stall, one short-lease reset and three Linux-only skips.
See the final section and `test-results/home-bridge-20261005.json`.

| Environment | Root suite with UDP extra | Separate TCP experiment | Demo |
|---|---|---|---|
| Windows, Python 3.12.10, cryptography 50.0.2 | 69 tests: 66 passed, 3 Linux-only skipped | Run on Linux below | Package-install smoke passed |
| remote LAN device B Linux x86_64, ordinary-user UID (redacted), Python 3.12.10, OpenSSL 3.0.2 | 69 passed, no skips | 22 passed, no skips | Passed |
| remote LAN device A Linux x86_64, ordinary-user UID (redacted), Python 3.12.3, OpenSSL 3.0.13 | 69 passed, no skips | 22 passed, no skips | Passed |
| Local WSL Ubuntu-24.04, Python 3.12.3 | Earlier 61 passed, no skips; new TCP diagnostic smoke passed | Covered by actual Linux hosts | Not counted as a network host |

Windows skipped only the blocked-stdio Linux process check and two Linux source-bound socket-adapter tests. All ran successfully on both real Linux hosts. UDP tests were executed with pinned aiortc 1.15.0/aioice 0.10.2, not skipped for missing extras. The latest suites include automatic strategy selection, alternate same-socket STUN, bounded prediction and a real TCP-failure → predicted UDP service stream. They also run after the selector accept cancellation fix; no earlier readiness exception or unclosed-socket warning is counted as a clean pass.

Latest sanitized executed output: `test-results/v0.2-auto-windows-tests.txt`, `v0.2-auto-remote-lan-b-tests.txt`, `v0.2-auto-remote-lan-a-tests.txt`. The earlier `v0.2-*-tests.txt` logs contain the 61-test checkpoint. Older unprefixed files describe the original v0.1 rewrite and are historical evidence.

Coverage includes independent identity/key/ACL storage, certificate expiry, policy snapshots/rollback, signed grants/expiry/replay, service admission before local dial, exact peer pins, forward candidate racing/loser cancellation, reverse direct connections, binary framing/half-close, renewal/control loss/revocation, bounded handlers/offers, raw CLI stdio, selected native UDP candidates, DTLS wrong-pin rejection, relay/unapproved-address rejection, UDP pending-path capacity, signed UDP signaling and 1 MiB bidirectional streams. Linux tests exercise actual prebound sockets and two authenticated same-source-port observations with a prebound listener.

## Package and process integration

- `compileall` passed for package, tests, scripts and the separate TCP experiment.
- Rebuilt `fan_ssh-0.2.0-py3-none-any.whl`, SHA-256 `ef38c326c8714451ff35200fd727d142691f4dc0aa13fd1cf499b1b055421029`.
- Installed that wheel in an isolated temporary target outside the checkout; verified the import came from the installed package.
- Separate CLI processes exercised identity-init/export, policy-build, coordinator, node, diagnose and proxy. The default automatic proxy selected TCP, stdout matched a 1 MiB binary payload exactly and preserved half-close. Package demo passed. Temporary identities/processes were removed.
- Windows explicit UDP uses the same selector event loop in CLI and tests. Sustained bidirectional DTLS stalled with the Python 3.12 proactor loop; this is a measured limitation, not hidden by a success claim.

This is a local build, not a package-registry release. `py3-none-any` describes the package's Python files; cryptography/optional UDP dependencies need compatible platform wheels. Python 3.11 and macOS runtimes remain untested.

## Authorized real-network campaign

Existing verified SSH was used for temporary setup, bounded metadata exchange and results only. Synthetic 1 MiB payloads and attempted SSH used peer sockets. Linux test directories were ordinary-user mktemp directories, removed after execution. No SSH key/host-key/sshd change, permanent service, route, driver or OS firewall change was made.

| Path/trial | Measured result |
|---|---|
| remote LAN device B → cloud peer, remote LAN device A → cloud peer, Windows → cloud peer | Pinned direct TLS, 1 MiB SHA-256 verified |
| Cloud peer → remote LAN device B | Reverse direct pinned TLS, 1 MiB verified |
| Windows → cloud existing SSH login through remote CLI | Exit 0, expected marker; existing strict host key/user credentials |
| remote LAN device B ↔ remote LAN device A approved private TCP candidates | No authenticated direct path |
| Cloud → remote LAN device A/Windows initial reverse trials | Initial listener reuse errors; adapter corrected, those external paths were not rerun and are not claimed |
| Six initial strict source-bound TCP trials | No authenticated direct path |
| Three additional TCP trials, same source port at two cloud destination ports | remote LAN device B mapping stable; remote LAN device A mapping changed by destination port; no pinned peer path |
| Three explicit active/passive hybrid TCP trials | No pinned peer TLS; target listener timed out, so TCP connect completion did not prove peer success |
| UDP echo and SSH attempts after cloud observation became reachable | ICE timed out before DTLS/SCTP; no SSH login |
| HMAC control trial: ephemeral source ports | 40 sent/host, 0 authenticated/0 unexpected datagrams received on either host |
| HMAC control trial: fixed UDP 22092 | 40 sent/host, same zero result |
| HMAC control trial: fixed UDP 3478 | 40 sent/host, same zero result |
| Standard STUN-formatted authenticated trial: fixed UDP 3478, repeated with physical capture | 40 sent/host each run; zero peer packets received |
| Four low-TTL/small-range UDP prediction trials, roles reversed and TTL 7/4 | Cloud observations succeeded; zero authenticated peer packets |
| Six multi-socket/random-port UDP trials, roles reversed and TTL 7/4/normal | 256 pool sockets vs 1000 random high-port checks; zero authenticated/unknown peer packets, TTL restored |
| Python predicted UDP campaign | SSH trial gathered both physical endpoints, then both timed out in ICE before DTLS; echo trial stopped at a target observation error |
| Four passive TCP/low-TTL SYN trials, roles reversed and TTL 7/4 | No two-ended peer MAC exchange; source EOF/timeout or refusal, receiver timeout; TTL restored |
| Fresh remote LAN device A-source frp 0.71.0 XTCP reference with EasyVoIP STUN | Source discovery timed out before hole punching; three attempts, no SSH |
| Fresh Windows ↔ remote LAN device B frp 0.71.0 XTCP/QUIC IPv4 comparator | Both peer-hole logs and strict existing-host-key SSH login, exit 0; no assisted address/data fallback |
| Cloud dual-port STUN after the second UDP observer became reachable | Both physical-IP-bound Linux hosts verified Binding replies on 22092 and 22093 |
| Extended native Linux frp XTCP/QUIC reference | Both discoveries exited 0; six SSH banner checks failed; neither peer hole established; all ten paired mode-0 strategies covered |
| EasyTier v2.6.4 no-TUN UDP and default TCP references | Eight snapshots per transport showed only a two-hop target route with no direct peer connection; no SSH data attempted |
| EasyTier with fixed native TCP observation endpoints | 17 cloud Binding responses; both native exits verified; remote LAN device B initiated TCP punching against the correct remote LAN device A exit, but eight snapshots still showed no direct peer |

All four control-packet formats/port trials returned successful cloud Binding observations for both hosts, with preserved source ports in these observations. The probes accept a valid peer HMAC from any source tuple so a changed egress IP would be recorded, rather than silently discarded. They carry no SSH/business payload. Successful cloud observation is not evidence of peer reachability or endpoint-independent UDP mapping.

Physical route checks showed the other public exit and cloud reached through each Linux host's native NIC/gateway, not Tailscale. Neither host had a global native IPv6 address. Read-only UPnP discovery found no usable gateway descriptor; NAT-PMP external-address queries received port-unreachable errors. No port mapping was attempted. An existing public SSH port offered a key different from the verified remote LAN device B key; strict checking stopped before login and known_hosts remained unchanged.

The standard STUN probe includes USERNAME, MESSAGE-INTEGRITY and FINGERPRINT per [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489.html); its encoded integrity/fingerprint were independently verified by aioice parsing. A read-only remote LAN device A capture without promiscuous mode saw all 40 probe datagrams leave its physical NIC, one cloud Binding request and its response, and zero peer ingress packets. The host input/output/nat/mangle rules examined did not identify a matching peer-UDP drop. remote LAN device B firewall inspection requires administrator access unavailable to the current ordinary-user session. Exit-gateway inspection was unavailable. This does not isolate the remaining failure between remote LAN device B host policy, upstream NAT/filtering and carrier routing.

Three same-local-port TCP comparisons establish destination-port-dependent mapping on remote LAN device A for those measurements. A complete NAT/filtering classification is not established. Other public STUN replies were absent on remote LAN device A; absence alone does not distinguish firewall policy, routing and mapping behavior. These findings do not prove that every possible direct method is impossible.

Temporary tests used cloud UDP 22092 and a second UDP 22093 observer restricted to the two Linux exits. Bounded observers stopped after testing; actual rule removal remains unverified, because process cleanup does not remove a cloud security-group rule. The dual-port observer passed actual frp 0.71.0 loopback discovery.

Before the second temporary observer became reachable, two physical-IP-bound checks verified 22092 replies and no 22093 replies. A read-only cloud capture saw two incoming 22092 requests, none on 22093 and no kernel drops. After the reachability change, **both ports responded on both Linux hosts**. The earlier missing-port observation is historical, not the latest result. No automated cloud-console configuration change was completed. Actual removal of the two temporary security-group rules remains unverified.

The completed extended frp reference performed six client-version/banner checks with up to 25 seconds per check. Both native-bound discoveries exited 0, the observer sent 48 responses and both control channels remained available. Logs covered all ten paired mode-0 strategies: both roles, receiver TTL 7/4/normal, delays 0/5/10 seconds and read timeouts 5/10/15 seconds. Neither endpoint established a peer hole. A 35-second non-promiscuous physical remote LAN device A capture saw four outgoing peer UDP packets, zero incoming peer packets and zero kernel drops. A preceding three-check reference also failed; two interrupted management/control attempts are not counted as completed failures. All owned frp processes, observers and validated temporary directories were stopped/removed. Sanitized evidence: `test-results/dual-stun-reachability-20261004.json`.

### STUN DNS and exit differences

Read-only DNS checks returned `198.18.*` addresses for three STUN domains on remote LAN device A, while remote LAN device B and the Windows EasyVoIP comparator resolved public IPv4 addresses. These answers are consistent with [Mihomo's documented Fake-IP range](https://wiki.metacubex.one/en/config/dns/); this is an inference, not identification of the responsible software/device. No active host Clash/Mihomo/sing-box process or listed host proxy-redirect rule was found. The gateways could not be inspected.

A numeric EasyVoIP A→B→A same-physical-socket sample verified all three replies on both hosts. The remote LAN device A exit differed from its native cloud observation; the remote LAN device B exit matched. A later socket failed to reproduce remote LAN device A's response, and numeric frp discovery timed out before punching. Two cloud→MiWiFi→cloud comparisons verified the cloud replies on remote LAN device A but no MiWiFi reply; remote LAN device B verified all replies. Four additional explicitly selected EasyTier-published domestic observers produced no external verified remote LAN device A response in either modern/classic mode, while remote LAN device B verified modern replies from three. All cloud-before/after checks passed. These samples do not establish cross-IP mapping independence on remote LAN device A. Evidence: `test-results/stun-routing-20261004.json`.

### Independent EasyTier comparator

Official v2.6.4 Linux/Windows archives were checked against their GitHub release SHA-256 digests. No system installation or service change occurred. A three-process Windows loopback smoke with `no_tun`, disabled UPnP and disabled data relay transferred and hash-verified 64 KiB with half-close. In a separate relay-denial case, the target was advertised with a two-hop route and application data did not reach it (zero target accepts). This checks a real denied relay path rather than an absent target route.

The ordinary-user Linux references ran as ordinary users with explicit physical listener addresses, loopback-only RPC, isolated temporary state, IPv6/DNS/exit-node features disabled and `p2p_only` enabled. Runtime configuration dumps verified the no-TUN/no-UPnP/no-data-relay constraints on all three processes. The cloud process and SSH tunnels carried coordination; the local smoke demonstrated the data-relay denial. The initial UDP reference obtained cloud STUN mappings and attempted cone-to-cone punching without a direct connection. Its two-port classification is limited to one observer IP. The default TCP reference actually exchanged mapped addresses and attempted TCP punching, but remote LAN device A's default TCP STUN services supplied a different exit from the native cloud observation. Neither reference produced a direct target peer; no SSH payload was attempted.

The final TCP comparison used temporary ordinary-user instrumentation of the supervised static binary's TCP STUN destinations, with two fixed original endpoints mapped to existing cloud TCP 22090/22110 and other default observer endpoints refused. The release binary and host DNS/routes/firewalls/authentication were unchanged. An ordinary-user WSL loopback smoke verified both redirected Binding responses and unused-endpoint refusal. Physical-IP-bound Python TCP probes also verified both cloud ports and native exits on both Linux hosts. The final engine reference produced 17 cloud Binding responses; both endpoints' classification observations used one local port and the correct native exit. remote LAN device A's mappings differed between the two cloud destination ports; remote LAN device B's source port was preserved. remote LAN device B actually exchanged the native mapped tuple with remote LAN device A and initiated TCP punching. It still obtained no direct peer in eight snapshots; no SSH data was attempted. This removes the different-exit setup error from that comparison without claiming a complete cross-IP NAT classification. Unsupported static-library override and aliased-observer attempts are not counted as corrected native trials.

All owned remote reference processes/directories and diagnostic-test directories were verified absent after the final run; cloud TCP 22090/22110 and UDP 22092/22093 test listeners were closed. Temporary security-group rule deletion is still awaiting user confirmation. Sanitized evidence: `test-results/easytier-native-reference-20261004.json`.

The UDP compatibility observer now emits OTHER-ADDRESS before legacy CHANGED-ADDRESS: v2.6.4 XOR-decodes the legacy attribute, while frp reads it normally. Actual frp loopback discovery still passed after that ordering change. The native-peer gate reads the nested CLI route/connection schema and requires the selected live direct connection, correct next hop and exact approved native IP; it also passed actual positive/negative loopback CLI snapshots. Six independent gate tests and seven STUN/TCP-observer wire cases passed on **Windows and both actual ordinary-user Linux hosts, with no skips**. Run them with `python -m unittest discover -s experiments/easytier-reference -v` and `python -m unittest discover -s experiments/stun-observer -v`. Logs are `test-results/reference-diagnostics-*-20261004.txt`. These do not change the production root suite's 69-test count.

## Remaining acceptance

The alternative topology permits the local workstation to bridge business
traffic if it connects directly to both Linux hosts. local workstation ↔ remote LAN device B is a
verified FRP reference positive; local workstation ↔ remote LAN device A and the complete two-leg topology
are unverified. This changes the acceptance target, not historical test results
or the metadata-only coordinator. The new explicit `home-bridge` command is
opt-in; it is not an automatic relay fallback. Both native legs, intended SSH identities and data integrity must
pass before this alternative is counted as complete.

### Historical Windows ↔ remote LAN device B success recovered on 2026-10-04

Historical evidence from 2026-09-30 contains an actual successful **Windows ↔ remote LAN device B IPv4/QUIC XTCP** trial, predating this Python implementation. The original remote LAN device B provider log and Windows visitor configuration were also read without modifying them. This corrects any implication that the remote LAN device B has never supported a native peer connection.

Both endpoint logs recorded successful NAT-hole establishment and public IPv4 peer tuples. The visitor had no `fallbackTo` setting, and assisted addresses were disabled. A strict existing-host-key SSH login through local port 16022 returned the expected remote LAN device B hostname/user with exit 0. Separate 32 MiB uploads/downloads exited 0 at 9.38/4.67 MB/s respectively. These are historical measurements, not a fresh rerun or a verified payload hash.

The successful observer was `stun.easyvoip.com:3478`, after the initially selected observer failed. The remote LAN device B-side frp strategy used receiver role, mode 1, TTL 7 and a bounded 17-port candidate interval; its learned peer port differed from the two initially observed source ports. These are promising differences from the current single-observed-tuple probes, not proof of which difference caused success. frp's reported EasyNAT/HardNAT labels apply only to that historical trial, not a full current NAT classification. Sanitized evidence is in `test-results/historical-frp-20260930.json`.

The historical pair was **Windows ↔ remote LAN device B**, not **remote LAN device A ↔ remote LAN device B**. It used IPv4, not native public IPv6. Current `ssh EXISTING_SSH_ALIAS` targets the Tailscale address and current route probes use DERP; this does not refute the earlier XTCP success. The next traversal work should compare/reproduce this concrete successful recipe with physical-IP binding and peer-path evidence, while keeping the required Linux-to-Linux acceptance separate. No existing frp configuration, Tailscale setting, authentication or network configuration was changed during this historical inspection.

### Fresh Windows ↔ remote LAN device B reference on 2026-10-04

A new temporary frp XTCP/QUIC trial completed both public-IPv4 hole-establishment logs and a strict existing-host-key SSH login with the expected marker and exit 0. Assisted addresses and data fallbacks were absent; existing cloud frps and SSH tunnels carried coordination only. This is fresh evidence that the remote LAN device B remains capable of a native peer path, not a success of the Python implementation or the required Linux pair. Temporary provider/visitor/tunnels and their directories were removed; existing frp configuration was unchanged. Sanitized evidence: `test-results/frp-windows-remote-lan-b-20261004.json`.

The initial passive-banner comparator did not send client bytes and failed to observe a banner even after a QUIC path existed. Sending the ordinary SSH client version line made the stream usable; a real SSH login then confirmed it. Those passive reads are not counted as failed NAT traversal. A separate setup attempt inherited the remote LAN device B's existing HTTP proxy environment; unsetting it only for the temporary frpc process allowed coordinator login. Neither fix changed host configuration.

The new diagnostic packet encoding passed independent aioice integrity/fingerprint parsing. The TCP low-TTL tool also passed a Linux loopback observation/MAC/64 KiB hash/half-close comparator. Real failed probes are in `test-results/native-traversal-20261004.json`. The multi-socket tests use consenting-peer control packets, not public service discovery. Their failures do not prove that all future strategies are impossible.

**No remote LAN device A ↔ remote LAN device B SSH success over physical networks is established.** No cloud relay, Tailscale data path or unverified public SSH server may count as success. Dual-port UDP observation and corrected native TCP observation have both been exercised; their setup limitations are no longer pending. The failed corrected TCP comparison demonstrates that the DNS/different-exit issue alone does not explain all failures. The remaining peer-path failure is not isolated to a specific gateway/filter. Gateway inspection was unavailable. Other network changes/deployment remain subject to user confirmation.

Not established: universal UDP-blocked/complex-NAT traversal, macOS/minimum-Python runtime, roaming/sleep recovery, production enrollment UI/key custody/service deployment, package release or CI/security audit. Private inventories, public exit addresses, identity PEMs/pins, credentials and ICE secrets remain under ignored `.fan-ssh/`; public evidence contains only sanitized results.

### Dual-listener TCP continuation and local workstation IPv6 feasibility

The separate Linux TCP diagnostic now supports prelistening at both ends while
actively connecting from the same source port with SO_REUSEADDR/SO_REUSEPORT.
Role 0 selects the authenticated stream; role 1 follows that selection. Three new
Linux controls verify exact 64 KiB exchange/half-close on the same stream, wrong-MAC
rejection, and bounded cancellation with no descriptor leak. remote LAN device B ordinary-user UID (redacted) and
remote LAN device A ordinary-user UID (redacted) each passed all 25 TCP diagnostic tests without skips. WSL separately
verified full source-bound observation/peer-MAC/payload/half-close orchestration
for the new mode and the existing low-TTL mode. Remote regression packaging now
includes the standalone script imported by these controls.

Three fresh native trials and one captured repeat all failed authenticated peer
connectivity. remote LAN device A's outbound TCP connect returned successfully, but remote LAN device B had no
corresponding accept, and no peer MAC was verified. The captured repeat saw nine
physical-NIC TCP packets with zero kernel drops, including inbound SYN-ACK and FIN;
the MAC read ended before receiving any bytes. These headers do not prove that
remote LAN device B generated the replies and do not localize the failed network device.
No SSH payload was sent. Owned remote processes, diagnostic directories and cloud
test listeners were verified absent afterward. Actual deletion of the temporary
UDP security-group rules is still unconfirmed. Sanitized results:
`test-results/tcp-reuse-native-20261004.json`.

For the local workstation relay alternative, Windows WLAN has a global IPv6
address/default route and passed native-source IPv6 HTTPS with the expected
reported source. Both Linux hosts lack a native IPv6 default route/global address
and return `Network is unreachable` for the local workstation IPv6 destination. An IPv6-only
local workstation entry therefore cannot currently be reached natively by those hosts. Router
WAN IPv4 was initially unavailable through the browser. A later source-bound
UPnP GetExternalIPAddress returned a private WAN address, establishing another
IPv4 layer; the upstream WAN is still unknown. IPv6 inbound firewall, ability to
host relay software and bandwidth remain unverified. No router/network/
authentication change or relay deployment occurred. Updated evidence:
`test-results/workstation-relay-feasibility-20261004.json`.

### Synchronized TCP, path comparison and cleanup regression (2026-10-05)

Four valid Python comparisons borrowed [DCUtR CONNECT/SYNC and half-RTT timing](https://github.com/libp2p/specs/blob/master/relay/DCUtR.md).
Both endpoints prelistened with ordinary same-port Linux sockets, waited at a
startup READY barrier and completed authenticated coordination. Both role
assignments failed peer authentication, with measured coordination RTTs of
54.406 and 55.255 ms. Releasing the observation socket before dialing, inspired
by [RustDesk's client](https://github.com/rustdesk/rustdesk/blob/master/src/client.rs),
also failed both role assignments (60.134 and 62.697 ms). remote LAN device B accepted zero
connections in all four; remote LAN device A's connected stream ended before any peer-MAC bytes.
No SSH payload was sent or cloud business data forwarded. Two WSL controls,
including the release variant, verified peer MAC, exact 64 KiB/hash and half-close.
These are research prototypes, not actual libp2p/RustDesk binary/wire tests.
Earlier startup/Python-version/frame-order setup failures are excluded. Evidence:
`test-results/tcp-sync-native-20261005.json`.

A separate remote LAN device B prelistener plus authenticated observation supplied a fresh
peer tuple. Physical-source-bound remote LAN device A TCP probes at TTL 2/4/7/64 completed
handshakes in 0.884/0.928/0.849/0.722 ms respectively; none authenticated, and
remote LAN device B had zero accepts. remote LAN device A's physical capture saw the configured TTL values,
incoming SYN-ACK TTL 63, 37 captured packets and zero kernel drops. Known-cloud
TCP/UDP observations failed at TTL 2 and succeeded at TTL 64; the TCP cloud
handshake took 27.208 ms and its authenticated response took 53.353 ms overall.
This is consistent with destination-dependent intermediary/handshake processing,
not successful peer connectivity. It does not identify the exact device or prove
the cause of all UDP failures. Low-TTL ICMP to the remote LAN device B exit also elicited a
roughly 29 ms reply, so these TTL values cannot establish an exact physical hop
count. [RFC 1812's TTL forwarding rule](https://www.rfc-editor.org/rfc/rfc1812.html#section-5.3.1)
describes ordinary IP forwarding; rewriting/tunneling/protocol-specific handling
can limit this inference. ICMP gateway replies never pass the SSH identity gate.
Known SSH-port checks sent no credentials and found no verified native target;
remote LAN device B's offered public port-2222 key did not match its trusted host key.
Evidence: `test-results/tcp-path-comparison-20261005.json`.

The private Python 3.12 comparator revealed a real shutdown bug in the standalone
TCP observer: `server.wait_closed()` could wait for held clients before reaching
handler cancellation. An observable subprocess regression timed out before the
fix and passed afterward. The observer now stops accepting, cancels/gathers
handlers first, bounds writer shutdown, then waits for server closure. The test
keeps an authenticated client open during controller EOF and requires process
exit within three seconds, client EOF and port rebinding. **remote LAN device B ordinary-user UID (redacted) and
remote LAN device A ordinary-user UID (redacted) each passed all 26 TCP diagnostic tests, with no skips; WSL passed all
26 too.** Logs: `tcp-reuse-diagnostics-*-20261005.txt`; evidence:
`test-results/tcp-observer-shutdown-20261005.json`. Production transports/root
69-test suite are unchanged; this repair is not a traversal success.

### local workstation path and IPv6 follow-up (2026-10-05)

A completed local Windows workstation ↔ remote LAN device A frp 0.71.0 XTCP/KCP comparator failed all six
client-version/banner checks and four completed hole strategies. Two strategies
ran their full 38-second receiver window with 256 local workstation sockets and 1000 bounded
random consenting-peer port probes from remote LAN device A, using TTL 4 and normal TTL. Its
physical capture saw 2008 peer-bound UDP packets, zero peer ingress and no kernel
drops. No data fallback, assisted address or cloud business relay was configured;
neither peer established a hole and SSH was not attempted. Some earlier
QUIC/short-KCP long strategies were interrupted and are excluded from completed
long-mode failures. The local workstation exit matched the fresh local workstation ↔ remote LAN device B positive.
Evidence: `test-results/workstation-remote-lan-a-frp-reference-20261005.json`.

Source-bound local workstation UPnP read-only discovery returned RFC1918 private WAN IPv4. The
upstream gateway exposes a login page, but its WAN status is not known.
No mapping was added and no upstream login was attempted. Both Linux hosts still
lacked native global IPv6/default routes. remote LAN device A NetworkManager's `ipv6.method=ignore`
leaves IPv6 alone; remote LAN device B's `auto` can manage it in userspace, so its kernel
`accept_ra=0` alone does not establish disabled IPv6. See [NetworkManager's IPv6
settings](https://networkmanager.dev/docs/api/latest/settings-ipv6.html).
Two standard link-local Router Solicitations, sent under separately authorized
read-only diagnostic permissions, received no RA within eight seconds; address/route snapshots
remained unchanged. The existing remote LAN device B loopback proxy returned CONNECT 200 for
an IPv6 destination, followed by SSLEOFError during TLS, so a usable bridge was
not demonstrated. No network/authentication configuration or deployment changed.
Evidence: `test-results/workstation-relay-feasibility-20261004.json`.

Owned test processes/directories and all four cloud observation listeners were
verified absent after this continuation. Temporary security-group rule deletion
is independently unverified. **Required remote LAN device A ↔ remote LAN device B native SSH remains unsolved.**

### Accepted local workstation topology and new comparisons (2026-10-05)

The alternative topology is **remote LAN device A ↔ local Windows workstation ↔ remote LAN device B**
when both legs independently use native direct paths. The existing local workstation ↔
remote LAN device B FRP visitor passed another strict-host-key SSH login, but the local workstation ↔
remote LAN device A leg remains unverified. A local workstation bridge is permitted business forwarding;
Tailscale and cloud business forwarding remain excluded. Neither accepted
topology has complete real SSH/data acceptance.

Four Windows loopback controls verified same-port TCP reuse, authenticated
CONNECT/SYNC timing, exact 64 KiB/hash and half-close with both roles and held/
released observation sockets. Four corresponding local workstation/remote LAN device A native trials completed
MACed coordination at approximately 39–49 ms RTT but authenticated no peer. local workstation
accepted no connection; remote LAN device A completed a TCP connect and received zero peer-MAC
bytes. These are Python timing prototypes, not actual libp2p/RustDesk binaries.
Evidence: `test-results/workstation-remote-lan-a-tcp-sync-20261005.json`.

A role-reversed frp 0.71.0 QUIC comparison used local workstation as provider and remote LAN device A as visitor.
Neither endpoint established a hole, and four authenticated echo checks failed.
Seven paired hole strategies have complete terminal logs, including one full
38-second local workstation receiver window with 256 sockets and 1000 bounded consenting-peer
port probes from remote LAN device A. The following long strategy has a completed local workstation window but
an earlier saved remote LAN device A log/capture, so its paired completion is excluded. The physical
remote LAN device A capture recorded 2082 outgoing peer UDP packets, zero incoming peer UDP and
zero kernel drops. No fallback/assisted addresses or cloud business relay was
configured; SSH was not attempted. Evidence:
`test-results/workstation-remote-lan-a-frp-reversed-20261005.json`.

Actual EasyTier v2.6.4 Windows/remote LAN device A references, with verified effective no-TUN,
no-UPnP and no-data-relay profiles, obtained no selected native peer in eight
UDP and eight TCP snapshots. UDP log retrieval timed out after the completed
observations; exact owned process/directory cleanup was rescued and audited.
TCP used corrected numeric observers on remote LAN device A only; local workstation retained default TCP
observers and their source scope is unverified. Both engines reported symmetric
TCP NAT. The [v2.6.4 initiator guard](https://raw.githubusercontent.com/EasyTier/EasyTier/v2.6.4/easytier/src/connector/tcp_hole_punch.rs)
skips symmetric initiators, so this TCP result must not be counted as a completed
symmetric/symmetric punching failure. These engine labels and two ports on one
observer IP do not establish a complete NAT classification. No SSH/data payload
was attempted without both selected-peer gates. Evidence:
`test-results/workstation-remote-lan-a-easytier-20261005.json`.

### Explicit local workstation bridge implementation (2026-10-05)

`home-bridge` now exposes one explicitly named incoming service bound to a fixed
final peer/service. Incoming and outgoing legs obtain independent pinned device
admissions and directed grants. It reuses the direct-method selector and adds no
cloud business operation or automatic relay fallback. Anonymous socket pairs
avoid a separate unauthenticated loopback forwarding port. Incoming readiness
means admission to the local workstation bridge; final SSH/login/data success remains a
separate requirement.

Synthetic integration covers a 1 MiB binary/hash comparison with delayed reply
after half-close, independent grant bindings, missing directed permissions,
wrong final pin, downstream and local workstation policy revocation, relay-evidence rejection,
caller cancellation and the real foreground CLI with binary-clean stdout. Two
128 KiB comparisons exercise TCP -> UDP and UDP -> UDP composition, using the
same Windows selector event loop as native UDP CLI operation. These are loopback
controls; none proves a native local workstation ↔ remote LAN device A path.

A deterministic pre-start cancellation regression initially timed out waiting
for anonymous-socket EOF. Closing that socket in the task completion callback
also covers cancellation before the broker coroutine enters its `finally` block.
The same regression passes after the fix. A separate bridge cleanup assertion
used an unreliable fixed 50 ms delay; it now waits at most three seconds for actual
task completion instead. All nine latest TCP bridge cases passed on both real
Linux hosts without skips.

| Latest environment | Full root suite | Separate TCP diagnostics | Bridge coverage |
|---|---|---|---|
| remote LAN device B ordinary-user UID (redacted), Python 3.12.10 | 80 passed, no skips | 26 passed, no skips; demo passed | All 11; latest TCP subset 9 passed |
| remote LAN device A ordinary-user UID (redacted), Python 3.12.3 | 80 passed, no skips | 26 passed, no skips; demo passed | All 11; latest TCP subset 9 passed |
| Windows Python 3.12.10 | 80 total: 75 passed, 1 failure, 1 error, 3 Linux-only skips | Linux runs above | All 11 bridge cases passed; full regression remains open |

The Windows failures occurred in existing renewal and UDP signaling tests. An
isolated one-second lease check then passed, but that does not resolve its full
run reset. The debug-enabled 1 MiB UDP echo stalled at 983040 bytes and produced
a background SCTP teardown error. A separate 15-second debug-enabled state
comparison also stalled, with ICE/DTLS/SCTP still connected and pending SCTP data.
Installed SCTP source matched the supplied offline aiortc wheel exactly. Three
non-debug comparisons, using the CLI's default debug setting, passed exact 1 MiB
echo and half-close in approximately 3.7–4.6 seconds. These controls narrow the
investigation; they do **not** establish that debug overhead is the only cause
or repair Windows UDP/lease reliability. Do not hide the failed full run or
report Windows as completely validated. Existing remote LAN device B FRP was unchanged.

The rebuilt development wheel includes `home_bridge.py`; SHA-256:
`735ddd0f8d7febf7f25e64b39bc571e9b3c0a8fceedc87c1e5c87045649aeb10`.
Installing it into a temporary target outside the checkout verified its actual
import location and foreground bridge CLI with binary/hash/half-close behavior
and empty stdout. This is a packaging smoke, not a release or real SSH login.
Sanitized evidence: `test-results/home-bridge-20261005.json` and
`home-bridge-*-20261005.txt`. The failed full Windows log is explicitly named
`home-bridge-windows-full-failed-20261005.txt`.

Real local workstation ↔ remote LAN device A and complete two-leg native SSH/data acceptance remain open.

### New remote LAN device D native reference success and publication gate (2026-10-05)

The extended reference coverage includes remote LAN devices A/C/D. Three ordinary
accounts passed physical-device-bound UDP/TCP observations. remote LAN device C's default route
included a virtual proxy interface; an owned-child syscall supervisor bound
the original static Go FRP binary's IPv4 UDP sockets to the physical interface,
without route/firewall/capability or executable changes. Its ordinary-user
socket-option control passed on all three hosts; the published generic helper
also passed a fresh ordinary-user Linux control and refuses root execution.

External numeric STUN observations differed from physical numeric-cloud
observations. All three peers actually received Binding replies from both
approved cloud UDP ports. With these numeric cloud observers, **local Windows workstation ↔
remote LAN device D passed native IPv4/QUIC XTCP**, both hole-establishment logs, exact selected
peer/native observation matching, physical route checks, strict existing SSH
host-key validation, a login marker/expected ordinary-user identity, a 1 MiB
upload SHA-256 and an exact 1 MiB echo SHA-256. The upload took 0.397 seconds in
that small control; it is not a sustained bandwidth benchmark. A separate random
1 MiB download exited 0; only upload/echo have independent expected hashes.
No data fallback, assisted address, cloud business relay, SSH-agent forwarding or
private SSH-key transfer was configured. The native SSH/hash result was repeated.

The two initial three-peer comparison rounds had six checks per unsolved peer.
Neither remote LAN device A nor remote LAN device C established a verified hole/SSH path. These failures
remain separate from remote LAN device D's positive. A later attempt to reuse the older
remote LAN device B loopback visitor refused the connection, so no complete remote LAN device D -> local workstation
-> remote LAN device B transfer is claimed; historical remote LAN device B positives remain valid.
Existing services were preserved, and owned tests/temporary directories were
stopped/removed. Security-group rule deletion remains independently unverified.

This is an original FRP reference success, not proof that the Python selector or home-bridge
has integrated that transport. Windows Python UDP/renewal issues and the original
remote LAN device A/remote LAN device B acceptance still remain open. Evidence:
`test-results/frp-workstation-remote-lan-d-native-20261005.json`,
`frp-remote-lan-d-anonymous-proof-20261005.txt`, `multi-peer-native-20261005.json`.
Reproducible generic process instrumentation is in
`experiments/frp-device-binding/`; endpoint profiles and raw logs are private.

### Usable Python SSH entry and actual native data (0.3, 2026-10-05)

A standalone FRP research success is insufficient to validate the Python product.
`python -m fan_ssh ssh` now invokes existing OpenSSH authentication over the actual
Python native transport. No original FRP process was launched in these tests.
Three distinct real logins to remote LAN device D passed strict existing-host-key validation.
An 8 MiB random upload passed its expected SHA-256, and an exact 8 MiB random
roundtrip passed SHA-256. All five returned authenticated native UDP evidence,
`relay: false`, matched Python receiving-node sessions and both physical routes.
Source automatic selection tried unreachable TCP, failed ordinary ICE, then
selected prediction; one fresh setup retry was exercised. See
`test-results/python-ssh-remote-lan-d-20261005.json`.

The entry was tested using the actual product CLI, not a test-only transport.
Original aliases supply OS credentials and host-key lookup while ProxyCommand
supplies the business path. No agent forwarding, SSH key copy, host-key update,
server authentication, network configuration or permanent deployment change was
made. Cloud carries pinned metadata and STUN only. Remote LAN devices A/C and the original
native Linux pair remain unverified; this validates the working Python route,
not universal traversal.

An earlier entry setup incorrectly placed ProxyJump before ProxyCommand, causing
OpenSSH to ignore the latter. That management-path result is excluded. The order
is corrected, actual `ssh -G` output must equal the Python proxy before launch,
and tests enforce fail-closed behavior for an inactive proxy. Localized whoami
output is parsed through its ASCII SID field. exFAT enrollment was directly
verified to reject before writing a private key; imported identity checks remain
strict. One setup's metadata reuses a bounded pinned mTLS connection (64 requests,
30 seconds, five-second operation/idle limit), rechecking current roster and
certificate validity on every operation. Prediction retries only connectivity
setup failures, with a new socket/grant; identity/policy errors are terminal.

SCTP send/reconfiguration callbacks racing a disconnected DTLS association now
surface failure by closing the owned application stream. The adapter does not
report readiness after failure. Actual regression cases exercise active failure
and expected teardown. Historical failed full Windows runs are not
rewritten as successes.

| Python 0.3 check | Result |
|---|---|
| Windows, actual product UDP event-loop configuration | 90 total: 87 passed, three Linux-only skips |
| Actual ordinary-user Linux host | 90 passed, no skips; 26 TCP diagnostics and demo passed |
| New SSH/control/identity entry checks | Eight passed, including real OpenSSH effective configuration and cancellation |
| Installed wheel outside source checkout | Correct 0.3 import/help; all eight entry checks passed |
| Separate Windows asyncio-debug stress | Intermittent stream error remains; retained failed log and opt-in reproduction |

Windows UDP ordinary-mode tests match the product's non-debug selector runner.
`FAN_SSH_UDP_DEBUG_TESTS=1` restores the separate debug stress run; its failure is
not claimed repaired. A one-second artificial renewal test and five-second whole
reverse test occasionally exceeded Windows scheduling/TLS overhead. Tests now
use a three-second shortened lease crossing multiple genuine renewals, and a
12-second total reverse budget; verification assertions are unchanged. Production
lease remains 30 seconds and its fail-closed behavior is unchanged. The final
remote subset of 23 cases also passed on Linux with the new test budgets.

The 0.3 wheel SHA-256 is
`defa716e4960bc4d24a870fa81a6f3547eda992f9cf3c38b6b6e03683dd0f677`.
Evidence: `test-results/python-product-regressions-20261005.json`,
`python-product-package-20261005.json`, `python-product-*-20261005.txt`.
No further broad/repeated tests are counted without new changes or concerns.
