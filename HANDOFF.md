# Python development notes

## Pending local validation: usability/profile branch (2026-10-05)

**Status: pending. This section is a test assignment, not a passing test report.**
Local Codex and the cloud reviewer exchange this task and its results **only
through GitHub**. Commit fixes and a sanitized report to the same independent
branch; no manual log paste or direct agent messaging is required.

Local follow-up: see [TEST_REPORT.md](TEST_REPORT.md) for completed Windows
source/wheel and WSL checks with pinned UDP extras. The report retains a Windows
debug UDP error and an intermittent WSL bridge EOF; it does not declare a clean
acceptance pass. The assignment below is preserved as historical instructions.

### Scope and starting point

- Repository: `FanWu-ai/fan-ssh`.
- Work branch: `feat/usability-profiles-anonymized-docs`.
- Reviewed implementation: `1ed85c24f5aec935320a8de8055271453026994e`.
- Main when this task was prepared: `026d943e0b5ca03c8092cceb0f77d4f46ba31656`.
- Validate the **complete usability/profile and anonymized-documentation
  patch**, not only the newest test or an earlier main checkout. This includes
  reusable connection profiles, `connect`, offline `doctor`, CLI behavior,
  privacy-preserving documentation, and the existing native transports,
  SSH entry and home bridge.
- The cloud run against the reviewed implementation reported **112 discovered:
  97 passed and 15 optional-UDP dependency skips**, for both source and installed
  wheel. The 15 skips mean UDP coverage is missing, not that UDP passed.
  Separate cloud TCP (26), STUN (7), EasyTier (6), offline CLI, demo, build and
  compile/diff checks passed. These are prior cloud results, not local results
  or proof of current Windows/native-network acceptance.

Before doing anything, fetch the current branch, read its newer commits and any
existing `TEST_REPORT.md` (or clearly identified equivalent), and preserve other
work. If a complete newer report already exists, review it instead of repeating
or overwriting it. Use the latest branch contents, including this handoff;
record the exact source SHA being tested. The SHA above identifies the reviewed
implementation, not an instruction to reset the branch. The older baseline and
historical findings below remain context, not the target for this assignment.
Read README.md, ARCHITECTURE.md, VALIDATION.md and any applicable repository
instructions before changing code.

### Environment and required checks

Use Python **3.11 or newer**, preferably **3.12**, in a fresh virtual environment.
Use the appropriate executable/activation syntax for the actual OS. Install the
optional UDP dependencies and build tooling, then verify the environment:

```sh
python -m pip install -e '.[udp]' build
python -m pip check
python -c "import sys, platform, importlib.metadata as m; print(sys.version); print(platform.system(), platform.release(), platform.machine()); print({p: m.version(p) for p in ('fan-ssh', 'cryptography', 'aiortc', 'aioice')})"
```

The current project pins **aiortc 1.15.0** and **aioice 0.10.2**. Check those actual
installed versions and successful imports; an optional-import failure must be
reported and fixed or left explicitly blocked, never hidden as a successful
full UDP run. Keep dependencies isolated; do not modify a production runtime.

Run the complete root suite and the targeted suites, retaining real command
exit codes and summaries. Discovery from the root suite does not cover the
separate experimental suites.

```sh
python -m unittest discover -s tests -v
python -m unittest discover -s tests -p 'test_udp.py' -v
python -m unittest discover -s tests -p 'test_home_bridge.py' -v
python -m unittest discover -s tests -p 'test_profiles.py' -v
python -m unittest discover -s experiments/tcp-simopen -v
python -m unittest discover -s experiments/stun-observer -v
python -m unittest discover -s experiments/easytier-reference -v
python -m fan_ssh demo
python -m compileall -q fan_ssh tests scripts experiments
git diff --check
```

Reference discovery sizes for the reviewed source are 112 root tests, 13 UDP,
11 home-bridge and 22 profile tests; the three separate experimental suites have
26 TCP, 7 STUN and 6 EasyTier tests. Report the observed counts if fixes add tests
or platform conditions differ. Test stdout/stderr and background exceptions
matter in addition to the final exit code.

Also check the installed CLI's help and offline profile/doctor flows described
in README.md using temporary synthetic fixtures. Preserve doctor’s explicit
unchecked-network/host-key limits and nonzero error exits. Do not point these
checks at private production profiles or write to the user's normal SSH/state
configuration.

### Wheel isolation check

Build a wheel with `python -m build --wheel`. Create a **second fresh virtual
environment**, install that exact wheel with its UDP extra (quote the local
wheel path plus `[udp]`), and run `python -m pip check` again. Do not install the
checkout editable in this second environment.

Change to a temporary working directory **outside the repository**, clear any
source-checkout `PYTHONPATH` override for the test process, and use the second
environment's Python. Verify `fan_ssh.__file__` resolves to that environment's
installed site-packages and check the installed distribution/dependency
versions. Redact the actual private absolute path in the public report.

From that external directory, rerun the full root suite by its absolute
`tests` path (for example, `python -m unittest discover -s ABSOLUTE_REPO/tests -v`),
the targeted UDP/home-bridge/profile suites, installed `fan-ssh --help`,
`python -m fan_ssh --help`, and the demo. The test files may come from the source
checkout, but imports and subprocess CLI calls must resolve to the installed
wheel. Record the wheel SHA-256 and source SHA; repeat build and wheel checks
after any source fix.

### Platform skips and retained limitations

For the reviewed root suite, native Windows has **five platform skips**:
the Linux signal/pipe CLI case, two Linux source-bound TCP cases, the profile
symlink case and the POSIX FIFO case. Two IPv6 loopback tests may additionally
skip if IPv6 is unavailable. Record every skipped test and its actual reason.
These platform/IPv6 skips are different from the cloud's **15 missing-UDP-
dependency skips**. Platform skips do not validate the skipped behavior;
Windows, WSL and native Linux are separate environments.

Run ordinary Windows UDP coverage with the product's existing non-debug
selector-loop configuration. Keep the separate, historically failing stress
mode visible: set `FAN_SSH_UDP_DEBUG_TESTS=1` **only for a bounded test process**
and rerun the UDP and UDP home-bridge coverage where that mode is supported.
Record the exact commands, timeout if one is used, exit codes, failure/error
details and any background exceptions separately. Do not relabel a timeout or
interruption as a pass. Preserve the historical failed evidence already in
`test-results/python-product-windows-debug-failed-20261005.txt` and
`test-results/home-bridge-windows-full-failed-20261005.txt`, even if a new run
passes. A normal-mode pass does not erase the intermittent debug stress issue.

Fix reproducible regressions within this branch's scope and rerun the affected
checks plus full source/wheel regressions. Do not delete or weaken assertions,
silence failures, add skips, arbitrarily enlarge timeouts, or alter security
checks merely to obtain green output. Preserve pinned identities, directed
grants, fail-closed behavior, strict existing SSH host keys, direct-path evidence,
binary integrity and half-close/cleanup checks.

Loopback tests are synthetic. Do not claim full native Windows, real SSH,
cross-network or two-leg home-bridge acceptance unless those exact checks were
actually run with matching evidence. Do not infer new live-test authorization
from historical notes. No production deployment, firewall/router/network
changes, SSH credential or authentication changes, unknown-host-key acceptance,
agent forwarding, new account permissions or relay workaround is authorized by
this assignment.

### GitHub result contract

Create or update a public-safe `TEST_REPORT.md` on
`feat/usability-profiles-anonymized-docs`, or preserve an established equivalent
and identify it here. The report must include:

1. Status: passed with explicit coverage limits, failed, blocked or pending.
   Name the exact tested code SHA; after report-only commits, identify the
   tested code parent and explain that only documentation changed.
2. Actual OS/runtime and dependency versions, source versus installed-wheel
   setup, wheel hash, and test date/time.
3. Every command, its exit code, discovered/passed/failed/error/skipped counts,
   and individual skip reasons. Keep failed, blocked, not-run and passed stages
   distinct, including the separate debug stress result.
4. Reproductions, root cause and fixes for new failures, with the matching
   fix/test commit SHAs and rerun evidence. Preserve unresolved limitations.
5. Whether real native Windows, real SSH, physical cross-network and two-leg
   home-bridge checks were run; if not, say **not run**. Historical evidence
   remains historical.
6. Any CI status observed for the exact remote commit. Pending, absent,
   skipped, or awaiting maintainer approval is not a passing online check.

Use synthetic peer labels and sanitized excerpts. Never commit real machine
aliases, private IPs/endpoints, account usernames/UIDs, keys, tokens, credential
material, private absolute paths, inventories or raw private logs, including in
intermediate commits. Review staged content and commit metadata for leakage.

Commit the validated fixes and report to **this same independent branch**.
Immediately before pushing, fetch again and compare the actual remote head.
If another contributor advanced it, preserve and integrate their work safely
and rerun applicable checks; stop and report conflicts rather than resetting,
overwriting or force-pushing. Push only by a normal fast-forward update, then
read GitHub back to verify the actual remote SHA, file contents and report.
Do not merge into or push to `main`, create a PR, deploy, force-push or expand
permissions without separate user approval. The cloud reviewer will read the
report and review the resulting GitHub changes directly.

---

Read README.md, ARCHITECTURE.md and VALIDATION.md first. The baseline is Python main at `2cd46ec7d2b6705c2f12527b6c1dc67de7ab50c4`; do not reintroduce the earlier Go draft.

## Product objective and acceptance

A usable Python connection requires the Python `ssh` entry and native transport
to pass strict SSH/data checks; an original-FRP reference success alone is
insufficient. Deployment and server network/authentication changes require
separate explicit approval.

Ordinary-user, multi-host SSH across different LANs. The acceptance targets are either **native remote LAN device A ↔ remote LAN device B SSH** or **remote LAN device A ↔ local Windows workstation ↔ remote LAN device B**, with both local workstation legs independently direct over physical networks. In the alternative topology the local workstation is an explicitly permitted business bridge; Tailscale and the cloud must not carry business traffic. A metadata-only cloud coordinator remains allowed. Verify both legs, the intended SSH identities and complete data transfer before counting that topology as success. One working local workstation ↔ remote LAN device B reference is insufficient. The new explicit `home-bridge` command has synthetic validation, not complete real-topology acceptance. Do not label the project complete or publish a completed product before accepted real-network behavior and product integration pass.

Reference tests used temporary Windows/Linux peers and a metadata coordinator.
Existing SSH provides management access only; retain verified host keys, no agent
forwarding and unchanged authentication. The reference coverage also includes
remote LAN devices A/C/D, whose outcomes must remain distinct. Publish only
sanitized evidence, never private endpoint inventories, addresses, usernames,
credentials, tokens, router details or raw logs, including intermediate commits.
Temporary tests do not authorize permanent deployment or network/authentication
changes.

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
- Explicit fixed-target local workstation business bridge: incoming named service and local workstation-to-final service require separate directed grants. Ordinary nodes retain loopback-only targets. Anonymous socket pairs compose the legs without an additional forwarding listener; cancellation/revocation closes both. The bridge is opt-in, never an automatic/cloud relay fallback. Policy revisions require a bridge restart.

The original loopback fixture remains isolated: synthetic identities, loopback restriction, 30-second session. Remote sessions use renewal and a 24-hour absolute deadline. The new remote protocols are not compatible with the old Go/v1 fixture.

## Real network findings

Cloud-bound direct TLS and a Windows → cloud existing-credential SSH login were demonstrated. They do not satisfy remote LAN device A ↔ remote LAN device B acceptance. Both Linux routes to the other public exit use physical NICs. Neither host has a global native IPv6 address.

With the temporary cloud UDP 22092 observer reachable, each host obtained a server-reflexive tuple. ICE still timed out before DTLS/SCTP. Three controlled HMAC trials used ephemeral, fixed 22092 and fixed 3478 source ports: each host sent 40 packets/trial; no verified or unexpected peer datagrams arrived. A standard STUN-formatted authenticated fixed-3478 trial also received no peer packets. Its wire integrity/fingerprint passed independent aioice parsing. A read-only non-promiscuous remote LAN device A NIC capture confirmed 40 peer-bound packets physically transmitted, cloud observation request/reply and zero peer ingress. No arbitrary port sweep was attempted.

Three same-source-port TCP observations at two approved cloud destination ports showed mapping changes on remote LAN device A and stable mappings on remote LAN device B. This demonstrates destination-port-dependent TCP mapping for those observations, not a complete NAT classification. Strict active and explicit passive/active hybrid attempts produced no pinned peer path. Hybrid TCP connect completion without matching target accept/TLS must not count as success.

Gateway UPnP discovery returned no usable descriptors; NAT-PMP external-address-only queries received port-unreachable errors. No mapping was created. An existing public SSH port responded with a host key different from the remote LAN device B's verified key: authentication was stopped, and known_hosts was not changed. Never count that other SSH endpoint as the remote LAN device B.

## Temporary cloud rules

Temporary tests used cloud UDP 22092. Bounded observers stopped after the tests,
but actual network-rule removal remains unverified. Process cleanup does not
prove security-group cleanup. Temporary test authorization does not permit
recreating rules or retaining permanent listeners.

After the second temporary observer on UDP 22093 became reachable,
physical-IP-bound checks verified replies on **both ports from both hosts**.
The earlier missing-22093 capture predates that change and is not the latest
reachability result. Both temporary rules still require verified cleanup.
Evidence: `test-results/dual-stun-reachability-20261004.json`.

`scripts/dual_stun_observer.py` passed actual frp 0.71.0 discovery locally. It emits compatible MAPPED/CHANGED/OTHER addresses at two ports on one IP, not a full RFC 5780 classification. An initial three-check reference and a completed six-check extended reference ran after both ports became reachable. Both hosts discovered successfully, but neither established a hole. The extended reference covered all ten paired frp mode-0 strategies (roles, receiver TTL 7/4/normal, delays and read timeouts); the observer sent 48 Binding responses. A 35-second non-promiscuous remote LAN device A capture saw four outgoing peer UDP packets, no incoming peer packet and no kernel drops. Interrupted management/control runs are not counted as completed traversal failures.

Stop owned observers after each bounded trial. No automated cloud-console edit
was completed; actual security-group rule deletion remains independently
unverified.

At this checkpoint, all owned reference/diagnostic-test processes and temporary directories were verified absent on all three servers. TCP 22090/22110 and UDP 22092/22093 test listeners were closed. Actual deletion of the two temporary UDP security-group rules is not yet confirmed. Do not claim complete network-rule cleanup or silently reopen a removed rule.

## Validation workflow

```sh
python -m pip install -e '.[udp]'
python -m unittest discover -s tests -v
python -m unittest discover -s experiments/tcp-simopen -v
python -m fan_ssh demo
```

Run Linux-specific tests on the authorized Linux hosts instead of counting Windows skips as completed Linux validation. `scripts/remote_tests.py --host ALIAS --python python3.12 --udp --output .fan-ssh/host-tests.log` ships supplied offline Linux wheels, runs root/experimental suites and the demo under an ordinary uid, and removes only its validated mktemp directory. Root discovery does not run the separate experiment suite. Latest results belong in VALIDATION.md and sanitized `test-results/v0.2-*`; do not publish private endpoint inventories, credentials or ICE secrets.

Exit-gateway inspection was unavailable. Read-only host firewall/capture checks
were performed only within available permissions; visibility was incomplete on
one peer. Do not infer gateway behavior from missing access or change
network/authentication settings to obtain it. Deployment and network changes
require separate approval.

## Continue from evidence

### Independent continuation (2026-10-05)

**Actual Python product entry passed native remote LAN device D acceptance.** The corrected
`python -m fan_ssh ssh` command completed three strict SSH logins, an 8 MiB upload
hash and exact 8 MiB roundtrip hash. All five operations emitted authenticated
native UDP evidence and had corresponding Python target sessions. Both physical
routes were verified. The trace failed TCP/ordinary ICE, then selected prediction;
one fresh prediction retry was observed. No original FRP process was started for
these tests; OpenSSH performs existing user/host authentication only. See
`test-results/python-ssh-remote-lan-d-20261005.json`.

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

**New native reference positive: local Windows workstation ↔ remote LAN device D.** Original frp 0.71.0
XTCP/IPv4/QUIC with numeric cloud STUN passed both endpoint hole logs, selected
native IP/physical-route checks, strict existing-host-key SSH login and expected
ordinary-user identity, a 1 MiB upload hash and 1 MiB roundtrip hash. No fallback,
assisted address, agent forwarding, SSH key copy or cloud business relay was used.
The new ordinary-user syscall supervisor binds the owned static Go child's IPv4
UDP sockets to a physical interface; no host routes/configuration were changed.
Generic source is in `experiments/frp-device-binding/`; private orchestrators,
profiles and raw addresses/logs stay ignored. Evidence:
`test-results/frp-workstation-remote-lan-d-native-20261005.json`.

Three ordinary accounts passed physical-device UDP/TCP address observation.
remote LAN device C's default route includes a virtual proxy interface, so it must not be
counted native without physical binding. External STUN observations varied from
numeric cloud observations; both numeric cloud UDP ports were reachable on all
three hosts. After the corrected comparison, remote LAN devices A/C still had no verified
hole/SSH success, while remote LAN device D passed. Existing services were preserved.

The alternative topology uses a local Windows workstation business bridge, with
both Linux hosts required to connect natively to the workstation. Focus on the remaining local workstation ↔ remote LAN device A leg; preserve the
working remote LAN device B FRP visitor. New four-role/held-release Windows/remote LAN device A TCP comparisons
all completed MACed coordination but failed peer MAC, while four Windows local
controls passed 64 KiB/hash/half-close. Role-reversed FRP QUIC also failed, with
seven fully logged paired hole strategies and one excluded partial paired record;
physical capture saw 2082 outgoing and zero incoming peer UDP packets, no drops.
Actual local workstation/remote LAN device A EasyTier UDP/TCP comparisons obtained no selected native peer in
eight snapshots each. Both reported symmetric TCP NAT; EasyTier skips symmetric
initiators, so do not call its TCP reference a completed hard-NAT punching failure.
Evidence: `workstation-remote-lan-a-tcp-sync-20261005.json`, `workstation-remote-lan-a-frp-reversed-20261005.json`,
`workstation-remote-lan-a-easytier-20261005.json`. No network/authentication configuration changed.

The new `home-bridge` command composes independently granted direct legs to one
fixed peer/service using anonymous socket pairs. Incoming readiness refers only
to the named local workstation service; outgoing readiness is separately logged, and complete
native SSH/data acceptance is still open. Source SSH checks the final host's key
and uses its existing credentials. Policy revisions close the bridge and require
restart. Tests cover TCP, mixed TCP/UDP and two UDP legs, revocation, wrong pins,
relay-evidence denial, cancellation, full binary/half-close behavior and foreground
CLI. A deterministic before/after regression fixed socket cleanup when a broker
is cancelled before starting. Do not present these synthetic positives as real
remote LAN device A traversal or a completed release.

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

Read-only inspection found the existing Windows XTCP visitor on loopback 16022
still running, with no configured
fallback. Its log records successful IPv4/QUIC hole establishment to remote LAN device B's
native public exit at 2026-10-05 06:52:01, with no assisted addresses. A new SSH
login through that existing visitor passed the existing remote LAN device B host-key alias
strictly and returned the expected marker, exit 0. No configuration/deployment
was changed or download speed remeasured. This confirms the existing Windows ↔
remote LAN device B positive and does not establish remote LAN device A ↔ remote LAN device B acceptance. Evidence:
`test-results/frp-live-windows-remote-lan-b-20261005.json`.

The TCP observer had a reproducible Python 3.12 cleanup defect: waiting for
`server.wait_closed()` before cancelling handlers delayed exit while an observed
client stayed connected. The fix stops accepting, cancels/gathers handlers and
bounds writer shutdown before waiting for the server. An actual subprocess/client
regression failed before the fix and passed afterward: authenticated observation,
controller stdin EOF with the client held open, process exit within three seconds,
client EOF and listener rebinding. remote LAN device B ordinary-user UID (redacted) and remote LAN device A ordinary-user UID (redacted) each passed
all **26 TCP diagnostic tests without skips**; WSL passed all 26 too. This fixes
cleanup, not NAT traversal. Logs: `tcp-reuse-diagnostics-*-20261005.txt`; evidence:
`test-results/tcp-observer-shutdown-20261005.json`.

Four valid native TCP timing trials borrowed DCUtR's CONNECT/SYNC/half-RTT
coordination, with a startup READY barrier and both role assignments. Two held
the observation socket; two released it before peer dialing, inspired by
RustDesk. Coordination completed in all four (approximately 54–63 ms round trip),
but no peer MAC passed and remote LAN device B accepted no connection. Two WSL controls
passed exact 64 KiB/hash/half-close. These are Python research prototypes, not
actual libp2p/RustDesk binary or wire-protocol runs and not production fallbacks.
Cloud forwarded zero business bytes. Setup failures preceding the barrier/frame
ordering/Python-version fixes are excluded. Evidence:
`test-results/tcp-sync-native-20261005.json`.

A fresh physical TCP comparison used a remote LAN device B socket prelistening before its
authenticated observation. remote LAN device A TTL 2/4/7/64 probes completed handshakes in about
0.7–0.9 ms, but remote LAN device B had zero accepts and no peer identity was verified. The
non-promiscuous capture saw 37 packets and zero drops, including TTL-2 outbound
SYN and TTL-63 incoming SYN-ACK. Against the known cloud observer, TCP/UDP TTL-2
probes failed while normal-TTL authenticated observations succeeded. remote LAN device B
exit-address ICMP also replied at TTL 2 in about 29 ms, so TTL alone cannot bound
the actual physical hop count: tunneling, rewriting or protocol-specific handling
remain possible. The combined TCP evidence is consistent with an intermediary
or handshake responder; it does not identify its device/software or explain all
UDP failures. The two gateway HTTP roots refused connections; no login attempt
or configuration change occurred. Known native SSH ports were checked without
credentials; the remote LAN device B exit's offered port-2222 key differed from the verified
remote LAN device B key, so no login was attempted. Evidence:
`test-results/tcp-path-comparison-20261005.json`.

local workstation ↔ remote LAN device A also failed a completed frp 0.71.0 XTCP/KCP comparison, with six
client-version/banner checks and four completed hole strategies, including two
full 38-second random-port strategies (256 local workstation sockets, 1000 consenting-peer
ports from remote LAN device A). remote LAN device A's physical capture contained 2008 outgoing peer UDP packets,
zero peer ingress and zero kernel drops. Earlier QUIC/short-KCP runs interrupted
some long strategies and must not be counted as completed long-mode failures.
The local workstation exit matched the fresh successful local workstation ↔ remote LAN device B comparator. Evidence:
`test-results/workstation-remote-lan-a-frp-reference-20261005.json`.

Read-only, physical-source-bound UPnP now returned the local workstation router's WAN IPv4:
it is RFC1918 private, proving an upstream IPv4 layer without proving CGNAT.
The upstream gateway's public HTTP page exposed a login form, not WAN status;
no login was attempted. Both Linux hosts still lack native
global IPv6/default routes. NetworkManager is `ignore` on remote LAN device A and `auto` at
remote LAN device B; these do not justify switching settings blindly. In particular,
remote LAN device B kernel `accept_ra=0` does not prove NM's userspace IPv6 handling is
disabled. Two standard link-local Router Solicitations on remote LAN device A received no RA in
eight seconds and changed no address/route snapshot. The existing remote LAN device B proxy
returned HTTP CONNECT 200 for an IPv6 destination but TLS ended with SSLEOFError;
that does not establish an IPv6 bridge. The local workstation relay remains undeployed.
Updated evidence: `test-results/workstation-relay-feasibility-20261004.json`.

After this continuation, all owned test processes/directories and cloud
TCP 22090/22110 and UDP 22092/22093 observation listeners were verified absent.
Security-group rule removal remains separately unverified. Do not publish a
completed product: native Linux-to-Linux SSH is still an open acceptance gate.

### Latest TCP and local workstation-relay continuation (2026-10-04)

The local workstation's IPv6-capable gateway was evaluated as an alternative
relay location. A workstation relay would not itself establish native remote LAN
device A ↔ remote LAN device B direct SSH acceptance. Deployment, network and
authentication changes require separate approval.
Source-bound Windows WLAN IPv6 HTTPS succeeded with the expected native source;
both Linux hosts still lack a native global IPv6 address/default route and return
`Network is unreachable` when looking up the local workstation IPv6 destination. Do not expose
an IPv6-only relay and assume those IPv4-only hosts can use it. WAN IPv4 inbound
reachability, router software hosting, IPv6 firewall and upload bandwidth remain
unverified. A public reachable IPv4 entry, native IPv6 access at both peers or an
explicitly selected IPv4/IPv6 bridge is required. Gateway-page inspection did not
complete; the later read-only UPnP result is the available WAN-status evidence.
Do not bypass access restrictions or alter router settings to fill that gap.
Sanitized evidence: `test-results/workstation-relay-feasibility-20261004.json`.

The standalone TCP control now supports `--strategy both-listen`: both Linux
hosts prelisten and actively connect from the same source port using SO_REUSEPORT.
Only role 0 selects a MAC-verified stream, so simultaneous accepted/outbound
streams cannot lead the two peers to choose different connections. WSL verified
the complete authenticated observation, peer MAC, exact 64 KiB echo and half-close;
the old TTL control also still passed. Both real Linux hosts, ordinary users, passed the expanded 25-test TCP diagnostic suite without skips.

Three fresh native trials plus one separately captured trial all failed peer
authentication. remote LAN device A completed an apparent outbound TCP connect in each; remote LAN device B
had zero successful connects and zero matching accepts. In the captured trial,
remote LAN device A's non-promiscuous physical NIC saw nine TCP packets, including inbound SYN-ACK
and FIN, with zero kernel drops; reading the peer MAC ended at EOF with zero bytes.
This does not identify the responding device or the exact failed gateway/filter.
No SSH payload was attempted. All owned processes, test directories and cloud
observation listeners were verified absent after cleanup; security-group removal
remains separately unconfirmed. This diagnostic is not a production fallback.
Evidence: `test-results/tcp-reuse-native-20261004.json` and the two
`tcp-reuse-diagnostics-*-20261004.txt` logs.

Historical evidence reviewed on 2026-10-04 records a 2026-09-30 Windows ↔ remote LAN device B **frp XTCP IPv4/QUIC** success: both peer establishment logs, existing-host-key SSH login (exit 0), and 32 MiB transfers at 9.38/4.67 MB/s. The original remote LAN device B log and Windows configuration still exist and were inspected read-only. No `fallbackTo` was configured; assisted addresses were disabled. It was not IPv6 and was not a remote LAN device A ↔ remote LAN device B acceptance run. The current Tailscale/DERP route does not invalidate it. See VALIDATION.md and `test-results/historical-frp-20260930.json`.

That successful trial switched from a failing observer to `stun.easyvoip.com:3478`. remote LAN device B frp used receiver/mode 1, TTL 7 and a bounded 17-port predicted candidate interval; the selected Windows public port differed from its initial observations. Prediction is now implemented and locally exercised, but four native control trials (both role assignments, TTL 7/4) received zero authenticated peer packets. A fresh remote LAN device A-source frp 0.71.0 reference trial failed its external STUN discovery before punching. These results do not invalidate the historical Windows pair. Require explicitly native sockets, approved peer IPs, bounded candidate attempts and actual authenticated peer-path evidence.

A fresh 2026-10-04 Windows ↔ remote LAN device B frp IPv4/QUIC comparator now also passed strict host-key SSH, exit 0. No assisted addresses or cloud business fallback was configured. Six Linux multi-socket/random-port UDP probes (both pool assignments, TTL 7/4/normal), a Python predicted ICE handshake and four passive TCP/low-TTL SYN probes still failed. Latest real-host suites: 69/69 on both Linux hosts plus 22 experiment tests, no skips; Windows 66 passed/3 Linux skips. New sanitized evidence and regression logs are in `test-results/`; VALIDATION.md records the rebuilt wheel.

For frp QUIC comparators, send the ordinary SSH client version before passively waiting for a server banner, and then perform strict existing-host-key SSH. Passive banner reads alone did not announce a usable QUIC stream in the measured trial. Unset proxy variables only in the temporary frpc process; do not alter the remote LAN device B's proxy environment or existing provider. Keep the remote LAN device A acceptance gate separate from successful Windows evidence.

The next comparison found remote LAN device A STUN DNS answers in the benchmark/Fake-IP range, destination-dependent exits and intermittent external UDP observations; remote LAN device B's corresponding samples were more stable. Do not identify an upstream proxy or complete NAT type from those facts alone. See `test-results/stun-routing-20261004.json`.

Actual EasyTier v2.6.4 no-TUN UDP/default-TCP references also failed. Default TCP STUN supplied a different remote LAN device A exit. A final ordinary-user comparison corrected only the supervised test child's two TCP STUN destinations to already reachable cloud ports 22090/22110; the static release binary and host configuration were unchanged. Both endpoints obtained the native exits. remote LAN device B initiated real TCP punching against remote LAN device A's native tuple, still without a direct peer. Each completed reference had eight peer snapshots with a two-hop target route and null direct peer; no SSH data was attempted. A local 64 KiB/hash/half-close positive and an advertised two-hop relay-denial negative also passed the actual CLI selected-connection gate. All 13 new diagnostic tests passed on Windows and both real Linux hosts without skips. Evidence: `test-results/easytier-native-reference-20261004.json` and `reference-diagnostics-*-20261004.txt`.

The instrumented TCP test is a reference experiment, not a production adapter. Failed static-library override and aliased-observer setup attempts are not counted as corrected native TCP references. A future EasyTier adapter must support explicit observation endpoints and preserve fan-ssh's directed signed grants, exact peer identity and direct-only data admission; a shared EasyTier network secret alone is insufficient.

The host-level adapters work in local tests. Source-bound port observations are useful diagnostics; do not predict a full NAT type from missing STUN replies or turn arbitrary public port scans into a fallback. Exit-gateway inspection remains unavailable. Router/network modifications and deployment still require user approval. Do not modify the existing frp/Tailscale setup to reproduce a temporary test.

Keep signed grant, exact peer identity and existing SSH host-key/user-auth checks at every new path. No TURN/DERP/cloud stream forwarding/TUN/driver/configuration workaround may silently satisfy the direct-only acceptance. Roaming/sleep recovery, macOS runtime, hardware key custody, production enrollment UI/service deployment and universal hard-NAT traversal remain open work.
