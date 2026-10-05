# fan-ssh

Python 3.11+ implementation of ordinary-user, multi-host SSH transport over direct peer paths, with an optional explicitly configured home bridge. Independent devices use directed service grants and peer TCP/TLS or explicitly enabled native UDP/DTLS/SCTP streams. Remote connections automatically try the available direct methods in order. The coordinator exchanges bounded metadata and never forwards business traffic.

**Working Python connection verified: home Windows ↔ peer-5.** The actual
`python -m fan_ssh ssh` entry completed three strict SSH logins, an 8 MiB upload
SHA-256 and an exact 8 MiB roundtrip SHA-256 over native Python ICE/DTLS/SCTP.
Automatic selection tried TCP and ordinary ICE, then selected UDP prediction.
One setup retry was exercised. No FRP process, Tailscale data path or cloud
business relay was used. See [test-results/python-ssh-peer5-20261005.json](test-results/python-ssh-peer5-20261005.json).

Peers 3/4 and the originally requested Linux pair remain unverified. This proves
a usable Python connection on the verified network pair, not a universal NAT
solution. All endpoints need approved identities/policy and foreground node/
coordinator processes; temporary test authorization is not permanent deployment
approval. Existing FRP research is retained as historical evidence, not a
runtime dependency. See [VALIDATION.md](VALIDATION.md).

## Install and test

```sh
python -m venv .venv
# Linux/macOS:
. .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e '.[udp]'
python -m fan_ssh demo
python -m unittest discover -s tests -v
python -m unittest discover -s experiments/tcp-simopen -v
```

Use the venv Python directly if activation is restricted. TCP-only installation is `python -m pip install -e .`. No packages are fetched at runtime. Optional UDP tests require the extra; run Linux socket and blocked-stdio tests on an actual Linux host. Root discovery does not include the experiment directory.

Base dependency: `cryptography>=42,<51`. UDP: `aiortc==1.15.0`, `aioice==0.10.2`. The isolated adapter uses private library APIs and rejects other versions. Tested: Windows Python 3.12.10, Linux Python 3.12.3/3.12.10, cryptography 50.0.2. macOS is untested. Windows explicit UDP uses a selector event loop after sustained bidirectional DTLS stalled with Python 3.12's proactor loop.

## Approve independent devices

Create the `.fan-ssh` parent directory first. Run each command on its corresponding host, keeping that host's private identity directory there:

```sh
python -m fan_ssh identity-init --id control --directory .fan-ssh/control --public control.public.json
python -m fan_ssh identity-init --id a --directory .fan-ssh/a --public a.public.json
python -m fan_ssh identity-init --id b --directory .fan-ssh/b --public b.public.json
```

Directories/files must be new; creation refuses overwrite. On Windows, put identity directories on an ACL-capable filesystem, such as NTFS under your user profile; a FAT checkout cannot provide private-key ACL protection. These commands do not install a service, modify SSH authentication or change a firewall/route. Exchange only public records over an existing trusted channel and verify printed SHA-256 fingerprints with the owner. The owner builds an approved policy and distributes it to the devices. Replace these documentation addresses with explicitly approved real addresses:

```sh
python -m fan_ssh policy-build --account wufan --revision 1 \
  --coordinator control --coordinator-address 198.51.100.10:22090 \
  --device control.public.json --device a.public.json --device b.public.json \
  --candidate a=192.0.2.10:22022 --candidate b=192.0.2.20:22022 \
  --allow a:b:ssh --allow b:a:ssh --output network.policy.json
```

PowerShell can use one line or its own continuation syntax. Policy-build creates a new file. Candidates are numeric unicast addresses with ports 1024–65535, at most eight/device. Names use ASCII letters, digits, underscores or hyphens. Up to 64 devices/4096 directed service edges are supported. `a:b:ssh` does not authorize the reverse direction.

Independent self-signed P-256 leaf certificates become exact trust anchors only after operator approval. TLS requires TLS 1.3, certificate validation and exact SHA-256 pins. The coordinator identity has no business role. Its host may run a separately enrolled peer using a different identity/data port.

## Start approved processes

These explicit listeners need an already available path or a separately authorized network change. A foreground ordinary-user socket does not create Internet reachability by itself.

```sh
# Coordinator:
python -m fan_ssh coordinator --identity .fan-ssh/control --policy network.policy.json \
  --listen 198.51.100.10:22090
# Receiving host b; use its existing local sshd:
python -m fan_ssh node --identity .fan-ssh/b --policy network.policy.json \
  --listen 192.0.2.20:22022 --service ssh=127.0.0.1:22
# Source a: peer TLS check only, no sshd connection:
python -m fan_ssh diagnose --identity .fan-ssh/a --policy network.policy.json --peer b
```

Nodes expose only operator-fixed **loopback** services. Default polling accepts bounded reverse/UDP offers; `--no-reverse` disables all offer polling. Forward TCP races approved candidates. An approved reachable source candidate can enable reverse direct TCP with `--reverse-listen IP:PORT --reverse-candidate IP:PORT`.

Remote `proxy`/`forward` default to `--transport auto`: TCP (12 seconds), optional reverse TCP (12 seconds), then explicitly enabled UDP ICE (28 seconds) and IPv4 UDP port prediction (50 seconds, including one fresh setup retry). Each method starts with fresh grant/path state. UDP is available only when `--udp-native` and `--stun` are supplied and the UDP extra is installed. Failed network attempts move to the next method; identity, certificate, policy, grant and permission errors stop the connection. Stderr records each attempt and the selected method. Exhausting the methods returns `NO_DIRECT_PATH`; no relay is selected. Use `--transport tcp` or `--transport udp` to choose one transport explicitly.

## Existing SSH login

Use the Python entry with your existing SSH alias, credentials and verified host
key. After enrollment/policy approval, run the receiving node with its existing
loopback sshd and configure native UDP on both peers. Documentation addresses
below must be replaced with explicitly approved real addresses.

```sh
# Metadata coordinator: both observation ports need available/approved paths.
python -m fan_ssh coordinator --identity PRIVATE_CONTROL --policy network.policy.json \
  --listen 198.51.100.10:22090 --stun-listen 198.51.100.10:22092 \
  --stun-alternate-listen 198.51.100.10:22093
# Receiving peer b; ordinary user, existing SSH authentication:
python -m fan_ssh node --identity PRIVATE_B --policy network.policy.json \
  --listen 192.0.2.20:22022 --service ssh=127.0.0.1:22 \
  --udp-native 192.0.2.20 --stun 198.51.100.10:22092 --stun-alternate 198.51.100.10:22093
# Source a; auto is the default. No manual SSH ProxyCommand is required.
python -m fan_ssh ssh --identity PRIVATE_A --policy network.policy.json \
  --peer b --ssh-host EXISTING_SSH_ALIAS --udp-native 192.0.2.10 \
  --stun 198.51.100.10:22092 --stun-alternate 198.51.100.10:22093
# Remote commands / binary stdin/stdout:
python -m fan_ssh ssh --identity PRIVATE_A --policy network.policy.json \
  --peer b --ssh-host EXISTING_SSH_ALIAS --udp-native 192.0.2.10 \
  --stun 198.51.100.10:22092 --stun-alternate 198.51.100.10:22093 -- uname -a
```

The alias provides OS credentials and original host-key lookup; its management
network address is not the business route. OpenSSH's effective configuration is
checked before launching: the Python ProxyCommand must be active. An inactive
proxy fails closed instead of silently using the alias's management connection.
`--ssh-user` / `--ssh-port` optionally select the existing login user / original
port. Strict host-key checking, no agent forwarding and no host-key updates are
forced. BatchMode requires existing noninteractive SSH credentials. No keys are
copied or installed on another host. The system OpenSSH client performs SSH
user authentication; Python provides the peer network connection.

Automatic setup can take tens of seconds on restrictive NATs. A known working
prediction path can use `--transport udp --udp-strategy predict` directly.
Prediction retries one connectivity failure with a fresh socket/grant, without
retrying identity/policy failures. Automatic prediction has a 50-second budget;
the entry allows 120 seconds for initial SSH setup. No business relay fallback
exists.

Windows private identities must live on an ACL-capable NTFS user directory, for
example under `$env:LOCALAPPDATA\fan-ssh`; the source checkout can be elsewhere.
New enrollment verifies the directory ACL before writing any private key and
rejects exFAT. Localized account names are supported without decoding whoami's
non-ASCII name field. Source/target/coordinator should run the current version;
older one-operation coordinators do not support signaling connection reuse.

Windows UDP tests normally use the same non-debug selector loop as the product.
The separate debug stress mode (`FAN_SSH_UDP_DEBUG_TESTS=1`) has exposed an
intermittent stream failure; it remains an open limit. Do not enable asyncio
debug instrumentation for the verified Windows connection path or interpret
ordinary-mode passes as a repaired debug stress case.

Advanced existing SSH configuration can still use the raw proxy entry below.

Preserve the existing verified host-key alias and SSH user credentials:

```sh
ssh -o 'ProxyCommand=python -m fan_ssh proxy --identity .fan-ssh/a --policy network.policy.json --peer b --service ssh' \
  -o HostKeyAlias=existing-b-alias -o StrictHostKeyChecking=yes user@existing-b-alias
```

Use an absolute venv Python path and appropriate shell quoting. Proxy stdout contains only SSH bytes; diagnostics go to stderr. Alternatively:

```sh
python -m fan_ssh forward --identity .fan-ssh/a --policy network.policy.json \
  --peer b --service ssh --listen 127.0.0.1:2222
ssh -p 2222 -o HostKeyAlias=existing-b-alias -o StrictHostKeyChecking=yes user@127.0.0.1
```

The local forward does not authenticate local callers. Device/service approval does not grant OS login. SSH still authenticates the user and checks the original host key. No agent forwarding, SSH key installation or sshd configuration change occurs.

## Explicit home business bridge

Use this only for an explicitly approved topology. Enroll the home computer as a
separate **peer**, with its own private identity and approved native candidates.
Approve two directed service edges in the policy: `a:home:hospital-ssh` and
`home:b:ssh`. The named incoming service delegates access to that one fixed final
peer/service. It does not authorize arbitrary targets or automatically select a
relay after a direct failure. The coordinator keeps its separate metadata role.

After policy approval and with independently available direct paths:

```sh
# Final receiving device b:
python -m fan_ssh node --identity .fan-ssh/b --policy home.policy.json \
  --listen 192.0.2.20:22022 --service ssh=127.0.0.1:22
# Home peer; foreground, ordinary user, fixed b/ssh destination:
python -m fan_ssh home-bridge --identity .fan-ssh/home --policy home.policy.json \
  --listen 192.0.2.30:22022 --bridge-service hospital-ssh --peer b --service ssh
# Source a: SSH authenticates b using b's existing verified host key:
ssh -o 'ProxyCommand=python -m fan_ssh proxy --identity .fan-ssh/a --policy home.policy.json --peer home --service hospital-ssh' \
  -o HostKeyAlias=existing-b-alias -o StrictHostKeyChecking=yes user@existing-b-alias
```

Addresses are documentation placeholders. These commands do not create NAT
reachability. Existing native UDP/reverse options can be configured on each leg;
on `home-bridge`, `--transport` selects outgoing direct methods and `--udp-native`
enables incoming/outgoing UDP. Both `--udp-native` and `--stun` are required.
`--no-reverse` disables incoming reverse/UDP offer polling. A reverse TCP listener
for the outgoing leg needs a separate approved port.

The home process bridges opaque SSH bytes through anonymous local socket pairs;
it exposes no additional unauthenticated loopback forwarding port. The incoming
`DIRECT_SERVICE_READY` admits the source to the **home bridge service**. The
outgoing leg can still fail; `HOME_BRIDGE_UPSTREAM_READY` records its independent
direct admission. Neither event alone proves a complete topology: require the
final strict SSH login, data integrity and native route evidence on both legs.
The home peer remains a trusted availability/traffic-metadata participant; SSH
encryption and user authentication terminate at the source and final device.

Each leg has its own pinned identity, directed grant and renewable lease. Either
leg failing/revoking closes the composed stream. Sessions retain the 32-session
cap and 24-hour deadline. A home policy revision closes sessions and requires a
bridge restart before new sessions; outgoing clients use a startup snapshot.
No deployment, network or SSH authentication change is implied by this example.

## Explicit native UDP

Optional experimental ICE, mutually pinned DTLS and reliable ordered SCTP. No automatic interface gathering, default external STUN or TURN. Supply an approved **physical-interface IP** and an explicitly approved numeric IPv4 STUN observer:

```sh
# Optional coordinator Binding observer; needs an authorized reachable UDP port:
python -m fan_ssh coordinator --identity .fan-ssh/control --policy network.policy.json \
  --listen 198.51.100.10:22090 --stun-listen 198.51.100.10:22092
# Receiving host b:
python -m fan_ssh node --identity .fan-ssh/b --policy network.policy.json \
  --listen 192.0.2.20:22022 --service ssh=127.0.0.1:22 \
  --udp-native 192.0.2.20 --stun 198.51.100.10:22092
# Source a; use as the SSH ProxyCommand:
python -m fan_ssh proxy --identity .fan-ssh/a --policy network.policy.json --peer b \
  --transport udp --udp-native 192.0.2.10 --stun 198.51.100.10:22092
```

The bind IP must appear in the device's approved candidates. UDP binds one ephemeral port on that IP. Signaled candidate IPs must match approved native addresses or the peer IP observed on its authenticated control connection; changed/multiple egress IPs are conservatively rejected. Only host/server-reflexive candidates are signaled. A learned peer-reflexive tuple remains subject to the approved-IP check and exact DTLS pin. ICE failure closes the path.

For automatic TCP/UDP selection, replace `--transport udp` above with `--transport auto`. Explicit UDP defaults to ordinary ICE; `--udp-strategy predict` adds authenticated low-TTL warmup to at most 21 high ports near the consenting peer's observed mappings, followed by ICE and pinned DTLS. This borrows the approach from [frp XTCP](https://gofrp.org/en/docs/features/xtcp/); it has not passed the required Linux pair's real-network acceptance. Receivers default to `--udp-strategy auto` and accept either enabled strategy. `--stun-alternate IP:PORT` optionally observes the same physical socket at a second explicitly supplied observer. No DNS server list or public-port sweep is automatically added.

The observer replies only to IPs previously seen on authenticated control connections: IPv4 Binding requests, 20–256 bytes, at most 60/minute/IP. No TURN allocation/forwarding exists. Temporary test authorization is not permanent observer deployment approval.

## Policy and security limits

Atomic policy replacements must increase revision. Coordinator/node check once/second; invalid updates and rollback retain the last valid snapshot. Node revisions conservatively close existing sessions. Coordinator pin rotation requires restart and fresh approval. Clients load policy at startup; restart after changes.

Signed grants bind account/revision, both device pins, directed service, transport, session, expiry and serial. Initial grants last 30 seconds and cannot be replayed. The receiver renews halfway through the lease; failed control/revocation closes the stream at failed renewal/expiry. Absolute session limit: 24 hours. Ongoing coordinator availability is required.

Identities reject overwrite, invalid ownership, permissive key reads and expired/mismatched certificates. POSIX uses owner-private directory/key modes. Windows protects/checks DACLs and owner SID; SYSTEM/Administrators remain permitted privileged principals. Keys are unencrypted at rest; this is not hardware-backed custody or protection against a compromised user/admin. User-private temporary PEM files are deleted immediately after loading TLS contexts.

Unchanged `demo` and `proxy/forward --target LOOPBACK:PORT` modes are synthetic loopback fixtures with fresh identities and a 30-second data deadline. They do not enroll/contact remote devices.

## Authorized research tools

- `scripts/remote_tests.py --udp`: both suites/demo in a validated temporary ordinary-user Linux directory, supplied offline wheels, exact-directory cleanup.
- `scripts/campaign.py`: requires a private explicit inventory; verified existing SSH carries setup/metadata/results only. Payload and SSH use peer sockets. TCP active/active/hybrid modes remain diagnostic research.
- `scripts/native_udp_probe.py`: bounded authenticated control probes, including low-TTL/small-range prediction, no SSH payload.
- `scripts/native_udp_birthday.py`: separate bounded multi-socket/random-port control diagnostic for two explicitly consenting native IPv4 peers; no service login or application-success claim.
- `scripts/native_tcp_ttl_probe.py`: Linux passive-listener/low-TTL SYN control diagnostic; peer MAC and bounded random test bytes are required, TCP connect completion alone is insufficient.
- `scripts/dual_stun_observer.py`: bounded, whitelisted dual-port observation compatibility tool for frp reference tests; each public port needs separate network authorization.
- `scripts/tcp_stun_observer.py`: bounded TCP Binding observations at two explicitly authorized high ports; no peer dialing or data forwarding.
- `scripts/stun_probe.py`: explicit physical-socket observations, including MAPPED-only servers and an optional second observer; validates response type, transaction and length.
- `scripts/easytier_peer_check.py`: checks a trusted v2.6.4 CLI snapshot's selected direct connection against explicitly approved native IPs. An advertised two-hop route or an unused native connection does not pass.
- `scripts/upnp_inspect.py`: read-only gateway discovery/external-address queries; no added mappings.

The 3k reference tests found STUN DNS answers in the `198.18.*` benchmark range and external observations with a different exit from the cloud observation. This is consistent with [Fake-IP DNS behavior](https://wiki.metacubex.one/en/config/dns/), but the responsible network component is not established. Bypassing a domain with a numeric observer sometimes obtained a response; it did not establish a peer path. Two ports on one observer IP also cannot establish cross-IP mapping independence. The Python transport continues to use only explicitly approved numeric observers and native peer IPs.

No universal direct-only guarantee exists when network policy supplies no allowed peer path. Both accepted topologies remain open acceptance gates. A home bridge must verify both native legs and the complete SSH/data path; one working leg is insufficient. Never count Tailscale or a cloud business relay as success.

See [ARCHITECTURE.md](ARCHITECTURE.md), [VALIDATION.md](VALIDATION.md) and [HANDOFF.md](HANDOFF.md). No permanent deployment, package release or owner-selected license is implied.
