# Authorized test tools

These tools are operator-run research helpers, not deployed services. Use only consenting hosts and explicitly approved native addresses/ports. Existing SSH aliases must already work with verified host keys. Setup SSH/scp carries code and bounded control/results; test business streams use peer sockets. No SSH authentication, OS route/firewall or router mapping is changed.

Keep private inventories, public exit addresses, certificate records and raw logs under ignored `.fan-ssh/`. Public records must be approved separately for normal application use. The campaign generates temporary identities solely for the authorized experiment and grants directed echo/SSH edges among its consenting peers.

## Offline Linux regression

Create `.fan-ssh/wheels` and download compatible wheels before running. The runner's checked versions are cryptography 50.0.2, cffi 2.1.1, pycparser 3.0, pip 26.2.1, aiortc 1.15.0 and aioice 0.10.2, including transitive dependencies. For Linux x86_64 Python 3.12 from another OS:

```sh
python -m pip download --dest .fan-ssh/wheels --only-binary=:all: \
  --platform manylinux_2_28_x86_64 --platform manylinux2014_x86_64 \
  --implementation cp --python-version 312 --abi cp312 --abi abi3 --abi none \
  cryptography==50.0.2 cffi==2.1.1 pycparser==3.0 pip==26.2.1 aiortc==1.15.0 aioice==0.10.2
python scripts/remote_tests.py --host approved-linux-alias --python python3.12 \
  --udp --output .fan-ssh/linux-tests.log
```

Download corresponding Python 3.11/base wheels separately if the coordinator uses that interpreter. The application does not download dependencies at runtime. Regression upload/run has bounded timeouts; a slow link can fail explicitly. The runner removes only its exact regex-validated `/tmp/fan-ssh-test.XXXXXXXX` directory in finally, including failures. It does not persist a dependency installation on the host.

## Campaign inventory

Copy this **documentation-only** example to `.fan-ssh/campaign-inventory.json` and replace every alias/address with consenting real endpoints. Put the coordinator agent first. Public mapped addresses and physical bind addresses may differ. The `udp` flag installs UDP dependencies on that agent; `--udp-source` selects a UDP campaign.

```json
{
  "coordinator": {"id": "control", "address": "198.51.100.10:22090"},
  "stun_address": "198.51.100.10:22092",
  "agents": [
    {"host": "approved-coordinator", "python": "python3.12",
     "stun_bind": "192.0.2.30:22092",
     "devices": [{"id": "control", "listen": "192.0.2.30:22090", "candidates": []}]},
    {"host": "approved-peer-a", "python": "python3.12", "udp": true,
     "ssh_target": "127.0.0.1:22",
     "devices": [{"id": "a", "listen": "192.0.2.10:22022", "candidates": ["192.0.2.10:22022"]}]},
    {"host": "approved-peer-b", "python": "python3.12", "udp": true,
     "ssh_target": "127.0.0.1:22",
     "devices": [{"id": "b", "listen": "192.0.2.20:22022", "candidates": ["192.0.2.20:22022"]}]}
  ]
}
```

```sh
python scripts/campaign.py --inventory .fan-ssh/campaign-inventory.json \
  --skip-matrix --udp-source a --udp-target b --output .fan-ssh/udp-results.json
```

Without `--skip-matrix`, every ordered peer pair runs a pinned TCP 1 MiB echo. A local agent uses `"local": true` instead of host/python. A coordinator host can additionally carry a distinct peer identity/data listener. Per-device reverse_listen/reverse_candidate are optional approved reverse TCP endpoints.

An optional `udp_ssh_check` object `{ "host": "existing-user@verified-host-key-name", "port": 22 }` enables a real source-host SSH marker trial using existing source credentials/known_hosts. The destination name is a host-key lookup: ProxyCommand carries data through the native UDP path. No key/known_hosts edit is permitted. An echo or banner alone is not SSH-login acceptance.

TCP research uses `--nat-source a --nat-target b --nat-trials 3`, with two distinct approved Linux agents. `--nat-mode active` is strict active/active; `hybrid` explicitly adds a target listener/SYN primer and is reported separately. Optional coordinator-agent tcp_observer_bind plus top-level tcp_observer_address enables same-source-port observations at a second approved coordinator port. No arbitrary peer port sweep or SO_REUSEPORT is used.

A campaign's exit 0 means its orchestration/cleanup completed, **not that peer trials succeeded**. Inspect each trial's ok/report, authenticated selected tuple, payload hash or SSH marker. No relay fallback exists. Remove separately authorized temporary cloud network rules after public trials; process cleanup does not remove a security group.

## Small read-only diagnostics

`native_udp_probe.py` requires a running approved observer and private JSON containing two peers (`host`, `python`, `native`, optional `bind_port`) plus observer IPv4 and port. It sends exactly 40 short HMAC control packets/peer, records authenticated source tuples and up to eight unexpected sources, and carries no SSH payload. `--wire stun` selects authenticated standard STUN-shaped packets (USERNAME, MESSAGE-INTEGRITY, FINGERPRINT) for protocol-filter comparison; it is not an SSH transport. A valid peer packet is recorded even if NAT changes the source IP/port. `bind_port` zero selects an ephemeral port.

`stun_probe.py --native PHYSICAL_IP --observer NUMERIC_IP --port HIGHPORT` uses one source-bound UDP socket and at most two small requests/endpoint. Optional `--alternate IP:PORT` observes primary/alternate/primary to compare that same source port. Missing replies do not classify NAT behavior.

`upnp_inspect.py --native PHYSICAL_IP --gateway APPROVED_GATEWAY --multicast --nat-pmp` makes bounded gateway discovery and external-address-only queries. Descriptor fetches stay at the approved gateway. It never sends AddPortMapping or a NAT-PMP mapping request. Unsupported/timeout results do not change network configuration.

`native_tcp_ttl_probe.py` is a separate Python 3.11+ Linux diagnostic. Its default
`--strategy ttl` uses a receiver listener and low-TTL SYN primer. The explicit
`--strategy both-listen --trials 3` variant binds both listeners before cloud
observation and active connect, using SO_REUSEADDR/SO_REUSEPORT on each physical
source address and the same local high port. It does not scan candidate ports.
Use only approved hosts and a private inventory containing `peers` (two entries
with host/python/native), `tcp_observer` (host/python/native/public/port), and
`approved_public_ips` (both observed exits).

```sh
python scripts/native_tcp_ttl_probe.py --strategy both-listen --trials 3 \
  --inventory .fan-ssh/tcp-inventory.json --output .fan-ssh/tcp-results.json
```

Existing verified SSH transfers setup and fresh MAC secrets; the whitelisted
observer reports source tuples and never forwards application traffic. In the
dual-listener variant, role 0 chooses one MAC-verified stream and role 1 follows
that choice, avoiding disagreement when two connections arrive. The diagnostic
then requires an exact 64 KiB echo and half-close; TCP connect completion alone
does not pass. This is not a pinned TLS or SSH transport and is not an automatic
production fallback. Each peer phase has a 12-second deadline, setup exchange
has a 20-second deadline, and the observer stops on stdin EOF or after 90 seconds.
