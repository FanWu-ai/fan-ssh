# fan-ssh

Readable Python research prototype for **direct-only SSH byte transport**. The former Go implementation has been replaced; there are no Go sources or Go build requirements.

**This is a loopback-only development fixture, not a cross-LAN NAT traversal product.** UDP-blocked connections with both endpoints behind complex NAT remain unsolved. There is no relay fallback, production enrollment, public listener, or real SSH login demonstrated here.

## Install and run

Python **3.11+**, with OpenSSL TLS 1.3 support. Run from the repository root:

```sh
python -m venv .venv
# Linux/macOS:
. .venv/bin/activate
# Windows PowerShell instead: .venv\Scripts\Activate.ps1
python -m pip install -e .
python -m fan_ssh demo
python -m unittest discover -s tests -v
python -m unittest discover -s experiments/tcp-simopen -v
```

Installed commands `fan-ssh` and `directssh` are aliases for `python -m fan_ssh`. If activation is restricted, run the virtual environment's Python executable directly rather than changing system policy. Installation requires package access; no package is fetched during runtime or tests.

The single runtime dependency is `cryptography` (>=42,<51), used only to issue ephemeral synthetic certificates. Networking, TLS, framing, concurrency, CLI, and tests use Python's standard library. Python's `ssl` module can load certificates but cannot issue them; using a maintained cryptography package avoids a custom certificate encoder or an `openssl` executable dependency. Only cryptography 50.0.0 was tested for this rewrite. The upper bound is a compatibility guard, not a dependency lock or security audit.

Expected demo output:

```text
PASS: coordinator-discovered, mutually authenticated direct TLS echo; no relay
```

Diagnostics go to stderr. Demo uses its own local echo fixture and requires no SSH service or keys.

## What works

- Each invocation creates two synthetic device identities and a metadata-only coordinator in one process.
- TLS 1.3 authenticates both ends using a short-lived session CA, certificate validity checks, and exact SHA-256 leaf-certificate pins.
- An immutable **directed** ACL gates metadata discovery. The initiator independently checks the approved destination pin; the receiver checks the approved client pin **before dialing** its fixed target.
- All listeners and dial destinations accept only numeric IPv4/IPv6 loopback literals, never DNS, wildcard binds, or Internet endpoints. The peer cannot select an arbitrary target.
- Concurrent local forwards and binary-clean SSH ProxyCommand streams preserve half-close using bounded internal framing.
- Setup operations are bounded to five seconds each. Data bridges have a fixed absolute 30-second lifetime. Admission caps of 32 include incomplete TLS handshakes; cancellation tears down sockets and handlers.

Everything disappears on exit. There is no persistent identity, trust store, device enrollment UI, revocation, distributed coordinator, candidate racing, reverse dialing, ICE/STUN/TURN, TUN, VPN, driver, firewall change, or deployment.

## Optional integration with an existing local SSH server

These are examples for your separate local validation, not commands executed against a real SSH server by this project:

```sh
python -m fan_ssh forward --target 127.0.0.1:22 --listen 127.0.0.1:2222
ssh -p 2222 -o HostKeyAlias=fan-ssh-dev-local -o StrictHostKeyChecking=yes user@127.0.0.1
```

Or, in a POSIX shell:

```sh
ssh -o 'ProxyCommand=python -m fan_ssh proxy --target 127.0.0.1:22' \
  -o HostKeyAlias=fan-ssh-dev-local -o StrictHostKeyChecking=yes user@fan-ssh-dev-local
```

Use an absolute virtual-environment Python path if SSH cannot find it; quote paths appropriately for your OS/shell. The correctly verified host key for the alias must already be in known_hosts. Existing SSH key/agent/certificate or password authentication is still required. Device approval does not authorize OS-user login. Never disable host-key checking. The 30-second development deadline makes this unsuitable for long interactive sessions.

Every run builds a fresh **local synthetic session**, not a connection to a remote enrolled device. Other local processes can use the forward listener; it has no local-client authentication. Existing SSH remains the login boundary.

## Platform status

The transport architecture uses portable asyncio, sockets, SSL, and raw stdio; Windows proxy descriptors are explicitly switched to binary mode. **Only Linux x86_64 runtime behavior has been tested.** Python source portability is not macOS/Windows runtime validation or cross-compilation. Windows/macOS TLS, cancellation, stdio, installation, and real SSH must be tested on those systems. Temporary-file permissions on Windows rely on the user-owned temp directory's ACLs; POSIX modes alone are not a Windows ACL guarantee.

The separate [TCP simultaneous-open diagnostic](experiments/tcp-simopen/README.md) is Linux-only and standard-library-only. It is intentionally not integrated into the transport. Local active/active socket success is not evidence of NAT traversal.

## Security and compatibility notes

- Certificate/private-key PEM files exist briefly in a private temporary directory because `SSLContext.load_cert_chain` takes filenames. They are deleted immediately after loading; no persistent credentials are created. Do not treat this as a production key-storage design.
- Coordinator requests/responses are length-prefixed JSON, maximum 4096 bytes. Only one exact-schema `lookup` request and one peer record are supported per connection. There is no data forwarding route or upstream dialer. Arbitrary clients can send bytes to any listener; “metadata-only” is not an information-theoretic covert-channel guarantee.
- TLS data uses 4-byte big-endian frame lengths, 1..16384 bytes per data frame; zero is directional EOF. A truncated TLS stream without EOF is an error. This replaces Go's raw TLS wire behavior and is **not wire-compatible** with the old prototype. The coordinator protocol also replaces the former fixture HTTP endpoint. Both sides are started together, so no upgrade interoperability is claimed.
- Stream buffers, handlers, metadata and deadlines are bounded. Proxy uses daemon threads for inherited stdio with raw `os.read`/`os.write`; cancellation lets the CLI process exit even when a pipe blocks. It is a one-shot process helper, not a reusable embedded stdio component.
- No automatic replay, relay fallback, CA-name bypass without pin checks, actual server login, or private endpoint inventory is included.

See [ARCHITECTURE.md](ARCHITECTURE.md), [VALIDATION.md](VALIDATION.md), and [HANDOFF.md](HANDOFF.md). No package release, CI workflow, deployment, or license has been invented. The owner has not selected a license.

## Layout

- `fan_ssh/identity.py`: short-lived synthetic PKI, TLS contexts, exact pins
- `fan_ssh/transport.py`: bounded socket service, loopback validation, framing and duplex bridge
- `fan_ssh/session.py`: metadata coordinator, directed ACL, synthetic session and forwarding
- `fan_ssh/cli.py`: demo, local forward, raw-stdio proxy
- `tests/`: stdlib unittest regression suite and real CLI subprocess tests
- `experiments/tcp-simopen/`: independent Linux socket diagnostic and tests
