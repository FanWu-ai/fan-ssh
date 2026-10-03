# fan-ssh Python development handoff

## Read first

Read README.md, ARCHITECTURE.md and VALIDATION.md. The repository is now Python, not Go. Start with `fan_ssh/session.py` to understand the fixture; transport/framing and identity issuance are separate small modules. The user works with Python on research servers, so prioritize readable Python and maintainable, narrow components over a second-language toolchain.

## Scope to preserve

The intended product is ordinary-user, many-to-many direct SSH connectivity across Windows/macOS/Linux and different LANs. The hard requirement is UDP blocked plus complex NAT on both sides. This is **not solved**. No business-data relay of any kind is allowed: no TURN, DERP, STCP, HTTP CONNECT, WebSocket relay, third-peer forwarding or silent proxy fallback. A coordinator may carry bounded control-plane metadata only.

Keep device identity, directed device/service authorization, and SSH host/OS-user authentication distinct. Never disable StrictHostKeyChecking, silently forward ssh-agent, or claim joining the overlay grants SSH login. Do not change host services/firewalls/routes or create persistent credentials without approval.

## What exists

- Python 3.11+ package, stdlib networking/TLS/asyncio, cryptography for ephemeral synthetic certificate issuance only.
- Single-process loopback fixture with pinned mutual TLS, directed immutable ACL, independent discovery/destination trust checks, fixed operator target and bounded concurrent forwarding.
- Five-second setup bounds, 32 accepted-handler limit including handshakes, bounded metadata and frames, absolute 30-second data sessions.
- Explicit TLS payload framing carries directional EOF because Python SSL streams cannot half-close. It is intentionally incompatible with the old Go wire format.
- One-shot ProxyCommand helper preserves stdout bytes; raw daemon stdio threads prevent blocked buffered-I/O finalization. Do not embed/reuse this helper in a long-lived process.
- Brief user-private temp PEM files are required by stdlib SSL, then removed after context loading. This is a synthetic demo, not durable key management.
- Separate Linux-only active/active TCP diagnostic, not an authenticated NAT transport.

## Local workflow

```sh
python -m venv .venv
. .venv/bin/activate  # Windows: use the corresponding venv Python/activation
python -m pip install -e .
python -m unittest discover -s tests -v
python -m unittest discover -s experiments/tcp-simopen -v
python -m fan_ssh demo
python experiments/tcp-simopen/tcp_simopen.py --help
```

Root test discovery does not automatically run the hyphenated experiment directory; run both commands. Consult that experiment's README for bounded trial commands and interpretation. No outside host is needed by any validation command above.

## Next work

Follow the five research gates in ARCHITECTURE.md: real enrollment/admission design; bounded direct candidates; safe platform-specific socket adapters; authorized two-network tests; then hardening demonstrated paths. Do not remove loopback safety restrictions simply to produce a more impressive demo. Public listening and real server/network trials are new scope.

Before publication, rerun all tests after the last edits, inspect source/metadata for secrets and private endpoints, and verify remote contents. Parent task handles the authorized repository upload; this local handoff does not itself authorize merge/deploy/new credentials. Keep Go build artifacts and stale Go validation out of the Python tree.

## Known validation limits

Linux runtime only. macOS/Windows architecture is intended but untested. No real SSH login, LAN traversal, NAT traversal, deployment, production enrollment, package release or CI pipeline is established. No license has been selected by the owner.
