# Python rewrite validation

Validation date: 2026-10-03 UTC. This report concerns the Python replacement only; no earlier Go test, race, build or cross-compilation result is counted as Python evidence.

## Environment

- Linux 6.18.44, x86_64, glibc 2.41; ordinary uid 1000
- Python 3.12.14
- OpenSSL 3.5.8 (25 Aug 2026)
- cryptography 50.0.0

## Executed checks

| Check | Result |
|---|---|
| `python -m unittest discover -s tests -v` | 27 tests passed |
| Three additional full root-suite runs | All passed |
| `python -m unittest discover -s experiments/tcp-simopen -v` | 22 tests passed |
| Five additional diagnostic-suite runs | All passed |
| `python -m compileall -q fan_ssh tests experiments/tcp-simopen` | Passed |
| `python -m fan_ssh demo` | Passed with coordinator-discovered pinned mTLS loopback echo |
| `python -m pip wheel --no-deps --no-build-isolation --wheel-dir /tmp/fan-ssh-wheel .` | Built Python wheel |
| Install wheel into isolated temporary target, run demo outside checkout | Passed |

Final wheel: `fan_ssh-0.1.0-py3-none-any.whl`, SHA-256 `fd30c93e1ff0ba91ab0d39cb65ecadbcc2294bef25511d7326ccee36985e1350`. This is a local build artifact, not a published package. `py3-none-any` describes the Python package's own files; its cryptography dependency still needs a compatible installation for the target platform.

Root suite covers loopback address rejection, encrypted IPv4 and IPv6 peer paths, IPv6 target leg, eight concurrent binary streams, delayed response after half-close, local forwarding, independent destination pin before dialing, actual peer-pin rejection, foreign CA rejection, directed ACL/immutable snapshots, unapproved enrolled certificate rejection, malformed/extra-operation metadata, 4096-byte metadata cap, duplicate-key/nonstandard-constant/deep-JSON rejection, oversized/truncated frames, stalled TLS handshake cancellation, handshake admission cap, absolute bridge deadline, active-session cancellation, and actual CLI subprocess behavior.

CLI subprocess tests verify payload-exact binary stdout, half-close through stdin, empty stdout on invalid target, and exit under SIGTERM while stdout is blocked and stdin remains open. The blocked-pipe test is Linux-only. Tests use echo or synthetic reply services, not a real SSH server.

Independent review additionally exercised eight concurrent 2 MiB delayed responses; 1 MiB payload-exact CLI output; blocked input/output cancellation; 32 stalled TLS handshakes; same-CA unknown pins; coordinator rejection cases; encrypted IPv6; and a 1 MiB direct exchange after the coordinator was stopped. These checks passed on Linux and do not extend platform claims.

## Separate socket diagnostic

A fresh Python run made 200 active/active attempts for each loopback IP family: IPv4 2/200 and IPv6 2/200 verified exact tuples and payload echoes. Total 4/400; total budget was not exhausted. Each family also recorded 197 active-connect failures and one deadline. These are environment-specific observations, not a required success rate, NAT result or inherited Go result. The diagnostic README explains methodology and limitations.

## Not executed or not established

- No Windows/macOS runtime, minimum-version Python 3.11 runtime, or other cryptography version validation
- No real SSH login, user SSH key/host-key installation, private server access, or authentication changes
- No public/LAN/non-loopback probes, two-network session, real NAT traversal, UDP-blocked complex-NAT success or firewall/router changes
- No production key storage/enrollment/revocation, deployment, package-registry release, external CI or dependency audit
- No claim equivalent to Go's race detector; Python concurrency tests are behavioral tests

Recorded test and demo output lives under `test-results/`. Re-run both suites after changes; root discovery does not include the separate hyphenated experiment directory.
