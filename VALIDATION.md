# Validation report

## Scope

The repository consolidates two previously separate dependency-free Go experiments. It preserves the original source/tests and selected historical evidence, then reruns checks on the consolidated tree. Neither source directory had independent Git history to preserve; historical logs and the architecture roadmap retain the relevant baseline. No downloaded toolchain, binary, private credentials or private endpoint inventory is included.

Runtime checked: Linux 6.18.44 amd64, ordinary unprivileged process. Go 1.27.1. Date: 2026-10-03 UTC. Linux loopback is the only runtime network environment validated. A cross-build is compilation evidence, not an OS runtime or NAT traversal result.

## Historical baseline

See `test-results/history/prototype/` for three race-test repetitions (18 named tests per repetition), vet output, compiled echo demo, blocked-stdout CLI regression and six-platform cross-build summary. Empty vet logs mean no diagnostics. See `test-results/history/tcp-simopen/` for recorded bounded diagnostic trials and test output: initial run 14/100 verified pairs; separate run 63/400 (IPv4 30/200, IPv6 33/200). The diagnostic suite also passed ten repetitions (2,000 trial attempts plus negative/lifecycle controls). No minimum active/active success rate is required by the test suite.

These results are historical observations, not predictions for another scheduler, kernel, platform or NAT.

## Consolidated checks

All consolidated checks passed: main race tests ×3, experiment race tests, vet in both modules, main echo demo, Linux blocked-stdout regression, and Linux/macOS/Windows × amd64/arm64 builds for both modules (12 cross-build targets). Only Linux amd64 binaries were executed. The fresh standalone diagnostic verified 12/100 loopback pairs; this is not a network success-rate claim.

Fresh logs are under `test-results/consolidated/`. See `summary.txt` for each command's exit status, `environment.txt` for runtime version, and the per-check logs for complete test output. Cross-build outputs are not checked in.

Reproduction commands and prerequisites are in [HANDOFF.md](HANDOFF.md). Root `go test ./...` deliberately does not enter the nested experimental module; both modules must be tested independently.

## Coverage and limits

Main tests cover address restrictions, four concurrent 144 KB streams, frozen directional ACLs, metadata method/body rejection and size limits, unknown identities, destination pin substitution, rejected non-loopback targets, opaque payload handling, half-close, backpressure/cancellation, incomplete handshake shutdown, IPv6 loopback, forwarding, clean stdout, input error propagation and actual CLI cancellation with blocked inherited stdout.

The main listener handler limits are 32; no saturation-boundary load test is claimed. Dedicated certificate-expiry/missing-certificate end-to-end fixtures remain outstanding. Fixed identities and ACLs are test fixtures, not a production authorization protocol.

Experimental tests cover loopback/high-port binding, no-connect negative control, cancellation/deadlines, pending-connect completion polling, stalled payload handling, exact verified endpoint tuples and descriptor cleanup. There is no passive listener fallback. Any successful diagnostic payload is unauthenticated test data, not SSH.

Never tested or not implemented: actual SSH login; real LAN/Internet peer reachability; UDP-blocked two-LAN operation; NAT mapping acquisition/traversal; Pion/ICE/STUN; distributed enrollment; active-session revocation/leases; Windows/macOS runtime socket behavior. The non-Linux simultaneous-open adapter is explicitly unsupported. No public deployment or package release is included. [ARCHITECTURE.md](ARCHITECTURE.md) describes proposed future behavior and must not be read as implementation status.
