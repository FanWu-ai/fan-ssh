# Bounded Python TCP simultaneous-open diagnostic

The original `tcp_simopen.py` below remains a no-listener, no-reuse, Python 3.10+
loopback experiment. A separate `test_tcp_reuse.py` now covers the dual-listener
research implementation in `scripts/native_tcp_ttl_probe.py`; those three real
Linux controls require Python 3.11+. They verify same-stream MAC selection and a
64 KiB exact echo with half-close, wrong-MAC rejection, and pending-connection
cancellation without leaked descriptors. They do not prove NAT traversal.
Full discovery now runs 25 tests on Linux. The two authorized Linux hosts each
passed all 25 without skips on 2026-10-04. Four external dual-listener trials
still failed peer authentication; see `test-results/tcp-reuse-native-20261004.json`.

This is a **Linux, numeric-loopback-only socket experiment**, isolated from the
main fan-ssh implementation. It uses Python's standard library. It does not
implement or demonstrate NAT traversal, ICE, authenticated peer connectivity,
SSH transport, or connectivity between independent machines.

## Safety and scope

- The only addresses are `127.0.0.1` and `::1`; no host, address, peer, or port
  command-line argument exists. No DNS or external network probe is performed.
- Two ordinary TCP sockets are bound concurrently to OS-allocated, distinct
  high ports. Both actively connect to the other's exact held binding.
- No listener, `accept`, relay, reuse-address/reuse-port setting, firewall or
  sysctl change, root privilege, packet capture, credential, or deployment.
- No third-party package, binary download, or non-Python build tool is needed.
- Non-Linux execution returns `TCP_SO_SOCKET_UNSUPPORTED` for attempts. IPv6
  absence is reported as an unverified trial error, not hidden by fallback.

## Run

From the repository root, with Python 3.10 or newer:

```sh
python3 -m unittest discover -s experiments/tcp-simopen -v
python3 experiments/tcp-simopen/tcp_simopen.py \
  --trials 200 --timeout 0.2 --budget 20
```

Or, from this directory:

```sh
python3 -m unittest -v
python3 tcp_simopen.py --family 4 --trials 50
```

Options:

- `--family 4`, `6`, or `both` (default)
- `--trials`: 1–500 attempts per family; default 50
- `--timeout`: finite seconds, 0.001–5; default 0.2
- `--budget`: finite seconds, 0.001–60 across both families; default 20

Nonblocking socket operations share a monotonic per-trial deadline capped by
the total budget. Barrier waits and worker joins are bounded. Cancellation is
checked during connect and payload I/O. Cleanup allows at most 50 ms per worker
after a deadline; operating-system scheduling and output-writing overhead mean
the budget is not a hard real-time wall-clock guarantee. No new attempt begins
after the total deadline. The Python API also accepts an explicit cancellation
event and an outer monotonic deadline.

The command writes newline-delimited JSON: an environment record, one result
per attempted trial, and a summary. Trial fields contain both allocated tuples,
initial connect results, monotonic connect offsets/durations, completion errors,
and `payload_roundtrip_verified`. The summary includes requested/actual attempt
counts and `budget_exhausted`.

Exit 0 means **at least one verified local pair**. Exit 1 means no verified pair;
exit 2 means invalid command-line arguments; interruption exits 130. Exit 0 does
not mean every attempt or family succeeded, or that the budget was sufficient.

## What a verified result means

Two Python worker threads wait at one barrier, then call nonblocking
`connect_ex` on separate prebound TCP sockets. There is no passive listener
fallback. Completion requires zero `SO_ERROR`, a successful `getpeername`, and
matching local/remote tuples; a pending socket with zero `SO_ERROR` is never
treated as connected. Both directions must complete successfully.

An exact 3,584-byte fixed diagnostic payload travels A → B → A and is compared
byte-for-byte at each receiving end. It contains no SSH data or peer identity.
Every socket is closed after its attempt, including bind, connect, verification,
timeout, and cancellation failure paths.

The barrier does not force simultaneous kernel processing. Python threading,
the interpreter, the scheduler, and fast loopback delivery can let one SYN
arrive before the other side starts connecting. Refusal and deadline outcomes
are expected and reported. The threads are not CPU-pinned, and no packet trace
was collected. The success percentage is not a predicted real-network rate.

No coordinator-observed mapping, same-port mapping-connection coexistence,
destination-dependent NAT, firewall behavior, interface change, cross-process
ownership race, or TIME_WAIT reuse was tested. A successful loopback result
does not establish those properties. A failed attempt does not disprove every
possible direct TCP approach.

## Fresh observation: 2026-10-03 UTC

In this execution environment: Linux 6.18.44, x86_64, Python 3.12.14, uid 1000.
The command above with 200 attempts per family produced:

- IPv4: 2 payload-verified pairs / 200 attempts
- IPv6: 2 payload-verified pairs / 200 attempts
- Total: 4 / 400; total budget was not exhausted
- Each family: 197 active-connect failures and one trial deadline

These are measurements of one run, not required outcomes or inherited results
from a different implementation. Repeats may legitimately verify zero pairs.

Validation performed on the final Python implementation:

- 22 unittest tests passed; five additional full repeat runs passed
- `python3 -m compileall -q experiments/tcp-simopen` passed
- No non-Linux runtime was tested; unsupported-platform behavior was mocked

## Test coverage

- Numeric-loopback-only binding, distinct high ports, non-inheritable handles,
  and unchanged reuse-address/reuse-port options
- Invalid families, host-like arguments, non-finite durations, and bounds
- A bound peer that never connects cannot become a verified connection
- Zero `SO_ERROR` with `ENOTCONN` remains pending; tuple mismatch is rejected
- Expired/cancelled attempts before binding, pending-connect timeout/cancel,
  and explicit error propagation
- Partial payload I/O, early EOF, exact byte verification, and mismatch rejection
- Successful local socket-pair echo and deliberately stalled local socket-pair
  timeout/cancellation; these are I/O controls, not active/active TCP proof
- Failure of the second bind closes the first socket
- Thirty real attempts per family per suite, with tuple consistency and no
  descriptor/thread growth; the test does not demand any success rate
- CLI JSON/exit semantics and exhaustion of a short total budget

Real-network research requires a separate authorized test plan with consenting
endpoints, exact source/observed/peer tuples, and any owner-approved NAT or
firewall changes. This harness intentionally cannot accept such endpoints.
