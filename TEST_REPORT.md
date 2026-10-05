# Local usability branch validation — 2026-10-05

**Status: validation executed; unresolved errors retained. Not an all-green acceptance report.**
**Recommendation: defer merge until the intermittent UDP/bridge EOF is triaged,
or the maintainer explicitly accepts the documented limitation.** The profile UX
and ordinary Windows source/wheel runs passed, but an initial WSL bridge run and
the separate Windows debug UDP run failed. Later successful repetitions do not
repair or erase those failures.

## Tested revision and handoff

- Branch: `feat/usability-profiles-anonymized-docs`.
- Actual tested code: **`38284740ca5b8303edc0dbeab3cb82995a9d7187`**.
- Reviewed implementation: `1ed85c24f5aec935320a8de8055271453026994e`.
  The newer `3828474` adds HANDOFF.md instructions only; its diff was inspected.
- The original workspace was clean and preserved. Testing used an independent
  NTFS worktree; no reset, force push, main merge, PR or release was performed.
- README.md, ARCHITECTURE.md, VALIDATION.md and HANDOFF.md were read. No applicable
  AGENTS.md or LOCAL_VALIDATION_HANDOFF.md was present in this checkout or its
  inspected parent directories.
- This handoff changes documentation and adds validation evidence/harnesses only.
  **No `fan_ssh/`, `tests/`, dependency declaration or runtime behavior changes.**
  The report commit's SHA is not the SHA used for the functional tests above.
- Tests ran on 2026-10-05, Asia/Shanghai; result preparation began at approximately
  22:55. Exact per-command durations are in the JSON manifests.

All communication with the cloud reviewer is through this branch and this report.
No cloud/local filesystem sharing or direct thread message was used.
Before publication, the command-line fetch failed with an SSL connection timeout
and ordinary push failed with a connection reset. Fresh remote-ref reads through
the authenticated GitHub connector still showed the tested parent, with no new
contributor commit. Publication therefore uses a normal Git commit and a
**fast-forward-only ref update (`force: false`)** through that connector. This is
not a force push or a main/PR update.

## Environments and exact dependencies

| Environment | OS / Python | fan-ssh | cryptography | aiortc | aioice |
|---|---|---:|---:|---:|---:|
| Windows source, fresh editable venv | Native Windows 11 x86_64, build 22631; CPython 3.12.10 | 0.3.0 | 50.0.2 | 1.15.0 | 0.10.2 |
| Windows wheel, second fresh venv | Same native Windows and CPython 3.12.10 | 0.3.0 | 50.0.2 | 1.15.0 | 0.10.2 |
| WSL source | Ubuntu 24.04 x86_64, glibc 2.39; WSL2 kernel 5.15.167.4; CPython 3.12.3 | 0.3.0 | 50.0.2 | 1.15.0 | 0.10.2 |

Both Windows venvs have `include-system-site-packages = false`. WSL also used a
dedicated ordinary-user venv on its Linux filesystem. Successful imports of
`aiortc`, `aioice` and `fan_ssh` were checked in each environment. Pins match
pyproject.toml; no library patch, version substitution or downgrade was made.
Other UDP dependencies: av 17.1.0, cffi 2.1.1, dnspython 2.8.0, google-crc32c
1.9.0, ifaddr 0.2.0, pyee 14.0.0, pylibsrtp 1.0.0, pyOpenSSL 26.4.0,
pycparser 3.0 and typing_extensions 4.16.0. Windows build tooling: build 1.6.1,
packaging 26.3, pyproject_hooks 1.3.3 (isolated build backend setuptools 84.0.0).

Windows setup commands used each venv's `python.exe` directly, without changing
PowerShell execution policy:

| Command | Exit | Result |
|---|---:|---|
| `python -m venv <source-venv>` | 0 | New dedicated source environment |
| `python -m pip install -e ".[udp]"` | 0 | Declared UDP extra installed |
| `python -m pip install build` | 0 | Build tooling installed |
| `python -m pip check` | 0 | No broken requirements |
| `python -m build` | 0 | sdist and wheel built; wheel built from the sdist |
| `python -m venv <wheel-venv>` | 0 | Second environment, no system packages |
| `python -m pip install "<wheel-path>[udp]"` | 0 | Exact built wheel plus declared UDP dependencies |
| `python -m pip check` in wheel venv | 0 | No broken requirements |

WSL's first `python3 -m venv` returned **1** because `ensurepip` was unavailable.
It was replaced with `python3 -m venv --without-pip`, followed by installation of
pip 26.2.1 from an existing offline wheel into that venv. The exact pinned UDP
wheels and build wheels were then installed using `--no-index --find-links`.
Editable installation and pip check returned 0. No apt/sudo or system package
change was made. The initial WSL temporary checkout was unavailable to a later
process; the diagnostic launch did not execute tests. A second isolated checkout
under the WSL user's private Linux directory was used for the recorded rerun.
These setup attempts are not counted as passing tests.
One additional `git diff --check` invocation from the external wheel working
directory returned **129** (not a Git repository); the corrected worktree
invocation returned **0**. The failed invocation is retained in
`diff-check-wrong-cwd.txt` and is not a whitespace-check pass.
The first staged diff check returned **2** for a trailing blank line in that
captured Git error log. Evidence formatting was normalized without removing its
error content, and the final staged diff check returned **0**.

## Required suite commands and results

`python` below means the indicated dedicated venv executable. Source commands ran
in the source checkout. Installed-wheel commands ran **outside** the checkout,
with `PYTHONPATH` removed and `-s <workspace>/tests` or the corresponding absolute
experiment path. Discovery adds the tests directory, not the package source root.
The installed import was explicitly asserted to be inside the wheel venv's
`Lib/site-packages/fan_ssh`, and its venv configuration was checked.

Cells contain **passed / failures / errors / skipped; exit code**. Counts are per
invocation and overlap; do not add targeted counts to the complete-suite count.

| Command | Windows source | Windows installed wheel | WSL first source run | WSL source rerun |
|---|---|---|---|---|
| `python -m unittest discover -s tests -v` | 107 / 0 / 0 / 5; **0** | 107 / 0 / 0 / 5; **0** | 112 / 0 / 0 / 0; **0** | 112 / 0 / 0 / 0; **0** |
| `python -m unittest discover -s tests -p test_udp.py -v` | 13 / 0 / 0 / 0; **0** | 13 / 0 / 0 / 0; **0** | 13 / 0 / 0 / 0; **0** | 13 / 0 / 0 / 0; **0** |
| `python -m unittest discover -s tests -p test_home_bridge.py -v` | 11 / 0 / 0 / 0; **0** | 11 / 0 / 0 / 0; **0** | **10 / 0 / 1 / 0; 1** | 11 / 0 / 0 / 0; **0** |
| `python -m unittest discover -s tests -p test_profiles.py -v` | 20 / 0 / 0 / 2; **0** | 20 / 0 / 0 / 2; **0** | 22 / 0 / 0 / 0; **0** | 22 / 0 / 0 / 0; **0** |
| `python -m unittest discover -s experiments/tcp-simopen -v` | 15 / 0 / 0 / 11; **0** | 15 / 0 / 0 / 11; **0** | 26 / 0 / 0 / 0; **0** | 26 / 0 / 0 / 0; **0** |
| `python -m unittest discover -s experiments/stun-observer -v` | 7 / 0 / 0 / 0; **0** | 7 / 0 / 0 / 0; **0** | 7 / 0 / 0 / 0; **0** | 7 / 0 / 0 / 0; **0** |
| `python -m unittest discover -s experiments/easytier-reference -v` | 6 / 0 / 0 / 0; **0** | 6 / 0 / 0 / 0; **0** | 6 / 0 / 0 / 0; **0** | 6 / 0 / 0 / 0; **0** |

The original **13 UDP transport + 2 UDP bridge tests executed**, with no
missing-extra skips, in the Windows source, Windows wheel and WSL complete runs.
All 15 passed in those complete invocations. The initial targeted WSL bridge
invocation later errored in one of the two UDP bridge cases, as recorded above.

| Non-unittest command | Windows source | Windows wheel | WSL first / rerun |
|---|---:|---:|---:|
| `python -m fan_ssh demo` | 0, PASS | 0, PASS | 0 / 0, PASS |
| `python -m compileall -q fan_ssh tests scripts experiments` | 0 | 0, absolute source paths | 0 / 0 |
| `python -m compileall -q <wheel-venv>/Lib/site-packages/fan_ssh` | — | 0 | — |
| `python -m pip check` | 0 | 0 | 0 / 0 |
| version/import inspection | 0 | 0, site-packages confirmed | 0 / 0 |
| `git diff --check` in independent worktree | 0 before evidence; 0 after final staging | Same checkout check | Not a separate Git checkout |

There were no process timeouts in the recorded suite runs. The runner uses an
outer 600-second bound for ordinary groups, independent of unchanged test
assertions/timeouts. Background-output review found no `Exception in callback`,
unretrieved task exception, destroyed task or ResourceWarning in these suite logs.
Asyncio debug slow-task messages remain visible.

## Platform and IPv6 skips

The **five Windows complete-suite skips** are platform skips, not missing UDP:

1. `test_cli.CLITests.test_proxy_blocked_stdout_cancellation` —
   `POSIX signal/pipe runtime regression`.
2. `test_native_diagnostics.LinuxBindingTests.test_cancelled_observation_closes_prebound_resources`
   — `Linux source-bound TCP adapter; run on Linux hosts`.
3. `test_native_diagnostics.LinuxBindingTests.test_same_source_port_two_authenticated_observers_and_prebound_listener`
   — same Linux adapter reason.
4. `test_profiles.ProfileTests.test_named_pipe_profile_is_rejected_without_blocking`
   — `POSIX FIFO regression`.
5. `test_profiles.ProfileTests.test_symlink_profile_is_rejected_and_never_overwritten`
   — `symlink creation may require Windows privileges`.

The **11 additional TCP experiment skips** are four `ReuseChannelControls`
cases requiring real Linux SO_REUSEPORT, plus seven `LocalSocketTests` cases
marked `Linux socket diagnostic`. Every individual name and reason is retained
in the Windows `tcp.txt` logs and `results.json` manifests.
All five root and all eleven experimental cases ran successfully in WSL.
**WSL results are Linux-on-WSL coverage, not native Windows or a native Linux host.**

IPv6 conditional skips: **zero**. Both existing IPv6 loopback cases ran on
Windows and WSL. This does not establish any public IPv6 path or router behavior.

## Separate debug stress and retained errors

Only the two Windows stress subprocesses received `FAN_SSH_UDP_DEBUG_TESTS=1`:

| Command under that environment variable | Passed | Failures | Errors | Skips | Exit |
|---|---:|---:|---:|---:|---:|
| `python -m unittest discover -s tests -p test_udp.py -v` | 12 | 0 | **1** | 0 | **1** |
| `python -m unittest discover -s tests -p test_home_bridge.py -v` | 11 | 0 | 0 | 0 | 0 |

Each stress group had a 300-second external process limit; neither hit it.
`UDPSignalingTests.test_signaled_direct_binary_half_close` errored with
`IncompleteReadError: 0 bytes read on a total of 4 expected bytes` while reading
the next frame header. No background exception was observed in this run.
The existing historical failed logs were preserved unchanged:
`test-results/python-product-windows-debug-failed-20261005.txt` and
`test-results/home-bridge-windows-full-failed-20261005.txt`.

The first ordinary WSL targeted bridge run errored in
`HomeBridgeUDPTests.test_tcp_incoming_udp_outgoing_binary_and_half_close`, also
with a missing four-byte frame header. The same code passed in the initial
complete suite, the second complete/targeted runs, and **six consecutive isolated
repetitions** (6 passed, 0 failures, 0 errors, 0 skips; wrapper exit 0).
The repetition harness additionally reported background service exceptions if
present; none occurred. Its instrumentation did not change deadlines/assertions.

**Root cause is not established.** Source inspection showed the error surface is
premature framed-stream closure, but no deterministic causative state was captured.
A transport rewrite, speculative close/flush change or timeout increase is not
presented as a fix. No tests were deleted, skipped additionally, weakened or
filtered. No unmodified successful rerun is labeled a repaired regression.
Debug pressure was checked on Windows source only, not the installed wheel.
WSL's existing async test runner enables debug by default on Linux; this differs
from ordinary Windows's product non-debug selector loop.

## CLI usability, documentation and SSH safety

The committed `check_ux.py` evidence harness was executed with source and installed
wheel Python, outside the source directory, each with **exit 0**. Each run covered
22 actual CLI subprocess checks, plus guarded offline/effective-SSH checks:

- Help for root, profile, add/list/show, connect, doctor, ssh, proxy and forward.
- Synthetic identity-init and policy-build, using temporary identities and
  loopback/documentation-only addresses; no coordinator/node was deployed.
- First profile listing, saving relative identity/policy paths, refusal to
  overwrite, and show/list/doctor from a different working directory.
- Actual doctor JSON and exit code 0; missing profile doctor exit 1 and connect
  exit 2; duplicate add exit 1. Existing tests cover invalid, revoked, unreadable
  and missing prerequisite cases independently.
- In-process doctor with `socket.socket` forbidden and SSH login forbidden,
  including the real pinned UDP metadata check. Fixture bytes were unchanged
  before/after. Windows local ACL inspection remains permitted and offline.
- Real `ssh -F <empty-synthetic-config> -G ...` returned 0 and confirmed the exact
  Python ProxyCommand, strict host-key checks, batch authentication, existing
  supplied user/port, disabled agent forwarding/key update and cleared forwards.
  No replacement known_hosts file or unknown-host trust was introduced.
- The 22 existing profile tests verify connect uses the same SSH entry, directed
  approval and identity checks, correct remote-command argument forwarding and
  nonzero failure before SSH when identity is invalid. SSH execution is mocked
  in these connect tests; **they are not real SSH logins**.

All **25 fan-ssh CLI examples** in README shell blocks parsed with the actual
argument parser. README separates first preparation from daily connection,
documents `--profiles-dir` placement before connect's alias, and discloses
doctor's unchecked network/SSH limits. OpenSSH/shell/installation snippets were
reviewed separately; parsing examples is not live execution of deployment steps.
The post-documentation-update UX/parser rerun also returned 0.

The installed `fan-ssh --help`, `directssh --help`, `fan-ssh demo`, and
`directssh demo` each returned **0** from the wheel venv's Scripts directory.
`python -m fan_ssh --help` and demo also returned 0. Original proxy binary/half-close
and foreground bridge subprocess cases are included in the full wheel suite.

Documentation corrections point README, VALIDATION and HANDOFF to these new
results instead of leaving Windows validation marked wholly unperformed.
There is no runtime fix commit: the unresolved errors above remain open.

## Build and installation evidence

- Built from code SHA `38284740ca5b8303edc0dbeab3cb82995a9d7187`, before these
  report/documentation-only edits.
- `fan_ssh-0.3.0-py3-none-any.whl` SHA-256:
  `6abd9089a00c306bebf69291cd86e71d760656dd651a5b63d479eda1747b2ebc`.
- `fan_ssh-0.3.0.tar.gz` SHA-256:
  `954b1013351080ec0bfd8ed43f9c820ae0df49c538cf89729b7189461631ff6e`.
- Editable source import: `<workspace>/fan_ssh/__init__.py`.
- Installed wheel import: `<wheel-venv>/Lib/site-packages/fan_ssh/__init__.py`;
  asserted against `sys.prefix`, with system-site-packages disabled.
- Wheel tests came from the checkout's absolute test paths; package imports and
  CLI subprocesses used the installed environment and external working directory.
  The wheel environment has no editable checkout installation.
- A Linux wheel installation, macOS, Python 3.11 and other Python versions were
  **not run**. No package-registry publication occurred.

## Coverage limits and online checks

Native Windows local source/wheel testing: **run**, including actual loopback UDP.
WSL Linux local supplementation: **run**. New connect/profile real SSH login,
physical cross-network connections, native Linux host testing, router IPv6 relay
and complete two-leg live bridge: **not run**. Historical successful `ssh`/FRP
records do not validate the new `connect` entry. No real profiles, SSH credentials,
known_hosts, authorization, firewall, routes or production service settings were
changed. Only temporary foreground loopback test processes were started.

GitHub checked the exact tested SHA: Actions runs **0**, check-runs **0**;
combined status `pending` with **zero statuses**. This means no online passing
check was observed, not that CI passed.

Full sanitized logs, per-command exit/count manifests and the exact generic
harnesses are in [test-results/usability-local-20261005](test-results/usability-local-20261005).
`wsl-source/home-bridge.txt` preserves the failed first targeted run;
`windows-debug/udp.txt` preserves the stress failure. Private paths and synthetic
identity fingerprints are redacted; test names, error traces, assertions,
measured outcomes and dependency versions are retained. Raw private logs are not
committed. The cloud reviewer can read these artifacts directly from GitHub.
