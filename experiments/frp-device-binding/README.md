# Ordinary-user physical-interface FRP reference

This Linux x86_64 research supervisor binds newly created IPv4 UDP sockets of
its own child to an explicitly selected physical interface. It was exercised
under ordinary accounts with original frp 0.71.0, including a verified native
SSH/data path. It does not modify the executable, host routing/firewall settings,
existing services, or unrelated processes. It refuses root/setuid execution.

Some hosts permit the first SO_BINDTODEVICE operation by an ordinary user; others
reject it. Verify permission on the actual host. PTRACE_GET_SYSCALL_INFO and
tracing the supervisor's own child must be allowed. No automatic sudo, capability
installation, or system configuration fallback exists. This is a diagnostic,
not a production transport adapter or a universal NAT solution.

```sh
cc -O2 -Wall -Wextra udp_device_child.c -o udp-device-child
FANSSH_NATIVE_DEVICE=YOUR_PHYSICAL_INTERFACE ./udp-device-child \
  /path/to/verified/frpc -c /path/to/owned-temporary-profile.toml
```

Use an operator-approved temporary XTCP profile, no data fallback, numeric STUN
observers whose replies were verified on this physical interface, and existing
verified SSH host keys. Cloud frps may exchange coordination only. Bind the
visitor to loopback. Successful discovery or an SSH banner is insufficient:
require both peer-hole logs, selected native addresses/physical routes, a strict
SSH login, and exact binary/hash verification. Keep endpoint inventories,
credentials, tokens, profiles and raw logs private; publish only sanitized flags
and counts. Temporary observers require existing authorized reachable ports.

The supervisor uses syscall tracing and temporarily saves/restores four stack
words and registers for a socket-option injection. It follows only its own child
threads, caps tracking at 256 threads, checks the x86_64 syscall instruction,
checks every injected return, and sets EXITKILL. Compiler/runtime errors fail
closed. Run inside a bounded ordinary-user test supervisor, stop owned children,
and remove only the validated temporary directory afterward.

The Python fan-ssh direct selector does not yet integrate this external FRP
reference. See ../../test-results/frp-home-peer5-native-20261005.json and the
remaining acceptance limits in ../../VALIDATION.md.
