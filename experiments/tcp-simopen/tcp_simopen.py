#!/usr/bin/env python3
"""Bounded Linux active/active TCP diagnostic. Numeric loopback only; no NAT claim."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
import errno
import json
import math
import os
import platform
import select
import socket
import sys
import threading
import time
from typing import Callable


PAYLOAD = b"SO-loopback-diagnostic-only\x00" * 128
POLL_SECONDS = 0.001
LOOPBACKS = {"4": (socket.AF_INET, "127.0.0.1"), "6": (socket.AF_INET6, "::1")}
PENDING_ERRORS = {errno.EINPROGRESS, errno.EALREADY, errno.EINTR, errno.EWOULDBLOCK}


class DiagnosticCancelled(Exception):
    """A caller explicitly cancelled the local diagnostic."""


@dataclass(frozen=True)
class Deadline:
    expires_at: float
    cancellations: tuple[threading.Event, ...] = ()

    def __post_init__(self) -> None:
        if not math.isfinite(self.expires_at):
            raise ValueError("a finite monotonic deadline is required")

    def remaining(self) -> float:
        if any(event.is_set() for event in self.cancellations):
            raise DiagnosticCancelled("diagnostic cancelled")
        remaining = self.expires_at - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("diagnostic deadline exceeded")
        return remaining


@dataclass
class Endpoint:
    local: str = ""
    remote: str = ""
    connect_start_us: int = 0
    connect_duration_us: int = 0
    initial_connect_result: str = "not attempted"
    error: str = ""


@dataclass
class Result:
    family: str
    trial: int = 0
    a: Endpoint = field(default_factory=Endpoint)
    b: Endpoint = field(default_factory=Endpoint)
    payload_roundtrip_verified: bool = False
    error: str = ""
    duration_us: int = 0


def _require_linux() -> None:
    if not sys.platform.startswith("linux"):
        raise RuntimeError("TCP_SO_SOCKET_UNSUPPORTED: this diagnostic supports Linux only")


def _address(sock: socket.socket) -> tuple:
    address = sock.getsockname()
    expected = {socket.AF_INET: "127.0.0.1", socket.AF_INET6: "::1"}.get(sock.family)
    if expected is None or address[0] != expected or not 1024 <= address[1] <= 65535:
        raise ValueError("refusing a socket outside numeric loopback high ports")
    return address


def _format(address: tuple) -> str:
    host, port = address[:2]
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def bound_socket(family: str) -> socket.socket:
    """Allocate and retain a distinct ephemeral loopback binding, without reuse."""
    if family not in LOOPBACKS:
        raise ValueError("family must be '4' or '6'")
    _require_linux()
    domain, host = LOOPBACKS[family]
    sock = socket.socket(domain, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    try:
        # Python sockets are non-inheritable by default. No SO_REUSE* or TCP option.
        sock.setblocking(False)
        sock.bind((host, 0))
        _address(sock)
        return sock
    except BaseException:
        sock.close()
        raise


def wait_connected(deadline: Deadline, probe: Callable[[], bool]) -> None:
    """A zero SO_ERROR alone is insufficient: the probe must verify getpeername."""
    while True:
        deadline.remaining()
        connected = probe()
        remaining = deadline.remaining()
        if connected:
            return
        time.sleep(min(POLL_SECONDS, remaining))


def connect_peer(sock: socket.socket, peer: socket.socket, deadline: Deadline,
                 report: Endpoint) -> None:
    """Actively connect only to another numeric-loopback socket's held binding."""
    deadline.remaining()
    local, remote = _address(sock), _address(peer)
    if sock.family != peer.family or local == remote:
        raise ValueError("same-family distinct loopback bindings required")
    sock.setblocking(False)
    code = sock.connect_ex(remote)
    report.initial_connect_result = (
        "connected immediately" if code == 0 else
        f"{errno.errorcode.get(code, 'UNKNOWN')} ({code}): {os.strerror(code)}"
    )
    if code not in PENDING_ERRORS and code not in (0, errno.EISCONN):
        raise OSError(code, os.strerror(code))

    def probe() -> bool:
        error = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if error:
            raise OSError(error, os.strerror(error))
        try:
            actual = sock.getpeername()
        except OSError as exc:
            if exc.errno == errno.ENOTCONN:
                return False
            raise
        if actual != remote or sock.getsockname() != local:
            raise RuntimeError("connected tuple mismatch")
        return True

    wait_connected(deadline, probe)


def _wait_io(sock: socket.socket, deadline: Deadline, *, reading: bool) -> None:
    while True:
        remaining = min(deadline.remaining(), 0.01)
        readable, writable, _ = select.select(
            [sock] if reading else [], [] if reading else [sock], [], remaining
        )
        deadline.remaining()
        if readable or writable:
            return


def _send_all(sock: socket.socket, data: bytes, deadline: Deadline) -> None:
    view = memoryview(data)
    while view:
        deadline.remaining()
        try:
            sent = sock.send(view)
        except (BlockingIOError, InterruptedError):
            _wait_io(sock, deadline, reading=False)
            continue
        if sent == 0:
            raise ConnectionError("socket closed during payload send")
        view = view[sent:]


def _recv_exact(sock: socket.socket, size: int, deadline: Deadline) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        deadline.remaining()
        try:
            part = sock.recv(size - len(chunks))
        except (BlockingIOError, InterruptedError):
            _wait_io(sock, deadline, reading=True)
            continue
        if not part:
            raise ConnectionError("socket closed before complete payload")
        chunks.extend(part)
    return bytes(chunks)


def roundtrip(a: socket.socket, b: socket.socket, deadline: Deadline) -> None:
    """A fixed small diagnostic payload travels A -> B -> A, byte-for-byte."""
    a.setblocking(False)
    b.setblocking(False)
    _send_all(a, PAYLOAD, deadline)
    received = _recv_exact(b, len(PAYLOAD), deadline)
    if received != PAYLOAD:
        raise ValueError("payload mismatch")
    _send_all(b, received, deadline)
    if _recv_exact(a, len(PAYLOAD), deadline) != PAYLOAD:
        raise ValueError("echo mismatch")
    deadline.remaining()


def run_trial(family: str, timeout: float = 0.2, *, expires_at: float | None = None,
              cancel: threading.Event | None = None) -> Result:
    """Run one attempt; refusals and timeouts are valid unverified observations."""
    if family not in LOOPBACKS:
        raise ValueError("family must be '4' or '6'")
    if not math.isfinite(timeout) or not 0.001 <= timeout <= 5:
        raise ValueError("timeout must be between 0.001 and 5 seconds")
    if expires_at is not None and not math.isfinite(expires_at):
        raise ValueError("a finite monotonic deadline is required")
    start = time.monotonic()
    stop = threading.Event()
    events = (stop,) if cancel is None else (stop, cancel)
    deadline = Deadline(min(start + timeout, expires_at) if expires_at is not None
                        else start + timeout, events)
    result = Result(family)
    sockets: list[socket.socket] = []
    threads: list[threading.Thread] = []
    gate = threading.Barrier(3)

    def worker(sock: socket.socket, peer: socket.socket, report: Endpoint) -> None:
        began = time.monotonic()
        try:
            gate.wait(timeout=deadline.remaining())
            began = time.monotonic()
            report.connect_start_us = int((began - start) * 1_000_000)
            connect_peer(sock, peer, deadline, report)
        except Exception as exc:
            report.error = str(exc) or type(exc).__name__
        finally:
            report.connect_duration_us = int((time.monotonic() - began) * 1_000_000)

    try:
        deadline.remaining()
        _require_linux()
        for _ in range(2):
            deadline.remaining()
            sockets.append(bound_socket(family))
        a, b = sockets
        a_address, b_address = _address(a), _address(b)
        if a_address == b_address:
            raise RuntimeError("distinct port invariant failed")
        result.a.local, result.a.remote = _format(a_address), _format(b_address)
        result.b.local, result.b.remote = _format(b_address), _format(a_address)
        for sock, peer, report in ((a, b, result.a), (b, a, result.b)):
            thread = threading.Thread(target=worker, args=(sock, peer, report), daemon=True)
            thread.start()
            threads.append(thread)
        gate.wait(timeout=deadline.remaining())
        for thread in threads:
            thread.join(timeout=deadline.remaining())
        deadline.remaining()
        if any(thread.is_alive() for thread in threads):
            raise TimeoutError("active connect worker deadline exceeded")
        if result.a.error or result.b.error:
            raise ConnectionError("one or both active connects failed")
        if a.getpeername() != b_address or b.getpeername() != a_address:
            raise RuntimeError("connected tuple mismatch")
        roundtrip(a, b, deadline)
        result.payload_roundtrip_verified = True
    except Exception as exc:
        result.error = str(exc) or type(exc).__name__
    finally:
        stop.set()
        gate.abort()
        # No operation blocks indefinitely. Allow up to 50 ms per worker to observe
        # cancellation before closing descriptors; never retain sockets between trials.
        for thread in threads:
            thread.join(timeout=0.05)
        for sock in sockets:
            sock.close()
        if any(thread.is_alive() for thread in threads):
            result.payload_roundtrip_verified = False
            result.error = "worker did not stop within bounded cleanup"
        result.duration_us = int((time.monotonic() - start) * 1_000_000)
    return result


def _bounded_float(low: float, high: float) -> Callable[[str], float]:
    def parse(value: str) -> float:
        number = float(value)
        if not math.isfinite(number) or not low <= number <= high:
            raise argparse.ArgumentTypeError(f"must be finite and in [{low}, {high}] seconds")
        return number
    return parse


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=50, help="attempts per family (1..500)")
    parser.add_argument("--timeout", type=_bounded_float(0.001, 5), default=0.2,
                        help="per-trial socket deadline in seconds (0.001..5)")
    parser.add_argument("--budget", type=_bounded_float(0.001, 60), default=20.0,
                        help="total socket budget in seconds (0.001..60)")
    parser.add_argument("--family", choices=("4", "6", "both"), default="both")
    args = parser.parse_args(argv)
    if not 1 <= args.trials <= 500:
        parser.error("--trials must be in [1, 500]")
    print(json.dumps({
        "kind": "environment", "python": platform.python_version(), "os": sys.platform,
        "kernel": platform.release(), "arch": platform.machine(), "loopback_only": True,
        "listener_used": False, "nat_traversal_proven": False,
        "socket_options_changed": False, "payload_bytes": len(PAYLOAD),
    }), flush=True)
    expires_at = time.monotonic() + args.budget
    attempts, verified = 0, 0
    families = ("4", "6") if args.family == "both" else (args.family,)
    for family in families:
        for trial in range(1, args.trials + 1):
            if time.monotonic() >= expires_at:
                break
            result = run_trial(family, args.timeout, expires_at=expires_at)
            result.trial = trial
            print(json.dumps({"kind": "trial", **asdict(result)}), flush=True)
            attempts += 1
            verified += int(result.payload_roundtrip_verified)
    exhausted = time.monotonic() >= expires_at
    print(json.dumps({
        "kind": "summary", "attempts": attempts, "verified": verified,
        "requested_attempts": args.trials * len(families), "budget_exhausted": exhausted,
        "claim": "socket feasibility only; no NAT tested",
    }), flush=True)
    return 0 if verified else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
