"""Stdlib tests; all real sockets stay on loopback or local socket pairs."""

from contextlib import redirect_stderr, redirect_stdout
import errno
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

import tcp_simopen as diagnostic


def deadline(seconds=0.1):
    return diagnostic.Deadline(time.monotonic() + seconds)


class DeterministicTests(unittest.TestCase):
    def test_deadline_must_be_finite(self):
        for value in (float("nan"), float("inf"), -float("inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                diagnostic.Deadline(value)

    def test_invalid_family_never_creates_socket(self):
        with mock.patch.object(socket, "socket") as factory:
            with self.assertRaises(ValueError):
                diagnostic.bound_socket("127.0.0.2")
            with self.assertRaises(ValueError):
                diagnostic.run_trial("external")
            factory.assert_not_called()

    def test_invalid_api_bounds(self):
        for timeout in (0, 0.0001, 6, float("inf"), float("nan")):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                diagnostic.run_trial("4", timeout)
        with self.assertRaises(ValueError):
            diagnostic.run_trial("4", expires_at=float("nan"))

    def test_expired_and_cancelled_trials_do_not_bind(self):
        cancelled = threading.Event()
        cancelled.set()
        with mock.patch.object(diagnostic, "bound_socket") as bind:
            expired = diagnostic.run_trial("4", expires_at=time.monotonic() - 1)
            cancelled_result = diagnostic.run_trial("4", cancel=cancelled)
            bind.assert_not_called()
        self.assertFalse(expired.payload_roundtrip_verified)
        self.assertIn("deadline", expired.error)
        self.assertFalse(cancelled_result.payload_roundtrip_verified)
        self.assertIn("cancelled", cancelled_result.error)

    def test_unsupported_platform_explicit_and_no_socket(self):
        with mock.patch.object(sys, "platform", "darwin"), \
                mock.patch.object(socket, "socket") as factory:
            result = diagnostic.run_trial("4")
        factory.assert_not_called()
        self.assertFalse(result.payload_roundtrip_verified)
        self.assertIn("TCP_SO_SOCKET_UNSUPPORTED", result.error)

    def test_pending_probe_times_out(self):
        began = time.monotonic()
        with self.assertRaises(TimeoutError):
            diagnostic.wait_connected(deadline(0.005), lambda: False)
        self.assertLess(time.monotonic() - began, 0.5)

    def test_pending_probe_cancels(self):
        cancel = threading.Event()
        bounded = diagnostic.Deadline(time.monotonic() + 1, (cancel,))

        def probe():
            cancel.set()
            return False

        with self.assertRaises(diagnostic.DiagnosticCancelled):
            diagnostic.wait_connected(bounded, probe)

    def test_probe_propagates_error(self):
        def probe():
            raise OSError(errno.ECONNREFUSED, "test refusal")
        with self.assertRaises(OSError) as raised:
            diagnostic.wait_connected(deadline(), probe)
        self.assertEqual(raised.exception.errno, errno.ECONNREFUSED)

    def test_zero_socket_error_does_not_prove_connection(self):
        local = mock.Mock(family=socket.AF_INET)
        local.getsockname.return_value = ("127.0.0.1", 30001)
        local.connect_ex.return_value = errno.EINPROGRESS
        local.getsockopt.return_value = 0
        local.getpeername.side_effect = OSError(errno.ENOTCONN, "still pending")
        peer = mock.Mock(family=socket.AF_INET)
        peer.getsockname.return_value = ("127.0.0.1", 30002)
        with self.assertRaises(TimeoutError):
            diagnostic.connect_peer(local, peer, deadline(0.005), diagnostic.Endpoint())
        local.getpeername.assert_called()

    def test_refuse_nonloopback_and_low_ports_before_connect(self):
        for address in (("0.0.0.0", 40000), ("192.0.2.1", 40000),
                        ("localhost", 40000), ("127.0.0.1", 22)):
            with self.subTest(address=address):
                local = mock.Mock(family=socket.AF_INET)
                local.getsockname.return_value = ("127.0.0.1", 30001)
                peer = mock.Mock(family=socket.AF_INET)
                peer.getsockname.return_value = address
                with self.assertRaises(ValueError):
                    diagnostic.connect_peer(local, peer, deadline(), diagnostic.Endpoint())
                local.connect_ex.assert_not_called()

    def test_connected_tuple_mismatch_rejected(self):
        local = mock.Mock(family=socket.AF_INET)
        local.getsockname.return_value = ("127.0.0.1", 30001)
        local.connect_ex.return_value = errno.EINPROGRESS
        local.getsockopt.return_value = 0
        local.getpeername.return_value = ("127.0.0.1", 30003)
        peer = mock.Mock(family=socket.AF_INET)
        peer.getsockname.return_value = ("127.0.0.1", 30002)
        with self.assertRaisesRegex(RuntimeError, "tuple mismatch"):
            diagnostic.connect_peer(local, peer, deadline(), diagnostic.Endpoint())

    def test_partial_io_and_early_eof(self):
        sender = mock.Mock()
        sender.send.side_effect = [1, 2]
        diagnostic._send_all(sender, b"abc", deadline())
        self.assertEqual(sender.send.call_count, 2)
        receiver = mock.Mock()
        receiver.recv.side_effect = [b"a", b"bc"]
        self.assertEqual(diagnostic._recv_exact(receiver, 3, deadline()), b"abc")
        receiver.recv.side_effect = [b"a", b""]
        with self.assertRaises(ConnectionError):
            diagnostic._recv_exact(receiver, 3, deadline())

    def test_payload_and_echo_mismatch(self):
        a, b = mock.Mock(), mock.Mock()
        with mock.patch.object(diagnostic, "_send_all"), \
                mock.patch.object(diagnostic, "_recv_exact", return_value=b"wrong"):
            with self.assertRaisesRegex(ValueError, "payload mismatch"):
                diagnostic.roundtrip(a, b, deadline())
        with mock.patch.object(diagnostic, "_send_all"), \
                mock.patch.object(diagnostic, "_recv_exact",
                                  side_effect=[diagnostic.PAYLOAD, b"wrong"]):
            with self.assertRaisesRegex(ValueError, "echo mismatch"):
                diagnostic.roundtrip(a, b, deadline())

    def test_cli_rejects_out_of_bounds_and_network_arguments(self):
        cases = (["--trials", "0"], ["--trials", "501"], ["--timeout", "nan"],
                 ["--budget", "inf"], ["--budget", "61"], ["--timeout", "0.0001"],
                 ["--family", "localhost"], ["--host", "example.com"], ["127.0.0.1"])
        for args in cases:
            with self.subTest(args=args), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    diagnostic.main(list(args))
                self.assertEqual(raised.exception.code, 2)

    def test_json_summary_and_exit_semantics(self):
        for verified in (False, True):
            captured = io.StringIO()
            result = diagnostic.Result("4", payload_roundtrip_verified=verified)
            with mock.patch.object(diagnostic, "run_trial", return_value=result), \
                    redirect_stdout(captured):
                status = diagnostic.main(["--family", "4", "--trials", "2"])
            records = [json.loads(line) for line in captured.getvalue().splitlines()]
            self.assertEqual(status, 0 if verified else 1)
            self.assertEqual(records[0]["kind"], "environment")
            self.assertFalse(records[0]["nat_traversal_proven"])
            self.assertFalse(records[0]["listener_used"])
            self.assertEqual(records[-1]["attempts"], 2)
            self.assertEqual(records[-1]["verified"], 2 if verified else 0)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux socket diagnostic")
class LocalSocketTests(unittest.TestCase):
    def test_numeric_loopback_bindings_distinct_and_noninheritable(self):
        for family in ("4", "6"):
            with self.subTest(family=family):
                try:
                    a = diagnostic.bound_socket(family)
                except OSError as exc:
                    if family == "6":
                        continue  # IPv6 absence remains visible in real trial output.
                    raise
                with a, diagnostic.bound_socket(family) as b:
                    self.assertEqual(a.getsockname()[0], "127.0.0.1" if family == "4" else "::1")
                    self.assertGreaterEqual(a.getsockname()[1], 1024)
                    self.assertNotEqual(a.getsockname(), b.getsockname())
                    self.assertFalse(a.getblocking())
                    self.assertFalse(a.get_inheritable())
                    self.assertEqual(a.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR), 0)
                    self.assertEqual(a.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT), 0)

    def test_bound_peer_that_never_connects_is_not_success(self):
        with diagnostic.bound_socket("4") as a, diagnostic.bound_socket("4") as b:
            report = diagnostic.Endpoint()
            with self.assertRaises((OSError, TimeoutError)):
                diagnostic.connect_peer(a, b, deadline(0.05), report)
            self.assertNotEqual(report.initial_connect_result, "not attempted")

    def test_roundtrip_local_socketpair(self):
        a, b = socket.socketpair()
        with a, b:
            diagnostic.roundtrip(a, b, deadline())

    def test_payload_stall_and_cancellation_bounded(self):
        for cancelled in (False, True):
            with self.subTest(cancelled=cancelled):
                a, unused_a = socket.socketpair()
                b, unused_b = socket.socketpair()
                cancel = threading.Event()
                if cancelled:
                    cancel.set()
                bounded = diagnostic.Deadline(time.monotonic() + 0.01, (cancel,))
                began = time.monotonic()
                with a, b, unused_a, unused_b:
                    with self.assertRaises((TimeoutError, diagnostic.DiagnosticCancelled)):
                        diagnostic.roundtrip(a, b, bounded)
                self.assertLess(time.monotonic() - began, 0.5)

    def test_second_bind_failure_closes_first_socket(self):
        a = diagnostic.bound_socket("4")
        with mock.patch.object(diagnostic, "bound_socket",
                               side_effect=[a, OSError(errno.EMFILE, "synthetic failure")]):
            result = diagnostic.run_trial("4")
        self.assertFalse(result.payload_roundtrip_verified)
        self.assertIn("synthetic failure", result.error)
        self.assertEqual(a.fileno(), -1)

    def test_repeat_trials_tuple_integrity_and_cleanup(self):
        baseline = len(os.listdir("/proc/self/fd"))
        threads = threading.active_count()
        for family in ("4", "6"):
            for _ in range(30):
                result = diagnostic.run_trial(family, 0.02)
                if result.payload_roundtrip_verified:
                    self.assertEqual(result.error, "")
                    self.assertEqual(result.a.error, "")
                    self.assertEqual(result.b.error, "")
                    self.assertEqual(result.a.local, result.b.remote)
                    self.assertEqual(result.b.local, result.a.remote)
                    self.assertNotEqual(result.a.local, result.b.local)
                else:
                    self.assertTrue(result.error)
        # Zero successes is a valid scheduler/kernel observation, not a test failure.
        self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)
        self.assertEqual(threading.active_count(), threads)

    def test_total_budget_cli_smoke(self):
        script = Path(__file__).with_name("tcp_simopen.py")
        began = time.monotonic()
        completed = subprocess.run(
            [sys.executable, str(script), "--trials", "500", "--timeout", "0.1",
             "--budget", "0.03"], capture_output=True, text=True, timeout=5,
        )
        self.assertIn(completed.returncode, (0, 1), completed.stderr)
        records = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual(records[-1]["kind"], "summary")
        self.assertTrue(records[-1]["budget_exhausted"])
        self.assertLess(records[-1]["attempts"], 1000)
        self.assertEqual(records[-1]["attempts"], len(records) - 2)
        self.assertLess(time.monotonic() - began, 2)


if __name__ == "__main__":
    unittest.main()
