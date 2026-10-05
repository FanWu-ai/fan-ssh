"""Real subprocess tests: no real SSH server, login, or external probes."""
import os
import signal
import socket
import subprocess
import sys
import threading
import unittest


class CLITests(unittest.TestCase):
    def test_demo(self):
        result = subprocess.run([sys.executable, '-m', 'fan_ssh', 'demo'], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.startswith(b'PASS:'))
        self.assertIn(b'DEV ONLY', result.stderr)

    def test_invalid_target_stdout_empty(self):
        result = subprocess.run([sys.executable, '-m', 'fan_ssh', 'proxy', '--target', '192.0.2.1:22'], capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            listener.setblocking(False)
            target = '%s:%s' % listener.getsockname()
            for options in (['--transport', 'udp'], ['--identity', 'unapproved'], ['--service', 'other']):
                with self.subTest(options=options):
                    result = subprocess.run([sys.executable, '-m', 'fan_ssh', 'proxy', '--target', target, *options],
                                            capture_output=True, timeout=5)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b'')
                    self.assertIn(b'require --peer', result.stderr)
                    with self.assertRaises(BlockingIOError):
                        listener.accept()  # No silent UDP-to-TCP fixture fallback/local service dial.

    def target(self, flood=False):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(5)
        self.addCleanup(listener.close)
        target = '%s:%s' % listener.getsockname()
        ready = threading.Event()
        def worker():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(5)
                    ready.set()
                    if flood:
                        while True:
                            connection.sendall(b'x' * 16384)
                    else:
                        data = bytearray()
                        while part := connection.recv(16384):
                            data.extend(part)
                        connection.sendall(b'reply:' + data)
            except OSError:
                pass
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        self.addCleanup(lambda: thread.join(timeout=6))
        return target, ready

    def test_proxy_clean_binary_and_half_close(self):
        target, _ = self.target()
        payload = bytes(range(256)) * 32
        result = subprocess.run([sys.executable, '-m', 'fan_ssh', 'proxy', '--target', target], input=payload,
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'reply:' + payload)
        self.assertIn(b'DEV ONLY', result.stderr)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'POSIX signal/pipe runtime regression')
    def test_proxy_blocked_stdout_cancellation(self):
        target, ready = self.target(flood=True)
        process = subprocess.Popen([sys.executable, '-m', 'fan_ssh', 'proxy', '--target', target],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertTrue(ready.wait(5))
            # Target traffic fills the unread stdout pipe; stdin also stays open.
            threading.Event().wait(0.3)
            process.send_signal(signal.SIGTERM)
            self.assertEqual(process.wait(timeout=3), 130)
            self.assertNotIn(b'Fatal Python error', process.stderr.read())
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdin.close()
            process.stdout.close()
            process.stderr.close()


if __name__ == '__main__':
    unittest.main()
