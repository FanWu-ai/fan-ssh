"""Real Linux socket controls for the separate native dual-listener diagnostic."""
import asyncio
import hmac
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import unittest

spec = importlib.util.spec_from_file_location(
    'native_tcp_control', Path(__file__).resolve().parents[2] / 'scripts/native_tcp_ttl_probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


@unittest.skipUnless(sys.platform.startswith('linux'), 'requires real Linux SO_REUSEPORT')
class ReuseChannelControls(unittest.IsolatedAsyncioTestCase):
    async def test_observer_stdin_eof_closes_held_authenticated_client_promptly(self):
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            port = reserved.getsockname()[1]
        process = await asyncio.create_subprocess_exec(
            sys.executable, str(Path(probe.__file__)), '--cloud',
            '--native', '127.0.0.1', '--port', str(port),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        writer = None
        try:
            secret = os.urandom(32)
            process.stdin.write(probe.encoded({'secret': secret.hex(), 'approved': ['127.0.0.1']}) + b'\n')
            await process.stdin.drain()
            async with asyncio.timeout(3):
                self.assertEqual(await process.stdout.readline(), b'TCP_OBSERVER_READY\n')
                reader, writer = await asyncio.open_connection('127.0.0.1', port)
                request = {'role': 0, 'nonce': os.urandom(16).hex()}
                request['mac'] = hmac.digest(secret, probe.encoded(request), 'sha256').hex()
                writer.write(probe.encoded(request) + b'\n'); await writer.drain()
                response = json.loads(await reader.readline())
                mac = response.pop('mac')
                self.assertEqual(mac, hmac.digest(secret, probe.encoded(response), 'sha256').hex())
                self.assertEqual(response['nonce'], request['nonce'])
            # Keep the observed connection open while the controller disappears.
            process.stdin.close()
            await process.stdin.wait_closed()
            async with asyncio.timeout(3):
                self.assertEqual(await process.wait(), 0)
                self.assertEqual(await reader.read(1), b'')
                self.assertEqual(await process.stdout.read(), b'TCP_OBSERVATIONS 1\n')
                self.assertEqual(await process.stderr.read(), b'')
            with socket.socket() as released:
                released.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                released.bind(('127.0.0.1', port)); released.listen(1)
        finally:
            if writer:
                writer.close()
                await writer.wait_closed()
            if process.returncode is None:
                process.terminate()
                await process.wait()

    def bindings(self):
        sockets = []
        for ip in ('127.0.0.2', '127.0.0.3'):
            listener = socket.socket()
            sockets.append(listener)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            listener.setblocking(False)
            listener.bind((ip, 0)); listener.listen(4)
            active = socket.socket()
            sockets.append(active)
            active.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            active.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            active.setblocking(False); active.bind(listener.getsockname())
        return sockets

    async def test_both_listeners_select_same_authenticated_stream_and_halfclose(self):
        sockets = self.bindings()
        reports = [{}, {}]
        writers = []
        try:
            a, active_a, b, active_b = sockets
            hello_a, hello_b = os.urandom(32), os.urandom(32)
            async with asyncio.timeout(3):
                left, right = await asyncio.gather(
                    probe.reuse_channel(active_a, a, b.getsockname(), hello_a, hello_b, 0, reports[0]),
                    probe.reuse_channel(active_b, b, a.getsockname(), hello_b, hello_a, 1, reports[1]))
                readers = [left[0], right[0]]
                writers = [left[1], right[1]]
                self.assertEqual(writers[0].get_extra_info('peername'),
                                 writers[1].get_extra_info('sockname'))
                payload = os.urandom(65536)
                writers[0].write(payload); await writers[0].drain(); writers[0].write_eof()
                self.assertEqual(await readers[1].readexactly(len(payload)), payload)
                self.assertEqual(await readers[1].read(1), b'')
                writers[1].write(payload); await writers[1].drain(); writers[1].write_eof()
                self.assertEqual(await readers[0].readexactly(len(payload)), payload)
                self.assertEqual(await readers[0].read(1), b'')
            self.assertTrue(all(r['authenticated_candidates'] >= 1 for r in reports))
        finally:
            for writer in writers:
                writer.close(); await writer.wait_closed()
            for sock in sockets:
                sock.close()

    async def test_wrong_mac_cannot_select_a_connected_stream(self):
        baseline = len(os.listdir('/proc/self/fd'))
        sockets = self.bindings()
        reports = [{}, {}]
        try:
            a, active_a, b, active_b = sockets
            async def rejected(coro):
                with self.assertRaises(TimeoutError):
                    async with asyncio.timeout(0.2):
                        await coro
            await asyncio.gather(
                rejected(probe.reuse_channel(active_a, a, b.getsockname(), b'a'*32, b'wrong'.ljust(32), 0, reports[0])),
                rejected(probe.reuse_channel(active_b, b, a.getsockname(), b'b'*32, b'wrong'.ljust(32), 1, reports[1])))
            self.assertTrue(all(r['authenticated_candidates'] == 0 for r in reports))
            self.assertTrue(all('ValueError' in r['candidate_errors'] for r in reports))
        finally:
            for sock in sockets:
                sock.close()
        await asyncio.sleep(0)
        self.assertEqual(len(os.listdir('/proc/self/fd')), baseline)

    async def test_cancel_pending_accept_and_active_connect_leaves_no_descriptors(self):
        baseline = len(os.listdir('/proc/self/fd'))
        sockets = self.bindings()
        try:
            a, active_a, b, _ = sockets
            with self.assertRaises(TimeoutError):
                async with asyncio.timeout(0.1):
                    await probe.reuse_channel(active_a, a, b.getsockname(), b'a'*32, b'b'*32, 0, {})
        finally:
            for sock in sockets:
                sock.close()
        await asyncio.sleep(0)
        self.assertEqual(len(os.listdir('/proc/self/fd')), baseline)


if __name__ == '__main__':
    unittest.main()
