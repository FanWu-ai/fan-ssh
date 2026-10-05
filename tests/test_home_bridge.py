"""Explicit two-leg bridge integration; all endpoints are synthetic loopback."""
import asyncio
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from fan_ssh.config import Policy
from fan_ssh.control import Control
from fan_ssh.device import save_identity, tls_context
from fan_ssh.home_bridge import HomeBridge, PeerService
from fan_ssh.remote import Client, Node
from fan_ssh.transport import BUFFER, Service, close_writer
from test_remote import fixture
from test_udp import NativeTestCase, UDPPath


class BridgeFixture:
    async def asyncSetUp(self):
        self.ids, self.data = fixture()
        # a cannot access b directly. The only permitted route is a -> c -> b.
        self.data['allow'] = [{'from': 'a', 'to': 'c', 'service': 'remote-ssh'},
                              {'from': 'c', 'to': 'b', 'service': 'ssh'}]
        self.cleanup = []
        self.accepted = 0
        self.received = []
        self.log = io.StringIO()
        self.connected = asyncio.Event()
        async def delayed_echo(reader, writer):
            self.accepted += 1
            self.connected.set()
            data = bytearray()
            while part := await reader.read(BUFFER):
                data.extend(part)
            self.received.append(bytes(data))
            await asyncio.sleep(0.02)
            writer.write(hashlib.sha256(data).digest() + data)
            await writer.drain()
            writer.write_eof()
            await writer.drain()
        self.target = await Service(delayed_echo).start()
        self.cleanup.append(self.target)
        initial = Policy.parse(self.data)
        self.control = await Control('control', self.ids['control'], initial).start('127.0.0.1:0')
        self.cleanup.append(self.control)
        self.data['coordinator']['address'] = self.control.service.address
        initial = Policy.parse(self.data)
        self.target_node = await Node('b', self.ids['b'], initial,
                                      {'ssh': self.target.address}, self.log).start('127.0.0.1:0', poll=False)
        self.cleanup.append(self.target_node)
        self.data['devices'][2]['candidates'] = [self.target_node.service.address]
        initial = Policy.parse(self.data)
        self.upstream = Client('c', self.ids['c'], initial)
        self.home = await HomeBridge('c', self.ids['c'], initial, 'remote-ssh', 'b', 'ssh',
                                     self.upstream, self.log).start('127.0.0.1:0', poll=False)
        self.cleanup.append(self.home)
        self.data['devices'][3]['candidates'] = [self.home.service.address]
        self.policy = Policy.parse(self.data)
        self.control.policy = self.target_node.policy = self.home.policy = self.upstream.policy = self.policy
        self.client = Client('a', self.ids['a'], self.policy)
        self.cleanup.append(self.client)

    async def asyncTearDown(self):
        for item in reversed(self.cleanup):
            await item.close()

    async def wait_settled(self):
        async def settled():
            while self.home.brokers or self.home.active or self.target_node.active:
                await asyncio.sleep(0.01)
        await asyncio.wait_for(settled(), 3)


class HomeBridgeTests(BridgeFixture, unittest.IsolatedAsyncioTestCase):
    async def test_two_independent_grants_binary_integrity_and_delayed_half_close(self):
        import fan_ssh.control as control
        operations = []
        original = control.request
        async def observe(identity, policy, message, **kwargs):
            operations.append((policy.caller(identity.pin), dict(message)))
            return await original(identity, policy, message, **kwargs)
        with patch('fan_ssh.remote.request', observe):
            pair, report = await self.client.dial('c', 'remote-ssh')
            payload = os.urandom(1024 * 1024)
            async def send():
                for offset in range(0, len(payload), BUFFER):
                    pair[1].write(payload[offset:offset + BUFFER])
                    await pair[1].drain()
                pair[1].write_eof()
                await pair[1].drain()
            sender = asyncio.create_task(send())
            try:
                async with asyncio.timeout(8):
                    output = bytearray()
                    while data := await pair[0].read():
                        output.extend(data)
                    await sender
                self.assertEqual(bytes(output), hashlib.sha256(payload).digest() + payload)
                self.assertEqual(self.received, [payload])
                self.assertEqual(report['code'], 'DIRECT_SERVICE_READY')  # Incoming leg only.
                self.assertIn('HOME_BRIDGE_UPSTREAM_READY', self.log.getvalue())
            finally:
                sender.cancel()
                await asyncio.gather(sender, return_exceptions=True)
                await close_writer(pair[1])
        grants = [(caller, op['target'], op['service']) for caller, op in operations if op['op'] == 'grant']
        self.assertEqual(grants, [('a', 'c', 'remote-ssh'), ('c', 'b', 'ssh')])
        self.assertTrue(all(op['op'] in ('grant', 'renew') for _, op in operations))
        self.assertEqual(self.accepted, 1)

    async def test_missing_either_directed_permission_never_opens_final_service(self):
        with self.assertRaisesRegex(ValueError, 'ACL_DENIED'):
            await self.client.dial('c', 'ssh')
        with self.assertRaisesRegex(ValueError, 'ACL_DENIED'):
            await self.client.dial('b', 'ssh')
        data = copy.deepcopy(self.data)
        data['allow'] = data['allow'][:1]
        with self.assertRaisesRegex(ValueError, 'BRIDGE_UPSTREAM_ACL_REQUIRED'):
            HomeBridge('c', self.ids['c'], Policy.parse(data), 'remote-ssh', 'b', 'ssh', self.upstream)
        self.assertEqual(self.accepted, 0)
        self.assertFalse(self.home.brokers)
        with self.assertRaisesRegex(ValueError, 'INVALID_ADDRESS'):
            Node('c', self.ids['c'], self.policy, {'ssh': PeerService('b', 'ssh')})

    async def test_wrong_final_peer_pin_fails_without_service_dial(self):
        self.target_node.service.context = tls_context(self.ids['a'], self.policy, server=True)
        pair, _ = await self.client.dial('c', 'remote-ssh')
        try:
            async with asyncio.timeout(3):
                try:
                    self.assertEqual(await pair[0].read(), b'')
                except asyncio.IncompleteReadError:
                    pass
            self.assertEqual(self.accepted, 0)
            self.assertNotIn('HOME_BRIDGE_UPSTREAM_READY', self.log.getvalue())
        finally:
            await close_writer(pair[1])

    async def test_policy_change_closes_live_two_leg_stream_and_requires_restart(self):
        pair, _ = await self.client.dial('c', 'remote-ssh')
        await asyncio.wait_for(self.connected.wait(), 3)
        data = copy.deepcopy(self.data)
        data['revision'] = 2
        data['allow'] = []
        self.home.update(Policy.parse(data))
        try:
            async with asyncio.timeout(3):
                try:
                    self.assertEqual(await pair[0].read(), b'')
                except asyncio.IncompleteReadError:
                    pass
            with self.assertRaisesRegex(ValueError, 'BRIDGE_POLICY_CHANGED_RESTART_REQUIRED'):
                await self.home.open_service('remote-ssh')
        finally:
            await close_writer(pair[1])
        await self.wait_settled()
        self.assertFalse(self.home.brokers)
        self.assertFalse(self.target_node.active)

    async def test_caller_disconnect_cancels_pending_upstream_and_closes_owned_client(self):
        started, cancelled = asyncio.Event(), asyncio.Event()
        async def pending(*args):
            started.set()
            try:
                await asyncio.Future()
            finally:
                cancelled.set()
        with patch.object(self.upstream, 'dial', pending), patch.object(self.upstream, 'close', wraps=self.upstream.close) as closed:
            pair, _ = await self.client.dial('c', 'remote-ssh')
            await asyncio.wait_for(started.wait(), 3)
            await close_writer(pair[1])
            await asyncio.wait_for(cancelled.wait(), 3)
            await self.home.close()
            self.assertEqual(closed.await_count, 1)
        self.assertFalse(self.home.brokers)
        self.assertEqual(self.accepted, 0)

    async def test_unstarted_broker_cancellation_closes_anonymous_socket(self):
        with patch.object(self.upstream, 'dial', wraps=self.upstream.dial) as dial:
            pair = await self.home.open_service('remote-ssh')
            broker = next(iter(self.home.brokers))
            broker.cancel()  # No event-loop yield after creating the broker.
            await asyncio.gather(broker, return_exceptions=True)
            try:
                self.assertEqual(await asyncio.wait_for(pair[0].read(1), 1), b'')
                self.assertEqual(dial.await_count, 0)
                self.assertFalse(self.home.brokers)
            finally:
                await close_writer(pair[1])

    async def test_final_node_revocation_closes_incoming_bridge_stream(self):
        pair, _ = await self.client.dial('c', 'remote-ssh')
        await asyncio.wait_for(self.connected.wait(), 3)
        data = copy.deepcopy(self.data)
        data['revision'] = 2
        data['allow'] = data['allow'][:1]
        self.target_node.update(Policy.parse(data))
        try:
            async with asyncio.timeout(3):
                try:
                    self.assertEqual(await pair[0].read(), b'')
                except asyncio.IncompleteReadError:
                    pass
        finally:
            await close_writer(pair[1])
        await self.wait_settled()
        self.assertFalse(self.home.brokers)
        self.assertFalse(self.home.active)

    async def test_upstream_relay_report_is_rejected_before_forwarding_payload(self):
        original = self.upstream.dial
        async def relayed(*args):
            pair, report = await original(*args)
            return pair, dict(report, relay=True)
        with patch.object(self.upstream, 'dial', relayed):
            pair, _ = await self.client.dial('c', 'remote-ssh')
            pair[1].write(b'ssh-credentials-must-not-reach-final-service')
            await pair[1].drain()
            try:
                async with asyncio.timeout(3):
                    try:
                        self.assertEqual(await pair[0].read(), b'')
                    except asyncio.IncompleteReadError:
                        pass
            finally:
                await close_writer(pair[1])
            await self.wait_settled()
        self.assertTrue(all(value == b'' for value in self.received))
        self.assertNotIn('HOME_BRIDGE_UPSTREAM_READY', self.log.getvalue())

    async def test_foreground_cli_fixed_target_and_binary_clean_stdout(self):
        endpoint = self.home.service.address
        await self.home.close()
        with tempfile.TemporaryDirectory(prefix='fan-home-bridge-test-') as temp:
            root = Path(temp)
            save_identity('c', self.ids['c'], root / 'identity')
            policy = root / 'policy.json'
            policy.write_text(json.dumps(self.data), encoding='utf8')
            with (root / 'stderr.log').open('wb') as log:
                process = subprocess.Popen([sys.executable, '-m', 'fan_ssh', 'home-bridge',
                                            '--identity', str(root / 'identity'), '--policy', str(policy),
                                            '--listen', endpoint, '--bridge-service', 'remote-ssh',
                                            '--peer', 'b', '--transport', 'auto', '--no-reverse'],
                                           stdout=subprocess.PIPE, stderr=log)
                try:
                    async with asyncio.timeout(12):
                        while b'HOME-BRIDGE listening=' not in (root / 'stderr.log').read_bytes():
                            self.assertIsNone(process.poll(), (root / 'stderr.log').read_bytes())
                            await asyncio.sleep(0.05)
                    pair, _ = await self.client.dial('c', 'remote-ssh')
                    payload = bytes(range(256)) * 32
                    try:
                        pair[1].write(payload)
                        pair[1].write_eof()
                        await pair[1].drain()
                        async with asyncio.timeout(5):
                            received = bytearray()
                            while part := await pair[0].read():
                                received.extend(part)
                        self.assertEqual(bytes(received), hashlib.sha256(payload).digest() + payload)
                    finally:
                        await close_writer(pair[1])
                finally:
                    if process.poll() is None:
                        process.terminate()
                    try:
                        await asyncio.to_thread(process.wait, timeout=4)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        await asyncio.to_thread(process.wait, timeout=3)
                    output = process.stdout.read()
                    process.stdout.close()
                self.assertEqual(output, b'')
                self.assertIn(b'HOME_BRIDGE_UPSTREAM_READY', (root / 'stderr.log').read_bytes())


@unittest.skipIf(UDPPath is None, 'install fan-ssh[udp] to exercise optional UDP bridge legs')
class HomeBridgeUDPTests(BridgeFixture, NativeTestCase):
    async def roundtrip(self, udp_incoming):
        from fan_ssh.control import request
        from fan_ssh.stun import Observer
        from fan_ssh.transport import format_address
        from fan_ssh.udp_remote import UDPClient, UDPNode
        observer = Observer(self.control)
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: observer, local_addr=('127.0.0.1', 0))
        self.cleanup.insert(0, observer)
        stun = format_address(transport.get_extra_info('sockname'))
        self.target_node.udp = UDPNode(self.target_node, '127.0.0.1', stun)
        self.target_node.poll_task = asyncio.create_task(self.target_node.poll())
        await request(self.ids['b'], self.policy, {'op': 'next'})
        await self.upstream.close()
        self.upstream = UDPClient('c', self.ids['c'], self.policy, '127.0.0.1', stun,
                                  context=tls_context(self.ids['c'], self.policy))
        self.home.client = self.upstream
        client = self.client
        if udp_incoming:
            self.home.udp = UDPNode(self.home, '127.0.0.1', stun)
            self.home.poll_task = asyncio.create_task(self.home.poll())
            await request(self.ids['c'], self.policy, {'op': 'next'})
            client = UDPClient('a', self.ids['a'], self.policy, '127.0.0.1', stun,
                               context=tls_context(self.ids['a'], self.policy))
            self.cleanup.append(client)
        pair, report = await client.dial('c', 'remote-ssh')
        payload = os.urandom(128 * 1024)
        async def send():
            for offset in range(0, len(payload), BUFFER):
                pair[1].write(payload[offset:offset + BUFFER])
                await pair[1].drain()
            pair[1].write_eof()
            await pair[1].drain()
        sender = asyncio.create_task(send())
        try:
            async with asyncio.timeout(15):
                received = bytearray()
                while part := await pair[0].read():
                    received.extend(part)
                await sender
            self.assertEqual(bytes(received), hashlib.sha256(payload).digest() + payload)
            event = next(json.loads(line) for line in self.log.getvalue().splitlines()
                         if line.startswith('{') and 'HOME_BRIDGE_UPSTREAM_READY' in line)
            self.assertEqual(event['upstream_direct']['code'], 'AUTHENTICATED_NATIVE_UDP')
            self.assertTrue(event['upstream_direct']['service_ready'])
            self.assertFalse(event['upstream_direct']['relay'])
            self.assertFalse(report['relay'])
            self.assertEqual(self.accepted, 1)
        finally:
            sender.cancel()
            await asyncio.gather(sender, return_exceptions=True)
            await close_writer(pair[1])

    async def test_tcp_incoming_udp_outgoing_binary_and_half_close(self):
        await self.roundtrip(False)

    async def test_two_udp_legs_binary_and_half_close(self):
        await self.roundtrip(True)


if __name__ == '__main__':
    unittest.main()
