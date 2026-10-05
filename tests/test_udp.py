"""Run explicitly with the pinned udp extra; all ICE endpoints are loopback."""
import asyncio
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from fan_ssh.config import Policy
from test_remote import fixture
from fan_ssh.stun import Observer
from fan_ssh.transport import format_address
from fan_ssh.transport import BUFFER, Service, close_writer
from fan_ssh.control import Control, request
from fan_ssh.remote import Node
import io
import os
import socket

try:
    from fan_ssh.udp_path import UDPPath
except ImportError:
    UDPPath = None


class NativeTestCase(unittest.IsolatedAsyncioTestCase):
    def _setupAsyncioRunner(self):
        # Exercise the same socket-only event loop selected by the UDP CLI.
        factory = asyncio.SelectorEventLoop if os.name == 'nt' else None
        # Windows debug instrumentation is a separately retained stress mode;
        # ordinary runs exercise the exact production event-loop configuration.
        debug = os.name != 'nt' or os.environ.get('FAN_SSH_UDP_DEBUG_TESTS') == '1'
        self._asyncioRunner = asyncio.Runner(debug=debug, loop_factory=factory)


@unittest.skipIf(UDPPath is None, 'install fan-ssh[udp] to exercise the optional UDP transport')
class UDPCapacityTests(NativeTestCase):
    async def test_pending_network_requests_share_cap_and_close_rejects_them(self):
        from fan_ssh.udp_remote import UDPPeer
        identities, data = fixture()
        peer = UDPPeer('a', identities['a'], Policy.parse(data), '127.0.0.1', '127.0.0.1:22092', context=None)
        gate, started = asyncio.Event(), asyncio.Event()
        requests = 0
        async def scope(*args, **kwargs):
            nonlocal requests
            requests += 1
            if requests == 32:
                started.set()
            await gate.wait()
            return {'ip': '127.0.0.1'}
        with patch('fan_ssh.udp_remote.request', scope):
            tasks = [asyncio.create_task(peer.path('b', True)) for _ in range(32)]
            try:
                await asyncio.wait_for(started.wait(), 2)
                with self.assertRaisesRegex(ValueError, 'UDP_SESSION_CAPACITY'):
                    await peer.path('b', True)
                await peer.close()
                gate.set()
                outcomes = await asyncio.gather(*tasks, return_exceptions=True)
                self.assertTrue(all(isinstance(outcome, ValueError) and str(outcome) == 'UDP_PEER_CLOSED'
                                    for outcome in outcomes))
                self.assertEqual(requests, 32)
                self.assertEqual(peer.pending, 0)
                self.assertEqual(peer.paths, set())
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                await peer.close()


@unittest.skipIf(UDPPath is None, 'install fan-ssh[udp] to exercise the optional UDP transport')
class UDPTests(NativeTestCase):
    async def asyncSetUp(self):
        identities, data = fixture()
        self.policy = Policy.parse(data)
        self.observer = Observer(SimpleNamespace(observed_ips={'a': '127.0.0.1'}))
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: self.observer, local_addr=('127.0.0.1', 0))
        stun = format_address(transport.get_extra_info('sockname'))
        self.a = UDPPath('a', identities['a'], self.policy, 'b', '127.0.0.1', stun, controlling=True, peer_observed_ip='127.0.0.1')
        self.b = UDPPath('b', identities['b'], self.policy, 'a', '127.0.0.1', stun, controlling=False, peer_observed_ip='127.0.0.1')

    async def asyncTearDown(self):
        await asyncio.gather(self.a.close(), self.b.close())
        await self.observer.close()

    async def test_disconnected_sctp_sender_closes_owned_stream_instead_of_background_exception(self):
        from aiortc.rtcsctptransport import AbortChunk
        self.a.sctp._remote_port = 5000
        self.a.sctp._remote_verification_tag = 1
        await self.a.sctp._send_chunk(AbortChunk())  # DTLS was never connected.
        self.assertTrue(self.a.sctp.send_failed)
        self.assertTrue(self.a.stream.closed.is_set())
        self.assertEqual(await self.a.stream.read(1), b'')
        with self.assertRaises(ConnectionError):
            self.a.stream.write(b'no data after failure')

    async def test_expected_sctp_shutdown_does_not_report_active_send_failure(self):
        from aiortc.rtcsctptransport import AbortChunk
        self.a.sctp._remote_port = 5000
        self.a.sctp._remote_verification_tag = 1
        self.a.sctp.stopping = True
        await self.a.sctp._send_chunk(AbortChunk())
        self.assertFalse(self.a.sctp.send_failed)

    async def test_native_dtls_credit_flow_binary_stream(self):
        a, b = await asyncio.gather(self.a.gather(), self.b.gather())
        pa, pb = await asyncio.gather(self.a.connect(b), self.b.connect(a))
        payload = bytes(range(256)) * 4096
        async def send():
            for offset in range(0, len(payload), 16384):
                pa[1].write(payload[offset:offset + 16384])
                await pa[1].drain()
        task = asyncio.create_task(send())
        output = bytearray()
        while len(output) < len(payload):
            output.extend(await asyncio.wait_for(pb[0].read(), 5))
        await task
        self.assertEqual(bytes(output), payload)
        self.assertFalse(self.a.report['relay'])
        self.assertEqual(self.a.report['selected']['local'].split(':')[0], '127.0.0.1')

    async def test_relay_candidate_rejected_before_connectivity_checks(self):
        a, b = await asyncio.gather(self.a.gather(), self.b.gather())
        b['candidates'][0]['type'] = 'relay'
        with self.assertRaisesRegex(ValueError, 'RELAY'):
            await self.a.connect(b)

    async def test_unapproved_candidate_rejected(self):
        a, b = await asyncio.gather(self.a.gather(), self.b.gather())
        b['candidates'][0]['ip'] = '192.0.2.123'
        with self.assertRaisesRegex(ValueError, 'UNAPPROVED_UDP_CANDIDATE'):
            await self.a.connect(b)

    async def test_wrong_dtls_pin_rejected(self):
        a, b = await asyncio.gather(self.a.gather(), self.b.gather())
        self.a.peer_pin = self.policy.devices['c'].pin
        outcomes = await asyncio.gather(self.a.connect(b), self.b.connect(a), return_exceptions=True)
        self.assertTrue(any(isinstance(value, ValueError) and 'UDP_PEER_AUTH_FAILED' in str(value) for value in outcomes))

    async def test_alternate_observer_uses_same_native_socket_when_primary_does_not_reply(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as blackhole:
            blackhole.bind(('127.0.0.1', 0))
            alternate = self.a.gatherer._connection.stun_server
            self.a.gatherer._connection.stun_server = blackhole.getsockname()
            self.a.gatherer._connection.alternate = alternate
            result = await self.a.gather()
            host = next(c for c in result['candidates'] if c['type'] == 'host')
            mapped = next(c for c in result['candidates'] if c['type'] == 'srflx')
            self.assertEqual((host['ip'], host['port']), (mapped['ip'], mapped['port']))

    async def test_port_prediction_limits_irregular_and_changed_ip_observations(self):
        from fan_ssh.udp_traversal import predicted_endpoints
        def candidate(ip, port):
            return {'ip': ip, 'port': port, 'type': 'srflx'}
        ports = predicted_endpoints([candidate('192.0.2.1', 5000), candidate('192.0.2.1', 5003)])
        self.assertEqual(len(ports), 17)
        self.assertIn(('192.0.2.1', 5004), ports)
        self.assertEqual(len(predicted_endpoints([candidate('192.0.2.1', 5000), candidate('192.0.2.1', 20000)])), 2)
        self.assertEqual(len(predicted_endpoints([candidate('192.0.2.1', 5000), candidate('192.0.2.2', 5003)])), 2)
        self.assertTrue(all(port >= 1024 for _, port in predicted_endpoints([candidate('192.0.2.1', 1024)])))


@unittest.skipIf(UDPPath is None, 'install fan-ssh[udp] to exercise the optional UDP transport')
class UDPSignalingTests(NativeTestCase):
    async def asyncSetUp(self):
        from fan_ssh.udp_remote import UDPClient, UDPNode
        from fan_ssh.device import tls_context
        self.ids, self.data = fixture()
        initial = Policy.parse(self.data)
        self.control = await Control('control', self.ids['control'], initial).start('127.0.0.1:0')
        self.data['coordinator']['address'] = self.control.service.address
        self.policy = Policy.parse(self.data)
        self.control.policy = self.policy
        self.observer = Observer(self.control)
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: self.observer, local_addr=('127.0.0.1', 0))
        stun = format_address(transport.get_extra_info('sockname'))
        self.accepted = 0
        async def echo(reader, writer):
            self.accepted += 1
            while part := await reader.read(BUFFER):
                writer.write(part)
                await writer.drain()
            writer.write_eof()
            await writer.drain()
        self.echo = await Service(echo).start()
        self.node = Node('b', self.ids['b'], self.policy, {'ssh': self.echo.address}, io.StringIO())
        self.node.udp = UDPNode(self.node, '127.0.0.1', stun)
        await self.node.start('127.0.0.1:0')
        await request(self.ids['b'], self.policy, {'op': 'next'})
        self.client = UDPClient('a', self.ids['a'], self.policy, '127.0.0.1', stun,
                                context=tls_context(self.ids['a'], self.policy))

    async def asyncTearDown(self):
        await self.client.close()
        await self.node.close()
        await self.echo.close()
        await self.observer.close()
        await self.control.close()

    async def test_signaled_direct_binary_half_close(self):
        pair, report = await self.client.dial('b')
        payload = os.urandom(1024 * 1024)
        async def send():
            for offset in range(0, len(payload), BUFFER):
                pair[1].write(payload[offset:offset + BUFFER])
                await pair[1].drain()
            pair[1].write_eof()
            await pair[1].drain()
        sender = asyncio.create_task(send())
        output = bytearray()
        try:
            try:
                async with asyncio.timeout(120):
                    while part := await pair[0].read():
                        output.extend(part)
                    await sender
            except TimeoutError:
                self.fail('stream stalled: bytes=%d sender_done=%s source=%s targets=%s' % (
                    len(output), sender.done(), [(p.stream.credits, len(p.stream.pending), p.stream.incoming.qsize(), p.channel.bufferedAmount) for p in self.client.paths],
                    [(p.stream.credits, len(p.stream.pending), p.stream.incoming.qsize(), p.channel.bufferedAmount) for p in self.node.udp.paths]))
            self.assertEqual(bytes(output), payload)
            self.assertEqual(self.accepted, 1)
            self.assertEqual(report['code'], 'AUTHENTICATED_NATIVE_UDP')
        finally:
            sender.cancel()
            await asyncio.gather(sender, return_exceptions=True)
            await close_writer(pair[1])

    async def test_acl_denied_before_udp_path_or_service(self):
        with self.assertRaisesRegex(ValueError, 'ACL_DENIED'):
            await self.client.dial('c')
        self.assertEqual(self.accepted, 0)
        self.assertEqual(len(self.client.paths), 0)

    async def test_automatic_tcp_failure_then_pinned_prediction_stream(self):
        from fan_ssh.strategies import AutomaticClient
        from fan_ssh.remote import Client
        # The approved TCP candidates are unused ports; UDP remains reachable.
        self.client.strategy = 'predict'
        tcp = Client('a', self.ids['a'], self.policy)
        automatic = AutomaticClient([('tcp', tcp, 'dial', 12), ('udp-predict', self.client, 'dial', 28)])
        pair = None
        try:
            pair, report = await automatic.dial('b')
            self.assertEqual(report['method'], 'udp-predict')
            self.assertEqual(report['method_attempts'][0]['code'], 'NO_DIRECT_PATH')
            self.assertTrue(report['service_ready'])
            self.assertFalse(report['relay'])
            path = next(iter(self.client.paths))
            sock = path.gatherer._connection._protocols[0].transport.get_extra_info('socket')
            self.assertGreater(sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL), 7)
            payload = os.urandom(65536)
            async def send():
                for offset in range(0, len(payload), BUFFER):
                    pair[1].write(payload[offset:offset+BUFFER])
                    await pair[1].drain()
                pair[1].write_eof()
                await pair[1].drain()
            sender = asyncio.create_task(send())
            output = bytearray()
            async with asyncio.timeout(15):
                while part := await pair[0].read():
                    output.extend(part)
                await sender
            self.assertEqual(bytes(output), payload)
            self.assertEqual(self.accepted, 1)
        finally:
            if pair:
                await close_writer(pair[1])
            await automatic.close()

    async def test_control_loss_closes_native_session(self):
        from fan_ssh import grants
        from unittest.mock import patch
        with patch.object(grants, 'LIFETIME', 4):
            pair, _ = await self.client.dial('b')
            await self.control.close()
            with self.assertRaises((asyncio.IncompleteReadError, ConnectionError)):
                await asyncio.wait_for(pair[0].read(), 5)
            await close_writer(pair[1])
