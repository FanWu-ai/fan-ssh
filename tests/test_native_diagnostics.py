"""Bounded observation and actual Linux socket-adapter regression tests."""
import asyncio
import io
import struct
import sys
from types import SimpleNamespace
import unittest

from fan_ssh.config import Policy, direct_address
from fan_ssh.control import Control
from fan_ssh.stun import Observer
from fan_ssh.tcp_probe import Binding
from fan_ssh.transport import Service, close_writer
from test_remote import fixture


class ObserverTests(unittest.TestCase):
    def test_only_approved_small_binding_requests_and_rate_limit(self):
        replies = []
        observer = Observer(SimpleNamespace(observed_ips={'a': '192.0.2.1'}))
        observer.connection_made(SimpleNamespace(sendto=lambda data, remote: replies.append((data, remote))))
        packet = struct.pack('!HHI', 1, 0, 0x2112A442) + bytes(range(12))
        observer.datagram_received(packet, ('192.0.2.2', 23456))
        observer.datagram_received(packet + b'x', ('192.0.2.1', 23456))
        observer.datagram_received(b'x' * 257, ('192.0.2.1', 23456))
        observer.datagram_received(struct.pack('!H', 3) + packet[2:], ('192.0.2.1', 23456))  # No TURN allocation.
        self.assertEqual(replies, [])
        for _ in range(61):
            observer.datagram_received(packet, ('192.0.2.1', 23456))
        self.assertEqual(len(replies), 60)
        response, remote = replies[0]
        self.assertEqual(len(response), 32)
        self.assertEqual(response[8:20], packet[8:20])
        self.assertEqual(struct.unpack('!H', response[26:28])[0] ^ 0x2112, remote[1])
        # Roaming approved devices must not accumulate unbounded old-IP buckets.
        for index in range(2, 72):
            ip = '192.0.2.%d' % index
            observer.control.observed_ips['a'] = ip
            observer.datagram_received(packet, (ip, 23456))
        self.assertEqual(len(observer.rates), 1)


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux source-bound TCP adapter; run on Linux hosts')
class LinuxBindingTests(unittest.IsolatedAsyncioTestCase):
    async def test_same_source_port_two_authenticated_observers_and_prebound_listener(self):
        identities, data = fixture()
        control = Control('control', identities['control'], Policy.parse(data))
        second = Service(control.handle, control.service.context, validator=direct_address)
        binding = Binding('127.0.0.1', passive=True)
        writer = None
        try:
            await control.start('127.0.0.1:0')
            await second.start('127.0.0.1:0')
            data['coordinator']['address'] = control.service.address
            policy = Policy.parse(data)
            control.policy = policy
            result = await binding.observe(identities['a'], policy, second.address)
            self.assertEqual(result['observed'], result['local'])
            self.assertEqual(result['secondary_observed'], result['local'])
            self.assertFalse(result['mapping_changed_by_observer_port'])
            accept = asyncio.create_task(binding.accept())
            reader, writer = await asyncio.open_connection(*binding.local[:2])
            accepted = await accept
            try:
                self.assertEqual(accepted.getsockname()[:2], binding.local[:2])
            finally:
                accepted.close()
        finally:
            if writer:
                await close_writer(writer)
            await binding.close()
            await second.close()
            await control.close()

    async def test_cancelled_observation_closes_prebound_resources(self):
        binding = Binding('127.0.0.1', passive=True)
        sockets = [binding.observer, binding.secondary, binding.peer, binding.listener]
        await binding.close()
        self.assertTrue(all(sock.fileno() == -1 for sock in sockets))
