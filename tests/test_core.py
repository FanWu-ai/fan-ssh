import asyncio
import ssl
import struct
import unittest
from unittest.mock import patch

from fan_ssh.identity import DemoPKI, require_pin
from fan_ssh.session import Coordinator, Peer, Session, connect_peer, discover, read_metadata, write_metadata
from fan_ssh.transport import (BUFFER, FramedReader, Service, address, bridge,
                               close_writer, connect, framed)


class AddressTests(unittest.TestCase):
    def test_loopback(self):
        self.assertEqual(address('127.0.0.1:22'), ('127.0.0.1', 22))
        self.assertEqual(address('[::1]:22'), ('::1', 22))
        self.assertEqual(address('127.0.0.1:0', bind=True)[1], 0)

    def test_reject_unsafe(self):
        for value in ['localhost:22', '0.0.0.0:22', '192.0.2.1:22', '[::]:22', '127.0.0.1:0',
                      '127.0.0.1:022', '127.0.0.1:+22', '127.0.0.1:65536', '127.0.0.1:ssh',
                      '::1:22', '[::1%lo]:22', '127.0.0.1:２２']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                address(value)


class AsyncTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.services = []

    async def asyncTearDown(self):
        for service in reversed(self.services):
            await service.close()

    async def service(self, handler, context=None, endpoint='127.0.0.1:0', limit=32):
        service = await Service(handler, context, limit).start(endpoint)
        self.services.append(service)
        return service

    async def echo(self, reader, writer):
        while data := await reader.read(BUFFER):
            writer.write(data)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
            await writer.drain()

    async def round_trip(self, session, payload):
        reader, writer = await session.dial()
        try:
            writer.write(payload)
            writer.write_eof()
            await writer.drain()
            got = bytearray()
            while data := await reader.read():
                got.extend(data)
            self.assertEqual(got, payload)
        finally:
            await close_writer(writer)

    async def test_binary_echo_and_concurrency(self):
        target = await self.service(self.echo)
        async with Session(target.address) as session:
            await asyncio.wait_for(asyncio.gather(*(self.round_trip(session, bytes(range(256)) * 128) for _ in range(8))), 5)

    async def test_half_close_delayed_response(self):
        async def reply(reader, writer):
            request = await reader.read()
            await asyncio.sleep(0.02)
            writer.write(b'response:' + request)
            await writer.drain()
        target = await self.service(reply)
        async with Session(target.address) as session:
            reader, writer = await session.dial()
            writer.write(b'complete request')
            writer.write_eof()
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.read(), 2), b'response:complete request')
            self.assertEqual(await reader.read(), b'')
            await close_writer(writer)

    async def test_local_forward(self):
        target = await self.service(self.echo)
        async with Session(target.address) as session:
            forward = await session.forward('127.0.0.1:0')
            reader, writer = await connect(forward.address)
            writer.write(b'forwarded')
            writer.write_eof()
            await writer.drain()
            self.assertEqual(await reader.read(), b'forwarded')
            await close_writer(writer)

    async def test_ipv6_target(self):
        try:
            target = await self.service(self.echo, endpoint='[::1]:0')
        except OSError as error:
            self.skipTest(f'IPv6 unavailable: {error}')
        async with Session(target.address) as session:
            await self.round_trip(session, b'ipv6')

    async def test_independent_destination_pin_before_dial(self):
        peer = Peer('target', '127.0.0.1:1', 'a' * 64)
        with patch('fan_ssh.session.connect') as dial:
            with self.assertRaisesRegex(ValueError, 'PIN_MISMATCH'):
                await connect_peer(peer, None, 'b' * 64)
            dial.assert_not_called()

    async def test_actual_server_pin_checked(self):
        pki = DemoPKI()
        client, server = pki.issue('client'), pki.issue('server')
        target = await self.service(self.echo, pki.context(server, server=True))
        wrong = Peer('target', target.address, 'a' * 64)
        with self.assertRaisesRegex(ValueError, 'IDENTITY_REJECTED'):
            await connect_peer(wrong, pki.context(client), wrong.pin)

    async def test_unknown_ca_rejected(self):
        pki, foreign = DemoPKI(), DemoPKI()
        target = await self.service(self.echo, pki.context(pki.issue('server'), server=True))
        with self.assertRaises((ssl.SSLError, ConnectionError)):
            await connect(target.address, foreign.context(foreign.issue('foreign')))

    async def coordinator(self):
        pki = DemoPKI()
        a, b, server = [pki.issue(name) for name in ('a', 'b', 'coordinator')]
        records = {'b': Peer('b', '127.0.0.1:22', b.pin)}
        acl = {('a', 'b')}
        coordinator = await Coordinator(pki.context(server, server=True), {a.pin: 'a', b.pin: 'b'}, records, acl).start()
        self.services.append(coordinator)
        return pki, a, b, server, coordinator, records, acl

    async def test_directional_acl_and_snapshot(self):
        pki, a, b, server, coordinator, records, acl = await self.coordinator()
        records.clear()
        acl.clear()
        peer = await discover(coordinator.service.address, pki.context(a), server.pin, 'b')
        self.assertEqual(peer.pin, b.pin)
        with self.assertRaisesRegex(ValueError, 'DISCOVERY_DENIED'):
            await discover(coordinator.service.address, pki.context(b), server.pin, 'b')

    async def test_coordinator_rejects_body_and_operations(self):
        pki, a, _, _, coordinator, *_ = await self.coordinator()
        for request in [{'op': 'connect', 'target': 'b'}, {'op': 'lookup', 'target': 'b', 'body': 'data'}, [],
                        {'op': 'lookup', 'target': '../b'}]:
            reader, writer = await connect(coordinator.service.address, pki.context(a))
            await write_metadata(writer, request)
            self.assertEqual(await reader.read(), b'')
            await close_writer(writer)

    async def test_coordinator_rejects_unapproved_enrolled_leaf(self):
        pki, _, _, _, coordinator, *_ = await self.coordinator()
        reader, writer = await connect(coordinator.service.address, pki.context(pki.issue('stranger')))
        await write_metadata(writer, {'op': 'lookup', 'target': 'b'})
        self.assertEqual(await reader.read(), b'')
        await close_writer(writer)

    async def test_wrong_coordinator_pin(self):
        pki, a, _, _, coordinator, *_ = await self.coordinator()
        with self.assertRaisesRegex(ValueError, 'IDENTITY_REJECTED'):
            await discover(coordinator.service.address, pki.context(a), 'a' * 64, 'b')

    async def test_metadata_size_before_payload(self):
        reader = asyncio.StreamReader()
        reader.feed_data(struct.pack('!I', 4097))
        with self.assertRaisesRegex(ValueError, 'METADATA_TOO_LARGE'):
            await read_metadata(reader)

    async def test_metadata_rejects_deep_json(self):
        payload = b'[' * 1100 + b'0' + b']' * 1100
        reader = asyncio.StreamReader()
        reader.feed_data(struct.pack('!I', len(payload)) + payload)
        with self.assertRaisesRegex(ValueError, 'METADATA_NESTING_TOO_DEEP'):
            await read_metadata(reader)

    async def test_metadata_rejects_duplicates_and_constants(self):
        for payload in [b'{"op":"lookup","op":"connect"}', b'{"target":NaN}']:
            reader = asyncio.StreamReader()
            reader.feed_data(struct.pack('!I', len(payload)) + payload)
            with self.assertRaises(ValueError):
                await read_metadata(reader)

    async def test_ipv6_encrypted_peer_path(self):
        pki = DemoPKI()
        client, server = pki.issue('client'), pki.issue('server')
        async def handler(reader, writer):
            require_pin(writer, {client.pin})
            incoming, outgoing = framed((reader, writer))
            while data := await incoming.read():
                outgoing.write(data)
                await outgoing.drain()
            outgoing.write_eof()
            await outgoing.drain()
        try:
            service = await self.service(handler, pki.context(server, server=True), endpoint='[::1]:0')
        except OSError as error:
            self.skipTest(f'IPv6 unavailable: {error}')
        reader, writer = await connect_peer(Peer('server', service.address, server.pin), pki.context(client), server.pin)
        writer.write(b'encrypted IPv6')
        writer.write_eof()
        await writer.drain()
        self.assertEqual(await reader.read(), b'encrypted IPv6')
        self.assertEqual(await reader.read(), b'')
        await close_writer(writer)

    async def test_frame_size_before_payload(self):
        reader = asyncio.StreamReader()
        reader.feed_data(struct.pack('!I', BUFFER + 1))
        with self.assertRaisesRegex(ValueError, 'FRAME_TOO_LARGE'):
            await FramedReader(reader).read()

    async def test_truncated_frame_not_eof(self):
        for content in [b'', b'\0\0', struct.pack('!I', 3) + b'x']:
            reader = asyncio.StreamReader()
            reader.feed_data(content)
            reader.feed_eof()
            with self.assertRaises(asyncio.IncompleteReadError):
                await FramedReader(reader).read()

    async def test_cancellation_closes_stalled_handshake(self):
        pki = DemoPKI()
        service = await self.service(self.echo, pki.context(pki.issue('server'), server=True))
        reader, writer = await connect(service.address)
        await asyncio.sleep(0.02)
        await asyncio.wait_for(service.close(), 1)
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b'')
        await close_writer(writer)

    async def test_handshake_admission_cap(self):
        pki = DemoPKI()
        service = await self.service(self.echo, pki.context(pki.issue('server'), server=True), limit=2)
        pairs = [await connect(service.address) for _ in range(5)]
        await asyncio.sleep(0.03)
        self.assertEqual(len(service.tasks), 2)
        await service.close()
        for _, writer in pairs:
            await close_writer(writer)

    async def test_absolute_bridge_timeout(self):
        idle = await self.service(lambda r, w: asyncio.sleep(10))
        a, b = await connect(idle.address), await connect(idle.address)
        with self.assertRaises(TimeoutError):
            await bridge(a, b, timeout=0.03)
        self.assertTrue(a[1].is_closing())
        self.assertTrue(b[1].is_closing())

    async def test_session_cancellation_closes_active_stream(self):
        target = await self.service(self.echo)
        session = await Session(target.address).__aenter__()
        reader, writer = await session.dial()
        await asyncio.wait_for(session.__aexit__(None, None, None), 2)
        with self.assertRaises(asyncio.IncompleteReadError):
            await reader.read()
        await close_writer(writer)


if __name__ == '__main__':
    unittest.main()
