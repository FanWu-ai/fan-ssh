"""Independent device integration; all endpoint inventories are synthetic loopback."""
import asyncio
import copy
from datetime import timedelta
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from fan_ssh import grants
from fan_ssh.config import Policy, certificate, direct_address
from fan_ssh.control import Control, request
from fan_ssh.device import generate, load, save, tls_context
from fan_ssh.remote import Client, DirectUnavailable, Node
from fan_ssh.session import read_metadata, write_metadata
from fan_ssh.transport import BUFFER, Service, close_writer, connect


def unused_endpoint():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return '127.0.0.1:%d' % sock.getsockname()[1]


def fixture():
    identities = {key: generate(key) for key in ('control', 'a', 'b', 'c')}
    data = dict(version=1, account='test', revision=1,
                coordinator={'id': 'control', 'address': unused_endpoint()},
                devices=[{'id': key, 'cert': value.cert.decode('ascii'),
                          'candidates': [] if key == 'control' else [unused_endpoint()]}
                         for key, value in identities.items()],
                allow=[{'from': 'a', 'to': 'b', 'service': 'ssh'},
                       {'from': 'b', 'to': 'a', 'service': 'ssh'},
                       {'from': 'c', 'to': 'b', 'service': 'ssh'}])
    return identities, data


class ConfigurationTests(unittest.TestCase):
    def test_explicit_numeric_scope_and_unprivileged_ports(self):
        for endpoint in ['192.0.2.10:22022', '[2001:db8::1]:22022', '100.64.0.1:22022', '127.0.0.1:22022']:
            self.assertEqual(direct_address(endpoint)[1], 22022)
        for endpoint in ['example.org:22022', '0.0.0.0:22022', '[::]:22022', '[fe80::1%eth0]:22022',
                         '224.1.1.1:22022', '255.255.255.255:22022', '127.0.0.1:22', '127.0.0.1:022022']:
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                direct_address(endpoint)

    def test_identity_roundtrip_no_overwrite(self):
        with tempfile.TemporaryDirectory() as root:
            state = Path(root) / 'device'
            identity = save('a', state)
            identifier, loaded = load(state)
            self.assertEqual(identifier, 'a')
            self.assertEqual(identity, loaded)
            with self.assertRaises(FileExistsError):
                save('a', state)

    def test_private_key_readable_by_other_users_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            state = Path(root) / 'device'
            save('a', state)
            if os.name == 'nt':
                subprocess.run(['icacls', str(state / 'key.pem'), '/grant', '*S-1-5-32-545:R'],
                               check=True, capture_output=True, timeout=5)
                error = 'WINDOWS_PRIVATE_IDENTITY_ACL_REQUIRED'
            else:
                (state / 'key.pem').chmod(0o644)
                error = 'PRIVATE_KEY_PERMISSIONS_REQUIRED'
            with self.assertRaisesRegex(ValueError, error):
                load(state)

    def test_key_mismatch_and_policy_schema(self):
        identities, data = fixture()
        for mutate in [lambda d: d.update(body='arbitrary'), lambda d: d.update(revision=True),
                       lambda d: d['devices'][0]['candidates'].append('127.0.0.1:22022'),
                       lambda d: d['devices'][1]['candidates'].append(d['coordinator']['address']),
                       lambda d: d['allow'].append({'from': 'control', 'to': 'a', 'service': 'ssh'})]:
            value = copy.deepcopy(data)
            mutate(value)
            with self.assertRaises(ValueError):
                Policy.parse(value)
        with tempfile.TemporaryDirectory() as root:
            state = Path(root) / 'device'
            save('a', state)
            (state / 'key.pem').write_bytes(identities['b'].key)
            with self.assertRaisesRegex(ValueError, 'KEY_MISMATCH'):
                load(state)

    def test_policy_snapshots_and_monotonic_revision(self):
        _, data = fixture()
        policy = Policy.parse(data)
        data['allow'].clear()
        self.assertTrue(policy.permits('a', 'b', 'ssh'))
        with self.assertRaisesRegex(ValueError, 'POLICY_REVISION_REJECTED'):
            policy.replacement(Policy.parse(data))
        data['revision'] = 2
        self.assertFalse(policy.replacement(Policy.parse(data)).permits('a', 'b', 'ssh'))

    def test_expired_certificate_cannot_be_enrolled_or_renew_grant(self):
        identities, data = fixture()
        pem = identities['control'].cert.decode('ascii')
        future = certificate(pem).not_valid_after_utc + timedelta(seconds=1)
        from types import SimpleNamespace
        with patch('fan_ssh.config.datetime', SimpleNamespace(now=lambda zone: future)):
            with self.assertRaisesRegex(ValueError, 'CERTIFICATE_EXPIRED_OR_FUTURE'):
                Policy.parse(data)


class GrantTests(unittest.TestCase):
    def setUp(self):
        self.ids, data = fixture()
        self.policy = Policy.parse(data)
        self.timestamp = grants.clock()
        self.grant = grants.issue(self.ids['control'], self.policy, 'a', 'b', 'ssh', now=self.timestamp)

    def test_signature_tampering_expiry_and_future(self):
        self.assertEqual(grants.verify(self.grant, self.policy)['source'], 'a')
        corrupted = dict(self.grant)
        corrupted['payload'] = corrupted['payload'][:-4] + 'AAAA'
        with self.assertRaisesRegex(ValueError, 'SIGNATURE'):
            grants.verify(corrupted, self.policy)
        for now in (self.timestamp - 1, self.timestamp + 30000):
            with self.assertRaisesRegex(ValueError, 'EXPIRED_OR_FUTURE'):
                grants.verify(self.grant, self.policy, now=now)
        with self.assertRaisesRegex(ValueError, 'ACL_DENIED'):
            grants.issue(self.ids['control'], self.policy, 'b', 'a', 'other')

    def test_replay_and_renewal_cannot_admit(self):
        claims = grants.verify(self.grant, self.policy)
        receiver = grants.Admissions()
        receiver.consume(claims)
        with self.assertRaisesRegex(ValueError, 'GRANT_REPLAYED'):
            receiver.consume(claims)
        renewed = grants.issue(self.ids['control'], self.policy, 'a', 'b', 'ssh', previous=claims, now=self.timestamp + 1)
        newer = grants.verify(renewed, self.policy, now=self.timestamp + 1)
        grants.renewal(claims, newer)
        with self.assertRaisesRegex(ValueError, 'RENEWAL_IS_NOT_ADMISSION'):
            receiver.consume(newer)
        altered = dict(newer, target='c')
        with self.assertRaisesRegex(ValueError, 'LEASE_RENEWAL_REJECTED'):
            grants.renewal(claims, altered)

    def test_bounded_replay_cache_never_evicts_live_tokens(self):
        receiver = grants.Admissions()
        claims = grants.verify(self.grant, self.policy)
        with patch.object(grants, 'MAX_REPLAYS', 2):
            receiver.consume(claims)
            receiver.consume(dict(claims, session='0' * 32))
            with self.assertRaisesRegex(ValueError, 'ADMISSION_CAPACITY'):
                receiver.consume(dict(claims, session='1' * 32))
            receiver.consume(dict(claims, session='1' * 32, expires_ms=self.timestamp + 60000), now=self.timestamp + 30000)
            self.assertEqual(len(receiver.consumed), 1)


class RemoteTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.ids, self.data = fixture()
        self.cleanup = []
        self.accepted = 0
        self.log = io.StringIO()
        async def echo(reader, writer):
            self.accepted += 1
            while part := await reader.read(BUFFER):
                writer.write(part)
                await writer.drain()
            writer.write_eof()
            await writer.drain()
        self.target = await Service(echo).start()
        self.cleanup.append(self.target)
        initial = Policy.parse(self.data)
        self.control = await Control('control', self.ids['control'], initial).start('127.0.0.1:0')
        self.cleanup.append(self.control)
        self.data['coordinator']['address'] = self.control.service.address
        initial = Policy.parse(self.data)
        self.node = await Node('b', self.ids['b'], initial, {'ssh': self.target.address}, self.log).start('127.0.0.1:0', poll=False)
        self.cleanup.append(self.node)
        self.data['devices'][2]['candidates'] = [self.node.service.address]
        self.policy = Policy.parse(self.data)
        # Final synthetic snapshot is frozen before clients or offers exist.
        self.control.policy = self.node.policy = self.policy
        self.client = Client('a', self.ids['a'], self.policy)
        self.cleanup.append(self.client)

    async def asyncTearDown(self):
        for service in reversed(self.cleanup):
            await service.close()

    async def roundtrip(self, client=None, target='b', payload=b'opaque\x00\xff'):
        pair, report = await (client or self.client).dial(target)
        async def send():
            for offset in range(0, len(payload), BUFFER):
                pair[1].write(payload[offset:offset + BUFFER])
                await pair[1].drain()
            pair[1].write_eof()
            await pair[1].drain()
        sender = asyncio.create_task(send())
        try:
            output = bytearray()
            while data := await pair[0].read():
                output.extend(data)
            self.assertEqual(bytes(output), payload)
            await sender
            return report
        finally:
            sender.cancel()
            await asyncio.gather(sender, return_exceptions=True)
            await close_writer(pair[1])

    async def test_direct_concurrent_payload_and_metadata_only_control(self):
        payload = bytes(range(256)) * 2048
        reports = await asyncio.wait_for(asyncio.gather(*(self.roundtrip(payload=payload) for _ in range(8))), 20)
        self.assertEqual(self.accepted, 8)
        self.assertTrue(all(report['selected']['direction'] == 'forward' and not report['relay'] for report in reports))
        self.assertEqual(self.control.requests, 8)
        self.assertLess(self.control.metadata_bytes, 4096)

    async def test_diagnosis_authenticates_without_opening_service(self):
        report = await self.client.diagnose('b')
        self.assertEqual(report['code'], 'AUTHENTICATED_DIRECT_TLS')
        self.assertFalse(report['service_opened'])
        await asyncio.sleep(0.03)
        self.assertEqual(self.accepted, 0)

    async def test_service_acl_denied_before_any_direct_dial(self):
        with patch('fan_ssh.remote.connect') as dial:
            with self.assertRaisesRegex(ValueError, 'ACL_DENIED'):
                await self.client.dial('b', 'unapproved')
            dial.assert_not_called()
        self.assertEqual(self.accepted, 0)

    async def test_coordinator_cannot_replace_identity_or_candidates(self):
        for changes in ({'pin': self.ids['c'].pin}, {'candidates': ['192.0.2.10:22022']}):
            original = self.control.peer
            self.control.peer = lambda identifier: dict(original(identifier), **changes)
            with patch('fan_ssh.remote.connect') as dial:
                with self.assertRaisesRegex(ValueError, 'DISCOVERY_CHANGED_APPROVED_PEER'):
                    await self.client.dial('b')
                dial.assert_not_called()
            self.control.peer = original

    async def open_raw(self, identity, grant):
        pair = await connect(self.node.service.address, tls_context(identity, self.policy), validator=direct_address)
        await write_metadata(pair[1], {'op': 'open', 'grant': grant})
        return pair

    async def test_wrong_tls_caller_expired_grant_and_replay(self):
        grant = grants.issue(self.ids['control'], self.policy, 'a', 'b', 'ssh')
        pair = await self.open_raw(self.ids['c'], grant)
        self.assertEqual(await asyncio.wait_for(pair[0].read(), 1), b'')
        await close_writer(pair[1])
        expired = grants.issue(self.ids['control'], self.policy, 'a', 'b', 'ssh', now=grants.clock() - 31000)
        pair = await self.open_raw(self.ids['a'], expired)
        self.assertEqual(await asyncio.wait_for(pair[0].read(), 1), b'')
        await close_writer(pair[1])
        self.assertEqual(self.accepted, 0)
        first = await self.open_raw(self.ids['a'], grant)
        self.assertTrue((await read_metadata(first[0]))['ok'])
        second = await self.open_raw(self.ids['a'], grant)
        self.assertEqual(await asyncio.wait_for(second[0].read(), 1), b'')
        await close_writer(second[1]); await close_writer(first[1])
        self.assertEqual(self.accepted, 1)

    async def test_unknown_device_never_dials_service(self):
        stranger = generate('stranger')
        try:
            pair = await connect(self.node.service.address, tls_context(stranger, self.policy), validator=direct_address)
            try:
                await write_metadata(pair[1], {'op': 'open', 'grant': {}})
                self.assertEqual(await asyncio.wait_for(pair[0].read(), 1), b'')
            except (OSError, asyncio.IncompleteReadError):
                pass
            finally:
                await close_writer(pair[1])
        except OSError:
            pass
        self.assertEqual(self.accepted, 0)

    async def test_failed_candidates_honest_no_relay(self):
        self.data['devices'][2]['candidates'] = [unused_endpoint()]
        self.policy = self.control.policy = Policy.parse(self.data)
        client = Client('a', self.ids['a'], self.policy)
        self.cleanup.append(client)
        with self.assertRaises(DirectUnavailable) as failure:
            await client.dial('b')
        self.assertEqual(failure.exception.report['code'], 'NO_DIRECT_PATH')
        self.assertFalse(failure.exception.report['relay'])
        self.assertEqual(self.accepted, 0)

    async def test_candidate_racing_cancels_stalled_handshake(self):
        stalled = await Service(lambda r, w: asyncio.sleep(10)).start()
        self.cleanup.append(stalled)
        self.data['devices'][2]['candidates'].insert(0, stalled.address)
        self.policy = self.control.policy = self.node.policy = Policy.parse(self.data)
        client = Client('a', self.ids['a'], self.policy)
        self.cleanup.append(client)
        report = await asyncio.wait_for(self.roundtrip(client), 2)
        self.assertEqual(report['selected']['remote'], self.node.service.address)
        self.assertTrue(any(attempt['code'] == 'CANCELLED' for attempt in report['attempts']))
        self.assertEqual(self.accepted, 1)

    async def test_control_unknown_operations_bodies_rate_and_offer_scope(self):
        for value in ({'op': 'connect', 'target': 'b'}, {'op': 'next', 'body': 'business'},
                      {'op': 'grant', 'target': 'b', 'service': 'ssh', 'direction': 'relay'}):
            with self.assertRaises(ValueError):
                await request(self.ids['a'], self.policy, value, context=self.client.context)
        grant = grants.issue(self.ids['control'], self.policy, 'a', 'b', 'ssh', 'reverse')
        with self.assertRaisesRegex(ValueError, 'UNAPPROVED_REVERSE_CANDIDATE'):
            await request(self.ids['a'], self.policy, {'op': 'offer', 'grant': grant, 'candidate': '192.0.2.10:22022'}, context=self.client.context)
        self.assertEqual(self.accepted, 0)
        for _ in range(240):
            self.control.rate('test-rate')
        with self.assertRaisesRegex(ValueError, 'RATE_LIMIT'):
            self.control.rate('test-rate')

    async def test_renewed_session_survives_initial_expiry(self):
        # A one-second artificial lease gives a loaded Windows TLS handshake
        # less than half a second to renew. Keep a shortened lease, but verify
        # multiple genuine renewals rather than the scheduler's subsecond speed.
        with patch.object(grants, 'LIFETIME', 3.0):
            pair, _ = await self.client.dial('b')
            try:
                await asyncio.sleep(6.2)
                pair[1].write(b'after initial expiry')
                await pair[1].drain()
                self.assertEqual(await asyncio.wait_for(pair[0].read(), 1), b'after initial expiry')
                self.assertGreaterEqual(self.control.requests, 3)
            finally:
                await close_writer(pair[1])

    async def test_coordinator_loss_and_revocation_close_sessions(self):
        with patch.object(grants, 'LIFETIME', 0.4):
            pair, _ = await self.client.dial('b')
            self.data['revision'] = 2
            self.data['allow'].clear()
            self.control.update(Policy.parse(self.data))
            with self.assertRaises(asyncio.IncompleteReadError):
                await asyncio.wait_for(pair[0].read(), 2)
            await close_writer(pair[1])

    async def test_local_policy_update_closes_active_session(self):
        pair, _ = await self.client.dial('b')
        self.data['revision'] = 2
        self.node.update(Policy.parse(self.data))
        with self.assertRaises(asyncio.IncompleteReadError):
            await asyncio.wait_for(pair[0].read(), 1)
        await close_writer(pair[1])

    async def test_reverse_direct_path_when_target_cannot_receive(self):
        self.data['devices'][2]['candidates'] = [unused_endpoint()]
        self.policy = self.control.policy = self.node.policy = Policy.parse(self.data)
        endpoint = self.policy.devices['a'].candidates[0]
        client = Client('a', self.ids['a'], self.policy, reverse_listen=endpoint)
        self.cleanup.append(client)
        self.node.poll_task = asyncio.create_task(self.node.poll())
        # Includes a new server TLS context, offer polling and TLS shutdown.
        # Retain a bounded end-to-end check without a five-second scheduler race.
        report = await asyncio.wait_for(self.roundtrip(client, payload=bytes(range(256)) * 128), 12)
        self.assertEqual(report['selected']['direction'], 'reverse')
        self.assertEqual(report['selected']['local'], endpoint)
        self.assertFalse(report['relay'])
        await asyncio.sleep(0.02)
        self.assertFalse(client.pending)
        self.assertEqual(self.accepted, 1)

    async def test_many_to_many_both_devices_initiate_and_receive(self):
        a_node = await Node('a', self.ids['a'], self.policy, {'ssh': self.target.address}, self.log).start('127.0.0.1:0', poll=False)
        self.cleanup.append(a_node)
        self.data['devices'][1]['candidates'] = [a_node.service.address]
        self.policy = self.control.policy = self.node.policy = a_node.policy = Policy.parse(self.data)
        a = Client('a', self.ids['a'], self.policy)
        b = Client('b', self.ids['b'], self.policy)
        self.cleanup.extend((a, b))
        await asyncio.wait_for(asyncio.gather(self.roundtrip(a, 'b'), self.roundtrip(b, 'a')), 5)
        self.assertEqual(self.accepted, 2)


if __name__ == '__main__':
    unittest.main()
