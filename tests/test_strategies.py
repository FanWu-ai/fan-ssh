"""Fallback cancellation, terminal identity errors and direct-evidence enforcement."""
import asyncio
import errno
import ssl
import unittest
from types import SimpleNamespace

from fan_ssh.remote import DirectUnavailable
from fan_ssh.strategies import AutomaticClient


class Stub:
    def __init__(self, error=None, wait=None):
        self.error, self.wait = error, wait
        self.calls = self.closed = 0
        self.cancelled = False

    async def dial(self, peer, service):
        self.calls += 1
        if self.wait:
            try:
                await self.wait.wait()
            finally:
                self.cancelled = True
        if self.error:
            raise self.error
        return ('reader', 'writer'), {'code': 'DIRECT_SERVICE_READY', 'relay': False}

    async def close(self):
        self.closed += 1


class StrategyTests(unittest.IsolatedAsyncioTestCase):
    async def test_connectivity_failure_then_next_method_with_attempt_evidence(self):
        a, b = Stub(DirectUnavailable({'code': 'NO_DIRECT_PATH', 'relay': False})), Stub()
        client = AutomaticClient([('tcp', a, 'dial', 1), ('udp', b, 'dial', 1)])
        try:
            pair, report = await client.dial('peer')
            self.assertEqual(pair, ('reader', 'writer'))
            self.assertEqual(report['method'], 'udp')
            self.assertEqual([r['code'] for r in report['method_attempts']], ['NO_DIRECT_PATH', 'DIRECT_SERVICE_READY'])
        finally:
            await client.close()
        self.assertEqual((a.closed, b.closed), (1, 1))

    async def test_identity_acl_and_permission_failures_do_not_attempt_next_method(self):
        for error in (ValueError('ACL_DENIED'), ssl.SSLError('wrong certificate'),
                      DirectUnavailable({'code': 'PEER_AUTH_FAILED'}), OSError(errno.EACCES, 'permission')):
            with self.subTest(error=type(error).__name__):
                a, b = Stub(error), Stub()
                client = AutomaticClient([('tcp', a, 'dial', 1), ('udp', b, 'dial', 1)])
                try:
                    with self.assertRaises(type(error)):
                        await client.dial('peer')
                    self.assertEqual(b.calls, 0)
                finally:
                    await client.close()

    async def test_deadline_cancels_first_path_before_starting_next(self):
        a, b = Stub(wait=asyncio.Event()), Stub()
        client = AutomaticClient([('tcp', a, 'dial', .01), ('udp', b, 'dial', 1)])
        try:
            _, report = await client.dial('peer')
            self.assertTrue(a.cancelled)
            self.assertEqual(report['method_attempts'][0]['code'], 'TimeoutError')
        finally:
            await client.close()

    async def test_user_cancellation_does_not_start_another_method(self):
        a, b = Stub(wait=asyncio.Event()), Stub()
        client = AutomaticClient([('tcp', a, 'dial', 1), ('udp', b, 'dial', 1)])
        task = asyncio.create_task(client.dial('peer'))
        await asyncio.sleep(.01)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(b.calls, 0)
        await client.close()

    async def test_all_methods_unreachable_report_without_relay(self):
        client = AutomaticClient([('tcp', Stub(ConnectionRefusedError()), 'dial', 1)])
        try:
            with self.assertRaises(DirectUnavailable) as raised:
                await client.dial('peer')
            self.assertFalse(raised.exception.report['relay'])
            self.assertEqual(len(raised.exception.report['method_attempts']), 1)
        finally:
            await client.close()
