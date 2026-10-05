"""Usable SSH command safety and localized identity enrollment regressions."""
import os
import asyncio
from pathlib import Path
import shlex
import tempfile
from types import SimpleNamespace
import unittest
import socket
import struct
import subprocess
import sys
import shutil
from unittest.mock import patch

from fan_ssh.device import windows_sid
from fan_ssh.ssh_cli import ssh_command, ssh_login
from fan_ssh.stun import start_observers
from fan_ssh.config import Policy
from fan_ssh.control import Control, ControlConnection, request
from fan_ssh.device import tls_context
from fan_ssh.grants import verify
from test_remote import fixture


class ProductEntryTests(unittest.TestCase):
    def test_localized_whoami_does_not_decode_the_account_name(self):
        expected = 'S-1-5-21-111-222-333-1001'
        for encoding in ('utf8', 'gbk'):
            output = ('"HOST\\用户","' + expected + '"\r\n').encode(encoding)
            self.assertEqual(windows_sid(output), expected)
        for output in (b'"name","S-1-5-$(bad)"', b'no SID', b'"name","S-2-5-123"'):
            with self.assertRaisesRegex(ValueError, 'WINDOWS_USER_SID_REQUIRED'):
                windows_sid(output)

    def test_existing_alias_and_credentials_are_used_with_python_proxy(self):
        with tempfile.TemporaryDirectory(prefix='fan product ') as root:
            args = SimpleNamespace(identity=str(Path(root) / 'identity'), policy=str(Path(root) / 'policy.json'),
                                   peer='peer', service='ssh', transport='auto', ssh_host='existing-alias',
                                   ssh_user=None, ssh_port=None, command=['--', 'echo', 'ok'],
                                   udp_native='192.0.2.1', stun='192.0.2.2:22092', stun_alternate='192.0.2.2:22093',
                                   udp_strategy='ice', reverse_listen=None, reverse_candidate=None)
            command = ssh_command(args)
            self.assertEqual(command[-4:], ['--', 'existing-alias', 'echo', 'ok'])
            self.assertIn('StrictHostKeyChecking=yes', command)
            self.assertIn('ForwardAgent=no', command)
            self.assertIn('ProxyJump=none', command)
            self.assertIn('ConnectTimeout=120', command)
            proxy = next(value for value in command if value.startswith('ProxyCommand='))
            self.assertIn('fan_ssh proxy', proxy)
            self.assertIn('--stun-alternate', proxy)
            self.assertNotIn('UserKnownHostsFile', ' '.join(command))
            if shutil.which('ssh'):
                checked = subprocess.run([command[0], '-G', *command[1:]],
                                         capture_output=True, text=True, timeout=10)
                self.assertEqual(checked.returncode, 0, checked.stderr)
                self.assertTrue(any(line.startswith('proxycommand ') and 'fan_ssh proxy' in line
                                    for line in checked.stdout.splitlines()), checked.stdout)
            if os.name != 'nt':
                words = shlex.split(proxy.split('=', 1)[1])
                self.assertEqual(words[words.index('--identity') + 1], args.identity)
                self.assertEqual(words[words.index('--policy') + 1], args.policy)

    def test_invalid_original_host_or_port_rejected_before_process(self):
        args = SimpleNamespace(ssh_host='-oWrong', peer='peer', ssh_port=None)
        with self.assertRaisesRegex(ValueError, 'INVALID_SSH_HOST'):
            ssh_command(args)
        args.ssh_host = 'host'; args.ssh_port = 65536
        with self.assertRaisesRegex(ValueError, 'INVALID_SSH_PORT'):
            ssh_command(args)


class ProductControlTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.ids, self.data = fixture()
        initial = Policy.parse(self.data)
        self.control = await Control('control', self.ids['control'], initial).start('127.0.0.1:0')
        self.data['coordinator']['address'] = self.control.service.address
        self.policy = Policy.parse(self.data)
        self.control.policy = self.policy
        self.connection = ControlConnection(self.ids['a'], self.policy,
                                             context=tls_context(self.ids['a'], self.policy))

    async def asyncTearDown(self):
        await self.connection.close()
        await self.control.close()

    async def test_two_fresh_grants_reuse_one_pinned_tcp_mapping(self):
        value = {'op': 'grant', 'target': 'b', 'service': 'ssh', 'direction': 'forward'}
        first = await request(self.ids['a'], self.policy, value, connection=self.connection)
        local = self.connection.pair[1].get_extra_info('sockname')
        second = await request(self.ids['a'], self.policy, value, connection=self.connection)
        self.assertEqual(self.connection.pair[1].get_extra_info('sockname'), local)
        a, b = verify(first['grant'], self.policy), verify(second['grant'], self.policy)
        self.assertNotEqual(a['session'], b['session'])
        self.assertEqual((a['source'], b['source']), ('a', 'a'))
        self.assertEqual(self.control.requests, 2)
        with self.assertRaisesRegex(ValueError, 'CONTROL_CONNECTION_SCOPE_REJECTED'):
            await request(self.ids['c'], self.policy, value, connection=self.connection)

    async def test_roster_removal_rejects_next_operation_on_already_open_tls(self):
        value = {'op': 'grant', 'target': 'b', 'service': 'ssh', 'direction': 'forward'}
        await self.connection.request(value)
        self.data['revision'] = 2
        self.data['devices'] = [d for d in self.data['devices'] if d['id'] != 'a']
        self.data['allow'] = [edge for edge in self.data['allow'] if 'a' not in (edge['from'], edge['to'])]
        self.control.update(Policy.parse(self.data))
        with self.assertRaises((ValueError, asyncio.IncompleteReadError, ConnectionError)):
            await self.connection.request(value)
        self.assertTrue(self.connection.closed)

    async def test_two_real_observer_sockets_share_the_aggregate_rate_budget(self):
        ports = []
        for _ in range(2):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.bind(('127.0.0.1', 0))
                ports.append(s.getsockname()[1])
        self.control.observed_ips['a'] = '127.0.0.1'
        observers = await start_observers(self.control, ['127.0.0.1:%d' % p for p in ports])
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(('127.0.0.1', 0)); client.setblocking(False)
        loop = asyncio.get_running_loop()
        try:
            for i in range(60):
                token = i.to_bytes(12, 'big')
                packet = struct.pack('!HHI', 1, 0, 0x2112A442) + token
                await loop.sock_sendto(client, packet, ('127.0.0.1', ports[i % 2]))
                reply, peer = await asyncio.wait_for(loop.sock_recvfrom(client, 512), 1)
                self.assertEqual(reply[8:20], token)
            await loop.sock_sendto(client, packet, ('127.0.0.1', ports[0]))
            with self.assertRaises(TimeoutError):
                await asyncio.wait_for(loop.sock_recvfrom(client, 512), 0.1)
            self.assertEqual(sum(o.packets for o in observers), 60)
        finally:
            client.close()
            for observer in observers:
                await observer.close()

    async def test_cancelling_python_entry_stops_its_native_ssh_child(self):
        with tempfile.TemporaryDirectory(prefix='fan-entry-cancel-') as temp:
            marker = Path(temp) / 'started'
            code = 'import pathlib,sys,time;pathlib.Path(sys.argv[1]).write_text("ready");time.sleep(120)'
            real = subprocess.Popen
            processes = []
            def start(*args, **kwargs):
                child = real([sys.executable, '-c', code, str(marker)], **kwargs)
                processes.append(child)
                return child
            configured = ['ssh', '-o', 'ProxyCommand=product-proxy', 'host']
            parsed = subprocess.CompletedProcess([], 0, b'proxycommand product-proxy\n', b'')
            with patch('fan_ssh.ssh_cli.ssh_command', return_value=configured), \
                    patch('fan_ssh.ssh_cli.subprocess.run', return_value=parsed), \
                    patch('fan_ssh.ssh_cli.subprocess.Popen', side_effect=start):
                task = asyncio.create_task(ssh_login(None))
                try:
                    async with asyncio.timeout(3):
                        while not marker.exists():
                            await asyncio.sleep(0.01)
                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await asyncio.wait_for(task, 4)
                    self.assertIsNotNone(processes[0].poll())
                finally:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    for child in processes:
                        if child.poll() is None:
                            child.kill(); child.wait(timeout=3)

    async def test_inactive_python_proxy_never_starts_a_direct_management_ssh(self):
        configured = ['ssh', '-o', 'ProxyCommand=product-proxy', 'host']
        parsed = subprocess.CompletedProcess([], 0, b'hostname existing-management\n', b'')
        with patch('fan_ssh.ssh_cli.ssh_command', return_value=configured), \
                patch('fan_ssh.ssh_cli.subprocess.run', return_value=parsed), \
                patch('fan_ssh.ssh_cli.subprocess.Popen') as start:
            with self.assertRaisesRegex(ValueError, 'SSH_PYTHON_PROXY_NOT_ACTIVE'):
                await ssh_login(None)
            start.assert_not_called()


if __name__ == '__main__':
    unittest.main()
