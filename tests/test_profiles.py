"""Offline profile UX, strict option reuse, and no automatic enrollment."""
import contextlib
import io
import json
import os
from pathlib import Path
import shlex
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from cryptography.hazmat.primitives import serialization

from fan_ssh import cli, profiles
from fan_ssh.device import save_identity
from fan_ssh.ssh_cli import ssh_command
from test_remote import fixture


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='fan profile ')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / 'saved profiles'
        self.value = dict.fromkeys(profiles.FIELDS)
        self.value.update(identity=str(self.root / 'private identity'), policy=str(self.root / 'approved policy.json'),
                          peer='b', service='ssh', transport='auto', ssh_host='existing-alias', udp_strategy='ice')

    def args(self, **changes):
        return SimpleNamespace(**dict(self.value, alias='remote', profiles_dir=str(self.directory), **changes))

    def write(self, data):
        self.directory.mkdir(exist_ok=True)
        path = self.directory / 'remote.json'
        path.write_text(json.dumps(data), encoding='utf8')
        return path

    def approved(self):
        identities, data = fixture()
        save_identity('a', identities['a'], self.value['identity'])
        Path(self.value['policy']).write_text(json.dumps(data), encoding='utf8')
        return data

    def invoke(self, *arguments):
        with patch.object(sys, 'argv', ['fan-ssh', *arguments]), contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()) as errors:
            try:
                code = cli.main()
            except SystemExit as error:
                code = error.code
        return code, output.getvalue(), errors.getvalue()

    def test_roundtrip_stores_only_connection_options_and_cannot_overwrite(self):
        path = profiles.save_profile(self.args())
        self.assertEqual(profiles.load_profile('remote', self.directory), self.value)
        data = json.loads(path.read_text())
        self.assertEqual(set(data), {'version', 'connection'})
        self.assertEqual(set(data['connection']), set(profiles.FIELDS))
        self.assertFalse(Path(self.value['identity']).exists())
        self.assertFalse(Path(self.value['policy']).exists())
        with self.assertRaisesRegex(ValueError, 'PROFILE_ALREADY_EXISTS'):
            profiles.save_profile(self.args())
        self.assertEqual(json.loads(path.read_text()), data)
        if os.name != 'nt':
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)

    def test_relative_paths_are_bound_to_creation_directory(self):
        args = self.args()
        args.identity, args.policy = 'private identity', 'network.policy.json'
        profiles.save_profile(args)
        value = profiles.load_profile('remote', self.directory)
        self.assertEqual(value['identity'], str(Path.cwd() / args.identity))
        self.assertEqual(value['policy'], str(Path.cwd() / args.policy))

    def test_unknown_name_has_actionable_error(self):
        with self.assertRaisesRegex(ValueError, 'PROFILE_NOT_FOUND.*profile add'):
            profiles.load_profile('missing', self.directory)
        self.assertFalse(self.directory.exists())

    def test_names_cannot_escape_directory_or_use_windows_reserved_names(self):
        for alias in ('../remote', '/tmp/remote', 'a/b', 'a\\b', '-flag', 'a.json', 'CON', 'lpt1', 'a' * 65, '', 'a\n'):
            with self.subTest(alias=alias), self.assertRaisesRegex(ValueError, 'INVALID_PROFILE_NAME'):
                profiles.profile_path(alias, self.directory)
        for alias in ('remote', 'remote-lan-a', 'A_2'):
            self.assertEqual(profiles.profile_path(alias, self.directory).parent, self.directory)

    def test_corrupt_duplicate_unknown_version_and_oversize_profiles_fail_closed(self):
        path = self.write({'version': 1, 'connection': self.value})
        for text in ('{', '{"version":1,"version":1,"connection":{}}', '{"version":NaN}', 'x' * (profiles.MAX_PROFILE + 1)):
            path.write_text(text)
            with self.subTest(text=text[:50]), self.assertRaises(ValueError):
                profiles.load_profile('remote', self.directory)
        for version in (True, 2, '1'):
            self.write({'version': version, 'connection': self.value})
            with self.assertRaisesRegex(ValueError, 'UNSUPPORTED_PROFILE_VERSION'):
                profiles.load_profile('remote', self.directory)
        self.write({'version': 1, 'connection': dict(self.value, password='not allowed')})
        with self.assertRaisesRegex(ValueError, 'INVALID_PROFILE_OPTIONS'):
            profiles.load_profile('remote', self.directory)

    @unittest.skipIf(os.name == 'nt', 'symlink creation may require Windows privileges')
    def test_symlink_profile_is_rejected_and_never_overwritten(self):
        target = self.root / 'target.json'
        target.write_text('unchanged')
        self.directory.mkdir()
        (self.directory / 'remote.json').symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'SYMLINK'):
            profiles.load_profile('remote', self.directory)
        with self.assertRaisesRegex(ValueError, 'PROFILE_ALREADY_EXISTS'):
            profiles.save_profile(self.args())
        self.assertEqual(target.read_text(), 'unchanged')

    @unittest.skipIf(os.name == 'nt', 'POSIX FIFO regression')
    def test_named_pipe_profile_is_rejected_without_blocking(self):
        self.directory.mkdir()
        os.mkfifo(self.directory / 'remote.json')
        with self.assertRaisesRegex(ValueError, 'PROFILE_MUST_BE_REGULAR_FILE'):
            profiles.load_profile('remote', self.directory)

    def test_invalid_or_unpaired_options_fail_before_writing(self):
        for changes in ({'identity': None}, {'policy': None}, {'peer': 'bad/name'}, {'ssh_host': '-oBad'},
                        {'ssh_port': True}, {'ssh_port': 65536}, {'ssh_user': 'bad\nuser'}, {'transport': 'relay'},
                        {'udp_native': '192.0.2.1'}, {'stun': '192.0.2.2:22092'},
                        {'stun_alternate': '192.0.2.2:22093'}, {'transport': 'udp'},
                        {'reverse_candidate': '192.0.2.1:22022'}):
            args = self.args()
            for key, value in changes.items():
                setattr(args, key, value)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                profiles.save_profile(args)
            self.assertFalse(self.directory.exists())

    def test_stored_relative_paths_are_rejected(self):
        self.write({'version': 1, 'connection': dict(self.value, identity='relative')})
        with self.assertRaisesRegex(ValueError, 'PATH_MUST_BE_ABSOLUTE'):
            profiles.load_profile('remote', self.directory)

    def test_default_directories_follow_platform_conventions(self):
        with patch.dict(os.environ, {'LOCALAPPDATA': str(self.root / 'Local'), 'XDG_CONFIG_HOME': str(self.root / 'config')}, clear=True):
            with patch.object(sys, 'platform', 'win32'):
                self.assertEqual(profiles.profile_directory(), self.root / 'Local/fan-ssh/profiles')
            with patch.object(sys, 'platform', 'darwin'), patch.object(Path, 'home', return_value=self.root):
                self.assertEqual(profiles.profile_directory(), self.root / 'Library/Application Support/fan-ssh/profiles')
            with patch.object(sys, 'platform', 'linux'):
                self.assertEqual(profiles.profile_directory(), self.root / 'config/fan-ssh/profiles')

    def test_connect_reuses_existing_ssh_entry_and_remote_command(self):
        profiles.save_profile(self.args())
        with patch('fan_ssh.cli.run', new_callable=AsyncMock, return_value=7) as run:
            code, output, errors = self.invoke('connect', '--profiles-dir', str(self.directory), 'remote', '--', 'uname', '-a')
        self.assertEqual((code, output, errors), (7, '', ''))
        args = run.call_args.args[0]
        self.assertEqual(args.mode, 'ssh')
        self.assertEqual(args.transport, 'auto')
        self.assertEqual(args.peer, 'b')
        command = ssh_command(args)
        self.assertEqual(command[-4:], ['--', 'existing-alias', 'uname', '-a'])
        for option in ('BatchMode=yes', 'StrictHostKeyChecking=yes', 'ForwardAgent=no', 'UpdateHostKeys=no', 'ClearAllForwardings=yes'):
            self.assertIn(option, command)
        if os.name != 'nt':
            words = shlex.split(next(item.partition('=')[2] for item in command if item.startswith('ProxyCommand=')))
            self.assertEqual(words[words.index('--identity') + 1], self.value['identity'])
            self.assertEqual(words[words.index('--policy') + 1], self.value['policy'])

    def test_connect_validates_existing_identity_before_starting_ssh(self):
        profiles.save_profile(self.args())
        with patch('fan_ssh.ssh_cli.ssh_login', new_callable=AsyncMock, return_value=23) as login:
            code, output, errors = self.invoke('connect', '--profiles-dir', str(self.directory), 'remote')
            self.assertEqual(code, 1)
            self.assertIn('INVALID_IDENTITY_DIRECTORY', errors)
            login.assert_not_awaited()
            self.approved()
            code, output, errors = self.invoke('connect', '--profiles-dir', str(self.directory), 'remote')
            self.assertEqual((code, output, errors), (23, '', ''))
            self.assertEqual(login.call_args.args[0].peer, 'b')

    def test_add_prints_working_next_commands_for_custom_directory(self):
        code, output, errors = self.invoke('profile', 'add', 'remote', '--identity', self.value['identity'],
                                           '--policy', self.value['policy'], '--peer', 'b',
                                           '--profiles-dir', str(self.directory))
        self.assertEqual(code, 0, errors)
        self.assertIn('--profiles-dir', output)
        self.assertIn(str(self.directory), output)
        self.assertEqual(profiles.load_profile('remote', self.directory)['transport'], 'auto')

    def test_profile_listing_show_and_first_run_are_readable(self):
        code, output, errors = self.invoke('profile', 'list', '--profiles-dir', str(self.directory))
        self.assertEqual(code, 0, errors)
        self.assertIn('profile add --help', output)
        self.assertFalse(self.directory.exists())
        profiles.save_profile(self.args())
        code, output, errors = self.invoke('profile', 'list', '--profiles-dir', str(self.directory))
        self.assertEqual((code, output, errors), (0, 'remote\n', ''))
        code, output, errors = self.invoke('profile', 'show', 'remote', '--profiles-dir', str(self.directory))
        self.assertEqual(code, 0, errors)
        self.assertEqual(json.loads(output)['connection'], self.value)

    def test_missing_profile_cli_returns_error_without_traceback_or_creation(self):
        for mode in ('connect', 'doctor'):
            code, output, errors = self.invoke(mode, '--profiles-dir', str(self.directory), 'unknown')
            self.assertNotEqual(code, 0)
            self.assertEqual(output, '')
            self.assertIn('PROFILE_NOT_FOUND', errors)
            self.assertNotIn('Traceback', errors)
        self.assertFalse(self.directory.exists())

    def test_doctor_reads_only_and_reports_unchecked_network_and_host_key(self):
        self.approved()
        before = {path: path.read_bytes() for path in self.root.rglob('*') if path.is_file()}
        with patch('fan_ssh.profiles.shutil.which', return_value='/usr/bin/ssh'), \
                patch('socket.socket', side_effect=AssertionError('doctor opened a socket')), \
                patch('fan_ssh.ssh_cli.ssh_login', side_effect=AssertionError('doctor ran SSH')):
            result = profiles.doctor(self.value)
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['scope'], 'offline-only')
        self.assertTrue(any('host key' in item for item in result['not_checked']))
        after = {path: path.read_bytes() for path in self.root.rglob('*') if path.is_file()}
        self.assertEqual(before, after)
        self.assertFalse(self.directory.exists())

    def test_doctor_reports_revoked_acl_and_missing_ssh_independently(self):
        data = self.approved()
        data['allow'] = []
        Path(self.value['policy']).write_text(json.dumps(data))
        with patch('fan_ssh.profiles.shutil.which', return_value=None):
            result = profiles.doctor(self.value)
        self.assertFalse(result['ok'])
        self.assertEqual(len(result['checks']), 2)
        self.assertIn('ACL_DENIED', result['checks'][0]['detail'])
        self.assertIn('SSH_NOT_FOUND', result['checks'][1]['detail'])

    def test_doctor_rejects_identity_not_enrolled(self):
        data = self.approved()
        data['devices'] = [device for device in data['devices'] if device['id'] != 'a']
        data['allow'] = [edge for edge in data['allow'] if 'a' not in (edge['from'], edge['to'])]
        Path(self.value['policy']).write_text(json.dumps(data))
        result = profiles.doctor(self.value)
        self.assertFalse(result['ok'])
        self.assertIn('LOCAL_DEVICE_NOT_APPROVED', result['checks'][0]['detail'])

    def test_doctor_encrypted_identity_returns_actionable_json_and_other_checks(self):
        self.approved()
        key_path = Path(self.value['identity']) / 'key.pem'
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.BestAvailableEncryption(b'temporary-test-only')))
        profiles.save_profile(self.args())
        with patch('fan_ssh.profiles.shutil.which', return_value='/usr/bin/ssh'):
            code, output, errors = self.invoke('doctor', '--profiles-dir', str(self.directory), 'remote')
        self.assertEqual((code, errors), (1, ''))
        result = json.loads(output)
        self.assertFalse(result['ok'])
        self.assertIn('IDENTITY_KEY_UNREADABLE', result['checks'][0]['detail'])
        self.assertTrue(result['checks'][1]['ok'])

    def test_doctor_checks_native_address_and_pinned_optional_dependencies(self):
        self.approved()
        options = dict(self.value, udp_native='192.0.2.99', stun='192.0.2.2:22092')
        with patch('fan_ssh.profiles.version', return_value='wrong'):
            result = profiles.doctor(options)
        self.assertFalse(result['ok'])
        self.assertIn('NATIVE_ADDRESS_NOT_APPROVED', result['checks'][0]['detail'])
        self.assertIn('UDP_VERSION_REQUIRED', result['checks'][-1]['detail'])

    def test_offline_cli_does_not_even_create_an_event_loop_socketpair(self):
        self.approved()
        profiles.save_profile(self.args())
        with patch('socket.socket', side_effect=AssertionError('offline CLI opened a socket')), \
                patch('fan_ssh.profiles.shutil.which', return_value='/usr/bin/ssh'):
            code, output, errors = self.invoke('doctor', '--profiles-dir', str(self.directory), 'remote')
            self.assertEqual(code, 0, errors)
            self.assertTrue(json.loads(output)['ok'])
            code, output, errors = self.invoke('profile', 'list', '--profiles-dir', str(self.directory))
            self.assertEqual((code, output, errors), (0, 'remote\n', ''))

    def test_doctor_cli_exit_code_and_json(self):
        profiles.save_profile(self.args())
        code, output, errors = self.invoke('doctor', '--profiles-dir', str(self.directory), 'remote')
        self.assertEqual(code, 1, errors)
        self.assertFalse(json.loads(output)['ok'])
        self.approved()
        with patch('fan_ssh.profiles.shutil.which', return_value='/usr/bin/ssh'):
            code, output, errors = self.invoke('doctor', '--profiles-dir', str(self.directory), 'remote')
        self.assertEqual(code, 0, errors)
        self.assertTrue(json.loads(output)['ok'])


if __name__ == '__main__':
    unittest.main()
