import argparse
import contextlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
import tempfile
from unittest.mock import patch

from fan_ssh import cli, profiles
from fan_ssh.ssh_cli import ssh_command
from types import SimpleNamespace

repo = Path(sys.argv[1])
checks = []
def run(arguments, cwd, expected=0):
    process = subprocess.run([sys.executable, '-m', 'fan_ssh', *arguments], cwd=cwd,
                             capture_output=True, text=True, encoding='utf8', timeout=30)
    print('COMMAND:', 'python -m fan_ssh', shlex.join(arguments))
    print('EXIT:', process.returncode)
    print(process.stdout, process.stderr, sep='')
    assert process.returncode == expected, process.stderr
    checks.append(arguments)
    return process

with tempfile.TemporaryDirectory(prefix='fan-usability-') as temporary:
    root = Path(temporary)
    for args in (['--help'], ['profile', '--help'], ['profile', 'add', '--help'],
                 ['profile', 'list', '--help'], ['profile', 'show', '--help'],
                 ['connect', '--help'], ['doctor', '--help'], ['ssh', '--help'],
                 ['proxy', '--help'], ['forward', '--help']):
        run(args, root)
    saved = root / 'saved profiles'
    run(['profile', 'list', '--profiles-dir', str(saved)], root)
    for identifier in ('control', 'a', 'b'):
        run(['identity-init', '--id', identifier, '--directory', identifier,
             '--public', identifier+'.public.json'], root)
    run(['policy-build', '--account', 'synthetic', '--revision', '1', '--coordinator', 'control',
         '--coordinator-address', '127.0.0.1:22090',
         '--device', 'control.public.json', '--device', 'a.public.json', '--device', 'b.public.json',
         '--candidate', 'a=127.0.0.2:22022', '--candidate', 'b=127.0.0.3:22022',
         '--allow', 'a:b:ssh', '--output', 'network.policy.json'], root)
    add = ['profile', 'add', 'remote', '--profiles-dir', str(saved), '--identity', 'a',
           '--policy', 'network.policy.json', '--peer', 'b', '--ssh-host', 'existing-alias',
           '--ssh-user', 'example-user', '--ssh-port', '2222', '--udp-native', '127.0.0.2',
           '--stun', '127.0.0.1:22092', '--stun-alternate', '127.0.0.1:22093']
    run(add, root)
    run(add, root, 1)
    elsewhere = root / 'different cwd'
    elsewhere.mkdir()
    shown = run(['profile', 'show', 'remote', '--profiles-dir', str(saved)], elsewhere)
    value = json.loads(shown.stdout)['connection']
    assert value['identity'] == str(root/'a') and value['policy'] == str(root/'network.policy.json')
    run(['profile', 'list', '--profiles-dir', str(saved)], elsewhere)
    doctor = run(['doctor', '--profiles-dir', str(saved), 'remote'], elsewhere)
    assert json.loads(doctor.stdout)['ok'] and json.loads(doctor.stdout)['scope'] == 'offline-only'
    before = {str(p): p.read_bytes() for p in root.rglob('*') if p.is_file()}
    with patch('socket.socket', side_effect=AssertionError('offline doctor opened socket')), \
         patch('fan_ssh.ssh_cli.ssh_login', side_effect=AssertionError('offline doctor ran SSH')), \
         patch.object(sys, 'argv', ['fan-ssh', 'doctor', '--profiles-dir', str(saved), 'remote']), \
         contextlib.redirect_stdout(io.StringIO()) as output:
        assert cli.main() == 0
        assert json.loads(output.getvalue())['ok']
    assert before == {str(p): p.read_bytes() for p in root.rglob('*') if p.is_file()}
    print('PASS: doctor guarded against sockets/SSH and wrote no fixture files, including UDP dependency check')
    command = ssh_command(SimpleNamespace(**value, command=['--', 'uname', '-a']))
    config = root / 'empty-ssh-config'
    config.write_text('')
    checked = subprocess.run([command[0], '-F', str(config), '-G', *command[1:]],
                             capture_output=True, timeout=10)
    assert checked.returncode == 0, checked.stderr
    lines = dict(x.partition(b' ')[::2] for x in checked.stdout.splitlines())
    assert lines[b'proxycommand'] == next(x.partition('=')[2].encode() for x in command if x.startswith('ProxyCommand='))
    for key, expected in [(b'stricthostkeychecking', b'true'), (b'batchmode', b'yes'),
                          (b'forwardagent', b'no'), (b'updatehostkeys', b'false'),
                          (b'clearallforwardings', b'yes'), (b'user', b'example-user'), (b'port', b'2222')]:
        assert lines[key] == expected, (key, lines[key])
    assert 'UserKnownHostsFile' not in ' '.join(command)
    print('PASS: saved connect options preserve strict OpenSSH effective proxy/user/port/auth settings using empty synthetic config; no login')
    run(['connect', '--profiles-dir', str(saved), 'missing'], elsewhere, 2)
    run(['doctor', '--profiles-dir', str(saved), 'missing'], elsewhere, 1)

class Parsed(Exception):
    pass
original = argparse.ArgumentParser.parse_args
def capture(parser, *args, **kwargs):
    original(parser, *args, **kwargs)
    raise Parsed()
readme = (repo/'README.md').read_text(encoding='utf8')
count = 0
for block in re.findall(r'```(?:sh|powershell)\n(.*?)```', readme, re.S):
    for line in block.replace('\\\n', ' ').splitlines():
        line = line.strip()
        if line.startswith('python -m fan_ssh '):
            arguments = shlex.split(line)[3:]
        elif line.startswith('fan-ssh '):
            arguments = shlex.split(line)[1:]
        else:
            continue
        with patch.object(sys, 'argv', ['fan-ssh', *arguments]), patch.object(argparse.ArgumentParser, 'parse_args', capture):
            try:
                cli.main()
            except Parsed:
                count += 1
                print('README ARGUMENTS PASS:', shlex.join(arguments))
            else:
                raise AssertionError('README command was not parsed')
print('PASS:', len(checks), 'CLI subprocess checks;', count, 'README examples parsed; synthetic offline/effective-SSH checks')
