"""Existing OpenSSH authentication over the actual Python peer transport."""
import asyncio
import os
from pathlib import Path
import shlex
import subprocess
import sys


def ssh_command(args):
    target = args.ssh_host or args.peer
    if not target or target.startswith('-') or any(c in target for c in '\r\n\0'):
        raise ValueError('INVALID_SSH_HOST')
    if args.ssh_port is not None and not 1 <= args.ssh_port <= 65535:
        raise ValueError('INVALID_SSH_PORT')
    proxy = [sys.executable, '-m', 'fan_ssh', 'proxy',
             '--identity', str(Path(args.identity).resolve()),
             '--policy', str(Path(args.policy).resolve()), '--peer', args.peer,
             '--service', args.service, '--transport', args.transport]
    for key in ('udp_native', 'stun', 'stun_alternate', 'udp_strategy',
                'reverse_listen', 'reverse_candidate'):
        value = getattr(args, key, None)
        if value is not None:
            proxy.extend(('--' + key.replace('_', '-'), value))
    if os.name == 'nt':
        # cmd expands percent references even inside quotes. Fail rather than
        # reinterpret an identity/policy path as another shell command.
        if any(any(c in value for c in '%&|<>^\r\n') for value in proxy):
            raise ValueError('UNSUPPORTED_WINDOWS_PROXY_ARGUMENT')
        proxy_command = subprocess.list2cmdline(proxy)
    else:
        proxy_command = shlex.join(proxy)
    command = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
               '-o', 'ForwardAgent=no', '-o', 'UpdateHostKeys=no',
               '-o', 'ClearAllForwardings=yes', '-o', 'ConnectTimeout=120',
               # OpenSSH accepts whichever of ProxyCommand/ProxyJump occurs first.
               # The direct Python proxy must win, including against "none".
               '-o', 'ProxyCommand=' + proxy_command, '-o', 'ProxyJump=none']
    if args.ssh_user:
        command.extend(('-l', args.ssh_user))
    if args.ssh_port:
        command.extend(('-p', str(args.ssh_port)))
    remote = args.command[1:] if args.command[:1] == ['--'] else args.command
    command.extend(('--', target, *remote))
    return command


async def ssh_login(args):
    command = ssh_command(args)
    checked = await asyncio.to_thread(subprocess.run, [command[0], '-G', *command[1:]],
                                      capture_output=True, timeout=10)
    active = [line.partition(b' ')[2].strip() for line in checked.stdout.splitlines()
              if line.startswith(b'proxycommand ')]
    expected = next(value.split('=', 1)[1] for value in command if value.startswith('ProxyCommand='))
    if checked.returncode or active != [expected.encode()]:
        raise ValueError('SSH_PYTHON_PROXY_NOT_ACTIVE')
    process = subprocess.Popen(command)  # Inherit native terminal/stdin/stdout.
    try:
        return await asyncio.to_thread(process.wait)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                await asyncio.to_thread(process.wait, timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                await asyncio.to_thread(process.wait, timeout=3)
