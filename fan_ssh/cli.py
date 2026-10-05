"""Development CLI. Proxy stdio is raw bytes; diagnostics never use stdout."""
import argparse
import asyncio
from contextlib import suppress
import os
import signal
import sys
import threading
import subprocess

from .session import Session
from .transport import BUFFER, SESSION_TIMEOUT, Service, close_writer


async def proxy(pair, timeout=SESSION_TIMEOUT):
    loop = asyncio.get_running_loop()
    done = loop.create_future()
    errors = []

    def report(error=None):
        if error:
            errors.append(error)
        if not done.done():
            done.set_result(None)

    async def send(data):
        if data:
            pair[1].write(data)
        else:
            pair[1].write_eof()
        await pair[1].drain()

    def input_worker():
        try:
            while True:
                data = os.read(0, BUFFER)
                asyncio.run_coroutine_threadsafe(send(data), loop).result()
                if not data:
                    return
        except Exception as error:
            with suppress(RuntimeError):
                loop.call_soon_threadsafe(report, error)

    def output_worker():
        try:
            while True:
                data = asyncio.run_coroutine_threadsafe(pair[0].read(BUFFER), loop).result()
                if not data:
                    break
                view = memoryview(data)
                while view:
                    count = os.write(1, view)
                    if not count:
                        raise OSError('STDOUT_FAILED')
                    view = view[count:]
            loop.call_soon_threadsafe(report)
        except Exception as error:
            with suppress(RuntimeError):
                loop.call_soon_threadsafe(report, error)

    # Daemons + raw os.read/os.write avoid buffered-I/O finalization locks.
    # This function is a one-shot CLI helper, not an embeddable stdio service.
    for worker in (input_worker, output_worker):
        threading.Thread(target=worker, daemon=True).start()
    try:
        async with asyncio.timeout(timeout):
            await done
        if errors:
            raise OSError('STDIO_FAILED') from errors[0]
    finally:
        await close_writer(pair[1])


async def run(args):
    if args.mode in ('identity-init', 'identity-export', 'policy-build', 'coordinator', 'node', 'home-bridge', 'diagnose') or getattr(args, 'peer', None):
        from .commands import run_remote
        return await run_remote(args, proxy)
    echo = None
    if args.mode == 'demo':
        async def echo_handler(reader, writer):
            while data := await reader.read(BUFFER):
                writer.write(data)
                await writer.drain()
            writer.write_eof()
            await writer.drain()
        echo = await Service(echo_handler).start()
        target = echo.address
    else:
        target = args.target
    try:
        async with Session(target) as session:
            print('DEV ONLY: ephemeral identities; loopback TLS; no NAT traversal or relay; 30-second data deadline', file=sys.stderr)
            if args.mode == 'demo':
                reader, writer = await session.dial()
                try:
                    async with asyncio.timeout(5):
                        payload = b'direct-only encrypted loopback demo\n'
                        writer.write(payload)
                        await writer.drain()
                        received = bytearray()
                        while len(received) < len(payload):
                            data = await reader.read()
                            if not data:
                                raise ValueError('UNEXPECTED_EOF')
                            received.extend(data)
                        if received != payload:
                            raise ValueError('PAYLOAD_MISMATCH')
                        writer.write_eof()
                        await writer.drain()
                        if await reader.read() != b'':
                            raise ValueError('UNEXPECTED_DATA')
                    print('PASS: coordinator-discovered, mutually authenticated direct TLS echo; no relay')
                finally:
                    await close_writer(writer)
            elif args.mode == 'forward':
                service = await session.forward(args.listen)
                print(f'Listening: {service.address} -> fixed target {target}', file=sys.stderr)
                await asyncio.Future()
            else:
                await proxy(await session.dial())
    finally:
        if echo:
            await echo.close()


def main():
    parser = argparse.ArgumentParser(prog='fan-ssh', description='Approved SSH streams over direct peer paths; optional explicit home bridge; no cloud data relay')
    commands = parser.add_subparsers(dest='mode', required=True)
    commands.add_parser('demo')
    for name in ('forward', 'proxy', 'ssh'):
        command = commands.add_parser(name)
        destination = command.add_mutually_exclusive_group(required=True)
        if name != 'ssh':
            destination.add_argument('--target', help='synthetic fixture with fixed numeric loopback TCP target')
        destination.add_argument('--peer', help='approved remote device ID')
        command.add_argument('--identity', help='user-private identity directory (remote mode)')
        command.add_argument('--policy', help='approved roster/ACL file (remote mode)')
        command.add_argument('--service', default='ssh')
        command.add_argument('--transport', choices=('auto', 'tcp', 'udp'), help='remote default: automatic direct methods; no relay fallback')
        command.add_argument('--udp-native', help='explicit approved physical IP; UDP transport requires udp extra')
        command.add_argument('--stun', help='explicit numeric STUN observer for UDP transport')
        command.add_argument('--stun-alternate', help='optional second explicitly approved numeric STUN observer')
        command.add_argument('--udp-strategy', choices=('ice', 'predict'), default='ice', help='explicit UDP strategy; auto mode tries both')
        command.add_argument('--reverse-listen', help='optional numeric high-port listener for reverse direct connections')
        command.add_argument('--reverse-candidate', help='approved advertised address of reverse listener, if different from local bind')
        if name == 'forward':
            command.add_argument('--listen', default='127.0.0.1:2222')
        if name == 'ssh':
            command.add_argument('--ssh-host', help='existing SSH alias for credentials and verified host key; defaults to peer ID')
            command.add_argument('--ssh-user', help='optional existing SSH user')
            command.add_argument('--ssh-port', type=int, help='optional original SSH port for host-key lookup')
            command.add_argument('command', nargs=argparse.REMAINDER, help='optional remote command after --')
    from .commands import add_commands
    add_commands(commands)
    args = parser.parse_args()
    if args.mode in ('proxy', 'forward', 'ssh') and args.transport is None:
        args.transport = 'tcp' if getattr(args, 'target', None) else 'auto'
    if args.mode in ('proxy', 'forward') and args.target:
        if (args.transport != 'tcp' or args.service != 'ssh' or any((args.identity, args.policy,
                args.udp_native, args.stun, args.stun_alternate, args.reverse_listen, args.reverse_candidate))
                or args.udp_strategy != 'ice'):
            parser.error('remote identity/transport options require --peer')
    if os.name == 'nt' and args.mode == 'proxy':
        import msvcrt
        msvcrt.setmode(0, os.O_BINARY)
        msvcrt.setmode(1, os.O_BINARY)

    async def with_signals():
        loop = asyncio.get_running_loop()
        task = asyncio.current_task()
        old = {}
        for sig in (signal.SIGINT, signal.SIGTERM):
            old[sig] = signal.signal(sig, lambda *_: loop.call_soon_threadsafe(task.cancel))
        try:
            return await run(args)
        finally:
            for sig, handler in old.items():
                signal.signal(sig, handler)
    try:
        # Python 3.12 Proactor UDP stalled in sustained bidirectional DTLS tests.
        # Use the verified socket-only selector loop for explicit UDP operation.
        native_udp = getattr(args, 'transport', None) == 'udp' or bool(getattr(args, 'udp_native', None))
        factory = asyncio.SelectorEventLoop if os.name == 'nt' and native_udp else None
        with asyncio.Runner(loop_factory=factory) as runner:
            return runner.run(with_signals()) or 0
    except (KeyboardInterrupt, asyncio.CancelledError):
        print('CANCELLED', file=sys.stderr)
        return 130
    except (OSError, ValueError, TimeoutError, asyncio.IncompleteReadError, subprocess.SubprocessError) as error:
        print(f'FAILED: {type(error).__name__}: {error}', file=sys.stderr)
        return 1
