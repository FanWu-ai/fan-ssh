"""Development CLI. Proxy stdio is raw bytes; diagnostics never use stdout."""
import argparse
import asyncio
from contextlib import suppress
import os
import signal
import sys
import threading

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
    parser = argparse.ArgumentParser(prog='fan-ssh', description='Loopback-only synthetic direct SSH transport research')
    commands = parser.add_subparsers(dest='mode', required=True)
    commands.add_parser('demo')
    for name in ('forward', 'proxy'):
        command = commands.add_parser(name)
        command.add_argument('--target', required=True, help='fixed numeric loopback TCP target')
        if name == 'forward':
            command.add_argument('--listen', default='127.0.0.1:2222')
    args = parser.parse_args()
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
            await run(args)
        finally:
            for sig, handler in old.items():
                signal.signal(sig, handler)
    try:
        asyncio.run(with_signals())
        return 0
    except (KeyboardInterrupt, asyncio.CancelledError):
        print('CANCELLED', file=sys.stderr)
        return 130
    except (OSError, ValueError, TimeoutError, asyncio.IncompleteReadError) as error:
        print(f'FAILED: {type(error).__name__}: {error}', file=sys.stderr)
        return 1
