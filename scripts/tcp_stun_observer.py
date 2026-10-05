"""Bounded, whitelisted IPv4 TCP Binding observer for authorized reference tests.

Only reports a connected client's address. No peer dialing, allocations or data
relay. Two ports on one IP do not establish a cross-IP NAT classification.
Reachability and network authorization must already exist for both high ports.
"""
import argparse
import asyncio
from collections import defaultdict, deque
import ipaddress
import json
import struct
import sys
import time


def binding_response(request, remote):
    if not 20 <= len(request) <= 256:
        return None
    kind, length = struct.unpack('!HH', request[:4])
    if kind != 1 or length != len(request) - 20 or length % 4:
        return None
    address = int(ipaddress.IPv4Address(remote[0]))
    body = struct.pack('!HHBBHI', 1, 8, 0, 1, remote[1], address)
    if request[4:8] == struct.pack('!I', 0x2112A442):
        body += struct.pack('!HHBBHI', 0x20, 8, 0, 1,
                            remote[1] ^ 0x2112, address ^ 0x2112A442)
    return struct.pack('!HH', 0x101, len(body)) + request[4:20] + body


async def serve(args):
    approved = set(args.allow)
    active, windows = set(), defaultdict(deque)
    stats = {'binding_responses': 0}
    servers = []

    async def handle(reader, writer):
        task = asyncio.current_task()
        try:
            remote = writer.get_extra_info('peername')
            if not remote or remote[0] not in approved or len(active) >= 16:
                return
            active.add(task)
            async with asyncio.timeout(4):
                for _ in range(2):
                    header = await reader.readexactly(20)
                    length = struct.unpack('!H', header[2:4])[0]
                    if length > 236 or length % 4:
                        return
                    request = header + await reader.readexactly(length)
                    now, window = time.monotonic(), windows[remote[0]]
                    while window and window[0] <= now - 60:
                        window.popleft()
                    if len(window) >= 60:
                        return
                    response = binding_response(request, remote)
                    if response is None:
                        return
                    window.append(now)
                    writer.write(response)
                    await writer.drain()
                    stats['binding_responses'] += 1
        except (TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
            try:
                async with asyncio.timeout(1):
                    await writer.wait_closed()
            except (TimeoutError, ConnectionError):
                pass
            active.discard(task)

    try:
        for port in args.ports:
            servers.append(await asyncio.start_server(handle, args.bind, port, limit=512))
        print('TCP_STUN_READY', flush=True)
        if args.stop_on_eof:
            if sys.platform == 'win32':
                raise ValueError('STDIN_WATCH_REQUIRES_POSIX')
            loop, stopped = asyncio.get_running_loop(), asyncio.Event()
            loop.add_reader(sys.stdin.fileno(), stopped.set)
            try:
                try:
                    await asyncio.wait_for(stopped.wait(), args.lifetime)
                except TimeoutError:
                    pass
            finally:
                loop.remove_reader(sys.stdin.fileno())
        else:
            await asyncio.sleep(args.lifetime)
    finally:
        for server in servers:
            server.close()
            await server.wait_closed()
        handlers = list(active)
        for task in handlers:
            task.cancel()
        await asyncio.gather(*handlers, return_exceptions=True)
        print(json.dumps(stats), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bind', required=True)
    parser.add_argument('--allow', action='append', required=True)
    parser.add_argument('--ports', type=int, nargs=2, required=True)
    parser.add_argument('--lifetime', type=int, default=120)
    parser.add_argument('--stop-on-eof', action='store_true')
    args = parser.parse_args()
    for ip in [args.bind, *args.allow]:
        address = ipaddress.IPv4Address(ip)
        if address.is_unspecified or address.is_multicast:
            raise ValueError('EXPLICIT_UNICAST_IPV4_REQUIRED')
    if (len(args.allow) > 8 or len(set(args.ports)) != 2
            or any(not 1024 <= port <= 65535 for port in args.ports)
            or not 1 <= args.lifetime <= 300):
        raise ValueError('BOUNDED_TWO_PORT_OBSERVER_REQUIRED')
    asyncio.run(serve(args))
