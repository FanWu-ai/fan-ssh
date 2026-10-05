"""Bounded, consenting native UDP multi-socket traversal diagnostic.

Inspired by frp's multi-socket / random-port NAT traversal. Only fresh MACed
control packets go to the two explicitly supplied peer IPs. This opens no SSH
service, changes no router rules, and never reports application-path success.
"""
import argparse
import asyncio
import hmac
import ipaddress
import json
import os
from pathlib import Path
import secrets
import selectors
import shlex
import socket
import struct
import sys
import time
import zlib


def control_packet(secret, role):
    """A small authenticated STUN Binding message, not a service query."""
    username = ('fan-ssh-birthday-%d' % role).encode('ascii')
    attributes = struct.pack('!HH', 6, len(username)) + username + b'\0' * (-len(username) % 4)
    transaction = hmac.digest(secret, b'fan-ssh-birthday' + bytes([role]), 'sha256')[:12]
    header = struct.pack('!HHI', 1, len(attributes) + 24, 0x2112A442) + transaction
    integrity = hmac.digest(secret.hex().encode('ascii'), header + attributes, 'sha1')
    body = attributes + struct.pack('!HH', 8, 20) + integrity
    message = struct.pack('!HHI', 1, len(body) + 8, 0x2112A442) + transaction + body
    return message + struct.pack('!HHI', 0x8028, 4, zlib.crc32(message) ^ 0x5354554e)


def observation(sock, observer):
    transaction = os.urandom(12)
    request = struct.pack('!HHI', 1, 0, 0x2112A442) + transaction
    sock.settimeout(3)
    for _ in range(2):
        sock.sendto(request, observer)
        try:
            reply, remote = sock.recvfrom(512)
        except socket.timeout:
            continue
        if remote != observer or len(reply) != 32 or reply[8:20] != transaction:
            continue
        kind, length, zero, family, port, ip = struct.unpack('!HHBBHI', reply[20:])
        if (kind, length, zero, family) == (0x20, 8, 0, 1):
            return [socket.inet_ntoa(struct.pack('!I', ip ^ 0x2112A442)), port ^ 0x2112]
    return None


def agent(args):
    sockets = []
    selector = selectors.DefaultSelector()
    try:
        primary = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sockets.append(primary)
        primary.bind((args.native, 0))
        observed = observation(primary, (args.observer, args.port))
        print(json.dumps({'local': primary.getsockname(), 'observed': observed}), flush=True)
        if observed is None:
            return 1
        data = json.loads(sys.stdin.readline(2048))
        peer = tuple(data['peer'])
        if ipaddress.ip_address(peer[0]).version != 4 or not 1024 <= peer[1] <= 65535:
            raise ValueError('APPROVED_IPV4_HIGH_PORT_REQUIRED')
        secret = bytes.fromhex(data['secret'])
        if len(secret) != 32 or data['role'] not in (0, 1):
            raise ValueError('FRESH_CONTROL_SECRET_REQUIRED')
        role = data['role']
        packet = control_packet(secret, role)
        expected = control_packet(secret, 1 - role)
        if role == 0:
            for _ in range(args.sockets - 1):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sockets.append(sock)
                sock.bind((args.native, 0))
        for sock in sockets:
            sock.setblocking(False)
            selector.register(sock, selectors.EVENT_READ)
        original_ttl = {sock: sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL) for sock in sockets}
        warmed, sent, errors, verified, unexpected = 0, 0, 0, 0, 0
        paths, replied = [], {}
        started = time.monotonic()
        if role == 0:
            for sock in sockets:
                try:
                    if args.ttl:
                        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, args.ttl)
                    try:
                        # The normal-TTL variant also compares EasyTier's
                        # three packets per socket against frp's TTL warmup.
                        for _ in range(3 if args.ttl == 0 else 1):
                            sock.sendto(packet, peer)
                            warmed += 1
                    finally:
                        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, original_ttl[sock])
                except OSError:
                    errors += 1
                time.sleep(.004)
        random_ports = secrets.SystemRandom().sample(range(1024, 65536), args.probes)
        next_send, index = started + 3, 0
        deadline = started + 20
        while time.monotonic() < deadline:
            now = time.monotonic()
            if role == 1 and index < len(random_ports) and now >= next_send:
                try:
                    primary.sendto(packet, (peer[0], random_ports[index]))
                    sent += 1
                except OSError:
                    errors += 1
                index += 1
                next_send = now + .01
            timeout = min(.03, max(0, next_send - now)) if role == 1 and index < len(random_ports) else .03
            for key, _ in selector.select(timeout):
                sock = key.fileobj
                try:
                    value, remote = sock.recvfrom(512)
                except OSError:
                    errors += 1
                    continue
                if remote[0] != peer[0] or not hmac.compare_digest(value, expected):
                    unexpected += 1
                    continue
                verified += 1
                path = {'local': list(sock.getsockname()), 'peer': list(remote)}
                if path not in paths and len(paths) < 8:
                    paths.append(path)
                identifier = (sock.fileno(), remote)
                if replied.get(identifier, 0) < 2:
                    sock.sendto(packet, remote)
                    sent += 1
                    replied[identifier] = replied.get(identifier, 0) + 1
        restored = all(sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL) == original_ttl[sock] for sock in sockets)
        print(json.dumps({'strategy': 'multi-socket-random-port', 'role': role,
                          'socket_count': len(sockets), 'random_ports_attempted': index,
                          'warmup_packets': warmed, 'sent_packets': sent, 'ttl': args.ttl,
                          'ttl_restored': restored, 'verified_packets': verified,
                          'verified_paths': paths, 'unexpected_packets': unexpected,
                          'socket_errors': errors, 'relay': False, 'application_validated': False}), flush=True)
        return 0
    finally:
        selector.close()
        for sock in sockets:
            sock.close()


async def run(args):
    inventory = json.loads(args.inventory.read_text(encoding='utf8'))
    if len(inventory['peers']) != 2:
        raise ValueError('TWO_EXPLICIT_PEERS_REQUIRED')
    code = Path(__file__).read_text(encoding='utf8')
    children = []
    try:
        for item in inventory['peers']:
            command = shlex.join([item['python'], '-u', '-c', code, '--agent', '--native', item['native'],
                                  '--observer', inventory['observer'], '--port', str(inventory['port']),
                                  '--sockets', str(args.sockets), '--probes', str(args.probes), '--ttl', str(args.ttl)])
            child = await asyncio.create_subprocess_exec('ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                                                        '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes',
                                                        '-o', 'ConnectTimeout=8', item['host'], command,
                                                        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE)
            children.append(child)
        async def receive(child, timeout):
            line = await asyncio.wait_for(child.stdout.readline(), timeout)
            if not line:
                error = await asyncio.wait_for(child.stderr.read(4096), 5)
                args.output.with_suffix('.stderr.log').write_bytes(error)
                raise ValueError('PROBE_AGENT_EXITED')
            return json.loads(line)
        bindings = await asyncio.gather(*(receive(child, 20) for child in children))
        if any(not item['observed'] for item in bindings):
            raise ValueError('STUN_OBSERVATION_REQUIRED')
        secret = os.urandom(32).hex()
        for index, child in enumerate(children):
            child.stdin.write(json.dumps({'peer': bindings[1-index]['observed'], 'secret': secret, 'role': index}).encode() + b'\n')
            await child.stdin.drain()
        results = await asyncio.gather(*(receive(child, 25) for child in children))
        args.output.write_text(json.dumps({'bindings': bindings, 'results': results}, indent=2), encoding='utf8')
        print('Multi-socket authenticated packets:', [item['verified_packets'] for item in results], flush=True)
    finally:
        for child in children:
            if child.stdin:
                child.stdin.close()
            if child.returncode is None:
                try:
                    await asyncio.wait_for(child.wait(), 5)
                except TimeoutError:
                    child.kill()
                    await child.wait()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent', action='store_true')
    parser.add_argument('--native')
    parser.add_argument('--observer')
    parser.add_argument('--port', type=int)
    parser.add_argument('--sockets', type=int, choices=(64, 128, 256), default=256)
    parser.add_argument('--probes', type=int, choices=(256, 512, 1000), default=1000)
    parser.add_argument('--ttl', type=int, choices=(0, 4, 7), default=7)
    parser.add_argument('--inventory', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.agent:
        raise SystemExit(agent(args))
    asyncio.run(run(args))
