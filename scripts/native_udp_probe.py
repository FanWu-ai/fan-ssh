"""Consenting two-host UDP control-packet diagnostic; no SSH/business forwarding."""
import argparse
import asyncio
import hashlib
import hmac
import json
import os
from pathlib import Path
import shlex
import socket
import struct
import subprocess
import sys
import time
import zlib


def stun_packet(secret, role):
    """RFC 8489 short-term USERNAME, SHA-1 MESSAGE-INTEGRITY and FINGERPRINT.

    Both diagnostic agents explicitly select SHA-1 for aioice interoperability;
    this is a small authenticated Binding probe, never an application transport.
    """
    username = ('fan-ssh-%d' % role).encode('ascii')
    attributes = struct.pack('!HH', 6, len(username)) + username + b'\0' * (-len(username) % 4)
    transaction = hmac.digest(secret, b'fan-ssh-stun-probe' + bytes([role]), 'sha256')[:12]
    header = struct.pack('!HHI', 1, len(attributes) + 24, 0x2112A442) + transaction
    integrity = hmac.digest(secret.hex().encode('ascii'), header + attributes, 'sha1')
    body = attributes + struct.pack('!HH', 8, 20) + integrity
    message = struct.pack('!HHI', 1, len(body) + 8, 0x2112A442) + transaction + body
    return message + struct.pack('!HHI', 0x8028, 4, zlib.crc32(message) ^ 0x5354554e)


def agent(args):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((args.native, args.local_port))
        sock.settimeout(3)
        observed = None
        transaction = os.urandom(12)
        request = struct.pack('!HHI', 1, 0, 0x2112A442) + transaction
        for _ in range(2):
            sock.sendto(request, (args.observer, args.port))
            try:
                reply, remote = sock.recvfrom(512)
            except socket.timeout:
                continue
            if remote != (args.observer, args.port) or len(reply) != 32 or reply[8:20] != transaction:
                continue
            kind, length, zero, family, port, ip = struct.unpack('!HHBBHI', reply[20:])
            if (kind, length, zero, family) == (0x20, 8, 0, 1):
                observed = (socket.inet_ntoa(struct.pack('!I', ip ^ 0x2112A442)), port ^ 0x2112)
                break
        print(json.dumps({'local': sock.getsockname(), 'observed': observed}), flush=True)
        if not observed:
            return 1
        data = json.loads(sys.stdin.readline(2048))
        peer = tuple(data['peer'])
        socket.inet_aton(peer[0])
        if not 1024 <= peer[1] <= 65535:
            raise ValueError('HIGH_PORT_REQUIRED')
        secret = bytes.fromhex(data['secret'])
        if len(secret) != 32:
            raise ValueError('CONTROL_NONCE_REQUIRED')
        local_tag = b'FSSH-PROBE\0' + bytes([data['role']])
        peer_tag = b'FSSH-PROBE\0' + bytes([1 - data['role']])
        packet = local_tag + hmac.digest(secret, local_tag, 'sha256')
        expected = peer_tag + hmac.digest(secret, peer_tag, 'sha256')
        if args.wire == 'stun':
            packet, expected = stun_packet(secret, data['role']), stun_packet(secret, 1 - data['role'])
        warmed = 0
        if data.get('strategy') == 'predict':
            if data['role'] == 1:
                # Only a bounded neighborhood of this consenting peer's observation.
                original = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                try:
                    for port in range(max(1024, peer[1]-5), min(65535, peer[1]+5)+1):
                        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, data['ttl'])
                        try:
                            sock.sendto(packet, (peer[0], port))
                        finally:
                            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, original)
                        warmed += 1
                        time.sleep(.002)
                finally:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, original)
            else:
                time.sleep(1)
        received, verified, unexpected = [], 0, []
        sent = 0
        for _ in range(40):
            if data.get('strategy') != 'predict' or data['role'] == 0:
                sock.sendto(packet, peer)
                sent += 1
            until = time.monotonic() + 0.25
            while time.monotonic() < until:
                sock.settimeout(max(0.001, until - time.monotonic()))
                try:
                    value, source = sock.recvfrom(512)
                except socket.timeout:
                    break
                if hmac.compare_digest(value, expected):
                    verified += 1
                    if list(source) not in received:
                        received.append(list(source))
                    if data.get('strategy') == 'predict' and data['role'] == 1:
                        sock.sendto(packet, source)
                        sent += 1
                elif list(source) not in unexpected and len(unexpected) < 8:
                    unexpected.append(list(source))
        print(json.dumps({'verified_packets': verified, 'peer_sources': received, 'sent_packets': sent,
                          'warmup_packets': warmed, 'strategy': data.get('strategy', 'basic'),
                          'unexpected_datagram_sources': unexpected, 'wire': args.wire}), flush=True)
    return 0


async def run(args):
    inventory = json.loads(args.inventory.read_text(encoding='utf8'))
    code = Path(__file__).read_text(encoding='utf8')
    children = []
    try:
        for item in inventory['peers']:
            command = shlex.join([item['python'], '-u', '-c', code, '--agent', '--native', item['native'],
                                  '--observer', inventory['observer'], '--port', str(inventory['port']),
                                  '--local-port', str(item.get('bind_port', 0)), '--wire', args.wire])
            child = await asyncio.create_subprocess_exec('ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                                                        '-o', 'ForwardAgent=no', '-o', 'ConnectTimeout=8', item['host'], command,
                                                        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE)
            children.append(child)
        async def receive(child):
            line = await asyncio.wait_for(child.stdout.readline(), 20)
            if not line:
                error = await asyncio.wait_for(child.stderr.read(4096), 5)
                args.output.with_suffix('.stderr.log').write_bytes(error)
                raise ValueError('PROBE_AGENT_EXITED')
            return json.loads(line)
        bindings = await asyncio.gather(*(receive(child) for child in children))
        if len(bindings) != 2 or any(not item['observed'] for item in bindings):
            raise ValueError('STUN_OBSERVATION_REQUIRED')
        secret = os.urandom(32).hex()
        for index, child in enumerate(children):
            child.stdin.write(json.dumps({'peer': bindings[1-index]['observed'], 'secret': secret, 'role': index,
                                         'strategy': args.strategy, 'ttl': args.warmup_ttl}).encode() + b'\n')
            await child.stdin.drain()
        results = await asyncio.gather(*(receive(child) for child in children))
        args.output.write_text(json.dumps({'bindings': bindings, 'results': results}, indent=2), encoding='utf8')
        print('Authenticated control packets received:', [item['verified_packets'] for item in results])
    finally:
        for child in children:
            if child.returncode is None:
                try:
                    await asyncio.wait_for(child.wait(), 5)
                except TimeoutError:
                    child.kill(); await child.wait()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent', action='store_true')
    parser.add_argument('--native')
    parser.add_argument('--observer')
    parser.add_argument('--port', type=int)
    parser.add_argument('--local-port', type=int, default=0)
    parser.add_argument('--wire', choices=('hmac', 'stun'), default='hmac', help='STUN-formatted authenticated probe for protocol-filter comparison')
    parser.add_argument('--strategy', choices=('basic', 'predict'), default='basic')
    parser.add_argument('--warmup-ttl', choices=(4, 7), type=int, default=7)
    parser.add_argument('--inventory', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.agent:
        raise SystemExit(agent(args))
    asyncio.run(run(args))
