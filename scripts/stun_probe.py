"""Two small Binding observations from one explicit native socket; no data relay."""
import argparse
import json
import os
import socket
import struct


def decode_binding(reply, transaction):
    """Accept only a complete matching IPv4 Binding response, preferring XOR."""
    if len(reply) < 20 or len(transaction) != 12:
        return None
    kind, length, cookie = struct.unpack('!HHI', reply[:8])
    if (kind != 0x0101 or cookie != 0x2112A442 or length % 4
            or length != len(reply) - 20 or reply[8:20] != transaction):
        return None
    mapped = xor_mapped = None
    offset = 20
    while offset < len(reply):
        if offset + 4 > len(reply):
            return None
        kind, length = struct.unpack('!HH', reply[offset:offset + 4])
        end = offset + 4 + ((length + 3) // 4) * 4
        if end > len(reply):
            return None
        value = reply[offset + 4:offset + 4 + length]
        if kind in (0x0020, 0x0001) and len(value) == 8 and value[:2] == b'\0\1':
            port, address = struct.unpack('!HI', value[2:])
            if kind == 0x0020:
                xor_mapped = [socket.inet_ntoa(struct.pack('!I', address ^ 0x2112A442)), port ^ 0x2112]
            else:
                mapped = [socket.inet_ntoa(struct.pack('!I', address)), port]
        offset = end
    return xor_mapped or mapped


def probe(native, host, ports, alternate=None):
    results = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((native, 0))
        sock.settimeout(3)
        endpoints = [(host, port) for port in ports]
        if alternate:
            other, port = alternate.rsplit(':', 1)
            endpoints = [endpoints[0], (other, int(port)), endpoints[0]]
        if len(endpoints) > 4:
            raise ValueError('OBSERVATION_LIMIT')
        for endpoint in endpoints:
            transaction = os.urandom(12)
            packet = struct.pack('!HHI', 1, 0, 0x2112A442) + transaction
            observed = None
            for _ in range(2):
                sock.sendto(packet, endpoint)
                try:
                    reply, sender = sock.recvfrom(512)
                except socket.timeout:
                    continue
                if sender != endpoint:
                    continue
                observed = decode_binding(reply, transaction)
                if observed:
                    break
            results.append({'observer': endpoint, 'local': sock.getsockname(), 'observed': observed})
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', required=True)
    parser.add_argument('--observer', required=True)
    parser.add_argument('--port', action='append', type=int, required=True)
    parser.add_argument('--alternate', help='explicit second public STUN IP:PORT, then repeat the first observer')
    args = parser.parse_args()
    print(json.dumps(probe(args.native, args.observer, args.port, args.alternate)))
