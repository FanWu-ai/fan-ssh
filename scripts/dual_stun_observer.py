"""Temporary IPv4 dual-port STUN observation compatibility tool.

Supports MAPPED, XOR-MAPPED, CHANGED and OTHER address attributes for a frp
reference trial. Both observation ports share one public IP: this is not a full
RFC 5780 NAT/filter classification server. Whitelist, aggregate rate and lifetime
are mandatory limits. No allocation, application payload or forwarding operation.
Network permission for both ports must exist separately before a public test.
"""
import argparse
import asyncio
from collections import defaultdict, deque
import ipaddress
import json
import struct
import sys
import time


def address_attribute(kind, ip, port, xor=False):
    number = int(ipaddress.IPv4Address(ip))
    if xor:
        number ^= 0x2112A442
        port ^= 0x2112
    return struct.pack('!HHBBHI', kind, 8, 0, 1, port, number)


class Observer(asyncio.DatagramProtocol):
    def __init__(self, approved, public, alternate, windows, stats):
        self.approved, self.public, self.alternate = approved, public, alternate
        self.windows, self.stats = windows, stats
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, remote):
        if remote[0] not in self.approved or not 20 <= len(data) <= 256:
            return
        kind, length = struct.unpack('!HH', data[:4])
        if kind != 1 or length != len(data)-20:
            return
        now = time.monotonic()
        window = self.windows[remote[0]]
        while window and window[0] <= now-60:
            window.popleft()
        if len(window) >= 60:
            return
        window.append(now)
        attributes = address_attribute(1, remote[0], remote[1])
        if data[4:8] == struct.pack('!I',0x2112A442):
            attributes += address_attribute(0x20, remote[0], remote[1], xor=True)
        attributes += address_attribute(0x802c, self.public, self.alternate)
        # EasyTier v2.6.4 XOR-decodes legacy CHANGED-ADDRESS. Prefer its supported
        # RFC 5780 OTHER-ADDRESS; frp still reads the legacy attribute below.
        attributes += address_attribute(5, self.public, self.alternate)
        # Preserve the complete transaction bytes for classic and modern STUN.
        reply = struct.pack('!HH',0x101,len(attributes))+data[4:20]+attributes
        self.transport.sendto(reply,remote)
        self.stats['observations'] += 1


async def main(args):
    for ip in [args.bind,args.public,*args.allow]:
        address = ipaddress.IPv4Address(ip)
        if address.is_unspecified or address.is_multicast:
            raise ValueError('EXPLICIT_UNICAST_IPV4_REQUIRED')
    if len(args.allow) > 8 or len(set(args.ports)) != 2 or not all(1024 <= p <= 65535 for p in args.ports):
        raise ValueError('TWO_DISTINCT_HIGH_PORTS_REQUIRED')
    if not 1 <= args.lifetime <= 300:
        raise ValueError('BOUNDED_LIFETIME_REQUIRED')
    windows, stats, transports = defaultdict(deque), {'observations':0}, []
    try:
        for index,port in enumerate(args.ports):
            observer = Observer(set(args.allow),args.public,args.ports[1-index],windows,stats)
            transport,_ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda observer=observer:observer,local_addr=(args.bind,port))
            transports.append(transport)
        print('DUAL_STUN_READY',flush=True)
        if args.stop_on_eof:
            if sys.platform == 'win32':
                raise ValueError('STDIN_WATCH_REQUIRES_POSIX')
            loop = asyncio.get_running_loop()
            stopped = loop.create_future()
            def stop():
                if not stopped.done():
                    stopped.set_result(None)
            loop.add_reader(sys.stdin.fileno(),stop)
            try:
                try: await asyncio.wait_for(stopped,args.lifetime)
                except TimeoutError: pass
            finally:
                loop.remove_reader(sys.stdin.fileno())
        else:
            await asyncio.sleep(args.lifetime)
    finally:
        for transport in transports: transport.close()
        print(json.dumps(stats),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bind',required=True)
    parser.add_argument('--public',required=True)
    parser.add_argument('--allow',action='append',required=True)
    parser.add_argument('--ports',type=int,nargs=2,required=True)
    parser.add_argument('--lifetime',type=int,default=120)
    parser.add_argument('--stop-on-eof',action='store_true',help='POSIX supervisor stdin readability ends the observer')
    asyncio.run(main(parser.parse_args()))
