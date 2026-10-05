"""Minimal bounded IPv4 Binding observations for explicitly approved test peers.

Only known authenticated coordinator-source IPs, 60 small packets/minute/IP.
No allocation, TURN, arbitrary destination, stored payload or forwarding operation.
"""
import asyncio
from collections import defaultdict, deque
import ipaddress
import struct
import time
from .config import direct_address


class Observer(asyncio.DatagramProtocol):
    def __init__(self, control):
        self.control = control
        self.transport = None
        self.rates = defaultdict(deque)
        self.packets = 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, remote):
        approved = set(self.control.observed_ips.values())
        if remote[0] not in approved or not 20 <= len(data) <= 256:
            return
        kind, length, cookie = struct.unpack('!HHI', data[:8])
        if kind != 1 or cookie != 0x2112A442 or length != len(data) - 20:
            return
        now = time.monotonic()
        for ip in tuple(self.rates):
            if ip not in approved:
                del self.rates[ip]
        window = self.rates[remote[0]]
        while window and window[0] <= now - 60:
            window.popleft()
        if len(window) >= 60:
            return
        window.append(now)
        ip = ipaddress.ip_address(remote[0])
        if ip.version != 4:
            return
        attribute = struct.pack('!HHBBHI', 0x0020, 8, 0, 1, remote[1] ^ 0x2112, int(ip) ^ cookie)
        response = struct.pack('!HHI', 0x0101, len(attribute), cookie) + data[8:20] + attribute
        self.transport.sendto(response, remote)
        self.packets += 1

    async def close(self):
        if self.transport:
            self.transport.close()


async def start_observers(control, endpoints):
    """One or two explicitly approved sockets with one aggregate per-IP budget."""
    if not 1 <= len(endpoints) <= 2 or len(set(endpoints)) != len(endpoints):
        raise ValueError('DISTINCT_STUN_LISTENERS_REQUIRED')
    addresses = [direct_address(value) for value in endpoints]
    observers = []
    try:
        for address in addresses:
            observer = Observer(control)
            if observers:
                observer.rates = observers[0].rates
            await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: observer, local_addr=address)
            observers.append(observer)
        return observers
    except BaseException:
        for observer in observers:
            await observer.close()
        raise
