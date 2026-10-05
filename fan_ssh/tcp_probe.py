"""Explicitly experimental Linux source-bound TCP mapping and simultaneous-open.

Only an independently approved coordinator and one consenting exact peer tuple.
No listener fallback, SO_REUSEPORT, arbitrary port sweep, raw socket or OS changes.
SO_REUSEADDR here is a Linux research gate; it is never enabled on Windows.
"""
import asyncio
import socket
import sys

from .config import direct_address
from .device import tls_context
from .identity import require_pin
from .session import read_metadata, write_metadata
from .transport import TIMEOUT, close_writer, format_address


class Binding:
    def __init__(self, native_ip, *, passive=False):
        if not sys.platform.startswith('linux'):
            raise ValueError('TCP_SO_SOCKET_UNSUPPORTED')
        direct_address(f'[{native_ip}]:22022' if ':' in native_ip else f'{native_ip}:22022')
        self.native_ip = native_ip
        self.family = socket.AF_INET6 if ':' in native_ip else socket.AF_INET
        self.observer = self.new_socket((native_ip, 0))
        self.local = self.observer.getsockname()
        self.listener = None
        try:
            # Prebind all sockets before using either; retain the observation socket.
            self.peer = self.new_socket(self.local)
            self.secondary = self.new_socket(self.local)
            if passive:
                self.listener = self.new_socket(self.local)
                self.listener.listen(8)
        except BaseException:
            self.observer.close()
            for resource in ('peer', 'secondary', 'listener'):
                if getattr(self, resource, None):
                    getattr(self, resource).close()
            raise
        self.control = None
        self.secondary_control = None

    def new_socket(self, local):
        sock = socket.socket(self.family, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setblocking(False)
            sock.bind(local)
            return sock
        except BaseException:
            sock.close()
            raise

    async def observe(self, identity, policy, secondary_endpoint=None):
        remote = direct_address(policy.endpoint)
        async with asyncio.timeout(TIMEOUT):
            await asyncio.get_running_loop().sock_connect(self.observer, remote)
            self.control = await asyncio.open_connection(sock=self.observer, ssl=tls_context(identity, policy),
                                                         server_hostname='', ssl_handshake_timeout=TIMEOUT)
            require_pin(self.control[1], {policy.devices[policy.coordinator].pin})
            await write_metadata(self.control[1], {'op': 'observe'})
            response = await read_metadata(self.control[0])
            if not isinstance(response, dict) or set(response) != {'observed', 'hold_ms'} or response['hold_ms'] != 15000:
                raise ValueError('INVALID_OBSERVATION')
            direct_address(response['observed'])
            result = {'local': format_address(self.local), 'observed': response['observed']}
        if secondary_endpoint:
            async with asyncio.timeout(TIMEOUT):
                await asyncio.get_running_loop().sock_connect(self.secondary, direct_address(secondary_endpoint))
                self.secondary_control = await asyncio.open_connection(sock=self.secondary, ssl=tls_context(identity, policy),
                                                                       server_hostname='', ssl_handshake_timeout=TIMEOUT)
                require_pin(self.secondary_control[1], {policy.devices[policy.coordinator].pin})
                await write_metadata(self.secondary_control[1], {'op': 'observe'})
                second = await read_metadata(self.secondary_control[0])
                if not isinstance(second, dict) or set(second) != {'observed', 'hold_ms'} or second['hold_ms'] != 15000:
                    raise ValueError('INVALID_OBSERVATION')
                direct_address(second['observed'])
                result['secondary_observed'] = second['observed']
                result['mapping_changed_by_observer_port'] = second['observed'] != response['observed']
        return result

    async def connect(self, observed_peer):
        remote = direct_address(observed_peer)
        if (':' in remote[0]) != (self.family == socket.AF_INET6):
            raise ValueError('ADDRESS_FAMILY_MISMATCH')
        async with asyncio.timeout(TIMEOUT):
            await asyncio.get_running_loop().sock_connect(self.peer, remote)
        if self.peer.getsockname()[:2] != self.local[:2] or self.peer.getpeername()[:2] != remote:
            raise ValueError('TCP_SO_TUPLE_MISMATCH')
        return self.peer

    async def accept(self):
        if self.listener is None:
            raise ValueError('EXPLICIT_PASSIVE_LISTENER_REQUIRED')
        async with asyncio.timeout(TIMEOUT):
            sock, _ = await asyncio.get_running_loop().sock_accept(self.listener)
        sock.setblocking(False)
        return sock

    async def close(self):
        if self.control:
            await close_writer(self.control[1])
        else:
            self.observer.close()
        self.peer.close()
        if self.listener:
            self.listener.close()
        if self.secondary_control:
            await close_writer(self.secondary_control[1])
        else:
            self.secondary.close()


async def server_stream(sock, context):
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=16384)
    protocol = asyncio.StreamReaderProtocol(reader)
    transport, _ = await loop.connect_accepted_socket(lambda: protocol, sock, ssl=context,
                                                     ssl_handshake_timeout=TIMEOUT, ssl_shutdown_timeout=0.5)
    return reader, asyncio.StreamWriter(transport, protocol, reader, loop)
