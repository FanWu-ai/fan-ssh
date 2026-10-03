"""Bounded asyncio TCP/TLS transport, restricted to numeric loopback."""
import asyncio
from contextlib import suppress
import ipaddress
import socket
import struct

TIMEOUT = 5.0
SESSION_TIMEOUT = 30.0
MAX_CONNECTIONS = 32
BUFFER = 16384


def address(value, *, bind=False):
    if not isinstance(value, str):
        raise ValueError('INVALID_ADDRESS')
    if value.startswith('['):
        host, separator, port = value[1:].partition(']:')
    else:
        host, separator, port = value.rpartition(':')
        if ':' in host:
            raise ValueError('IPv6 requires brackets')
    if not separator or not port.isascii() or not port.isdecimal() or str(int(port)) != port:
        raise ValueError('INVALID_PORT: canonical numeric TCP port required')
    ip = ipaddress.ip_address(host)
    if '%' in host or not ip.is_loopback:
        raise ValueError('NON_LOOPBACK_DENIED')
    if not (0 if bind else 1) <= int(port) <= 65535:
        raise ValueError('INVALID_PORT')
    return str(ip), int(port)


def format_address(pair):
    host, port = pair[:2]
    return f'[{host}]:{port}' if ':' in host else f'{host}:{port}'


async def close_writer(writer):
    writer.close()
    with suppress(Exception):
        await asyncio.wait_for(writer.wait_closed(), 0.5)


async def connect(endpoint, context=None):
    host, port = address(endpoint)
    kwargs = dict(ssl=context, server_hostname='' if context else None, limit=BUFFER)
    if context:
        kwargs.update(ssl_handshake_timeout=TIMEOUT, ssl_shutdown_timeout=0.5)
    return await asyncio.wait_for(asyncio.open_connection(host, port, **kwargs), TIMEOUT)


class FramedReader:
    def __init__(self, reader):
        self.reader, self.eof = reader, False

    async def read(self, size=BUFFER):
        if self.eof:
            return b''
        length = struct.unpack('!I', await self.reader.readexactly(4))[0]
        if length > BUFFER:
            raise ValueError('FRAME_TOO_LARGE')
        if length == 0:
            self.eof = True
            return b''
        return await self.reader.readexactly(length)


class FramedWriter:
    def __init__(self, writer):
        self.writer, self.eof = writer, False

    def write(self, data):
        if self.eof:
            raise ValueError('WRITE_AFTER_EOF')
        for offset in range(0, len(data), BUFFER):
            part = data[offset:offset + BUFFER]
            self.writer.write(struct.pack('!I', len(part)) + part)

    def write_eof(self):
        if not self.eof:
            self.writer.write(b'\0\0\0\0')
            self.eof = True

    async def drain(self):
        await self.writer.drain()

    def close(self):
        self.writer.close()

    async def wait_closed(self):
        await self.writer.wait_closed()


def framed(pair):
    return FramedReader(pair[0]), FramedWriter(pair[1])


async def bridge(a, b, timeout=SESSION_TIMEOUT):
    async def copy(reader, writer):
        while data := await reader.read(BUFFER):
            writer.write(data)
            await writer.drain()
        writer.write_eof()
        await writer.drain()
    tasks = [asyncio.create_task(copy(a[0], b[1])), asyncio.create_task(copy(b[0], a[1]))]
    try:
        async with asyncio.timeout(timeout):
            await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.gather(close_writer(a[1]), close_writer(b[1]))


class Service:
    """Admission cap includes TLS handshakes, not only authenticated handlers."""
    def __init__(self, handler, context=None, limit=MAX_CONNECTIONS):
        self.handler, self.context = handler, context
        self.slots = asyncio.Semaphore(limit)
        self.tasks = set()
        self.listener = None
        self.accept_task = None

    async def start(self, endpoint='127.0.0.1:0'):
        host, port = address(endpoint, bind=True)
        sock = socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind((host, port))
            sock.listen(MAX_CONNECTIONS)
            sock.setblocking(False)
            self.listener = sock
            self.address = format_address(sock.getsockname())
            self.accept_task = asyncio.create_task(self._accept())
            return self
        except BaseException:
            sock.close()
            raise

    async def _accept(self):
        loop = asyncio.get_running_loop()
        while True:
            await self.slots.acquire()
            try:
                sock, _ = await loop.sock_accept(self.listener)
            except BaseException:
                self.slots.release()
                raise
            task = asyncio.create_task(self._handle(sock))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)

    async def _handle(self, sock):
        writer = None
        try:
            loop = asyncio.get_running_loop()
            reader = asyncio.StreamReader(limit=BUFFER)
            protocol = asyncio.StreamReaderProtocol(reader)
            kwargs = {}
            if self.context:
                kwargs = dict(ssl=self.context, ssl_handshake_timeout=TIMEOUT, ssl_shutdown_timeout=0.5)
            transport, _ = await asyncio.wait_for(loop.connect_accepted_socket(lambda: protocol, sock, **kwargs), TIMEOUT)
            writer = asyncio.StreamWriter(transport, protocol, reader, loop)
            await self.handler(reader, writer)
        except (OSError, ValueError, TimeoutError, asyncio.IncompleteReadError):
            pass  # Expected per-connection rejection; never print business bytes.
        finally:
            if writer:
                await close_writer(writer)
            else:
                sock.close()
            self.slots.release()

    async def close(self):
        if self.accept_task:
            self.accept_task.cancel()
            await asyncio.gather(self.accept_task, return_exceptions=True)
        if self.listener:
            self.listener.close()
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
