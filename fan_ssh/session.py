"""Metadata-only, one-record discovery and synthetic directed authorization."""
import asyncio
from dataclasses import asdict, dataclass
import json
import re
import struct
from types import MappingProxyType

from .identity import DemoPKI, require_pin
from .transport import BUFFER, TIMEOUT, Service, address, bridge, close_writer, connect, framed

MAX_METADATA = 4096
NAME = re.compile(r'[A-Za-z0-9_-]{1,64}\Z')
PIN = re.compile(r'[0-9a-f]{64}\Z')


@dataclass(frozen=True)
class Peer:
    id: str
    address: str
    pin: str
    transport: str = 'direct-tcp-tls-framed-v1'

    def validate(self):
        if not NAME.fullmatch(self.id) or not PIN.fullmatch(self.pin) or self.transport != 'direct-tcp-tls-framed-v1':
            raise ValueError('INVALID_METADATA')
        address(self.address)
        return self


async def read_metadata(reader):
    length = struct.unpack('!I', await reader.readexactly(4))[0]
    if length < 1 or length > MAX_METADATA:
        raise ValueError('METADATA_TOO_LARGE')
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('DUPLICATE_METADATA_KEY')
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError('INVALID_JSON_CONSTANT')

    try:
        value = json.loads(await reader.readexactly(length), object_pairs_hook=unique_object,
                           parse_constant=reject_constant)
        pending = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            if depth > 16:
                raise ValueError('METADATA_NESTING_TOO_DEEP')
            if isinstance(item, dict):
                pending.extend((child, depth + 1) for child in item.values())
            elif isinstance(item, list):
                pending.extend((child, depth + 1) for child in item)
        return value
    except RecursionError as error:
        raise ValueError('METADATA_NESTING_TOO_DEEP') from error


async def write_metadata(writer, value):
    payload = json.dumps(value, separators=(',', ':')).encode('utf8')
    if len(payload) > MAX_METADATA:
        raise ValueError('METADATA_TOO_LARGE')
    writer.write(struct.pack('!I', len(payload)) + payload)
    await writer.drain()


class Coordinator:
    """One bounded request, one response, then close; no forwarding methods."""
    def __init__(self, context, members, records, acl):
        self.members = MappingProxyType(dict(members))  # pin -> name
        self.records = MappingProxyType({key: value.validate() for key, value in records.items()})
        self.acl = frozenset(acl)  # directed (caller, destination) pairs
        self.service = Service(self.handle, context)

    async def handle(self, reader, writer):
        async with asyncio.timeout(TIMEOUT):
            caller = self.members[require_pin(writer, self.members)]
            request = await read_metadata(reader)
            if not isinstance(request, dict) or set(request) != {'op', 'target'} or request['op'] != 'lookup':
                raise ValueError('METADATA_LOOKUP_ONLY')
            target = request['target']
            if not isinstance(target, str) or not NAME.fullmatch(target):
                raise ValueError('INVALID_TARGET')
            if (caller, target) not in self.acl or target not in self.records:
                await write_metadata(writer, {'error': 'ACL_DENIED'})
                return
            await write_metadata(writer, asdict(self.records[target]))

    async def start(self):
        await self.service.start()
        return self

    async def close(self):
        await self.service.close()


async def discover(endpoint, context, coordinator_pin, target):
    if not NAME.fullmatch(target):
        raise ValueError('INVALID_TARGET')
    async with asyncio.timeout(TIMEOUT):
        reader, writer = await connect(endpoint, context)
        try:
            require_pin(writer, {coordinator_pin})
            await write_metadata(writer, {'op': 'lookup', 'target': target})
            response = await read_metadata(reader)
            if not isinstance(response, dict) or set(response) != {'id', 'address', 'pin', 'transport'}:
                raise ValueError('DISCOVERY_DENIED')
            if not all(isinstance(value, str) for value in response.values()):
                raise ValueError('INVALID_METADATA')
            peer = Peer(**response).validate()
            if peer.id != target:
                raise ValueError('INVALID_METADATA')
            return peer
        finally:
            await close_writer(writer)


async def connect_peer(peer, context, approved_pin):
    peer.validate()
    if peer.pin != approved_pin:
        raise ValueError('PIN_MISMATCH: discovery cannot replace approved identity')
    pair = await connect(peer.address, context)
    try:
        require_pin(pair[1], {approved_pin})
        return framed(pair)
    except BaseException:
        await close_writer(pair[1])
        raise


class Session:
    def __init__(self, target):
        address(target)
        self.target = target
        self.services = []

    async def __aenter__(self):
        pki = DemoPKI()
        client, server, coordinator = [pki.issue(name) for name in ('client', 'target', 'coordinator')]
        self.client_context = pki.context(client)
        self.approved_pin = server.pin
        self.client_pin = client.pin
        approved_clients = frozenset({client.pin})
        target = self.target  # Freeze operator-selected target, never read peer input for it.

        async def tunnel(reader, writer):
            require_pin(writer, approved_clients)
            upstream = await connect(target)
            await bridge(framed((reader, writer)), upstream)

        try:
            self.tunnel = await Service(tunnel, pki.context(server, server=True)).start()
            self.services.append(self.tunnel)
            expected = Peer('target', self.tunnel.address, server.pin)
            self.coordinator = await Coordinator(pki.context(coordinator, server=True),
                                                  {client.pin: 'client', server.pin: 'target'},
                                                  {'target': expected}, {('client', 'target')}).start()
            self.services.append(self.coordinator)
            self.peer = await discover(self.coordinator.service.address, self.client_context, coordinator.pin, 'target')
            if self.peer.pin != self.approved_pin:
                raise ValueError('PIN_MISMATCH')
            return self
        except BaseException:
            await self.__aexit__(None, None, None)
            raise

    async def dial(self):
        return await connect_peer(self.peer, self.client_context, self.approved_pin)

    async def forward(self, endpoint):
        async def handler(reader, writer):
            await bridge((reader, writer), await self.dial())
        service = await Service(handler).start(endpoint)
        self.services.append(service)
        return service

    async def __aexit__(self, *unused):
        for service in reversed(self.services):
            await service.close()
        self.services.clear()
