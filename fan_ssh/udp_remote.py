"""Explicit native ICE signaling, admission and renewable service sessions."""
import asyncio

from .config import direct_address, schema
from .control import ControlConnection, request
from .grants import UDP_TRANSPORT, verify
from .remote import MAX_SESSION, check_ready
from .session import read_metadata, write_metadata
from .transport import framed
from .udp_path import UDPPath


class UDPPeer:
    def __init__(self, identifier, identity, policy, native, stun, *, context, strategy='ice', alternate=None):
        self.identifier, self.identity, self.policy = identifier, identity, policy
        self.native, self.stun, self.context = native, stun, context
        # Bind only the address explicitly approved for this device.
        if native not in {direct_address(candidate)[0] for candidate in policy.devices[identifier].candidates}:
            raise ValueError('NATIVE_ADDRESS_NOT_APPROVED')
        direct_address(stun)
        if strategy not in ('ice', 'predict', 'auto'):
            raise ValueError('INVALID_UDP_STRATEGY')
        if alternate:
            direct_address(alternate)
        self.strategy, self.alternate = strategy, alternate
        self.paths = set()
        self.pending = 0
        self.closed = False

    async def path(self, peer, controlling, observed=None, strategy=None, connection=None):
        if self.closed:
            raise ValueError('UDP_PEER_CLOSED')
        if len(self.paths) + self.pending >= 32:
            raise ValueError('UDP_SESSION_CAPACITY')
        # Reserve before the first network await; concurrent callers share the cap.
        self.pending += 1
        try:
            if observed is None:
                scope = await request(self.identity, self.policy, {'op': 'udp_scope', 'peer': peer},
                                      context=self.context, connection=connection)
                schema(scope, ('ip',))
                observed = scope['ip']
            if self.closed:
                raise ValueError('UDP_PEER_CLOSED')
            path = UDPPath(self.identifier, self.identity, self.policy, peer, self.native, self.stun,
                           controlling=controlling, peer_observed_ip=observed,
                           strategy=strategy or ('ice' if self.strategy == 'auto' else self.strategy),
                           alternate=self.alternate)
            self.paths.add(path)
            return path
        finally:
            self.pending -= 1

    async def release(self, path):
        try:
            await path.close()
        finally:
            self.paths.discard(path)

    async def close(self):
        self.closed = True
        await asyncio.gather(*(self.release(path) for path in tuple(self.paths)))


class UDPClient(UDPPeer):
    async def dial(self, peer, service='ssh'):
        attempts = 2 if self.strategy == 'predict' else 1
        for number in range(1, attempts + 1):
            try:
                pair, report = await self.dial_once(peer, service)
                return pair, dict(report, connection_attempt=number)
            except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
                if number == attempts:
                    raise
                await asyncio.sleep(0.1)

    async def dial_once(self, peer, service='ssh'):
        if not self.policy.permits(self.identifier, peer, service):
            raise ValueError('ACL_DENIED')
        connection = ControlConnection(self.identity, self.policy, context=self.context)
        path = None
        try:
            path = await self.path(peer, True, connection=connection)
            ice = await path.gather()
            reply = await request(self.identity, self.policy, {'op': 'udp_grant', 'target': peer, 'service': service},
                                  context=self.context, connection=connection)
            schema(reply, ('grant',))
            grant = reply['grant']
            claims = verify(grant, self.policy)
            if (claims['source'], claims['target'], claims['service'], claims['direction'], claims['transport'], claims['serial']) != (
                    self.identifier, peer, service, 'forward', UDP_TRANSPORT, 0):
                raise ValueError('SESSION_BINDING_REJECTED')
            if await request(self.identity, self.policy, {'op': 'udp_offer', 'grant': grant, 'ice': ice},
                             context=self.context, connection=connection) != {'ok': True}:
                raise ValueError('UDP_OFFER_REJECTED')
            async with asyncio.timeout(25):
                while True:
                    reply = await request(self.identity, self.policy, {'op': 'udp_result', 'grant': grant},
                                          context=self.context, connection=connection)
                    schema(reply, ('answer',))
                    if reply['answer'] is not None:
                        schema(reply['answer'], ('ice', 'observed_ip'))
                        # The coordinator observed this IP on the authenticated target's control socket.
                        # Retain independent pin and approved native-address checks.
                        if reply['answer']['observed_ip'] not in path.allowed_peer_ips:
                            raise ValueError('UDP_PEER_OBSERVATION_CHANGED')
                        pair = await path.connect(reply['answer']['ice'])
                        break
                    await asyncio.sleep(0.5)
                await write_metadata(pair[1], {'op': 'open', 'grant': grant})
                check_ready(await read_metadata(pair[0]), claims)
                path.report['service_ready'] = True
            reader, writer = framed(pair)
            return (reader, PathWriter(writer, self, path)), path.report
        except BaseException:
            if path is not None:
                await self.release(path)
            raise
        finally:
            await connection.close()


class PathWriter:
    def __init__(self, writer, owner, path):
        self.writer, self.owner, self.path = writer, owner, path
        self.closer = None

    def __getattr__(self, name):
        return getattr(self.writer, name)

    def close(self):
        self.writer.close()
        if self.closer is None:
            self.closer = asyncio.create_task(self.owner.release(self.path))

    async def wait_closed(self):
        if self.closer:
            await self.closer


class UDPNode(UDPPeer):
    def __init__(self, node, native, stun, *, strategy='auto', alternate=None):
        super().__init__(node.identifier, node.identity, node.policy, native, stun, context=node.client_context,
                         strategy=strategy, alternate=alternate)
        self.node = node

    async def accept(self, offer):
        path = None
        try:
            schema(offer, ('grant', 'ice', 'observed_ip'))
            claims = verify(offer['grant'], self.node.policy)
            if claims['target'] != self.identifier or claims['transport'] != UDP_TRANSPORT or claims['direction'] != 'forward':
                raise ValueError('INVALID_UDP_OFFER')
            self.policy, self.context = self.node.policy, self.node.client_context
            strategy = offer['ice'].get('strategy', 'ice')
            if strategy not in ('ice', 'predict') or self.strategy not in ('auto', strategy):
                raise ValueError('UDP_STRATEGY_NOT_ENABLED')
            path = await self.path(claims['source'], False, offer['observed_ip'], strategy=strategy)
            ice = await path.gather()
            if await request(self.identity, self.policy, {'op': 'udp_answer', 'grant': offer['grant'], 'ice': ice}, context=self.context) != {'ok': True}:
                raise ValueError('UDP_ANSWER_REJECTED')
            pair = await path.connect(offer['ice'])
            async with asyncio.timeout(5):
                data = await read_metadata(pair[0])
                schema(data, ('op', 'grant'))
                if data['op'] != 'open' or data['grant'] != offer['grant']:
                    raise ValueError('UDP_OPEN_REJECTED')
                claims = self.node.admit(data['grant'], path.peer_pin, 'forward', transport=UDP_TRANSPORT)
            await self.node.serve(pair, data['grant'], claims)
        finally:
            if path:
                await self.release(path)
