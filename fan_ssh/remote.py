"""Independent direct peers, candidate racing, reverse dialing and renewable leases."""
import asyncio
from contextlib import suppress
import platform
import ssl
import sys
import time

from .config import direct_address, name, schema
from .control import request
from .device import enrolled, tls_context
from .grants import Admissions, clock, renewal, verify
from .identity import peer_pin, require_pin
from .session import read_metadata, write_metadata
from .transport import TIMEOUT, Service, address, bridge, close_writer, connect, format_address, framed

MAX_SESSION = 24 * 60 * 60


def evidence(pair, direction):
    return dict(transport='direct-tcp-tls-framed-v2', direction=direction,
                local=format_address(pair[1].get_extra_info('sockname')),
                remote=format_address(pair[1].get_extra_info('peername')),
                peer_pin=peer_pin(pair[1]), tls=pair[1].get_extra_info('ssl_object').version())


def ready(claims):
    return {'ok': True, 'session': claims['session'], 'expires_ms': claims['expires_ms']}


def check_ready(value, claims):
    if value != ready(claims) or type(value.get('ok')) is not bool:
        raise ValueError('SERVICE_ADMISSION_FAILED')


async def guarded(claims, grant, identity, policy, context):
    while True:
        remaining = (claims['expires_ms'] - clock()) / 1000
        if remaining <= 0:
            raise ValueError('LEASE_EXPIRED')
        await asyncio.sleep(remaining / 2)
        async with asyncio.timeout(max(0.001, (claims['expires_ms'] - clock()) / 1000)):
            response = await request(identity, policy, {'op': 'renew', 'grant': grant}, context=context)
        schema(response, ('grant',))
        updated = verify(response['grant'], policy)
        renewal(claims, updated)
        grant, claims = response['grant'], updated


class Node:
    def __init__(self, identifier, identity, policy, services, log=sys.stderr):
        enrolled(identifier, identity, policy)
        if identifier == policy.coordinator or not 1 <= len(services) <= 16:
            raise ValueError('INVALID_PEER_SERVICES')
        for service, endpoint in services.items():
            name(service)
            self.validate_service(endpoint)
        self.identifier, self.identity, self.policy = identifier, identity, policy
        self.services, self.log = dict(services), log
        self.client_context = tls_context(identity, policy)
        self.service = Service(self.incoming, tls_context(identity, policy, server=True), validator=direct_address)
        self.admissions = Admissions()
        self.slots = asyncio.Semaphore(32)
        self.active = set()
        self.reverse_tasks = set()
        self.poll_task = None
        self.udp = None

    def validate_service(self, endpoint):
        address(endpoint)  # Ordinary nodes expose only fixed loopback services.

    async def open_service(self, service):
        return await connect(self.services[service])

    def admit(self, grant, caller, direction, *, transport='direct-tcp-tls-framed-v2'):
        claims = verify(grant, self.policy)
        if claims['transport'] != transport:
            raise ValueError('SESSION_TRANSPORT_REJECTED')
        # In reverse mode this node is the dialing target, not a TLS listener.
        if claims['target'] != self.identifier or claims['target_pin'] != self.identity.pin or claims['direction'] != direction:
            raise ValueError('SESSION_TARGET_REJECTED')
        expected = claims['source_pin']
        if caller != expected or claims['service'] not in self.services:
            raise ValueError('SERVICE_OR_PEER_DENIED')
        self.admissions.consume(claims)
        return claims

    async def incoming(self, reader, writer):
        async with asyncio.timeout(TIMEOUT):
            caller = peer_pin(writer)
            self.policy.caller(caller)
            data = await read_metadata(reader)
            schema(data, ('op', 'grant'))
            if data['op'] != 'open':
                raise ValueError('OPEN_REQUIRED')
            claims = self.admit(data['grant'], caller, 'forward')
        await self.serve((reader, writer), data['grant'], claims)

    async def serve(self, pair, grant, claims):
        if self.slots.locked():
            raise ValueError('NODE_SESSION_CAPACITY')
        await self.slots.acquire()
        task = asyncio.current_task()
        self.active.add(task)
        upstream, pumps = None, []
        try:
            upstream = await self.open_service(claims['service'])
            verify(grant, self.policy)  # Expiry/revocation can occur during the local dial.
            await write_metadata(pair[1], ready(claims))
            print(f'DIRECT_SESSION service={claims["service"]} direction={claims["direction"]}', file=self.log)
            pumps = [asyncio.create_task(bridge(framed(pair), upstream, timeout=MAX_SESSION)),
                     asyncio.create_task(guarded(claims, grant, self.identity, self.policy, self.client_context))]
            done, _ = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            for completed in done:
                completed.result()
        finally:
            for pump in pumps:
                pump.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            await close_writer(pair[1])
            if upstream:
                await close_writer(upstream[1])
            self.active.discard(task)
            self.slots.release()

    async def reverse(self, offer):
        pair = None
        try:
            schema(offer, ('grant', 'candidate'))
            claims = verify(offer['grant'], self.policy)
            if claims['direction'] != 'reverse' or claims['target'] != self.identifier:
                raise ValueError('INVALID_REVERSE_OFFER')
            if offer['candidate'] not in self.policy.devices[claims['source']].candidates:
                raise ValueError('UNAPPROVED_REVERSE_CANDIDATE')
            async with asyncio.timeout(TIMEOUT):
                pair = await connect(offer['candidate'], self.client_context, validator=direct_address)
                require_pin(pair[1], {claims['source_pin']})
                await write_metadata(pair[1], {'op': 'reverse_open', 'grant': offer['grant']})
                ack = await read_metadata(pair[0])
                if ack != {'ok': True, 'session': claims['session']} or type(ack.get('ok')) is not bool:
                    raise ValueError('REVERSE_ADMISSION_FAILED')
                claims = self.admit(offer['grant'], peer_pin(pair[1]), 'reverse')
            await self.serve(pair, offer['grant'], claims)
        except (OSError, ValueError, TimeoutError, asyncio.IncompleteReadError):
            print('REVERSE_SESSION_FAILED', file=self.log)
        finally:
            if pair:
                await close_writer(pair[1])

    async def poll(self):
        failed = False
        while True:
            try:
                if len(self.reverse_tasks) < 32:
                    response = await request(self.identity, self.policy, {'op': 'next'}, context=self.client_context)
                    schema(response, ('offer',))
                    if response['offer'] is not None:
                        if 'ice' in response['offer']:
                            if not self.udp:
                                raise ValueError('UDP_NOT_ENABLED')
                            task = asyncio.create_task(self.udp.accept(response['offer']))
                        else:
                            task = asyncio.create_task(self.reverse(response['offer']))
                        self.reverse_tasks.add(task)
                        task.add_done_callback(self.reverse_tasks.discard)
                        task.add_done_callback(self.session_result)
                failed = False
            except (OSError, ValueError, TimeoutError, asyncio.IncompleteReadError):
                if not failed:
                    print('CONTROL_UNAVAILABLE: new reverse offers paused', file=self.log)
                failed = True
            await asyncio.sleep(1)

    async def start(self, endpoint, *, poll=True):
        await self.service.start(endpoint)
        if poll:
            self.poll_task = asyncio.create_task(self.poll())
        return self

    def session_result(self, task):
        if not task.cancelled() and task.exception():
            print('DIRECT_OFFER_FAILED', file=self.log)

    def update(self, policy):
        new = self.policy.replacement(policy)
        enrolled(self.identifier, self.identity, new)
        context = tls_context(self.identity, new)
        server_context = tls_context(self.identity, new, server=True)
        self.policy, self.client_context, self.service.context = new, context, server_context
        for task in self.active | self.reverse_tasks:
            task.cancel()  # Conservative: every local policy revision closes existing sessions.

    async def close(self):
        if self.poll_task:
            self.poll_task.cancel()
            await asyncio.gather(self.poll_task, return_exceptions=True)
        tasks = list(self.reverse_tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await self.service.close()
        if self.udp:
            await self.udp.close()


class DirectUnavailable(ValueError):
    def __init__(self, report):
        self.report = report
        super().__init__(report['code'])


class ReleasingWriter:
    def __init__(self, writer, release):
        self.writer, self.release = writer, release

    def __getattr__(self, name):
        return getattr(self.writer, name)

    def close(self):
        self.release.set()
        self.writer.close()


class Client:
    def __init__(self, identifier, identity, policy, *, reverse_listen=None, reverse_candidate=None):
        enrolled(identifier, identity, policy)
        if identifier == policy.coordinator:
            raise ValueError('PEER_IDENTITY_REQUIRED')
        self.identifier, self.identity, self.policy = identifier, identity, policy
        self.context = tls_context(identity, policy)
        self.reverse_listen = reverse_listen
        self.reverse_candidate = reverse_candidate or reverse_listen
        if reverse_listen:
            direct_address(reverse_listen, bind=True)
            if self.reverse_candidate not in policy.devices[identifier].candidates:
                raise ValueError('UNAPPROVED_REVERSE_CANDIDATE')
        elif reverse_candidate:
            raise ValueError('REVERSE_LISTEN_REQUIRED')
        self.reverse_service = None
        self.reverse_lock = asyncio.Lock()
        self.pending = {}

    async def grant(self, target, service, direction):
        name(target); name(service)
        if not self.policy.permits(self.identifier, target, service):
            raise ValueError('ACL_DENIED')
        response = await request(self.identity, self.policy,
                                 {'op': 'grant', 'target': target, 'service': service, 'direction': direction}, context=self.context)
        schema(response, ('grant', 'peer'))
        claims = verify(response['grant'], self.policy)
        if (claims['source'], claims['target'], claims['service'], claims['direction']) != (self.identifier, target, service, direction) or claims['serial'] != 0:
            raise ValueError('SESSION_BINDING_REJECTED')
        peer = response['peer']
        schema(peer, ('id', 'pin', 'candidates'))
        approved = self.policy.devices[target]
        if peer != {'id': target, 'pin': approved.pin, 'candidates': list(approved.candidates)}:
            raise ValueError('DISCOVERY_CHANGED_APPROVED_PEER')
        return response['grant'], claims, peer

    async def race(self, peer):
        attempts = []
        report = {'code': 'NO_DIRECT_PATH', 'attempts': attempts, 'platform': platform.system(), 'relay': False}
        async def attempt(endpoint):
            pair = None
            start = time.monotonic()
            record = {'endpoint': endpoint}
            attempts.append(record)
            try:
                pair = await connect(endpoint, self.context, validator=direct_address)
                require_pin(pair[1], {peer['pin']})
                record['code'] = 'AUTHENTICATED_DIRECT_TLS'
                return pair
            except asyncio.CancelledError:
                record['code'] = 'CANCELLED'
                if pair:
                    await close_writer(pair[1])
                raise
            except (OSError, ValueError, TimeoutError) as error:
                record['code'] = 'PEER_AUTH_FAILED' if isinstance(error, (ValueError, ssl.SSLError)) else 'TCP_UNREACHABLE'
                if pair:
                    await close_writer(pair[1])
                return None
            finally:
                record['elapsed_ms'] = round((time.monotonic() - start) * 1000)
        tasks = [asyncio.create_task(attempt(endpoint)) for endpoint in peer['candidates']]
        pending, selected = set(tasks), None
        try:
            while pending and selected is None:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    pair = task.result()
                    if pair and selected is None:
                        selected = pair
                    elif pair:
                        await close_writer(pair[1])
        finally:
            for task in pending:
                task.cancel()
            remaining = await asyncio.gather(*pending, return_exceptions=True)
            for pair in remaining:
                if isinstance(pair, tuple):
                    await close_writer(pair[1])
            if selected and asyncio.current_task().cancelling():
                await close_writer(selected[1])
        if not selected:
            if any(a['code'] == 'PEER_AUTH_FAILED' for a in attempts):
                report['code'] = 'PEER_AUTH_FAILED'
            raise DirectUnavailable(report)
        report.update(code='AUTHENTICATED_DIRECT_TLS', selected=evidence(selected, 'forward'))
        return selected, report

    async def dial(self, target, service='ssh'):
        grant, claims, peer = await self.grant(target, service, 'forward')
        try:
            pair, report = await self.race(peer)
        except DirectUnavailable as error:
            if not self.reverse_listen or error.report['code'] != 'NO_DIRECT_PATH':
                raise
            pair, report = await self.reverse_dial(target, service)
            report['forward_attempts'] = error.report['attempts']
            return pair, report
        try:
            async with asyncio.timeout(TIMEOUT):
                await write_metadata(pair[1], {'op': 'open', 'grant': grant})
                check_ready(await read_metadata(pair[0]), claims)
            report['code'] = 'DIRECT_SERVICE_READY'
            return framed(pair), report
        except BaseException:
            await close_writer(pair[1])
            raise

    async def incoming_reverse(self, reader, writer):
        async with asyncio.timeout(TIMEOUT):
            data = await read_metadata(reader)
            schema(data, ('op', 'grant'))
            if data['op'] != 'reverse_open':
                raise ValueError('REVERSE_OPEN_REQUIRED')
            claims = verify(data['grant'], self.policy)
            entry = self.pending.get(claims['session'])
            if not entry or entry[1] != data['grant'] or entry[0].done() or peer_pin(writer) != claims['target_pin']:
                raise ValueError('UNEXPECTED_REVERSE_SESSION')
            # Consume this pending slot before another connection can use it.
            del self.pending[claims['session']]
            await write_metadata(writer, {'ok': True, 'session': claims['session']})
            check_ready(await read_metadata(reader), claims)
            release = asyncio.Event()
            pair = framed((reader, writer))
            wrapped = pair[0], ReleasingWriter(pair[1], release)
            report = {'code': 'DIRECT_SERVICE_READY', 'relay': False, 'selected': evidence((reader, writer), 'reverse')}
            if entry[0].done():
                raise ValueError('REVERSE_SESSION_CANCELLED')
            entry[0].set_result((wrapped, report))
        await release.wait()

    async def reverse_dial(self, target, service):
        async with self.reverse_lock:
            if self.reverse_service is None:
                self.reverse_service = await Service(self.incoming_reverse, tls_context(self.identity, self.policy, server=True),
                                                     validator=direct_address).start(self.reverse_listen)
        if len(self.pending) >= 32:
            raise ValueError('REVERSE_CAPACITY')
        grant, claims, _ = await self.grant(target, service, 'reverse')
        future = asyncio.get_running_loop().create_future()
        self.pending[claims['session']] = (future, grant)
        try:
            response = await request(self.identity, self.policy,
                                     {'op': 'offer', 'grant': grant, 'candidate': self.reverse_candidate}, context=self.context)
            if response != {'ok': True}:
                raise ValueError('REVERSE_OFFER_REJECTED')
            async with asyncio.timeout(max(0.001, (claims['expires_ms'] - clock()) / 1000)):
                return await future
        finally:
            self.pending.pop(claims['session'], None)
            if not future.done():
                future.cancel()

    async def diagnose(self, target, service='ssh'):
        _, _, peer = await self.grant(target, service, 'forward')
        try:
            pair, report = await self.race(peer)
            await close_writer(pair[1])  # No OPEN and no local service dial or SSH bytes.
            report['service_opened'] = False
            return report
        except DirectUnavailable as error:
            error.report['service_opened'] = False
            return error.report

    async def close(self):
        for future, _ in self.pending.values():
            future.cancel()
        self.pending.clear()
        if self.reverse_service:
            await self.reverse_service.close()
