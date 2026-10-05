"""Bounded metadata operations over pinned mTLS; no business-data dialer."""
import asyncio
from collections import defaultdict, deque
from pathlib import Path
import time

from .config import Policy, certificate, direct_address, name, schema
from .device import enrolled, tls_context
from .grants import UDP_TRANSPORT, clock, issue, verify
from .identity import peer_pin, require_pin
from .session import read_metadata, write_metadata
from .transport import TIMEOUT, Service, close_writer, connect, format_address
from .ice_metadata import validate as validate_ice


async def request(identity, policy, value, *, context=None, connection=None):
    if connection is not None:
        if connection.identity != identity or connection.policy is not policy:
            raise ValueError('CONTROL_CONNECTION_SCOPE_REJECTED')
        return await connection.request(value)
    async with asyncio.timeout(TIMEOUT):
        pair = await connect(policy.endpoint, context or tls_context(identity, policy), validator=direct_address)
        try:
            require_pin(pair[1], {policy.devices[policy.coordinator].pin})
            await write_metadata(pair[1], value)
            result = await read_metadata(pair[0])
            if not isinstance(result, dict):
                raise ValueError('INVALID_CONTROL_RESPONSE')
            if set(result) == {'error'}:
                raise ValueError(str(result['error']))
            return result
        finally:
            await close_writer(pair[1])


class ControlConnection:
    """One dial's metadata reuses its TCP mapping while UDP candidates are prepared."""
    def __init__(self, identity, policy, *, context=None):
        self.identity, self.policy, self.context = identity, policy, context
        self.pair = None
        self.lock = asyncio.Lock()
        self.closed = False

    async def request(self, value):
        async with self.lock:
            if self.closed:
                raise ValueError('CONTROL_CONNECTION_CLOSED')
            try:
                async with asyncio.timeout(TIMEOUT):
                    certificate(self.policy.devices[self.policy.coordinator].cert)
                    if self.pair is None:
                        self.pair = await connect(self.policy.endpoint,
                                                  self.context or tls_context(self.identity, self.policy),
                                                  validator=direct_address)
                    require_pin(self.pair[1], {self.policy.devices[self.policy.coordinator].pin})
                    await write_metadata(self.pair[1], value)
                    result = await read_metadata(self.pair[0])
                    if not isinstance(result, dict):
                        raise ValueError('INVALID_CONTROL_RESPONSE')
                    if set(result) == {'error'}:
                        raise ValueError(str(result['error']))
                    return result
            except BaseException:
                await self.close()
                raise

    async def close(self):
        self.closed = True
        if self.pair is not None:
            await close_writer(self.pair[1])
            self.pair = None


class Control:
    def __init__(self, identifier, identity, policy):
        enrolled(identifier, identity, policy)
        if identifier != policy.coordinator:
            raise ValueError('COORDINATOR_IDENTITY_REQUIRED')
        self.identity, self.policy = identity, policy
        self.service = Service(self.handle, tls_context(identity, policy, server=True), validator=direct_address)
        self.rates = defaultdict(deque)
        self.offers = {}
        self.requests = 0
        self.metadata_bytes = 0
        self.observed_ips = {}
        self.udp_answers = {}

    def rate(self, caller):
        now = time.monotonic()
        window = self.rates[caller]
        while window and window[0] <= now - 60:
            window.popleft()
        if len(window) >= 240:
            raise ValueError('CONTROL_RATE_LIMIT')
        window.append(now)

    def peer(self, identifier):
        device = self.policy.devices[identifier]
        return {'id': device.id, 'pin': device.pin, 'candidates': list(device.candidates)}

    async def handle(self, reader, writer):
        # Reuse is bounded; each operation rechecks current roster/validity/rate.
        async with asyncio.timeout(30):
            for _ in range(64):
                if await self.handle_operation(reader, writer):
                    return

    async def handle_operation(self, reader, writer):
        observe, rejected = False, False
        async with asyncio.timeout(TIMEOUT):
            caller = self.policy.caller(peer_pin(writer))
            certificate(self.policy.devices[caller].cert)
            self.observed_ips[caller] = writer.get_extra_info('peername')[0]
            self.rate(caller)
            data = await read_metadata(reader)
            self.requests += 1
            self.metadata_bytes += len(str(data))
            try:
                if data == {'op': 'observe'}:
                    observe = True
                    result = {'observed': format_address(writer.get_extra_info('peername')), 'hold_ms': 15000}
                else:
                    result = self.operation(caller, data)
            except ValueError as error:
                # Codes contain no untrusted payload, credential or network inventory.
                result = {'error': str(error)}
                rejected = True
            await write_metadata(writer, result)
        if observe:
            # Hold this authenticated observation mapping, never read/forward data.
            await asyncio.sleep(15)
        return observe or rejected

    def operation(self, caller, data):
        if not isinstance(data, dict) or not isinstance(data.get('op'), str):
            raise ValueError('INVALID_CONTROL_REQUEST')
        self.offers = {sid: offer for sid, offer in self.offers.items() if offer['expires'] > clock()}
        self.udp_answers = {sid: answer for sid, answer in self.udp_answers.items() if answer['expires'] > clock()}
        op = data['op']
        if op == 'grant':
            schema(data, ('op', 'target', 'service', 'direction'))
            target, service = name(data['target']), name(data['service'])
            if data['direction'] not in ('forward', 'reverse'):
                raise ValueError('INVALID_DIRECTION')
            grant = issue(self.identity, self.policy, caller, target, service, data['direction'])
            return {'grant': grant, 'peer': self.peer(target)}
        if op == 'udp_grant':
            schema(data, ('op', 'target', 'service'))
            grant = issue(self.identity, self.policy, caller, name(data['target']), name(data['service']), transport=UDP_TRANSPORT)
            return {'grant': grant}
        if op == 'udp_scope':
            schema(data, ('op', 'peer'))
            peer = name(data['peer'])
            if not any((source == caller and target == peer) or (source == peer and target == caller)
                       for source, target, _ in self.policy.allow):
                raise ValueError('ACL_DENIED')
            if peer not in self.observed_ips:
                raise ValueError('PEER_OBSERVATION_UNAVAILABLE')
            return {'ip': self.observed_ips[peer]}
        if op == 'renew':
            schema(data, ('op', 'grant'))
            previous = verify(data['grant'], self.policy)
            if previous['target'] != caller:
                raise ValueError('RECEIVER_RENEWAL_ONLY')
            return {'grant': issue(self.identity, self.policy, previous['source'], previous['target'],
                                   previous['service'], previous['direction'], previous=previous, transport=previous['transport'])}
        if op in ('udp_offer', 'udp_answer', 'udp_result'):
            schema(data, ('op', 'grant') if op == 'udp_result' else ('op', 'grant', 'ice'))
            claims = verify(data['grant'], self.policy)
            if claims['transport'] != UDP_TRANSPORT or claims['direction'] != 'forward' or claims['serial'] != 0:
                raise ValueError('INVALID_UDP_SESSION')
            sid = claims['session']
            expected = claims['target'] if op == 'udp_answer' else claims['source']
            if caller != expected:
                raise ValueError('UDP_CALLER_REJECTED')
            if op == 'udp_result':
                answer = self.udp_answers.get(sid)
                if answer and answer['grant'] != data['grant']:
                    raise ValueError('UDP_SESSION_CHANGED')
                return {'answer': None if not answer or answer['ice'] is None else {'ice': answer['ice'], 'observed_ip': answer['observed_ip']}}
            allowed = {direct_address(candidate)[0] for candidate in self.policy.devices[caller].candidates}
            allowed.add(self.observed_ips[caller])
            validate_ice(data['ice'], allowed)
            if op == 'udp_offer':
                if sid in self.offers or sid in self.udp_answers or len(self.offers) >= 128 or len(self.udp_answers) >= 128:
                    raise ValueError('OFFER_CAPACITY_OR_DUPLICATE')
                self.offers[sid] = dict(target=claims['target'], expires=claims['expires_ms'], grant=data['grant'],
                                       ice=data['ice'], observed_ip=self.observed_ips[caller])
                self.udp_answers[sid] = dict(expires=claims['expires_ms'], grant=data['grant'], ice=None, observed_ip=None)
            else:
                answer = self.udp_answers.get(sid)
                if not answer or answer['grant'] != data['grant'] or answer['ice'] is not None:
                    raise ValueError('UNEXPECTED_UDP_ANSWER')
                answer.update(ice=data['ice'], observed_ip=self.observed_ips[caller])
            return {'ok': True}
        if op == 'offer':
            schema(data, ('op', 'grant', 'candidate'))
            claims = verify(data['grant'], self.policy)
            if claims['source'] != caller or claims['direction'] != 'reverse' or claims['serial'] != 0:
                raise ValueError('INVALID_REVERSE_OFFER')
            if data['candidate'] not in self.policy.devices[caller].candidates:
                raise ValueError('UNAPPROVED_REVERSE_CANDIDATE')
            if claims['session'] in self.offers or len(self.offers) >= 128:
                raise ValueError('OFFER_CAPACITY_OR_DUPLICATE')
            self.offers[claims['session']] = dict(target=claims['target'], expires=claims['expires_ms'],
                                                grant=data['grant'], candidate=data['candidate'])
            return {'ok': True}
        if op == 'next':
            schema(data, ('op',))
            for sid, offer in self.offers.items():
                if offer['target'] == caller:
                    del self.offers[sid]
                    if 'ice' in offer:
                        return {'offer': {key: offer[key] for key in ('grant', 'ice', 'observed_ip')}}
                    return {'offer': {'grant': offer['grant'], 'candidate': offer['candidate']}}
            return {'offer': None}
        raise ValueError('UNSUPPORTED_CONTROL_OPERATION')

    async def start(self, endpoint):
        await self.service.start(endpoint)
        return self

    def update(self, policy):
        new = self.policy.replacement(policy)
        context = tls_context(self.identity, new, server=True)
        self.policy = new
        self.rates.clear()
        self.offers.clear()
        self.udp_answers.clear()
        self.observed_ips.clear()
        self.service.context = context

    async def close(self):
        await self.service.close()


async def watch_policy(path, service, log):
    """Invalid updates leave the last approved snapshot; versions never roll back."""
    last = Path(path).stat().st_mtime_ns
    while True:
        await asyncio.sleep(1)
        try:
            stamp = Path(path).stat().st_mtime_ns
            if stamp == last:
                continue
            last = stamp
            new = Policy.load(path)
            service.update(new)
            print(f'POLICY_UPDATED revision={new.revision}', file=log)
        except (OSError, ValueError) as error:
            print(f'POLICY_UPDATE_REJECTED {type(error).__name__}', file=log)
