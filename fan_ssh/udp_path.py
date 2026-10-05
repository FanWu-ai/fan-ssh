"""Experimental native-only ICE/DTLS/SCTP path with bounded byte-stream framing.

Requires pinned optional dependencies. Private adapter accesses are isolated here.
No default public STUN, TURN, relay candidate or automatic interface discovery.
"""
import asyncio
from dataclasses import asdict
from importlib.metadata import version
import ipaddress
import socket
from aioice import stun
from aioice.ice import StunProtocol, server_reflexive_candidate
from aioice.candidate import Candidate, candidate_foundation, candidate_priority

from aioice import Connection
from aiortc import (RTCCertificate, RTCDataChannel, RTCDataChannelParameters, RTCDtlsFingerprint,
                    RTCDtlsParameters, RTCDtlsTransport, RTCIceCandidate, RTCIceGatherer,
                    RTCIceParameters, RTCIceTransport, RTCSctpCapabilities, RTCSctpTransport)
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .config import certificate, direct_address, schema
from .device import enrolled
from .transport import BUFFER, format_address
from .ice_metadata import validate


class SafeTransaction(stun.Transaction):
    def _Transaction__retry(self):
        # A response callback can complete the future before a due retry callback
        # executes, while run() has not yet resumed to cancel its timer.
        if not self._Transaction__future.done():
            super()._Transaction__retry()


class NativeProtocol(StunProtocol):
    async def request(self, request, addr, integrity_key=None, retransmissions=None):
        if integrity_key is not None:
            request.add_message_integrity(integrity_key)
        transaction = SafeTransaction(request, addr, self, retransmissions=retransmissions)
        self.transactions[request.transaction_id] = transaction
        try:
            return await transaction.run()
        finally:
            self.transactions.pop(request.transaction_id, None)


class NativeConnection(Connection):
    def __init__(self, native, stun, controlling, alternate=None, allowed_peer_ips=None):
        super().__init__(ice_controlling=controlling, stun_server=stun, turn_server=None,
                         components=1, use_ipv4=':' not in native, use_ipv6=':' in native)
        self.native = native
        self.alternate = alternate
        self.allowed_peer_ips = allowed_peer_ips

    def request_received(self, message, addr, protocol, raw_data):
        if self.allowed_peer_ips is not None and addr[0] not in self.allowed_peer_ips:
            return
        return super().request_received(message, addr, protocol, raw_data)

    async def gather_candidates(self):
        # Reviewed against aioice 0.10.2; never gather Tailscale/TUN/other interfaces.
        if not self._local_candidates_start:
            self._local_candidates_start = True
            transport, protocol = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: NativeProtocol(self), local_addr=(self.native, 0))
            transport.get_extra_info('socket').setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
            endpoint = transport.get_extra_info('sockname')
            protocol.local_candidate = Candidate(foundation=candidate_foundation('host', 'udp', self.native),
                                                component=1, transport='udp', priority=candidate_priority(1, 'host'),
                                                host=endpoint[0], port=endpoint[1], type='host')
            self._protocols.append(protocol)
            self._local_candidates = [protocol.local_candidate]
            if ':' not in self.native:
                for observer in [self.stun_server] + ([self.alternate] if self.alternate else []):
                    try:
                        message = stun.Message(message_method=stun.Method.BINDING, message_class=stun.Class.REQUEST)
                        response, _ = await asyncio.wait_for(protocol.request(message, observer, retransmissions=1), 2.5)
                        mapped = response.attributes.get('XOR-MAPPED-ADDRESS') or response.attributes.get('MAPPED-ADDRESS')
                        if not mapped:
                            continue
                        ip, port = direct_address(format_address(mapped))
                        candidate = Candidate(foundation=candidate_foundation('srflx', 'udp', self.native),
                                              component=1, transport='udp', priority=candidate_priority(1, 'srflx'),
                                              host=ip, port=port, type='srflx', related_address=self.native,
                                              related_port=endpoint[1])
                        if not any(c.host == ip and c.port == port and c.type == 'srflx' for c in self._local_candidates):
                            self._local_candidates.append(candidate)
                    except (OSError, ValueError, stun.TransactionError, TimeoutError):
                        pass
            self._local_candidates_end = True


UDP_CHUNK = 16384
WINDOW = 4


class NativeSCTP(RTCSctpTransport):
    """Surface a disconnected DTLS sender through the owned stream, including timers."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stopping = False
        self.send_failed = False
        self.on_send_failure = None

    async def _send_chunk(self, chunk):
        try:
            await super()._send_chunk(chunk)
        except ConnectionError:
            # Upstream timer/reconfiguration tasks may race association shutdown.
            # Active failure closes the application stream; it never becomes success.
            if not self.stopping:
                self.send_failed = True
                if self.on_send_failure is not None:
                    self.on_send_failure()


class ChannelStream:
    """Four 16-KiB credits; <=64 KiB receive/pending queues; bounded reads."""
    def __init__(self, channel):
        self.channel = channel
        self.incoming = asyncio.Queue(maxsize=WINDOW)
        self.remainder = bytearray()
        self.pending = bytearray()
        self.credits = WINDOW
        self.available = asyncio.Event()
        self.writable = asyncio.Event()
        self.closed = asyncio.Event()
        self.opened = asyncio.Event()
        channel.on('open', self.opened.set)
        channel.on('close', self.close)
        channel.on('message', self.message)

    def message(self, value):
        if not isinstance(value, bytes) or not value:
            self.close(); return
        if value == b'\x01':
            self.credits += 1
            if self.credits > WINDOW:
                self.close(); return
            self.writable.set()
        elif value[0] == 0 and 1 < len(value) <= UDP_CHUNK + 1:
            try:
                self.incoming.put_nowait(value[1:])
                self.available.set()
            except asyncio.QueueFull:
                self.close()
        else:
            self.close()

    async def chunk(self):
        while self.incoming.empty():
            if self.closed.is_set():
                return b''
            self.available.clear()
            await self.available.wait()
        value = self.incoming.get_nowait()
        if not self.closed.is_set():
            self.channel.send(b'\x01')
        return value

    async def read(self, size=BUFFER):
        if not self.remainder:
            self.remainder.extend(await self.chunk())
        result = bytes(self.remainder[:size])
        del self.remainder[:size]
        return result

    async def readexactly(self, size):
        if not 0 <= size <= BUFFER:
            raise ValueError('UDP_STREAM_READ_LIMIT')
        result = bytearray()
        while len(result) < size:
            value = await self.read(size - len(result))
            if not value:
                raise asyncio.IncompleteReadError(bytes(result), size)
            result.extend(value)
        return bytes(result)

    def write(self, value):
        if self.closed.is_set():
            raise ConnectionError('UDP_STREAM_CLOSED')
        if len(self.pending) + len(value) > 65536:
            raise ValueError('UDP_STREAM_WRITE_LIMIT')
        self.pending.extend(value)

    async def drain(self):
        while self.pending:
            if self.closed.is_set():
                raise ConnectionError('UDP_STREAM_CLOSED')
            if self.credits:
                part = bytes(self.pending[:UDP_CHUNK])
                del self.pending[:UDP_CHUNK]
                self.credits -= 1
                self.channel.send(b'\0' + part)
                # Let DTLS/SCTP flush and receive ACK/credit callbacks between messages.
                await asyncio.sleep(0)
            else:
                self.writable.clear()
                await self.writable.wait()

    def close(self):
        if not self.closed.is_set():
            self.closed.set()
            self.available.set()
            self.writable.set()
            self.opened.set()
            self.channel.close()

    async def wait_closed(self):
        await self.closed.wait()


class UDPPath:
    def __init__(self, identifier, identity, policy, peer, native, stun, *, controlling, peer_observed_ip,
                 strategy='ice', alternate=None):
        if version('aiortc') != '1.15.0' or version('aioice') != '0.10.2':
            raise ValueError('UDP_ADAPTER_VERSION_UNSUPPORTED')
        enrolled(identifier, identity, policy)
        self.policy = policy
        self.native = str(ipaddress.ip_address(native))
        self.allowed_peer_ips = {direct_address(candidate)[0] for candidate in policy.devices[peer].candidates}
        self.allowed_peer_ips.add(str(ipaddress.ip_address(peer_observed_ip)))
        if strategy not in ('ice', 'predict'):
            raise ValueError('INVALID_UDP_STRATEGY')
        if strategy == 'predict' and ':' in self.native:
            raise ValueError('UDP_PREDICTION_REQUIRES_IPV4')
        self.strategy, self.traversal = strategy, None
        self.gatherer = RTCIceGatherer(iceServers=[])  # No library-default external STUN server.
        self.gatherer._connection = NativeConnection(self.native, direct_address(stun), controlling,
                                                     direct_address(alternate) if alternate else None,
                                                     self.allowed_peer_ips)
        self.ice = RTCIceTransport(self.gatherer)
        cert = RTCCertificate(serialization.load_pem_private_key(identity.key, password=None),
                              x509.load_pem_x509_certificate(identity.cert))
        self.dtls = RTCDtlsTransport(self.ice, [cert])
        self.sctp = NativeSCTP(self.dtls, port=5000)
        self.channel = RTCDataChannel(self.sctp, RTCDataChannelParameters(label='fan-ssh', ordered=True, negotiated=True, id=0))
        self.stream = ChannelStream(self.channel)
        self.sctp.on_send_failure = self.stream.close
        self.peer_pin = policy.devices[peer].pin
        self.peer = peer
        self.controlling = controlling
        self.report = None
        self.phase = 'new'
        self.closer = None

    async def gather(self):
        self.phase = 'gather'
        async with asyncio.timeout(6):
            await self.gatherer.gather()
        candidates = [asdict(value) for value in self.gatherer.getLocalCandidates()]
        if any(value['type'] not in ('host', 'srflx') or value['protocol'] != 'udp' for value in candidates):
            raise ValueError('RELAY_OR_NON_UDP_CANDIDATE_DENIED')
        result = {'parameters': asdict(self.gatherer.getLocalParameters()), 'candidates': candidates}
        if self.strategy != 'ice':
            result['strategy'] = self.strategy
        return result

    async def connect(self, remote):
        self.phase = 'validate'
        certificate(self.policy.devices[self.peer].cert)
        validate(remote, self.allowed_peer_ips)
        candidates = remote['candidates']
        if not isinstance(candidates, list) or not 1 <= len(candidates) <= 8:
            raise ValueError('UDP_CANDIDATE_LIMIT')
        async with asyncio.timeout(15):
            for value in candidates:
                if not isinstance(value, dict) or value.get('type') not in ('host', 'srflx') or value.get('protocol') != 'udp' or value.get('component') != 1:
                    raise ValueError('RELAY_OR_NON_UDP_CANDIDATE_DENIED')
                ip, port = direct_address(format_address((value['ip'], value['port'])))
                if ip not in self.allowed_peer_ips:
                    raise ValueError('UNAPPROVED_UDP_CANDIDATE')
                await self.ice.addRemoteCandidate(RTCIceCandidate(**value))
            await self.ice.addRemoteCandidate(None)
            self.phase = 'ice'
            if self.strategy == 'predict':
                from .udp_traversal import warmup
                self.traversal = await warmup(self.gatherer._connection,
                                              [asdict(c) for c in self.gatherer.getLocalCandidates()],
                                              remote, self.allowed_peer_ips)
            await self.ice.start(RTCIceParameters(**remote['parameters']))
            if self.ice.state != 'completed':
                raise ValueError('NO_DIRECT_UDP_PATH')
            selected = self.gatherer._connection._nominated.get(1)
            if not selected or selected.local_candidate.host != self.native or selected.remote_candidate.host not in self.allowed_peer_ips or selected.remote_candidate.type not in ('host', 'srflx', 'prflx'):
                raise ValueError('UNAPPROVED_SELECTED_UDP_PAIR')
            fingerprint = ':'.join(self.peer_pin[i:i + 2] for i in range(0, 64, 2)).upper()
            self.phase = 'dtls'
            await self.dtls.start(RTCDtlsParameters(fingerprints=[RTCDtlsFingerprint('sha-256', fingerprint)],
                                                   role='server' if self.controlling else 'client'))
            if self.dtls.state != 'connected':
                raise ValueError('UDP_PEER_AUTH_FAILED')
            self.phase = 'sctp'
            await self.sctp.start(RTCSctpCapabilities(maxMessageSize=UDP_CHUNK + 1), 5000)
            await self.stream.opened.wait()
            if self.stream.closed.is_set():
                raise ConnectionError('UDP_STREAM_SETUP_CLOSED')
            self.phase = 'ready'
            self.report = {'code': 'AUTHENTICATED_NATIVE_UDP', 'relay': False, 'selected': {
                'transport': 'direct-udp-dtls-sctp-v1', 'local': format_address((selected.local_candidate.host, selected.local_candidate.port)),
                'remote': format_address((selected.remote_candidate.host, selected.remote_candidate.port)),
                'local_candidate_type': selected.local_candidate.type, 'remote_candidate_type': selected.remote_candidate.type,
                'peer_pin': self.peer_pin, 'native_bind_verified': True}}
            if self.traversal:
                self.report['traversal'] = self.traversal
        return self.stream, self.stream

    def diagnostics(self):
        return {'phase': self.phase, 'ice': self.ice.state, 'dtls': self.dtls.state,
                'sctp': self.sctp.state, 'channel': self.channel.readyState,
                'sctp_send_failed': self.sctp.send_failed,
                'checks': [{'type': pair.remote_candidate.type, 'state': pair.state.name,
                            'remote': format_address(pair.remote_addr)}
                           for pair in self.gatherer._connection._check_list]}

    async def close(self):
        if self.closer is None:
            self.closer = asyncio.create_task(self._close())
        await asyncio.shield(self.closer)

    async def _close(self):
        self.sctp.stopping = True
        self.stream.close()
        # aioice's cancelled connect() does not reach its normal check cleanup.
        checks = [pair.task for pair in self.gatherer._connection._check_list if pair.task]
        for task in checks:
            task.cancel()
        await asyncio.gather(*checks, return_exceptions=True)
        for transport in (self.sctp, self.dtls, self.ice):
            try:
                await asyncio.wait_for(transport.stop(), 1)
            except (OSError, ValueError, TimeoutError):
                pass
