"""Explicit fixed-peer business bridge; the coordinator remains metadata-only."""
import asyncio
from dataclasses import dataclass
import json
import socket
import sys

from .config import name
from .remote import MAX_SESSION, Node
from .transport import BUFFER, bridge, close_writer


@dataclass(frozen=True)
class PeerService:
    peer: str
    service: str


class HomeBridge(Node):
    def __init__(self, identifier, identity, policy, bridge_service, peer, service,
                 client, log=sys.stderr):
        name(peer); name(service); name(bridge_service)
        if peer == identifier or peer == policy.coordinator or not policy.permits(identifier, peer, service):
            raise ValueError('BRIDGE_UPSTREAM_ACL_REQUIRED')
        self.client = client
        self.brokers = set()
        self.restart_required = False
        super().__init__(identifier, identity, policy,
                         {bridge_service: PeerService(peer, service)}, log)

    def validate_service(self, endpoint):
        if type(endpoint) is not PeerService:
            raise ValueError('FIXED_BRIDGE_PEER_REQUIRED')

    async def open_service(self, service):
        if self.restart_required:
            raise ValueError('BRIDGE_POLICY_CHANGED_RESTART_REQUIRED')
        destination = self.services[service]
        sockets = socket.socketpair()
        pairs = []
        try:
            for sock in sockets:
                sock.setblocking(False)
                pairs.append(await asyncio.open_connection(sock=sock, limit=BUFFER))
            # Anonymous local sockets expose no unauthenticated forwarding listener.
            owner = asyncio.current_task()
            task = asyncio.create_task(self.forward(pairs[1], destination))
            self.brokers.add(task)
            def cancel_with_owner(_):
                task.cancel()
            owner.add_done_callback(cancel_with_owner)
            def completed(done):
                # Cancellation can happen before forward() enters its finally block.
                pairs[1][1].close()
                owner.remove_done_callback(cancel_with_owner)
                self.brokers.discard(done)
                self.session_result(done)
            task.add_done_callback(completed)
            return pairs[0]
        except BaseException:
            for pair in pairs:
                await close_writer(pair[1])
            for sock in sockets:
                sock.close()
            raise

    async def forward(self, pair, destination):
        upstream = None
        try:
            upstream, report = await self.client.dial(destination.peer, destination.service)
            ready = report.get('code') == 'DIRECT_SERVICE_READY' or (
                report.get('code') == 'AUTHENTICATED_NATIVE_UDP' and report.get('service_ready') is True)
            if report.get('relay') is not False or not ready:
                raise ValueError('BRIDGE_UPSTREAM_DIRECT_EVIDENCE_REQUIRED')
            print(json.dumps({'event': 'HOME_BRIDGE_UPSTREAM_READY', 'business_bridge': self.identifier,
                              'peer': destination.peer, 'service': destination.service,
                              'upstream_direct': report}, separators=(',', ':')), file=self.log)
            await bridge(pair, upstream, timeout=MAX_SESSION)
        finally:
            await close_writer(pair[1])
            if upstream:
                await close_writer(upstream[1])

    def update(self, policy):
        super().update(policy)
        # Outgoing clients use a startup snapshot. New sessions fail closed until restart.
        self.restart_required = True
        for task in self.brokers:
            task.cancel()

    async def close(self):
        await super().close()
        pending = list(self.brokers)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        await self.client.close()
