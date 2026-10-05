"""Small explicit native-UDP warmup inspired by frp's TTL/range strategies.

This original adapter uses authenticated ICE packets, never arbitrary port sweeps.
Up to 21 high ports near two observed peer mappings, on approved peer IPs only.
See frp v0.71.0 pkg/nathole/{nathole,controller,analysis}.go for research context.
"""
import asyncio
import socket

from aioice import stun
from aioice.candidate import candidate_priority


def predicted_endpoints(candidates):
    observations = [(c['ip'], c['port']) for c in candidates if c['type'] == 'srflx']
    observations = list(dict.fromkeys(observations))
    if not observations:
        return []
    ips = {ip for ip, _ in observations}
    if len(ips) != 1 or len(observations) > 2:
        return observations[:2]  # No prediction across changed egress IPs.
    last = observations[-1][1]
    difference = abs(observations[0][1] - last)
    if difference > 10:
        return observations  # Irregular observations do not justify a range sweep.
    radius = min(10, difference + 5)
    return [(observations[-1][0], p) for p in range(max(1024, last-radius), min(65535, last+radius)+1)]


def varying(candidates):
    return len({(c['ip'], c['port']) for c in candidates if c['type'] == 'srflx'}) > 1


async def warmup(connection, local, remote, allowed_ips):
    endpoints = predicted_endpoints(remote['candidates'])
    if any(ip not in allowed_ips for ip, _ in endpoints):
        raise ValueError('UNAPPROVED_UDP_CANDIDATE')
    local_changes, remote_changes = varying(local), varying(remote['candidates'])
    # Prefer the observed stable side as receiver, independent of ICE controlling role.
    receiver = (not local_changes and remote_changes) or (
        local_changes == remote_changes and not connection.ice_controlling)
    connection.remote_username = remote['parameters']['usernameFragment']
    connection.remote_password = remote['parameters']['password']
    if receiver and endpoints:
        protocol = connection._protocols[0]
        sock = protocol.transport.get_extra_info('socket')
        original = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        try:
            for endpoint in endpoints:
                request = stun.Message(message_method=stun.Method.BINDING, message_class=stun.Class.REQUEST)
                request.attributes['USERNAME'] = connection.remote_username + ':' + connection.local_username
                request.attributes['PRIORITY'] = candidate_priority(1, 'prflx')
                request.attributes['ICE-CONTROLLING' if connection.ice_controlling else 'ICE-CONTROLLED'] = connection._tie_breaker
                request.add_message_integrity(connection.remote_password.encode('utf8'))
                # No await while the socket's packet TTL is temporarily changed.
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 7)
                try:
                    protocol.send_stun(request, endpoint)
                finally:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, original)
                await asyncio.sleep(0.002)
        finally:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, original)
        await asyncio.sleep(1.2)
    else:
        # Give the peer time to prepare its filter before ordinary ICE checks.
        await asyncio.sleep(1)
    return {'strategy': 'predict', 'warmup_role': 'receiver' if receiver else 'sender',
            'candidate_ports': len(endpoints), 'ttl': 7 if receiver else None}
