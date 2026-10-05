"""Ephemeral authorized campaign endpoint. Stdio carries control/results only.

Business test bytes use fan_ssh's direct TLS stream; they never cross this stdio.
Run only through a verified existing SSH connection or as a local subprocess.
"""
import argparse
import asyncio
import hashlib
import json
import os
import sys
import shlex

from fan_ssh.config import Policy, strict_json, direct_address, schema
from fan_ssh.control import Control, request
from fan_ssh.device import generate, save_identity
from fan_ssh.remote import Client, DirectUnavailable, Node
from fan_ssh.transport import BUFFER, Service, close_writer, bridge
from fan_ssh.transport import framed
from fan_ssh.device import tls_context
from fan_ssh.identity import require_pin
from fan_ssh.session import read_metadata, write_metadata
from fan_ssh.remote import check_ready
from fan_ssh.tcp_probe import Binding, server_stream
from fan_ssh.grants import UDP_TRANSPORT, verify
from fan_ssh.stun import Observer


def emit(value):
    print(json.dumps(value, separators=(',', ':')), flush=True)


async def exchange(client, target, service='echo'):
    pair, report = await client.dial(target, service)
    return await exchange_pair(pair, report, service)


async def exchange_pair(pair, report, service='echo'):
    try:
        if service == 'ssh':
            async with asyncio.timeout(5):
                banner = await pair[0].read()
            report['ssh_banner'] = banner.startswith(b'SSH-2.0-')
            return report
        # Fixed size, random incompressible bytes generated at the initiator.
        payload = os.urandom(1024 * 1024)
        async def send():
            for offset in range(0, len(payload), BUFFER):
                pair[1].write(payload[offset:offset + BUFFER])
                await pair[1].drain()
            pair[1].write_eof()
            await pair[1].drain()
        sender = asyncio.create_task(send())
        checksum, count = hashlib.sha256(), 0
        try:
            async with asyncio.timeout(20):
                while data := await pair[0].read():
                    checksum.update(data)
                    count += len(data)
                await sender
        finally:
            sender.cancel()
            await asyncio.gather(sender, return_exceptions=True)
        report.update(payload_bytes=count, sha256=checksum.hexdigest(),
                      payload_verified=(count == len(payload) and checksum.digest() == hashlib.sha256(payload).digest()))
        return report
    finally:
        await close_writer(pair[1])


async def main(args):
    identities = {identifier: generate(identifier) for identifier in args.id}
    if args.local_state:
        from pathlib import Path
        for identifier, identity in identities.items():
            save_identity(identifier, identity, Path(args.local_state) / identifier)
    emit({'devices': [{'id': key, 'pin': value.pin, 'cert': value.cert.decode('ascii')}
                      for key, value in identities.items()]})
    services, policy, nodes, control, binding = [], None, {}, None, None
    prepared, udp, udp_prepared = None, None, None
    try:
        while True:
            line = await asyncio.to_thread(sys.stdin.buffer.readline, 1024 * 1024 + 1)
            if not line:
                break
            if len(line) > 1024 * 1024:
                raise ValueError('CAMPAIGN_CONTROL_TOO_LARGE')
            data = strict_json(line)
            op = data['op']
            try:
                if op == 'start':
                    if policy:
                        raise ValueError('CAMPAIGN_ALREADY_STARTED')
                    policy = Policy.parse(data['policy'])
                    async def echo(reader, writer):
                        while part := await reader.read(BUFFER):
                            writer.write(part)
                            await writer.drain()
                        writer.write_eof()
                        await writer.drain()
                    target = await Service(echo).start()
                    services.append(target)
                    for identifier, endpoint in data['listeners'].items():
                        if identifier == policy.coordinator:
                            control = await Control(identifier, identities[identifier], policy).start(endpoint)
                            services.append(control)
                            if data.get('tcp_observer_bind'):
                                secondary = await Service(control.handle, control.service.context,
                                                          validator=direct_address).start(data['tcp_observer_bind'])
                                services.append(secondary)
                            if data.get('stun_bind'):
                                observer = Observer(control)
                                await asyncio.get_running_loop().create_datagram_endpoint(
                                    lambda: observer, local_addr=direct_address(data['stun_bind']))
                                services.append(observer)
                        else:
                            local = {'echo': target.address}
                            if data.get('ssh_target'):
                                local['ssh'] = data['ssh_target']
                            node = await Node(identifier, identities[identifier], policy, local).start(endpoint)
                            nodes[identifier] = node
                            services.append(node)
                    emit({'ok': True, 'uid': os.getuid() if hasattr(os, 'getuid') else 'Windows'})
                elif op == 'exchange':
                    identifier = data['source']
                    client = Client(identifier, identities[identifier], policy,
                                    reverse_listen=data.get('reverse_listen'), reverse_candidate=data.get('reverse_candidate'))
                    try:
                        async with asyncio.timeout(12):
                            report = await exchange(client, data['target'], data.get('service', 'echo'))
                        emit({'ok': True, 'report': report})
                    finally:
                        await client.close()
                elif op == 'stats':
                    emit({'ok': True, 'control_requests': control.requests if control else 0,
                          'metadata_request_bytes': control.metadata_bytes if control else 0})
                elif op == 'nat_prepare':
                    if binding:
                        await binding.close()
                    identifier = data['device']
                    native, _ = direct_address(data['native_bind'])
                    binding = Binding(native, passive=data.get('mode') == 'hybrid' and data['role'] == 'server')
                    observed = await binding.observe(identities[identifier], policy, data.get('tcp_observer_address'))
                    prepared = dict(data)
                    if data['role'] == 'client':
                        client = Client(identifier, identities[identifier], policy)
                        try:
                            prepared['grant'], prepared['claims'], _ = await client.grant(data['target'], 'echo', 'forward')
                        finally:
                            await client.close()
                    emit({'ok': True, **observed})
                elif op == 'nat_go':
                    if not binding or not prepared:
                        raise ValueError('NAT_PREPARE_REQUIRED')
                    pair = None
                    try:
                        primer = None
                        if prepared.get('mode') == 'hybrid' and prepared['role'] == 'server':
                            primer = asyncio.create_task(binding.connect(data['peer']))
                            try:
                                sock = await binding.accept()
                            finally:
                                primer.cancel()
                                await asyncio.gather(primer, return_exceptions=True)
                        else:
                            sock = await binding.connect(data['peer'])
                        identifier = prepared['device']
                        if prepared['role'] == 'client':
                            pair = await asyncio.open_connection(sock=sock, ssl=tls_context(identities[identifier], policy),
                                                                 server_hostname='', ssl_handshake_timeout=5, ssl_shutdown_timeout=0.5)
                            require_pin(pair[1], {policy.devices[prepared['target']].pin})
                            await write_metadata(pair[1], {'op': 'open', 'grant': prepared['grant']})
                            check_ready(await read_metadata(pair[0]), prepared['claims'])
                            from fan_ssh.remote import evidence
                            hybrid = prepared.get('mode') == 'hybrid'
                            report = {'code': 'TCP_NAT_HYBRID_AUTHENTICATED' if hybrid else 'TCP_SIMULTANEOUS_OPEN_AUTHENTICATED', 'relay': False,
                                      'selected': evidence(pair, 'hybrid' if hybrid else 'simultaneous-open'), 'listener_fallback': hybrid}
                            result = await exchange_pair(framed(pair), report)
                            emit({'ok': True, 'report': result})
                        else:
                            pair = await server_stream(sock, tls_context(identities[identifier], policy, server=True))
                            await nodes[identifier].incoming(*pair)
                            emit({'ok': True, 'listener_fallback': prepared.get('mode') == 'hybrid'})
                    finally:
                        if pair:
                            await close_writer(pair[1])
                        await binding.close()
                        binding = None
                elif op == 'udp_prepare':
                    from fan_ssh.udp_path import UDPPath
                    if udp:
                        await udp.close()
                    identifier = data['device']
                    scope = await request(identities[identifier], policy, {'op': 'udp_scope', 'peer': data['target']})
                    schema(scope, ('ip',))
                    native, _ = direct_address(data['native_bind'])
                    udp = UDPPath(identifier, identities[identifier], policy, data['target'], native,
                                  data['stun_address'], controlling=data['role'] == 'client', peer_observed_ip=scope['ip'],
                                  strategy=data.get('udp_strategy', 'ice'), alternate=data.get('stun_alternate'))
                    udp_prepared = dict(data)
                    gathered = await udp.gather()
                    if data['role'] == 'client':
                        response = await request(identities[identifier], policy,
                                                 {'op': 'udp_grant', 'target': data['target'], 'service': data['service']})
                        udp_prepared['grant'] = response['grant']
                        udp_prepared['claims'] = verify(response['grant'], policy)
                    emit({'ok': True, 'ice': gathered})
                elif op == 'udp_go':
                    if not udp or not udp_prepared:
                        raise ValueError('UDP_PREPARE_REQUIRED')
                    try:
                        pair = await udp.connect(data['peer'])
                        identifier = udp_prepared['device']
                        if udp_prepared['role'] == 'client':
                            await write_metadata(pair[1], {'op': 'open', 'grant': udp_prepared['grant']})
                            check_ready(await read_metadata(pair[0]), udp_prepared['claims'])
                            if udp_prepared['service'] == 'echo':
                                report = await exchange_pair(framed(pair), udp.report)
                            else:
                                # Existing SSH key and known_hosts remain on the source host.
                                # ProxyCommand opens loopback only; original SSH hostname is a host-key lookup.
                                async def tunnel(reader, writer):
                                    await bridge((reader, writer), framed(pair), timeout=30)
                                forward = await Service(tunnel).start()
                                try:
                                    proxy = shlex.join([sys.executable, '-m', 'fan_ssh', 'proxy', '--target', forward.address])
                                    check = udp_prepared['ssh_check']
                                    command = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                                               '-o', 'ForwardAgent=no', '-o', 'UpdateHostKeys=no',
                                               '-o', 'ClearAllForwardings=yes', '-o', 'ProxyCommand=' + proxy,
                                               '-p', str(check['port']), check['host'], "printf 'native-p2p-ssh-ok\\n'"]
                                    process = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE,
                                                                                 stderr=asyncio.subprocess.PIPE)
                                    try:
                                        stdout, stderr = await asyncio.wait_for(process.communicate(), 25)
                                    finally:
                                        if process.returncode is None:
                                            process.kill(); await process.wait()
                                    report = dict(udp.report, ssh_exit=process.returncode,
                                                  ssh_verified=stdout.strip() == b'native-p2p-ssh-ok',
                                                  ssh_error=stderr.decode(errors='replace')[-1000:])
                                finally:
                                    await forward.close()
                            emit({'ok': True, 'report': report})
                        else:
                            metadata = await read_metadata(pair[0])
                            schema(metadata, ('op', 'grant'))
                            if metadata['op'] != 'open':
                                raise ValueError('OPEN_REQUIRED')
                            claims = nodes[identifier].admit(metadata['grant'], udp.peer_pin, 'forward', transport=UDP_TRANSPORT)
                            await nodes[identifier].serve(pair, metadata['grant'], claims)
                            emit({'ok': True, 'report': udp.report})
                    except (OSError, ValueError, TimeoutError, asyncio.IncompleteReadError) as error:
                        emit({'ok': False, 'error': type(error).__name__, 'code': str(error)[:120],
                              'diagnostics': udp.diagnostics()})
                    finally:
                        await udp.close()
                        udp = None
                elif op == 'stop':
                    emit({'ok': True})
                    break
                else:
                    raise ValueError('UNKNOWN_CAMPAIGN_OPERATION')
            except DirectUnavailable as error:
                emit({'ok': False, 'report': error.report})
            except (OSError, ValueError, TimeoutError, asyncio.IncompleteReadError) as error:
                emit({'ok': False, 'error': type(error).__name__, 'code': str(error)[:120]})
    finally:
        if binding:
            await binding.close()
        if udp:
            await udp.close()
        for service in reversed(services):
            await service.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--id', action='append', required=True)
    parser.add_argument('--local-state', help='authorized local-only temporary state for the CLI SSH check')
    asyncio.run(main(parser.parse_args()))
