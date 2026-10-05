"""Consenting Linux TCP listener / low-TTL or dual-listener control diagnostic.

Existing verified SSH carries setup and fresh MAC secrets only. Observation is
authenticated with those secrets; 64 KiB random test bytes use peer TCP sockets.
No raw sockets, port range, SSH login, relay, router or authentication changes.
"""
import argparse
import asyncio
import hashlib
import hmac
import json
import os
from pathlib import Path
import shlex
import socket
import sys


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


async def cloud(args):
    config = json.loads(sys.stdin.readline(2048))
    secret = bytes.fromhex(config['secret'])
    approved = set(config['approved'])
    active = set()
    count = 0
    async def handle(reader, writer):
        nonlocal count
        task = asyncio.current_task(); active.add(task)
        try:
            if writer.get_extra_info('peername')[0] not in approved or count >= 16:
                return
            count += 1
            async with asyncio.timeout(5):
                request = json.loads(await reader.readline())
                role, nonce = request['role'], request['nonce']
                tag = encoded({'role': role, 'nonce': nonce})
                if role not in (0, 1) or not hmac.compare_digest(request['mac'], hmac.digest(secret, tag, 'sha256').hex()):
                    raise ValueError('OBSERVATION_AUTH_FAILED')
                response = {'role': role, 'nonce': nonce, 'observed': list(writer.get_extra_info('peername')[:2])}
                response['mac'] = hmac.digest(secret, encoded(response), 'sha256').hex()
                writer.write(encoded(response) + b'\n'); await writer.drain()
            await asyncio.wait_for(reader.read(1), 25)
        except (OSError, ValueError, TimeoutError, KeyError):
            pass
        finally:
            writer.close()
            try: await asyncio.wait_for(writer.wait_closed(), 0.5)
            except (OSError, TimeoutError): pass
            active.discard(task)
    server = await asyncio.start_server(handle, args.native, args.port, limit=2048)
    print('TCP_OBSERVER_READY', flush=True)
    try:
        try:
            control = asyncio.StreamReader()
            transport, _ = await asyncio.get_running_loop().connect_read_pipe(
                lambda: asyncio.StreamReaderProtocol(control), sys.stdin)
            try:
                await asyncio.wait_for(control.readline(), 90)
            finally:
                transport.close()
        except TimeoutError:
            pass
    finally:
        server.close()
        # Python 3.12 also waits for clients in wait_closed(). Cancel handlers
        # first so controller EOF does not wait for their observation deadline.
        await asyncio.sleep(0)
        tasks = list(active)
        for task in tasks: task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.wait_for(server.wait_closed(), 1)
        print('TCP_OBSERVATIONS', count, flush=True)


async def reuse_channel(outbound, listener, peer, hello, other_hello, role, report):
    """Role 0 selects one authenticated stream; role 1 follows that selection.

    Both sides listen before attempting active connect. Incoming and outgoing
    streams can coexist: selecting independently at each end could select two
    different connections, so only role 0 sends the selection byte.
    """
    loop = asyncio.get_running_loop()
    winner = loop.create_future()
    tasks, writers, accepted_sockets = set(), [], []
    selected = None
    report.update(accepted=0, connected=0, authenticated_candidates=0,
                  candidate_errors=[])

    async def candidate(sock, kind):
        nonlocal selected
        writer = None
        try:
            reader, writer = await asyncio.open_connection(sock=sock)
            writers.append(writer)
            if writer.get_extra_info('peername')[0] != peer[0]:
                raise ValueError('UNEXPECTED_PEER_IP')
            if writer.get_extra_info('sockname')[:2] != listener.getsockname()[:2]:
                raise ValueError('LOCAL_BIND_CHANGED')
            writer.write(hello); await writer.drain()
            if not hmac.compare_digest(await reader.readexactly(32), other_hello):
                raise ValueError('PEER_MAC_FAILED')
            report['authenticated_candidates'] += 1
            if role == 0:
                if selected is not None:
                    return
                selected = writer
                writer.write(b'S'); await writer.drain()
                if await reader.readexactly(1) != b'A':
                    raise ValueError('PEER_SELECTION_FAILED')
            else:
                if await reader.readexactly(1) != b'S' or selected is not None:
                    raise ValueError('PEER_SELECTION_FAILED')
                selected = writer
                writer.write(b'A'); await writer.drain()
            report['selected_kind'] = kind
            if not winner.done():
                winner.set_result((reader, writer))
        except (OSError, ValueError, asyncio.IncompleteReadError) as error:
            report['candidate_errors'].append(type(error).__name__)
            if isinstance(error, asyncio.IncompleteReadError):
                report.setdefault('incomplete_peer_mac_bytes', []).append(len(error.partial))
            if writer is selected and not winner.done():
                winner.set_exception(error)
        finally:
            if writer is not selected:
                if writer is not None:
                    writer.close()
                else:
                    sock.close()

    def start(coro):
        task = asyncio.create_task(coro)
        tasks.add(task)
        return task

    async def active():
        try:
            await loop.sock_connect(outbound, peer)
            report['connected'] += 1
            await candidate(outbound, 'active')
        except OSError as error:
            report['candidate_errors'].append(type(error).__name__)

    async def passive():
        for _ in range(4):
            sock, remote = await loop.sock_accept(listener)
            accepted_sockets.append(sock)
            sock.setblocking(False)
            if remote[0] != peer[0]:
                sock.close()
                continue
            report['accepted'] += 1
            start(candidate(sock, 'passive'))

    try:
        start(passive()); start(active())
        channel = await winner
        return channel
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        successful = winner.done() and not winner.cancelled() and winner.exception() is None
        selected_fd = selected.get_extra_info('socket').fileno() if successful else -1
        for writer in writers:
            if winner.cancelled() or not winner.done() or winner.exception() is not None or writer is not selected:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), 1)
                except (OSError, TimeoutError):
                    pass
        for sock in accepted_sockets:
            if sock.fileno() != selected_fd:
                sock.close()


async def agent(args):
    config = json.loads(sys.stdin.readline(2048))
    secret, role = bytes.fromhex(config['secret']), config['role']
    resources, streams = [], []
    outbound, original = None, None
    def new(local):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        resources.append(sock)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if args.strategy == 'both-listen':
            if not sys.platform.startswith('linux') or not hasattr(socket, 'SO_REUSEPORT'):
                raise ValueError('LINUX_REUSEPORT_REQUIRED')
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setblocking(False); sock.bind(local)
        return sock
    report = {'strategy':'tcp-passive-ttl-prime', 'role':role, 'relay':False,
              'application_validated':False, 'ttl':args.ttl, 'peer_verified':False}
    if args.strategy == 'both-listen':
        report.update(strategy='tcp-both-listen-reuseport', ttl=None, uid=os.getuid(),
                      both_listen=True, reuseport=True, ttl_modified=False)
    try:
        observer = new((args.native, 0)); local = observer.getsockname()
        outbound = new(local)
        listener = new(local) if role == 1 or args.strategy == 'both-listen' else None
        if listener: listener.listen(8)
        loop = asyncio.get_running_loop()
        async with asyncio.timeout(8):
            await loop.sock_connect(observer, (args.observer, args.port))
            reader, writer = await asyncio.open_connection(sock=observer)
            streams.append(writer)
            request = {'role':role, 'nonce':os.urandom(16).hex()}
            request['mac'] = hmac.digest(secret, encoded(request), 'sha256').hex()
            writer.write(encoded(request) + b'\n'); await writer.drain()
            response = json.loads(await reader.readline())
            mac = response.pop('mac')
            if response['role'] != role or response['nonce'] != request['nonce'] or not hmac.compare_digest(mac, hmac.digest(secret, encoded(response), 'sha256').hex()):
                raise ValueError('OBSERVATION_AUTH_FAILED')
            print(json.dumps({'local':local,'observed':response['observed'],'nonce':request['nonce']}), flush=True)
        control = asyncio.StreamReader()
        control_transport, _ = await loop.connect_read_pipe(
            lambda: asyncio.StreamReaderProtocol(control), sys.stdin)
        try:
            data = json.loads(await asyncio.wait_for(control.readline(), 20))
        finally:
            control_transport.close()
        peer = tuple(data['peer'])
        socket.inet_aton(peer[0])
        if not 1024 <= peer[1] <= 65535:
            raise ValueError('HIGH_PORT_REQUIRED')
        hello = hmac.digest(secret, b'peer-source-' + request['nonce'].encode(), 'sha256')
        other_hello = hmac.digest(secret, b'peer-source-' + data['peer_nonce'].encode(), 'sha256')
        acknowledgement = hmac.digest(secret, b'peer-receiver-' + data['pair_nonce'].encode(), 'sha256')
        if args.strategy == 'ttl':
            original = outbound.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        report['local'] = list(local)
        async with asyncio.timeout(12):
            if args.strategy == 'both-listen':
                my_hello = hmac.digest(secret, encoded({'role': role, 'nonce': request['nonce'],
                                      'pair': data['pair_nonce']}), 'sha256')
                peer_hello = hmac.digest(secret, encoded({'role': 1-role, 'nonce': data['peer_nonce'],
                                        'pair': data['pair_nonce']}), 'sha256')
                incoming, outgoing = await reuse_channel(outbound, listener, peer,
                                                         my_hello, peer_hello, role, report)
                streams.append(outgoing)
                if role == 0:
                    payload = os.urandom(65536)
                    outgoing.write(payload); await outgoing.drain(); outgoing.write_eof()
                    if await incoming.readexactly(65536) != payload or await incoming.read(1):
                        raise ValueError('CONTROL_PAYLOAD_MISMATCH')
                else:
                    payload = await incoming.readexactly(65536)
                    if await incoming.read(1):
                        raise ValueError('CONTROL_PAYLOAD_TOO_LARGE')
                    outgoing.write(payload); await outgoing.drain(); outgoing.write_eof()
            elif role == 1:
                outbound.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, args.ttl)
                report['prime_connect_code'] = outbound.connect_ex(peer)
                accepted, remote = await loop.sock_accept(listener)
                resources.append(accepted); accepted.setblocking(False)
                if remote[0] != peer[0]:
                    raise ValueError('UNEXPECTED_PEER_IP')
                incoming, outgoing = await asyncio.open_connection(sock=accepted)
                streams.append(outgoing)
                if not hmac.compare_digest(await incoming.readexactly(32), other_hello):
                    raise ValueError('PEER_MAC_FAILED')
                outgoing.write(acknowledgement); await outgoing.drain()
                payload = await incoming.readexactly(65536)
                if await incoming.read(1):
                    raise ValueError('CONTROL_PAYLOAD_TOO_LARGE')
                outgoing.write(payload); await outgoing.drain(); outgoing.write_eof()
            else:
                await asyncio.sleep(1)
                await loop.sock_connect(outbound, peer)
                incoming, outgoing = await asyncio.open_connection(sock=outbound)
                streams.append(outgoing)
                outgoing.write(hello); await outgoing.drain()
                if not hmac.compare_digest(await incoming.readexactly(32), acknowledgement):
                    raise ValueError('PEER_MAC_FAILED')
                payload = os.urandom(65536)
                outgoing.write(payload); await outgoing.drain(); outgoing.write_eof()
                if await incoming.readexactly(65536) != payload or await incoming.read(1):
                    raise ValueError('CONTROL_PAYLOAD_MISMATCH')
            report.update(peer_verified=True, test_bytes=65536, sha256=hashlib.sha256(payload).hexdigest())
            # This is a diagnostic MAC exchange, not production pinned TLS/SSH.
    except (OSError, ValueError, TimeoutError, asyncio.IncompleteReadError) as error:
        report['error'] = type(error).__name__
    finally:
        if outbound and original is not None:
            try:
                outbound.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, original)
                report['ttl_restored'] = True
            except OSError:
                report['ttl_restored'] = False
        for writer in streams:
            writer.close()
            try: await writer.wait_closed()
            except OSError: pass
        for sock in resources: sock.close()
    print(json.dumps(report), flush=True)


async def run(args):
    inventory = json.loads(args.inventory.read_text(encoding='utf8'))
    secret = os.urandom(32).hex()
    code = Path(__file__).read_text(encoding='utf8')
    children = []
    async def launch(item, flags):
        command = shlex.join([item['python'],'-u','-c',code,*flags])
        child = await asyncio.create_subprocess_exec('ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                                                    '-o','ForwardAgent=no','-o','ConnectTimeout=8',item['host'],command,
                                                    stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.PIPE)
        children.append(child)
        return child
    async def send(child, data):
        child.stdin.write(encoded(data)+b'\n'); await child.stdin.drain()
    async def receive(child, timeout):
        line = await asyncio.wait_for(child.stdout.readline(), timeout)
        if not line:
            args.output.with_suffix('.stderr.log').write_bytes(await child.stderr.read(4096))
            raise ValueError('TCP_AGENT_EXITED')
        return json.loads(line)
    try:
        obs = inventory['tcp_observer']
        cloud_child = await launch(obs,['--cloud','--native',obs['native'],'--port',str(obs['port'])])
        await send(cloud_child,{'secret':secret,'approved':inventory['approved_public_ips']})
        ready = await asyncio.wait_for(cloud_child.stdout.readline(),12)
        if ready.strip() != b'TCP_OBSERVER_READY':
            raise ValueError('TCP_OBSERVER_NOT_READY')
        print('TCP observer ready',flush=True)
        results=[]
        for ttl in ((7,4) if args.strategy == 'ttl' else (7,) * args.trials):
            agents=[]
            for role,item in enumerate(inventory['peers']):
                child = await launch(item,['--agent','--native',item['native'],'--observer',obs['public'],
                                          '--port',str(obs['port']),'--ttl',str(ttl),
                                          '--strategy',args.strategy])
                agents.append(child)
                await send(child,{'secret':secret,'role':role})
            bindings = await asyncio.gather(*(receive(child,15) for child in agents))
            # Nonce is already MACed in each agent's cloud observation; return it
            # only over the verified management channel for the peer challenge.
            # A separate pair nonce binds the receiver's response to this trial.
            pair_nonce = os.urandom(16).hex()
            # Agent challenge uses its observation nonce, so expose it explicitly.
            for index,child in enumerate(agents):
                await send(child,{'peer':bindings[1-index]['observed'],
                                  'peer_nonce':bindings[1-index]['nonce'],'pair_nonce':pair_nonce})
            reports = await asyncio.gather(*(receive(child,18) for child in agents))
            results.append({'ttl':ttl if args.strategy == 'ttl' else None,
                            'strategy':args.strategy,'bindings':bindings,'results':reports})
            print('TCP '+args.strategy+' peer verified:',[r['peer_verified'] for r in reports],flush=True)
        args.output.write_text(json.dumps(results,indent=2),encoding='utf8')
    finally:
        for child in children:
            if child.stdin: child.stdin.close()
            if child.returncode is None:
                try: await asyncio.wait_for(child.wait(),2)
                except TimeoutError: child.kill(); await child.wait()


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cloud',action='store_true')
    parser.add_argument('--agent',action='store_true')
    parser.add_argument('--native'); parser.add_argument('--observer')
    parser.add_argument('--port',type=int); parser.add_argument('--ttl',type=int,choices=(4,7),default=7)
    parser.add_argument('--strategy', choices=('ttl', 'both-listen'), default='ttl')
    parser.add_argument('--trials', type=int, choices=(1,2,3), default=3)
    parser.add_argument('--inventory',type=Path); parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if args.cloud: asyncio.run(cloud(args))
    elif args.agent: asyncio.run(agent(args))
    else: asyncio.run(run(args))
