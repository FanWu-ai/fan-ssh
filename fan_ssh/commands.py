"""Actual device CLI, kept separate from the unchanged synthetic fixture."""
import asyncio
import hashlib
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization

from .config import Policy, certificate, direct_address, name, schema, strict_json
from .control import Control, watch_policy
from .device import load, save
from .remote import Client, MAX_SESSION, Node
from .transport import Service, bridge


def add_commands(commands):
    init = commands.add_parser('identity-init', help='explicitly create a new device key in a new private directory')
    init.add_argument('--id', required=True)
    init.add_argument('--directory', required=True)
    init.add_argument('--public', required=True, help='new public enrollment record file; never contains a private key')
    export = commands.add_parser('identity-export', help='export a device public certificate for operator approval')
    export.add_argument('--identity', required=True)
    export.add_argument('--output', required=True)
    build = commands.add_parser('policy-build', help='build a manually approved roster and directed service ACL')
    build.add_argument('--account', required=True)
    build.add_argument('--revision', type=int, default=1)
    build.add_argument('--coordinator', required=True)
    build.add_argument('--coordinator-address', required=True)
    build.add_argument('--device', action='append', required=True, help='public enrollment record file (repeatable)')
    build.add_argument('--candidate', action='append', default=[], help='DEVICE=IP:HIGHPORT (repeatable, explicitly approved)')
    build.add_argument('--allow', action='append', default=[], help='SOURCE:TARGET:SERVICE (repeatable, directed)')
    build.add_argument('--output', required=True)
    for mode in ('coordinator', 'node', 'diagnose'):
        command = commands.add_parser(mode)
        command.add_argument('--identity', required=True)
        command.add_argument('--policy', required=True)
        if mode == 'diagnose':
            command.add_argument('--peer', required=True)
            command.add_argument('--service', default='ssh')
        else:
            command.add_argument('--listen', default=None if mode == 'coordinator' else '127.0.0.1:22022')
        if mode == 'node':
            command.add_argument('--service', action='append', required=True, help='ID=NUMERIC_LOOPBACK:PORT (repeatable)')
            command.add_argument('--no-reverse', action='store_true', help='disable reverse-offer polling')
            command.add_argument('--udp-native', help='explicit approved physical IP for direct ICE; requires udp extra')
            command.add_argument('--stun', help='explicit numeric approved STUN observation endpoint; no TURN')
            command.add_argument('--stun-alternate', help='optional second explicitly approved numeric STUN observer')
            command.add_argument('--udp-strategy', choices=('auto', 'ice', 'predict'), default='auto')
        if mode == 'coordinator':
            command.add_argument('--stun-listen', help='optional bounded IPv4 Binding observer on an approved high port')
            command.add_argument('--stun-alternate-listen', help='optional second separately approved UDP observation port')
    command = commands.add_parser('home-bridge', help='explicit business bridge to one fixed approved peer; no cloud data relay')
    command.add_argument('--identity', required=True)
    command.add_argument('--policy', required=True)
    command.add_argument('--listen', default='127.0.0.1:22022')
    command.add_argument('--bridge-service', required=True, help='incoming service name approved for this home device')
    command.add_argument('--peer', required=True, help='fixed final device; callers cannot choose another target')
    command.add_argument('--service', default='ssh', help='fixed final service approved for home -> peer')
    command.add_argument('--transport', choices=('auto', 'tcp', 'udp'), default='auto', help='outgoing direct methods only')
    command.add_argument('--udp-native', help='explicit physical IP for incoming/outgoing UDP')
    command.add_argument('--stun', help='explicit numeric approved UDP observer')
    command.add_argument('--stun-alternate')
    command.add_argument('--udp-strategy', choices=('ice', 'predict'), default='ice')
    command.add_argument('--reverse-listen', help='optional separate outgoing reverse-TCP listener')
    command.add_argument('--reverse-candidate')
    command.add_argument('--no-reverse', action='store_true', help='disable incoming reverse/UDP offer polling')


def public_record(identifier, identity):
    return {'id': identifier, 'pin': identity.pin, 'cert': identity.cert.decode('ascii')}


def write_new(path, value):
    with Path(path).open('x', encoding='utf8') as file:
        json.dump(value, file, indent=2)
        file.write('\n')


def build_policy(args):
    records = {}
    if len(args.device) > 64 or len(args.candidate) > 512 or len(args.allow) > 4096:
        raise ValueError('CONFIG_LIMIT')
    for path in args.device:
        with Path(path).open('rb') as file:
            data = file.read(8193)
        if len(data) > 8192:
            raise ValueError('PUBLIC_RECORD_TOO_LARGE')
        record = strict_json(data)
        schema(record, ('id', 'pin', 'cert'))
        identifier = name(record['id'])
        cert = certificate(record['cert'])
        pin = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        if record['pin'] != pin or identifier in records:
            raise ValueError('INVALID_PUBLIC_RECORD')
        records[identifier] = {'id': identifier, 'cert': record['cert'], 'candidates': []}
    for value in args.candidate:
        identifier, separator, endpoint = value.partition('=')
        if not separator or identifier not in records:
            raise ValueError('INVALID_CANDIDATE_DEVICE')
        direct_address(endpoint)
        records[identifier]['candidates'].append(endpoint)
    edges = []
    for value in args.allow:
        parts = value.split(':')
        if len(parts) != 3:
            raise ValueError('INVALID_ACL_EDGE')
        edges.append(dict(zip(('from', 'to', 'service'), parts)))
    data = dict(version=1, account=args.account, revision=args.revision,
                coordinator={'id': args.coordinator, 'address': args.coordinator_address},
                devices=list(records.values()), allow=edges)
    Policy.parse(data)
    write_new(args.output, data)


def make_client(args, identifier, identity, policy):
    client = Client(identifier, identity, policy, reverse_listen=getattr(args, 'reverse_listen', None),
                    reverse_candidate=getattr(args, 'reverse_candidate', None))
    transport = getattr(args, 'transport', 'tcp')
    if transport in ('udp', 'auto'):
        if bool(args.udp_native) != bool(args.stun) or (args.stun_alternate and not args.stun):
            raise ValueError('--udp-native and --stun must be supplied together')
    if transport == 'udp':
        if not args.udp_native or not args.stun:
            raise ValueError('UDP requires --udp-native and --stun')
        if args.reverse_listen:
            raise ValueError('UDP does not use a TCP reverse listener')
        try:
            from .udp_remote import UDPClient
        except ImportError as error:
            raise ValueError('UDP_EXTRA_REQUIRED: install fan-ssh[udp]') from error
        client = UDPClient(identifier, identity, policy, args.udp_native, args.stun, context=client.context,
                           strategy=args.udp_strategy, alternate=args.stun_alternate)
    elif transport == 'auto':
        from .strategies import AutomaticClient
        forward = Client(identifier, identity, policy)
        methods = [('tcp', forward, 'dial', 12)]
        if client.reverse_listen:
            methods.append(('reverse-tcp', client, 'reverse_dial', 12))
        if args.udp_native:
            try:
                from .udp_remote import UDPClient
            except ImportError as error:
                raise ValueError('UDP_EXTRA_REQUIRED: install fan-ssh[udp]') from error
            for strategy in ('ice', 'predict'):
                if ':' in args.udp_native and strategy == 'predict':
                    continue
                udp = UDPClient(identifier, identity, policy, args.udp_native, args.stun, context=client.context,
                                strategy=strategy, alternate=args.stun_alternate)
                methods.append(('udp-' + strategy, udp, 'dial', 50 if strategy == 'predict' else 28))
        client = AutomaticClient(methods, log=lambda entry: print(json.dumps(entry, separators=(',', ':')), file=sys.stderr))
    return client


async def run_remote(args, proxy):
    if args.mode == 'identity-init':
        # Check both destinations before generating anything; never replace an identity.
        if Path(args.directory).exists() or Path(args.public).exists():
            raise ValueError('IDENTITY_OR_PUBLIC_FILE_ALREADY_EXISTS')
        identity = save(args.id, args.directory)
        write_new(args.public, public_record(args.id, identity))
        print(f'Device {args.id}; SHA256 {identity.pin}; public record {args.public}')
        return
    if args.mode == 'identity-export':
        identifier, identity = load(args.identity)
        write_new(args.output, public_record(identifier, identity))
        return
    if args.mode == 'policy-build':
        build_policy(args)
        print(f'Approved policy written: {args.output}')
        return
    if not args.identity or not args.policy:
        raise ValueError('--identity and --policy are required for remote mode')
    identifier, identity = load(args.identity)
    policy = Policy.load(args.policy)
    if args.mode == 'ssh':
        from .ssh_cli import ssh_login
        return await ssh_login(args)
    if args.mode in ('coordinator', 'node', 'home-bridge'):
        if args.mode == 'coordinator':
            service = Control(identifier, identity, policy)
            await service.start(args.listen or policy.endpoint)
            observers = []
            if args.stun_alternate_listen and not args.stun_listen:
                await service.close()
                raise ValueError('PRIMARY_STUN_LISTENER_REQUIRED')
            if args.stun_listen:
                from .stun import start_observers
                endpoints = [args.stun_listen]
                if args.stun_alternate_listen:
                    endpoints.append(args.stun_alternate_listen)
                try:
                    observers = await start_observers(service, endpoints)
                except BaseException:
                    await service.close()
                    raise
        else:
            if args.mode == 'home-bridge':
                from .home_bridge import HomeBridge
                client = make_client(args, identifier, identity, policy)
                try:
                    service = HomeBridge(identifier, identity, policy, args.bridge_service,
                                         args.peer, args.service, client)
                except BaseException:
                    await client.close()
                    raise
            else:
                services = {}
                for item in args.service:
                    key, separator, endpoint = item.partition('=')
                    if not separator or key in services:
                        raise ValueError('INVALID_OR_DUPLICATE_SERVICE')
                    services[key] = endpoint
                service = Node(identifier, identity, policy, services)
            try:
                if bool(args.udp_native) != bool(args.stun):
                    raise ValueError('--udp-native and --stun must be supplied together')
                if args.udp_native:
                    try:
                        from .udp_remote import UDPNode
                    except ImportError as error:
                        raise ValueError('UDP_EXTRA_REQUIRED: install fan-ssh[udp]') from error
                    service.udp = UDPNode(service, args.udp_native, args.stun,
                                          strategy='auto' if args.mode == 'home-bridge' else args.udp_strategy,
                                          alternate=args.stun_alternate)
                elif args.stun_alternate or (args.mode == 'node' and args.udp_strategy != 'auto'):
                    raise ValueError('UDP options require --udp-native and --stun')
                await service.start(args.listen, poll=not args.no_reverse)
            except BaseException:
                await service.close()
                raise
        watcher = asyncio.create_task(watch_policy(args.policy, service, sys.stderr))
        try:
            print(f'{args.mode.upper()} listening={service.service.address} revision={policy.revision}', file=sys.stderr)
            await asyncio.Future()
        finally:
            watcher.cancel()
            await asyncio.gather(watcher, return_exceptions=True)
            await service.close()
            if args.mode == 'coordinator':
                for observer in observers:
                    await observer.close()
        return
    client = make_client(args, identifier, identity, policy)
    local_forward = None
    try:
        if args.mode == 'diagnose':
            report = await client.diagnose(args.peer, args.service)
            print(json.dumps(report, indent=2))
            return 0 if report['code'] == 'AUTHENTICATED_DIRECT_TLS' else 1
        if args.mode == 'proxy':
            pair, report = await client.dial(args.peer, args.service)
            print(json.dumps(report, separators=(',', ':')), file=sys.stderr)
            await proxy(pair, timeout=MAX_SESSION)
        else:
            async def handler(reader, writer):
                pair, report = await client.dial(args.peer, args.service)
                print(json.dumps(report, separators=(',', ':')), file=sys.stderr)
                await bridge((reader, writer), pair, timeout=MAX_SESSION)
            local_forward = await Service(handler).start(args.listen)  # Local callers only.
            print(f'FORWARD listening={local_forward.address} peer={args.peer} service={args.service}', file=sys.stderr)
            await asyncio.Future()
    finally:
        if local_forward:
            await local_forward.close()
        await client.close()
