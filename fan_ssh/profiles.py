"""Named connection options; no stored secrets, enrollment, or network probes."""
import argparse
from importlib.metadata import PackageNotFoundError, version
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
from types import SimpleNamespace

from .config import Policy, direct_address, name, schema, strict_json
from .device import enrolled, load
from .ssh_cli import ssh_command


MAX_PROFILE = 16 * 1024
FIELDS = ('identity', 'policy', 'peer', 'service', 'transport', 'ssh_host', 'ssh_user',
          'ssh_port', 'udp_native', 'stun', 'stun_alternate', 'udp_strategy',
          'reverse_listen', 'reverse_candidate')
REQUIRED = {'identity', 'policy', 'peer', 'service', 'transport', 'udp_strategy'}
WINDOWS_RESERVED = {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)),
                    *(f'LPT{i}' for i in range(1, 10))}


def connection_options(command, *, ssh=False):
    """Keep saved profiles and explicit commands on the same option vocabulary."""
    command.add_argument('--identity', help='existing user-private identity directory')
    command.add_argument('--policy', help='existing approved roster/ACL file')
    command.add_argument('--service', default='ssh')
    command.add_argument('--transport', choices=('auto', 'tcp', 'udp'), help='default: automatic direct methods; no relay fallback')
    command.add_argument('--udp-native', help='explicit approved physical IP; requires udp extra')
    command.add_argument('--stun', help='explicit numeric STUN observer for UDP transport')
    command.add_argument('--stun-alternate', help='optional second explicitly approved numeric STUN observer')
    command.add_argument('--udp-strategy', choices=('ice', 'predict'), default='ice', help='explicit UDP strategy; auto mode tries both')
    command.add_argument('--reverse-listen', help='optional numeric high-port listener for reverse direct connections')
    command.add_argument('--reverse-candidate', help='approved advertised reverse listener address, if different from bind')
    if ssh:
        command.add_argument('--ssh-host', help='existing SSH alias for credentials and verified host key; defaults to peer ID')
        command.add_argument('--ssh-user', help='optional existing SSH user')
        command.add_argument('--ssh-port', type=int, help='optional original SSH port for host-key lookup')


def profile_directory():
    if sys.platform == 'win32':
        base = Path(os.environ.get('LOCALAPPDATA') or Path.home() / 'AppData' / 'Local')
    elif sys.platform == 'darwin':
        base = Path.home() / 'Library' / 'Application Support'
    else:
        base = Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config')
    return base / 'fan-ssh' / 'profiles'


def profile_name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', value) or value.upper() in WINDOWS_RESERVED:
        raise ValueError('INVALID_PROFILE_NAME: use 1-64 letters, digits, underscores or hyphens, starting with a letter or digit; avoid Windows reserved names')
    return value


def profile_path(alias, directory=None):
    return (Path(directory).expanduser() if directory else profile_directory()) / (profile_name(alias) + '.json')


def validate_options(value):
    if not isinstance(value, dict) or set(value) != set(FIELDS):
        raise ValueError('INVALID_PROFILE_OPTIONS')
    for key, item in value.items():
        if key == 'ssh_port':
            if item is not None and (type(item) is not int or not 1 <= item <= 65535):
                raise ValueError('INVALID_SSH_PORT')
        elif item is not None and (not isinstance(item, str) or not 1 <= len(item) <= 4096 or any(c in item for c in '\r\n\0')):
            raise ValueError('INVALID_PROFILE_VALUE: ' + key)
        if key in REQUIRED and item is None:
            raise ValueError('PROFILE_REQUIRES: --' + key.replace('_', '-'))
    name(value['peer']); name(value['service'])
    if value['transport'] not in ('auto', 'tcp', 'udp') or value['udp_strategy'] not in ('ice', 'predict'):
        raise ValueError('INVALID_PROFILE_TRANSPORT')
    for key in ('identity', 'policy'):
        if not Path(value[key]).is_absolute():
            raise ValueError('PROFILE_PATH_MUST_BE_ABSOLUTE: ' + key)
    if bool(value['udp_native']) != bool(value['stun']) or (value['stun_alternate'] and not value['stun']):
        raise ValueError('--udp-native and --stun must be supplied together')
    if value['transport'] == 'udp':
        if not value['udp_native']:
            raise ValueError('UDP requires --udp-native and --stun')
        if value['reverse_listen']:
            raise ValueError('UDP does not use a TCP reverse listener')
    if value['transport'] == 'tcp' and any(value[key] for key in ('udp_native', 'stun', 'stun_alternate')):
        raise ValueError('UDP options require --transport auto or udp')
    for key in ('stun', 'stun_alternate', 'reverse_candidate'):
        if value[key]:
            direct_address(value[key])
    if value['reverse_listen']:
        direct_address(value['reverse_listen'], bind=True)
    elif value['reverse_candidate']:
        raise ValueError('REVERSE_LISTEN_REQUIRED')
    if value['udp_native']:
        native = value['udp_native']
        direct_address(f'[{native}]:22022' if ':' in native else f'{native}:22022')
    # Build, but never execute, the same strict OpenSSH invocation.
    ssh_command(SimpleNamespace(**value, command=[]))
    return value


def load_profile(alias, directory=None):
    path = profile_path(alias, directory)
    if path.is_symlink():
        raise ValueError('PROFILE_SYMLINK_REJECTED')
    if path.exists() and not path.is_file():
        raise ValueError('PROFILE_MUST_BE_REGULAR_FILE')
    try:
        with path.open('rb') as file:
            raw = file.read(MAX_PROFILE + 1)
    except FileNotFoundError as error:
        raise ValueError(f'PROFILE_NOT_FOUND: {alias}; use fan-ssh profile list or fan-ssh profile add') from error
    if len(raw) > MAX_PROFILE:
        raise ValueError('PROFILE_TOO_LARGE')
    data = strict_json(raw)
    schema(data, ('version', 'connection'))
    if type(data['version']) is not int or data['version'] != 1:
        raise ValueError('UNSUPPORTED_PROFILE_VERSION')
    return validate_options(data['connection'])


def save_profile(args):
    path = profile_path(args.alias, args.profiles_dir)
    value = {key: getattr(args, key, None) for key in FIELDS}
    value['transport'] = value['transport'] or 'auto'
    for key in ('identity', 'policy'):
        if not value[key]:
            raise ValueError('PROFILE_REQUIRES: --' + key)
        # Make paths independent of the working directory used by future connects.
        value[key] = str(Path(value[key]).expanduser().absolute())
    validate_options(value)
    raw = (json.dumps({'version': 1, 'connection': value}, indent=2) + '\n').encode('utf8')
    if len(raw) > MAX_PROFILE:
        raise ValueError('PROFILE_TOO_LARGE')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise ValueError('PROFILE_ALREADY_EXISTS: choose another name or explicitly edit the existing profile') from error
    try:
        with os.fdopen(descriptor, 'wb') as file:
            file.write(raw)
    except BaseException:
        path.unlink()
        raise
    return path


def connection_args(args):
    options = load_profile(args.alias, args.profiles_dir)
    return SimpleNamespace(**options, mode='ssh', command=args.command)


def check_approval(options):
    try:
        identifier, identity = load(options['identity'])
    except TypeError as error:
        # cryptography reports an unsupported encrypted identity as TypeError.
        raise ValueError('IDENTITY_KEY_UNREADABLE: ' + str(error)) from error
    policy = Policy.load(options['policy'])
    enrolled(identifier, identity, policy)
    if identifier == policy.coordinator:
        raise ValueError('PEER_IDENTITY_REQUIRED')
    if options['peer'] not in policy.devices:
        raise ValueError('PEER_NOT_APPROVED')
    if not policy.permits(identifier, options['peer'], options['service']):
        raise ValueError('ACL_DENIED')
    candidates = policy.devices[identifier].candidates
    if options['reverse_listen'] and (options['reverse_candidate'] or options['reverse_listen']) not in candidates:
        raise ValueError('UNAPPROVED_REVERSE_CANDIDATE')
    if options['udp_native'] and options['udp_native'] not in {direct_address(item)[0] for item in candidates}:
        raise ValueError('NATIVE_ADDRESS_NOT_APPROVED')
    return identifier, policy


def doctor(options):
    """Read local files/metadata only. Do not run ssh -G (Match exec can execute)."""
    checks = []
    def record(label, operation):
        try:
            detail = operation()
        except (OSError, ValueError, PackageNotFoundError, subprocess.SubprocessError) as error:
            checks.append({'check': label, 'ok': False, 'detail': str(error)})
        else:
            checks.append({'check': label, 'ok': True, 'detail': detail})
    def approval():
        identifier, policy = check_approval(options)
        return f'{identifier} -> {options["peer"]}:{options["service"]}; policy revision {policy.revision}'
    record('identity-policy-acl', approval)
    def ssh():
        executable = shutil.which('ssh')
        if not executable:
            raise ValueError('SSH_NOT_FOUND: install the system OpenSSH client')
        return executable
    record('openssh-client', ssh)
    if options['udp_native']:
        def udp():
            for package, expected in (('aiortc', '1.15.0'), ('aioice', '0.10.2')):
                if version(package) != expected:
                    raise ValueError(f'UDP_VERSION_REQUIRED: {package}=={expected}')
            return 'pinned UDP dependencies installed'
        record('udp-dependencies', udp)
    return {'ok': all(item['ok'] for item in checks), 'scope': 'offline-only', 'checks': checks,
            'not_checked': ['network reachability and NAT traversal', 'running coordinator or receiving node',
                            'SSH effective configuration, credentials and verified host key']}


def add_commands(commands):
    def directory(command):
        command.add_argument('--profiles-dir', help='override the per-user profile directory; put before the alias for connect')
    profile = commands.add_parser('profile', help='save/list/show reusable connection options; never stores keys or grants access')
    actions = profile.add_subparsers(dest='profile_action', required=True)
    add = actions.add_parser('add', help='save a new profile without overwriting an existing one')
    add.add_argument('alias')
    add.add_argument('--peer', required=True)
    connection_options(add, ssh=True)
    directory(add)
    listing = actions.add_parser('list', help='list saved profile names')
    directory(listing)
    show = actions.add_parser('show', help='show a profile and its file location')
    show.add_argument('alias')
    directory(show)
    connect = commands.add_parser('connect', help='connect using a saved profile and existing SSH credentials',
                                  epilog='Example: fan-ssh connect remote -- uname -a')
    directory(connect)
    connect.add_argument('alias')
    connect.add_argument('command', nargs=argparse.REMAINDER, help='optional remote command after --')
    check = commands.add_parser('doctor', help='check a profile offline; no connections, listeners or SSH config execution')
    directory(check)
    check.add_argument('alias')


def run_profile(args):
    if args.mode == 'doctor':
        result = doctor(load_profile(args.alias, args.profiles_dir))
        print(json.dumps(result, indent=2))
        return 0 if result['ok'] else 1
    if args.profile_action == 'add':
        path = save_profile(args)
        location = ['--profiles-dir', str(path.parent.absolute())] if args.profiles_dir else []
        quote = subprocess.list2cmdline if os.name == 'nt' else shlex.join
        check = quote(['fan-ssh', 'doctor', *location, args.alias])
        connect = quote(['fan-ssh', 'connect', *location, args.alias])
        print(f'Profile saved: {path}\nCheck local prerequisites: {check}\nConnect: {connect}')
    elif args.profile_action == 'show':
        options = load_profile(args.alias, args.profiles_dir)
        print(json.dumps({'path': str(profile_path(args.alias, args.profiles_dir)), 'connection': options}, indent=2))
    else:
        root = Path(args.profiles_dir).expanduser() if args.profiles_dir else profile_directory()
        names = sorted(path.stem for path in root.glob('*.json') if path.is_file())
        print('\n'.join(names) if names else 'No profiles yet. Use fan-ssh profile add --help.')
    return 0
