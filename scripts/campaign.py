"""Explicitly authorized native-network campaign, with a private endpoint inventory.

No host defaults; supply consenting hosts, native bind/advertised addresses and ports.
Uses existing verified SSH only to deploy test code and exchange bounded metadata.
All synthetic business bytes use direct peer TLS. Temporary files/processes are cleaned.
"""
import argparse
import asyncio
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile

from remote_tests import SSH_OPTIONS


class Agent:
    def __init__(self, item, repository, archive, output, local_state):
        self.item, self.repository, self.archive = item, repository, archive
        self.output, self.local_state = output, local_state
        self.root, self.process, self.log = None, None, None

    async def connect(self):
        ids = [device['id'] for device in self.item['devices']]
        self.log = (self.output.parent / (ids[-1] + '-campaign.stderr.log')).open('wb')
        command = [sys.executable, str(self.repository / 'scripts/campaign_agent.py')]
        if self.item.get('local'):
            command += ['--local-state', str(self.local_state)]
        else:
            host, python = self.item['host'], self.item['python']
            result = await asyncio.to_thread(subprocess.run, ['ssh', *SSH_OPTIONS, host, 'umask 077; mktemp -d /tmp/fan-ssh-test.XXXXXXXX'], capture_output=True, timeout=20)
            if result.returncode:
                self.log.write(result.stderr); self.log.flush()
                raise ValueError('MANAGEMENT_SSH_FAILED: ' + ids[-1])
            self.root = result.stdout.decode().strip()
            if not re.fullmatch(r'/tmp/fan-ssh-test\.[A-Za-z0-9]{8}', self.root):
                raise ValueError('Unexpected temporary directory')
            await asyncio.to_thread(subprocess.run, ['scp', *SSH_OPTIONS, '-q', str(self.archive), host + ':' + self.root + '/input.tar.gz'], check=True, timeout=240)
            extra = ' aiortc==1.15.0 aioice==0.10.2' if self.item.get('udp') else ''
            script = f'''set -e
cd {shlex.quote(self.root)}
tar xzf input.tar.gz
PYTHONPATH="$PWD/wheels/pip-26.2.1-py3-none-any.whl" {shlex.quote(python)} -m pip install --target "$PWD/deps" --no-index --find-links "$PWD/wheels" cryptography==50.0.2 cffi==2.1.1 pycparser==3.0{extra}
'''
            installed = await asyncio.to_thread(subprocess.run, ['ssh', *SSH_OPTIONS, host, 'sh -s'], input=script.encode(), capture_output=True, timeout=90)
            if installed.returncode:
                self.log.write(installed.stdout + installed.stderr); self.log.flush()
                raise ValueError('TEMPORARY_DEPENDENCY_INSTALL_FAILED')
            remote = 'cd ' + shlex.quote(self.root) + '; PYTHONPATH=' + shlex.quote(self.root + '/deps:' + self.root) + ' ' + shlex.quote(python) + ' scripts/campaign_agent.py'
            remote += ''.join(' --id ' + shlex.quote(identifier) for identifier in ids)
            command = ['ssh', *SSH_OPTIONS, host, remote]
        if self.item.get('local'):
            for identifier in ids:
                command += ['--id', identifier]
        self.process = await asyncio.create_subprocess_exec(*command, stdin=asyncio.subprocess.PIPE,
                                                           stdout=asyncio.subprocess.PIPE, stderr=self.log,
                                                           cwd=self.repository, limit=1024 * 1024)
        return await self.receive(20)

    async def receive(self, timeout=35):
        line = await asyncio.wait_for(self.process.stdout.readline(), timeout)
        if not line:
            raise ValueError('CAMPAIGN_AGENT_EXITED')
        return json.loads(line)

    async def send(self, value, timeout=35):
        self.process.stdin.write(json.dumps(value, separators=(',', ':')).encode() + b'\n')
        await self.process.stdin.drain()
        return await self.receive(timeout)

    async def close(self):
        if self.process and self.process.returncode is None:
            try:
                await self.send({'op': 'stop'}, timeout=5)
                await asyncio.wait_for(self.process.wait(), 5)
            except (OSError, ValueError, TimeoutError, asyncio.IncompleteReadError):
                self.process.kill()
                await self.process.wait()
        if self.root:
            # Exact path returned by mktemp and validated above; never a computed parent.
            await asyncio.to_thread(subprocess.run, ['ssh', *SSH_OPTIONS, self.item['host'], 'rm -rf -- ' + shlex.quote(self.root)], check=True, timeout=15)
        if self.log:
            self.log.close()


async def run(args):
    repository = Path(__file__).resolve().parents[1]
    inventory = json.loads(args.inventory.read_text(encoding='utf8'))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    result = {'scope': 'native addresses; ephemeral approved devices; no relay or network changes', 'pairs': []}
    with tempfile.TemporaryDirectory(prefix='fan-ssh-local-campaign-') as local:
        archive = args.output.with_suffix('.tar.gz')
        with tarfile.open(archive, 'w:gz') as tar:
            for directory in ('fan_ssh',):
                for path in (repository / directory).glob('*.py'):
                    tar.add(path, arcname=path.relative_to(repository).as_posix())
            tar.add(repository / 'scripts/campaign_agent.py', arcname='scripts/campaign_agent.py')
            for path in args.wheels.glob('*.whl'):
                if path.name.startswith(('cryptography-', 'cffi-', 'pycparser-', 'pip-')) or (
                    args.udp_source and path.name.startswith(('aiortc-', 'aioice-', 'av-', 'dnspython-', 'ifaddr-',
                                                             'google_crc32c-', 'pyee-', 'pylibsrtp-', 'pyopenssl-', 'typing_extensions-'))):
                    tar.add(path, arcname='wheels/' + path.name)
        agents = [Agent(item, repository, archive, args.output, Path(local)) for item in inventory['agents']]
        try:
            announcements = await asyncio.gather(*(agent.connect() for agent in agents), return_exceptions=True)
            failed = [value for value in announcements if isinstance(value, BaseException)]
            if failed:
                raise ValueError('CAMPAIGN_SETUP_FAILED: ' + str(failed[0]))
            records, owners = [], {}
            for agent, announced in zip(agents, announcements):
                for record, device in zip(announced['devices'], agent.item['devices']):
                    if record['id'] != device['id']:
                        raise ValueError('CAMPAIGN_ID_MISMATCH')
                    records.append({'id': record['id'], 'cert': record['cert'], 'candidates': device['candidates']})
                    owners[record['id']] = agent, device
            peers = [identifier for identifier in owners if identifier != inventory['coordinator']['id']]
            policy = {'version': 1, 'account': 'authorized-campaign', 'revision': 1,
                      'coordinator': inventory['coordinator'], 'devices': records,
                      'allow': [{'from': source, 'to': target, 'service': service}
                                for source in peers for target in peers if source != target for service in ('echo', 'ssh')]}
            from fan_ssh.config import Policy
            Policy.parse(policy)
            policy_path = Path(local) / 'campaign.policy.json'
            policy_path.write_text(json.dumps(policy), encoding='utf8')
            # The coordinator agent must be first in the explicit inventory.
            for agent in agents:
                listeners = {device['id']: device['listen'] for device in agent.item['devices']}
                ready = await agent.send({'op': 'start', 'policy': policy, 'listeners': listeners,
                                          'ssh_target': agent.item.get('ssh_target'), 'stun_bind': agent.item.get('stun_bind'),
                                          'tcp_observer_bind': agent.item.get('tcp_observer_bind')})
                if not ready.get('ok'):
                    raise ValueError('CAMPAIGN_START_FAILED: ' + str(ready))
            for source in ([] if args.skip_matrix else peers):
                agent, device = owners[source]
                for target in peers:
                    if target == source:
                        continue
                    message = {'op': 'exchange', 'source': source, 'target': target,
                               'reverse_listen': device.get('reverse_listen'), 'reverse_candidate': device.get('reverse_candidate')}
                    response = await agent.send(message)
                    result['pairs'].append({'source': source, 'target': target, **response})
                    args.output.write_text(json.dumps(result, indent=2), encoding='utf8')
                    print(f'{source} -> {target}: ' + (response.get('report', {}).get('code') or response.get('error', 'unknown')), flush=True)
            if args.nat_source and args.nat_target:
                source_agent, source_device = owners[args.nat_source]
                target_agent, target_device = owners[args.nat_target]
                if source_agent is target_agent or source_agent.item.get('local') or target_agent.item.get('local'):
                    raise ValueError('NAT_PROBE_REQUIRES_TWO_APPROVED_LINUX_HOSTS')
                result['tcp_nat_trials'] = []
                for trial in range(args.nat_trials):
                    a, b = await asyncio.gather(source_agent.send({'op': 'nat_prepare', 'device': args.nat_source,
                                                                 'target': args.nat_target, 'role': 'client', 'native_bind': source_device['listen'],
                                                                 'tcp_observer_address': inventory.get('tcp_observer_address'), 'mode': args.nat_mode}),
                                                target_agent.send({'op': 'nat_prepare', 'device': args.nat_target,
                                                                   'target': args.nat_source, 'role': 'server', 'native_bind': target_device['listen'],
                                                                   'tcp_observer_address': inventory.get('tcp_observer_address'), 'mode': args.nat_mode}))
                    entry = {'trial': trial + 1, 'source_binding': a, 'target_binding': b}
                    if a.get('ok') and b.get('ok'):
                        entry['source_result'], entry['target_result'] = await asyncio.gather(
                            source_agent.send({'op': 'nat_go', 'peer': b['observed']}),
                            target_agent.send({'op': 'nat_go', 'peer': a['observed']}))
                    result['tcp_nat_trials'].append(entry)
                    args.output.write_text(json.dumps(result, indent=2), encoding='utf8')
                    print('TCP NAT trial %d: %s / %s' % (trial + 1, entry.get('source_result', a).get('ok'),
                                                         entry.get('target_result', b).get('ok')), flush=True)
            if args.udp_source and args.udp_target:
                source_agent, source_device = owners[args.udp_source]
                target_agent, target_device = owners[args.udp_target]
                result['udp_trials'] = []
                for service in ('echo', 'ssh') if inventory.get('udp_ssh_check') else ('echo',):
                    a, b = await asyncio.gather(
                        source_agent.send({'op': 'udp_prepare', 'device': args.udp_source, 'target': args.udp_target,
                                           'role': 'client', 'service': service, 'native_bind': source_device['listen'],
                                           'stun_address': inventory['stun_address'], 'ssh_check': inventory.get('udp_ssh_check'),
                                           'udp_strategy': inventory.get('udp_strategy', 'ice'), 'stun_alternate': inventory.get('stun_alternate')}),
                        target_agent.send({'op': 'udp_prepare', 'device': args.udp_target, 'target': args.udp_source,
                                           'role': 'server', 'service': service, 'native_bind': target_device['listen'],
                                           'stun_address': inventory['stun_address'], 'udp_strategy': inventory.get('udp_strategy', 'ice'),
                                           'stun_alternate': inventory.get('stun_alternate')}))
                    entry = {'service': service, 'source_gather': a, 'target_gather': b}
                    if a.get('ok') and b.get('ok'):
                        entry['source_result'], entry['target_result'] = await asyncio.gather(
                            source_agent.send({'op': 'udp_go', 'peer': b['ice']}),
                            target_agent.send({'op': 'udp_go', 'peer': a['ice']}))
                    result['udp_trials'].append(entry)
                    args.output.write_text(json.dumps(result, indent=2), encoding='utf8')
                    if 'source_result' in entry:
                        print('UDP %s peer path: %s / %s' % (service, entry['source_result'].get('ok'),
                                                           entry['target_result'].get('ok')), flush=True)
                    else:
                        print('UDP %s not started: gather %s / %s' % (service, a.get('ok'), b.get('ok')), flush=True)
            control_agent = owners[inventory['coordinator']['id']][0]
            result['coordinator'] = await control_agent.send({'op': 'stats'})
            if args.ssh_host:
                local_id = next(identifier for identifier in peers if owners[identifier][0].item.get('local'))
                proxy = subprocess.list2cmdline([sys.executable, '-m', 'fan_ssh', 'proxy', '--identity', str(Path(local) / local_id),
                                                '--policy', str(policy_path), '--peer', args.ssh_peer, '--service', 'ssh'])
                command = ['ssh', *SSH_OPTIONS, '-o', 'ProxyCommand=' + proxy, args.ssh_host, "printf 'fan-ssh-login-ok\\n'"]
                login = await asyncio.to_thread(subprocess.run, command, capture_output=True, timeout=30, cwd=repository)
                result['existing_ssh_login'] = {'exit': login.returncode, 'verified': login.stdout.strip() == b'fan-ssh-login-ok'}
                (args.output.parent / 'existing-ssh.stderr.log').write_bytes(login.stderr)
            args.output.write_text(json.dumps(result, indent=2), encoding='utf8')
            return 0
        finally:
            outcomes = await asyncio.gather(*(agent.close() for agent in agents), return_exceptions=True)
            archive.unlink(missing_ok=True)
            errors = [str(error) for error in outcomes if isinstance(error, BaseException)]
            if errors:
                raise ValueError('CAMPAIGN_CLEANUP_FAILED: ' + '; '.join(errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True, help='private explicitly approved endpoints and bind addresses')
    parser.add_argument('--wheels', type=Path, default=Path('.fan-ssh/wheels'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--ssh-host', help='optional authorized existing SSH login, with existing verified host key')
    parser.add_argument('--ssh-peer', default='cloud', help='device that serves the existing SSH target')
    parser.add_argument('--skip-matrix', action='store_true')
    parser.add_argument('--nat-source', help='explicitly consenting Linux source device')
    parser.add_argument('--nat-target', help='explicitly consenting Linux target device')
    parser.add_argument('--nat-trials', type=int, choices=range(1, 9), default=6)
    parser.add_argument('--nat-mode', choices=('active', 'hybrid'), default='active', help='hybrid explicitly prebinds a consenting target listener')
    parser.add_argument('--udp-source', help='explicitly consenting native UDP source device')
    parser.add_argument('--udp-target', help='explicitly consenting native UDP target device')
    args = parser.parse_args()
    try:
        return asyncio.run(run(args))
    except (OSError, ValueError, TimeoutError) as error:
        print(f'CAMPAIGN_FAILED: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
