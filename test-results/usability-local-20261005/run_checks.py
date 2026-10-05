import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time

p = argparse.ArgumentParser()
p.add_argument('--python', required=True)
p.add_argument('--cwd', required=True)
p.add_argument('--logs', required=True)
p.add_argument('--repo', required=True)
p.add_argument('--debug', action='store_true')
p.add_argument('--skip-build', action='store_true')
a = p.parse_args()
root = Path(a.logs)
root.mkdir(parents=True, exist_ok=True)
repo = Path(a.repo)
env = dict(os.environ, PYTHONUNBUFFERED='1', PYTHONIOENCODING='utf-8')
env.pop('PYTHONPATH', None)
env.pop('FAN_SSH_UDP_DEBUG_TESTS', None)
if a.debug:
    env['FAN_SSH_UDP_DEBUG_TESTS'] = '1'
groups = [('full', ['-m', 'unittest', 'discover', '-s', str(repo / 'tests'), '-v']),
          ('udp', ['-m', 'unittest', 'discover', '-s', str(repo / 'tests'), '-p', 'test_udp.py', '-v']),
          ('home-bridge', ['-m', 'unittest', 'discover', '-s', str(repo / 'tests'), '-p', 'test_home_bridge.py', '-v']),
          ('profiles', ['-m', 'unittest', 'discover', '-s', str(repo / 'tests'), '-p', 'test_profiles.py', '-v'])]
if a.debug:
    groups = groups[1:3]
else:
    groups += [(name, ['-m', 'unittest', 'discover', '-s', str(repo / 'experiments' / folder), '-v'])
               for name, folder in [('tcp', 'tcp-simopen'), ('stun', 'stun-observer'), ('easytier', 'easytier-reference')]]
    groups += [('demo', ['-m', 'fan_ssh', 'demo']),
               ('compileall', ['-m', 'compileall', '-q', *[str(repo / x) for x in ['fan_ssh', 'tests', 'scripts', 'experiments']]]),
               ('pip-check', ['-m', 'pip', 'check']),
               ('versions', ['-c', "import sys,platform,importlib.metadata as m,fan_ssh,aiortc,aioice;print(sys.version);print(platform.platform());print('fan_ssh.__file__='+fan_ssh.__file__);print({x:m.version(x) for x in ('fan-ssh','cryptography','aiortc','aioice')})"])]
results = []
for label, args in groups:
    command = [a.python, *args]
    start = time.monotonic()
    with (root / (label + '.txt')).open('wb') as log:
        try:
            run = subprocess.run(command, cwd=a.cwd, env=env, stdout=log, stderr=subprocess.STDOUT,
                                 timeout=300 if a.debug else 600)
            code, timeout = run.returncode, False
        except subprocess.TimeoutExpired:
            code, timeout = None, True
    output = (root / (label + '.txt')).read_text(encoding='utf8', errors='replace')
    count = re.findall(r'^Ran (\d+) tests?', output, re.M)
    summary = re.search(r'^(?:FAILED|OK)\s*(?:\(([^\n]*)\))?\s*$', output, re.M)
    stats = {key: 0 for key in ['failures', 'errors', 'skipped']}
    if summary and summary[1]:
        stats.update({k: int(v) for k, v in re.findall(r'(failures|errors|skipped)=(\d+)', summary[1])})
    total = int(count[-1]) if count else None
    row = dict(group=label, command=command, exit_code=code, timed_out=timeout,
               seconds=round(time.monotonic()-start, 3), total=total,
               passed=total-sum(stats.values()) if total is not None else None, **stats,
               skips=[x for x in output.splitlines() if ' ... skipped ' in x],
               background_errors=bool(re.search(r'Exception in callback|Task exception was never retrieved|ResourceWarning|Task was destroyed', output)))
    results.append(row)
    (root / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf8')
    print(json.dumps(row), flush=True)
