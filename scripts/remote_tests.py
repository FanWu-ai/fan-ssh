"""Run authorized regression tests in a temporary ordinary-user Linux directory.

Requires SSH/scp with preverified host keys and offline Linux cp312 dependency wheels.
This does not start externally reachable services or modify SSH/network configuration.
"""
import argparse
from pathlib import Path
import re
import shlex
import subprocess
import tarfile

SSH_OPTIONS = ['-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ForwardAgent=no',
               '-o', 'ClearAllForwardings=yes', '-o', 'UpdateHostKeys=no', '-o', 'ConnectTimeout=8']


def bundle(repository, wheels, archive, udp=False):
    with tarfile.open(archive, 'w:gz') as file:
        for directory in ('fan_ssh', 'tests', 'experiments/tcp-simopen'):
            for path in (repository / directory).rglob('*.py'):
                file.add(path, arcname=path.relative_to(repository).as_posix())
        # The Linux dual-listener controls import the standalone diagnostic.
        file.add(repository / 'scripts/native_tcp_ttl_probe.py',
                 arcname='scripts/native_tcp_ttl_probe.py')
        for path in wheels.glob('*.whl'):
            if (udp and not path.name.startswith('uv-')) or path.name.startswith(('cryptography-', 'cffi-', 'pycparser-', 'pip-')):
                file.add(path, arcname='wheels/' + path.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True, help='already authorized SSH host alias')
    parser.add_argument('--python', default='python3.12')
    parser.add_argument('--wheels', type=Path, default=Path('.fan-ssh/wheels'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--udp', action='store_true', help='install offline UDP extras and run actual Linux UDP tests')
    parser.add_argument('--pattern', default='test*.py', help='root unittest file pattern; defaults to the full suite')
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    archive = args.output.with_suffix('.tar.gz')
    bundle(repository, args.wheels, archive, args.udp)
    result = subprocess.run(['ssh', *SSH_OPTIONS, args.host, 'umask 077; mktemp -d /tmp/fan-ssh-test.XXXXXXXX'],
                            capture_output=True, check=True, timeout=20)
    root = result.stdout.decode().strip()
    if not re.fullmatch(r'/tmp/fan-ssh-test\.[A-Za-z0-9]{8}', root):
        raise ValueError('Unexpected temporary directory')
    try:
        subprocess.run(['scp', *SSH_OPTIONS, '-q', str(archive), args.host + ':' + root + '/input.tar.gz'], check=True, timeout=240)
        extra = ' aiortc==1.15.0 aioice==0.10.2' if args.udp else ''
        script = f'''set -u
test_root={shlex.quote(root)}
test_python={shlex.quote(args.python)}
cd "$test_root" || exit 2
tar xzf input.tar.gz || exit 2
export PYTHONPATH="$test_root/wheels/pip-26.2.1-py3-none-any.whl"
"$test_python" -m pip install --target "$test_root/deps" --no-index --find-links "$test_root/wheels" cryptography==50.0.2 cffi==2.1.1 pycparser==3.0{extra} || exit 2
export PYTHONPATH="$test_root/deps:$test_root"
"$test_python" -c 'import platform,ssl,cryptography,os; print("ENV",platform.system(),platform.machine(),platform.python_version(),ssl.OPENSSL_VERSION,"cryptography",cryptography.__version__,"uid",os.getuid())'
"$test_python" -m unittest discover -s tests -p {shlex.quote(args.pattern)} -v
root_status=$?
"$test_python" -m unittest discover -s experiments/tcp-simopen -v
diagnostic_status=$?
"$test_python" -m fan_ssh demo
demo_status=$?
echo "CHECK_STATUS root=$root_status diagnostic=$diagnostic_status demo=$demo_status"
test "$root_status" -eq 0 && test "$diagnostic_status" -eq 0 && test "$demo_status" -eq 0
'''
        result = subprocess.run(['ssh', *SSH_OPTIONS, args.host, 'sh -s'], input=script.encode(), capture_output=True, timeout=240)
        output = (result.stdout + result.stderr).decode('utf8', errors='replace').replace(root, '<temporary-test-directory>')
        args.output.write_text(output, encoding='utf8')
        print(f'Test exit={result.returncode}; evidence={args.output}')
        return result.returncode
    finally:
        subprocess.run(['ssh', *SSH_OPTIONS, args.host, 'rm -rf -- ' + shlex.quote(root)], check=True, timeout=15)
        archive.unlink(missing_ok=True)


if __name__ == '__main__':
    raise SystemExit(main())
