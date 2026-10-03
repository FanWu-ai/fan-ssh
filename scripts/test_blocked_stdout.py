#!/usr/bin/env python3
"""Linux runtime regression: Ctrl-C exits proxy even with an unread stdout pipe."""
import pathlib
import signal
import socket
import subprocess
import threading
import time

binary = pathlib.Path(__file__).resolve().parents[1] / 'dist/directssh-linux-amd64'
listener = socket.socket()
listener.bind(('127.0.0.1', 0))
listener.listen(1)
accepted = threading.Event()
def send_forever():
    conn, _ = listener.accept()
    accepted.set()
    try:
        with conn:
            while True:
                conn.sendall(b'x' * 65536)
    except OSError:
        pass
threading.Thread(target=send_forever, daemon=True).start()
process = subprocess.Popen([str(binary), 'proxy', '--target', f'127.0.0.1:{listener.getsockname()[1]}'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
try:
    assert accepted.wait(5), 'proxy never connected to target'
    time.sleep(0.3)  # Let the intentionally unread stdout pipe fill.
    process.send_signal(signal.SIGINT)
    result = process.wait(timeout=3)
    assert result != 0, 'cancellation was reported as success'
    stderr = process.stderr.read().decode()
    assert 'context canceled' in stderr, stderr
    print('PASS: actual CLI exits on SIGINT with inherited stdout pipe blocked')
finally:
    if process.poll() is None:
        process.kill()
        process.wait()
    for stream in (process.stdin, process.stdout, process.stderr):
        stream.close()
    listener.close()
