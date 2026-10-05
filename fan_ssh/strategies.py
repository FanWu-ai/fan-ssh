"""Bounded, opt-in direct-path selection. Identity/admission errors are terminal."""
import asyncio
import ssl
import time

from .remote import DirectUnavailable


class AutomaticClient:
    def __init__(self, methods, *, log=None):
        # Each entry has its own client and therefore fresh grants/path state.
        if not methods or len(methods) > 8 or len({m[0] for m in methods}) != len(methods):
            raise ValueError('INVALID_DIRECT_METHODS')
        self.methods = tuple(methods)
        self.log = log
        self.closed = False

    async def dial(self, peer, service='ssh'):
        if self.closed:
            raise ValueError('CLIENT_CLOSED')
        attempts = []
        for method, client, operation, deadline in self.methods:
            started = time.monotonic()
            record = {'method': method}
            if self.log:
                self.log({'event': 'DIRECT_ATTEMPT', 'method': method})
            try:
                async with asyncio.timeout(deadline):
                    pair, report = await getattr(client, operation)(peer, service)
                # A transport plugin must provide affirmative direct-path evidence.
                ready = report.get('code') == 'DIRECT_SERVICE_READY' or (
                    report.get('code') == 'AUTHENTICATED_NATIVE_UDP' and report.get('service_ready') is True)
                if report.get('relay') is not False or not ready:
                    pair[1].close()
                    await pair[1].wait_closed()
                    raise ValueError('DIRECT_METHOD_EVIDENCE_REJECTED')
                record['code'] = report['code']
                record['elapsed_ms'] = round((time.monotonic() - started) * 1000)
                attempts.append(record)
                return pair, dict(report, method=method, method_attempts=attempts)
            except DirectUnavailable as error:
                if error.report.get('code') != 'NO_DIRECT_PATH':
                    raise  # Peer identity failures must never become another method.
                record['code'] = 'NO_DIRECT_PATH'
                record['details'] = error.report
            except ssl.SSLError:
                raise
            except (TimeoutError, ConnectionError) as error:
                record['code'] = type(error).__name__
            except OSError as error:
                # Only ordinary connectivity failures permit a new transport attempt.
                import errno
                if error.errno not in {errno.ECONNREFUSED, errno.ECONNRESET, errno.ETIMEDOUT,
                                       errno.ENETUNREACH, errno.EHOSTUNREACH}:
                    raise
                record['code'] = type(error).__name__
            record['elapsed_ms'] = round((time.monotonic() - started) * 1000)
            attempts.append(record)
            if self.log:
                self.log({'event': 'DIRECT_ATTEMPT_FAILED', **record})
        raise DirectUnavailable({'code': 'NO_DIRECT_PATH', 'relay': False, 'method_attempts': attempts})

    async def close(self):
        self.closed = True
        clients = {id(entry[1]): entry[1] for entry in self.methods}
        await asyncio.gather(*(client.close() for client in clients.values()))
