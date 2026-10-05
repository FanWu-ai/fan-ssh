"""Domain-separated signed, session-bound grants and bounded replay admission."""
import base64
import json
import secrets
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .config import TRANSPORT, certificate, name, schema, strict_json
from .session import PIN

LIFETIME = 30.0
UDP_TRANSPORT = 'direct-udp-dtls-sctp-v1'
MAX_REPLAYS = 1024
DOMAIN = b'fan-ssh/direct-session/v2\0'
FIELDS = ('version', 'account', 'revision', 'session', 'source', 'source_pin', 'target', 'target_pin',
          'service', 'direction', 'transport', 'issued_ms', 'expires_ms', 'serial')


def clock():
    return int(time.time() * 1000)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def encode(data):
    return base64.urlsafe_b64encode(data).decode('ascii')


def decode(value):
    if not isinstance(value, str):
        raise ValueError('INVALID_GRANT')
    try:
        result = base64.b64decode(value, altchars=b'-_', validate=True)
    except (ValueError, UnicodeError) as error:
        raise ValueError('INVALID_GRANT') from error
    if encode(result) != value:
        raise ValueError('NONCANONICAL_GRANT')
    return result


def issue(identity, policy, source, target, service, direction='forward', *, previous=None, now=None, transport='direct-tcp-tls-framed-v2'):
    if direction not in ('forward', 'reverse') or not policy.permits(source, target, service):
        raise ValueError('ACL_DENIED')
    if transport not in (TRANSPORT, UDP_TRANSPORT):
        raise ValueError('DIRECT_TRANSPORT_REQUIRED')
    timestamp = clock() if now is None else now
    claims = dict(version=2, account=policy.account, revision=policy.revision,
                  session=secrets.token_hex(16), source=source, source_pin=policy.devices[source].pin,
                  target=target, target_pin=policy.devices[target].pin, service=service,
                  direction=direction, transport=transport, issued_ms=timestamp,
                  expires_ms=timestamp + int(LIFETIME * 1000), serial=0)
    if previous:
        claims['session'] = previous['session']
        claims['serial'] = previous['serial'] + 1
    key = serialization.load_pem_private_key(identity.key, password=None)
    payload = canonical(claims)
    signature = key.sign(DOMAIN + payload, ec.ECDSA(hashes.SHA256()))
    return {'payload': encode(payload), 'signature': encode(signature)}


def verify(grant, policy, *, now=None):
    schema(grant, ('payload', 'signature'))
    if any(not isinstance(v, str) or len(v) > 2048 for v in grant.values()):
        raise ValueError('INVALID_GRANT')
    payload, signature = decode(grant['payload']), decode(grant['signature'])
    public = certificate(policy.devices[policy.coordinator].cert).public_key()
    try:
        public.verify(signature, DOMAIN + payload, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as error:
        raise ValueError('GRANT_SIGNATURE_REJECTED') from error
    claims = strict_json(payload)
    schema(claims, FIELDS)
    if canonical(claims) != payload or type(claims['version']) is not int or claims['version'] != 2:
        raise ValueError('INVALID_GRANT')
    for key in ('account', 'source', 'target', 'service'):
        name(claims[key])
    if not isinstance(claims['session'], str) or len(claims['session']) != 32 or any(c not in '0123456789abcdef' for c in claims['session']):
        raise ValueError('INVALID_SESSION')
    for key in ('source_pin', 'target_pin'):
        if not isinstance(claims[key], str) or not PIN.fullmatch(claims[key]):
            raise ValueError('INVALID_GRANT_PIN')
    for key in ('issued_ms', 'expires_ms', 'revision', 'serial'):
        if type(claims[key]) is not int or not 0 <= claims[key] < 2**53:
            raise ValueError('INVALID_GRANT_NUMBER')
    timestamp = clock() if now is None else now
    lifetime = claims['expires_ms'] - claims['issued_ms']
    if not 0 < lifetime <= int(LIFETIME * 1000):
        raise ValueError('INVALID_GRANT_LIFETIME')
    if not claims['issued_ms'] <= timestamp < claims['expires_ms']:
        raise ValueError('GRANT_EXPIRED_OR_FUTURE')
    if claims['account'] != policy.account or claims['revision'] != policy.revision:
        raise ValueError('POLICY_REVISION_REJECTED')
    if claims['transport'] not in (TRANSPORT, UDP_TRANSPORT) or claims['direction'] not in ('forward', 'reverse'):
        raise ValueError('DIRECT_TRANSPORT_REQUIRED')
    for role in ('source', 'target'):
        if claims[role] not in policy.devices or policy.devices[claims[role]].pin != claims[role + '_pin']:
            raise ValueError('SESSION_IDENTITY_REJECTED')
    if not policy.permits(claims['source'], claims['target'], claims['service']):
        raise ValueError('ACL_DENIED')
    return claims


def renewal(previous, current):
    stable = set(FIELDS) - {'issued_ms', 'expires_ms', 'serial'}
    if any(previous[key] != current[key] for key in stable) or current['serial'] != previous['serial'] + 1 or current['expires_ms'] <= previous['expires_ms']:
        raise ValueError('LEASE_RENEWAL_REJECTED')


class Admissions:
    def __init__(self):
        self.consumed = {}

    def consume(self, claims, *, now=None):
        timestamp = clock() if now is None else now
        self.consumed = {sid: expiry for sid, expiry in self.consumed.items() if expiry > timestamp}
        if claims['serial'] != 0:
            raise ValueError('RENEWAL_IS_NOT_ADMISSION')
        if claims['session'] in self.consumed:
            raise ValueError('GRANT_REPLAYED')
        if len(self.consumed) >= MAX_REPLAYS:
            raise ValueError('ADMISSION_CAPACITY')
        self.consumed[claims['session']] = claims['expires_ms']
