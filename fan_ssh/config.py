"""Explicit operator-approved device roster and direct endpoint scope."""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
from types import MappingProxyType

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .session import NAME, PIN

MAX_CONFIG = 1024 * 1024
TRANSPORT = 'direct-tcp-tls-framed-v2'


def direct_address(value, *, bind=False):
    """Numeric unicast endpoints only; listeners use ordinary-user high ports."""
    if not isinstance(value, str) or len(value) > 80:
        raise ValueError('INVALID_ADDRESS')
    if value.startswith('['):
        host, separator, port = value[1:].partition(']:')
    else:
        host, separator, port = value.rpartition(':')
        if ':' in host:
            raise ValueError('IPv6 requires brackets')
    if not separator or not port.isascii() or not port.isdecimal() or str(int(port)) != port:
        raise ValueError('INVALID_PORT')
    ip = ipaddress.ip_address(host)
    if '%' in host or ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_reserved:
        raise ValueError('INVALID_DIRECT_ENDPOINT')
    if ip.version == 4 and (str(ip) == '255.255.255.255' or ip in ipaddress.ip_network('0.0.0.0/8')):
        raise ValueError('INVALID_DIRECT_ENDPOINT')
    if not ((bind and int(port) == 0) or 1024 <= int(port) <= 65535):
        raise ValueError('HIGH_PORT_REQUIRED')
    return str(ip), int(port)


def strict_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('DUPLICATE_CONFIG_KEY')
            result[key] = value
        return result
    def constant(unused):
        raise ValueError('INVALID_JSON_CONSTANT')
    try:
        return json.loads(data, object_pairs_hook=unique, parse_constant=constant)
    except (RecursionError, UnicodeError) as error:
        raise ValueError('INVALID_CONFIG_JSON') from error


def schema(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError('INVALID_SCHEMA')


def name(value):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise ValueError('INVALID_NAME')
    return value


def certificate(pem):
    if not isinstance(pem, str) or len(pem) > 4096:
        raise ValueError('INVALID_CERTIFICATE')
    try:
        cert = x509.load_pem_x509_certificate(pem.encode('ascii'))
        public = cert.public_key()
        if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(public.curve, ec.SECP256R1):
            raise ValueError('P256_IDENTITY_REQUIRED')
        # Independent devices use self-signed certificates as exact trust anchors.
        if cert.issuer != cert.subject or cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError('SELF_SIGNED_LEAF_REQUIRED')
        public.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        if not cert.not_valid_before_utc <= datetime.now(timezone.utc) < cert.not_valid_after_utc:
            raise ValueError('CERTIFICATE_EXPIRED_OR_FUTURE')
        if cert.public_bytes(serialization.Encoding.PEM).decode('ascii') != pem:
            raise ValueError('CANONICAL_CERTIFICATE_REQUIRED')
        return cert
    except (UnicodeError, x509.ExtensionNotFound, InvalidSignature) as error:
        raise ValueError('INVALID_CERTIFICATE') from error


@dataclass(frozen=True)
class Device:
    id: str
    cert: str
    pin: str
    candidates: tuple


@dataclass(frozen=True)
class Policy:
    account: str
    revision: int
    coordinator: str
    endpoint: str
    devices: object
    allow: frozenset

    @classmethod
    def parse(cls, data):
        schema(data, ('version', 'account', 'revision', 'coordinator', 'devices', 'allow'))
        if type(data['version']) is not int or data['version'] != 1:
            raise ValueError('UNSUPPORTED_POLICY_VERSION')
        account = name(data['account'])
        revision = data['revision']
        if type(revision) is not int or not 1 <= revision < 2**53:
            raise ValueError('INVALID_REVISION')
        schema(data['coordinator'], ('id', 'address'))
        coordinator = name(data['coordinator']['id'])
        endpoint = data['coordinator']['address']
        direct_address(endpoint)
        records = data['devices']
        if not isinstance(records, list) or not 2 <= len(records) <= 64:
            raise ValueError('INVALID_DEVICE_COUNT')
        devices, pins = {}, set()
        for item in records:
            schema(item, ('id', 'cert', 'candidates'))
            identifier = name(item['id'])
            cert = certificate(item['cert'])
            pin = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
            candidates = item['candidates']
            if not isinstance(candidates, list) or len(candidates) > 8:
                raise ValueError('CANDIDATE_LIMIT')
            for value in candidates:
                direct_address(value)
                if value == endpoint:
                    raise ValueError('CONTROL_ENDPOINT_IS_NOT_DATA_PATH')
            if len(set(candidates)) != len(candidates) or identifier in devices or pin in pins:
                raise ValueError('DUPLICATE_DEVICE_OR_CANDIDATE')
            devices[identifier] = Device(identifier, item['cert'], pin, tuple(candidates))
            pins.add(pin)
        if coordinator not in devices or devices[coordinator].candidates:
            raise ValueError('COORDINATOR_MUST_HAVE_NO_DATA_CANDIDATES')
        edges = data['allow']
        if not isinstance(edges, list) or len(edges) > 4096:
            raise ValueError('ACL_LIMIT')
        allow = set()
        for edge in edges:
            schema(edge, ('from', 'to', 'service'))
            source, target, service = (name(edge[key]) for key in ('from', 'to', 'service'))
            if source not in devices or target not in devices or coordinator in (source, target) or source == target:
                raise ValueError('INVALID_ACL_EDGE')
            if (source, target, service) in allow:
                raise ValueError('DUPLICATE_ACL_EDGE')
            allow.add((source, target, service))
        return cls(account, revision, coordinator, endpoint, MappingProxyType(devices), frozenset(allow))

    @classmethod
    def load(cls, path):
        with Path(path).open('rb') as file:
            data = file.read(MAX_CONFIG + 1)
        if len(data) > MAX_CONFIG:
            raise ValueError('CONFIG_TOO_LARGE')
        return cls.parse(strict_json(data))

    def caller(self, pin):
        for device in self.devices.values():
            if device.pin == pin:
                return device.id
        raise ValueError('IDENTITY_REJECTED')

    def permits(self, source, target, service):
        return (source, target, service) in self.allow

    def replacement(self, new):
        if new.account != self.account or new.coordinator != self.coordinator or new.revision <= self.revision:
            raise ValueError('POLICY_REVISION_REJECTED')
        if new.devices[new.coordinator].pin != self.devices[self.coordinator].pin:
            raise ValueError('COORDINATOR_ROTATION_REQUIRES_RESTART')
        return new
