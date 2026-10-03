"""Synthetic, short-lived demo PKI; never an enrollment or credential store."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import ssl
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass(frozen=True)
class Identity:
    cert: bytes
    key: bytes
    pin: str


class DemoPKI:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'fan-ssh demo CA')])
        self.ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                   .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
                   .sign(self.key, hashes.SHA256()))

    def issue(self, name):
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
                .issuer_name(self.ca.subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(self.key, hashes.SHA256()))
        return Identity(cert.public_bytes(serialization.Encoding.PEM),
                        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()),
                        hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest())

    def context(self, identity, *, server=False):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        # Names are synthetic: CA validation plus independent exact leaf pins bind identity.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cadata=self.ca.public_bytes(serialization.Encoding.PEM).decode('ascii'))
        # stdlib SSL requires filenames. POSIX directory/file modes are 0700/0600;
        # Windows relies on inherited user-temp ACLs (not runtime-validated).
        # Files are removed immediately after OpenSSL loads them.
        with tempfile.TemporaryDirectory(prefix='fan-ssh-') as directory:
            for name, data in [('cert.pem', identity.cert), ('key.pem', identity.key)]:
                path = Path(directory, name)
                with path.open('xb') as file:
                    path.chmod(0o600)
                    file.write(data)
            context.load_cert_chain(str(Path(directory, 'cert.pem')), str(Path(directory, 'key.pem')))
        return context


def peer_pin(writer):
    tls = writer.get_extra_info('ssl_object')
    if tls is None:
        raise ValueError('TLS_REQUIRED')
    return hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()


def require_pin(writer, approved):
    pin = peer_pin(writer)
    if pin not in approved:
        raise ValueError('IDENTITY_REJECTED: certificate not explicitly approved')
    return pin
