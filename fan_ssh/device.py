"""User-owned independent device keys; manual public-certificate enrollment."""
import re
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .config import certificate, name, schema, strict_json
from .identity import Identity


def generate(identifier):
    name(identifier)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identifier)])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))
    return Identity(cert.public_bytes(serialization.Encoding.PEM),
                    key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
                    hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest())


def private_directory(path):
    """Only newly created directories; no overwrite, privilege or system ACL edits."""
    path = Path(path)
    path.mkdir(mode=0o700)
    if os.name == 'nt':
        result = subprocess.run(['whoami', '/user', '/fo', 'csv', '/nh'], capture_output=True, check=True, timeout=5)
        sid = windows_sid(result.stdout)
        subprocess.run(['icacls', str(path), '/inheritance:r', '/grant:r', f'*{sid}:(OI)(CI)F'],
                       capture_output=True, check=True, timeout=5)
        subprocess.run(['icacls', str(path), '/setowner', f'*{sid}'], capture_output=True, check=True, timeout=5)
    return path


def windows_sid(output):
    """The SID is ASCII even when whoami's account name uses a local code page."""
    match = re.search(rb',"(S-1-(?:[0-9]+-)*[0-9]+)"\s*$', output)
    if match is None:
        raise ValueError('WINDOWS_USER_SID_REQUIRED')
    return match[1].decode('ascii')


def save(identifier, directory):
    identity = generate(identifier)
    return save_identity(identifier, identity, directory)


def save_identity(identifier, identity, directory):
    root = private_directory(directory)
    if os.name == 'nt':
        try:
            windows_private(root, directory_only=True)
        except BaseException:
            root.rmdir()  # Only the newly created, still-empty directory.
            raise
    for filename, data in [('cert.pem', identity.cert), ('key.pem', identity.key),
                           ('device.json', json.dumps({'id': identifier, 'pin': identity.pin}).encode())]:
        fd = os.open(root / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as file:
            file.write(data)
    return identity


def load(directory):
    root = Path(directory)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('INVALID_IDENTITY_DIRECTORY')
    if os.name != 'nt' and (root.stat().st_mode & 0o077 or root.stat().st_uid != os.getuid()):
        raise ValueError('IDENTITY_DIRECTORY_MUST_BE_USER_PRIVATE')
    if os.name == 'nt':
        windows_private(root)
    def read(filename, private=False):
        path = root / filename
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 8192:
            raise ValueError('INVALID_IDENTITY_FILE')
        if os.name != 'nt' and private and (path.stat().st_mode & 0o077 or path.stat().st_uid != os.getuid()):
            raise ValueError('PRIVATE_KEY_PERMISSIONS_REQUIRED')
        return path.read_bytes()
    data = strict_json(read('device.json'))
    schema(data, ('id', 'pin'))
    identifier = name(data['id'])
    pem, key_bytes = read('cert.pem'), read('key.pem', private=True)
    cert = certificate(pem.decode('ascii'))
    key = serialization.load_pem_private_key(key_bytes, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.public_key().public_numbers() != cert.public_key().public_numbers():
        raise ValueError('IDENTITY_KEY_MISMATCH')
    now = datetime.now(timezone.utc)
    if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
        raise ValueError('IDENTITY_EXPIRED')
    pin = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    if pin != data['pin']:
        raise ValueError('IDENTITY_PIN_MISMATCH')
    return identifier, Identity(pem, key_bytes, pin)


def windows_private(root, *, directory_only=False):
    """Read-only DACL/owner checks; never silently repair an imported identity."""
    script = '''$ErrorActionPreference = 'Stop'
try {
  $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $root = $env:FAN_SSH_ACL_PATH
  $keyPath = [System.IO.Path]::Combine($root, 'key.pem')
  $directoryAcl = [System.IO.Directory]::GetAccessControl($root)
  if (-not $directoryAcl.AreAccessRulesProtected) { throw 'inheritance' }
  $checks = @($directoryAcl)
  if ($env:FAN_SSH_ACL_DIRECTORY_ONLY -ne '1') {
    $checks += [System.IO.File]::GetAccessControl($keyPath)
  }
  foreach ($acl in $checks) {
    if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $sid) { throw 'owner' }
    $readable = $false
    foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
      if ($rule.AccessControlType -eq 'Allow' -and (([int]$rule.FileSystemRights -band 1) -ne 0)) {
        if ($rule.IdentityReference.Value -notin @($sid, 'S-1-5-18', 'S-1-5-32-544')) { throw 'read access' }
        if ($rule.IdentityReference.Value -eq $sid) { $readable = $true }
      }
    }
    if (-not $readable) { throw 'unreadable' }
  }
  [Console]::Out.WriteLine('{"ok":true}')
} catch { [Console]::Out.WriteLine('{"ok":false}'); exit 1 }
'''
    environment = dict(os.environ, FAN_SSH_ACL_PATH=str(root.resolve()),
                       FAN_SSH_ACL_DIRECTORY_ONLY='1' if directory_only else '0')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand',
                             base64.b64encode(script.encode('utf-16-le')).decode('ascii')],
                            env=environment, capture_output=True, timeout=10)
    if result.returncode or result.stdout.strip() != b'{"ok":true}':
        raise ValueError('WINDOWS_PRIVATE_IDENTITY_ACL_REQUIRED')


def tls_context(identity, policy, *, server=False):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False  # Exact leaf pins replace names; CA verification stays enabled.
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cadata=''.join(device.cert for device in policy.devices.values()))
    with tempfile.TemporaryDirectory(prefix='fan-ssh-tls-') as temporary:
        root = private_directory(Path(temporary) / 'private')
        for filename, data in [('cert.pem', identity.cert), ('key.pem', identity.key)]:
            fd = os.open(root / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as file:
                file.write(data)
        context.load_cert_chain(str(root / 'cert.pem'), str(root / 'key.pem'))
    return context


def enrolled(identifier, identity, policy):
    if identifier not in policy.devices or policy.devices[identifier].pin != identity.pin:
        raise ValueError('LOCAL_DEVICE_NOT_APPROVED')
