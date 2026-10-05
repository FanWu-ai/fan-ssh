"""Read-only IGD discovery at one explicitly approved native gateway.

No AddPortMapping, route, firewall, authentication or persistent configuration changes.
"""
import argparse
import http.client
import json
import socket
import struct
from urllib.parse import urljoin, urlsplit
import xml.etree.ElementTree as ET


def fetch(url, native, gateway, *, action=None, body=None):
    parts = urlsplit(url)
    if parts.scheme != 'http' or parts.hostname != gateway or parts.username or parts.password:
        raise ValueError('DESCRIPTOR_OUTSIDE_APPROVED_GATEWAY')
    connection = http.client.HTTPConnection(gateway, parts.port or 80, timeout=3, source_address=(native, 0))
    headers = {} if action is None else {'SOAPAction': '"' + action + '"', 'Content-Type': 'text/xml; charset=utf-8'}
    try:
        connection.request('GET' if action is None else 'POST', parts.path or '/', body=body, headers=headers)
        response = connection.getresponse()
        content = response.read(32769)
        if response.status != 200 or len(content) > 32768 or b'<!DOCTYPE' in content.upper():
            raise ValueError('INVALID_IGD_RESPONSE')
        return ET.fromstring(content)
    finally:
        connection.close()


def inspect(native, gateway, multicast=False):
    socket.inet_aton(native); socket.inet_aton(gateway)
    locations = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((native, 0))
        sock.settimeout(2)
        packet = (b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n'
                  b'MX: 1\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n')
        # Unicast only to the selected gateway, not a LAN scan or multicast search.
        if multicast:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(native))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sock.sendto(packet, ('239.255.255.250' if multicast else gateway, 1900))
        for _ in range(8):
            try:
                reply, peer = sock.recvfrom(4096)
            except socket.timeout:
                break
            if peer[0] != gateway:
                continue
            for line in reply.decode('ascii', errors='replace').splitlines():
                key, separator, value = line.partition(':')
                if separator and key.lower() == 'location' and value.strip() not in locations:
                    locations.append(value.strip())
    result = {'gateway': gateway, 'descriptors': len(locations), 'igd': []}
    for location in locations[:4]:
        document = fetch(location, native, gateway)
        for service in document.iter():
            if service.tag.rsplit('}', 1)[-1] != 'service':
                continue
            fields = {child.tag.rsplit('}', 1)[-1]: child.text for child in service}
            kind = fields.get('serviceType', '')
            if kind not in ('urn:schemas-upnp-org:service:WANIPConnection:1', 'urn:schemas-upnp-org:service:WANIPConnection:2',
                            'urn:schemas-upnp-org:service:WANPPPConnection:1'):
                continue
            control = urljoin(location, fields['controlURL'])
            body = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
                    '<u:GetExternalIPAddress xmlns:u="' + kind + '"/></s:Body></s:Envelope>').encode()
            answer = fetch(control, native, gateway, action=kind + '#GetExternalIPAddress', body=body)
            ips = [node.text for node in answer.iter() if node.tag.rsplit('}', 1)[-1] == 'NewExternalIPAddress']
            result['igd'].append({'external_ip': ips[0] if ips else None, 'control': control, 'service': kind})
    return result


def nat_pmp(native, gateway):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((native, 0))
        sock.connect((gateway, 5351))
        for delay in (0.25, 0.5, 1.0, 2.0):
            sock.settimeout(delay)
            sock.send(b'\0\0')  # RFC 6886 external-address query only; never a mapping request.
            try:
                reply = sock.recv(64)
            except socket.timeout:
                continue
            except ConnectionRefusedError:
                return {'supported': False, 'reason': 'ICMP_PORT_UNREACHABLE'}
            if len(reply) == 12:
                version, opcode, result, epoch, ip = struct.unpack('!BBHII', reply)
                if version == 0 and opcode == 128:
                    return {'supported': result == 0, 'result': result,
                            'external_ip': socket.inet_ntoa(struct.pack('!I', ip)) if result == 0 else None}
        return {'supported': None, 'reason': 'NO_RESPONSE_WITHIN_BOUNDED_QUERY'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', required=True)
    parser.add_argument('--gateway', required=True)
    parser.add_argument('--multicast', action='store_true', help='one standard IGD search on the explicit physical LAN; accept gateway responses only')
    parser.add_argument('--nat-pmp', action='store_true', help='read-only external-address query at the same gateway')
    args = parser.parse_args()
    try:
        result = inspect(args.native, args.gateway, args.multicast)
        if args.nat_pmp:
            result['nat_pmp'] = nat_pmp(args.native, args.gateway)
        print(json.dumps(result))
    except (OSError, ValueError, ET.ParseError) as error:
        print(json.dumps({'error': type(error).__name__, 'code': str(error)[:100]}))
        raise SystemExit(1)
