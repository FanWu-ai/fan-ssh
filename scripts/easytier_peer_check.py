"""Check a trusted EasyTier v2.6.4 CLI peer snapshot for a selected native path.

This is a reference-test gate, not a transport or authentication adapter. Obtain
the snapshot from the test's loopback-only RPC portal with `-o json -v peer list`.
An advertised route or an unused connection alone is not a direct-path proof.
Interface/routing checks and authenticated application validation are separate;
the caller must supply previously verified native addresses.
"""
import argparse
import ipaddress
import json
from pathlib import Path
from urllib.parse import urlsplit
import uuid


def connection_id(value):
    if not isinstance(value, dict):
        return None
    parts = [value.get('part' + str(index)) for index in range(1, 5)]
    if any(type(part) is not int or not 0 <= part < 2**32 for part in parts):
        return None
    return str(uuid.UUID(hex=''.join(f'{part:08x}' for part in parts)))


def native_peer_verified(rows, target, approved_native_ips, transport):
    if transport not in ('tcp', 'udp') or not isinstance(rows, list):
        return False
    approved = {str(ipaddress.ip_address(ip)) for ip in approved_native_ips}
    for row in rows:
        if not isinstance(row, dict):
            continue
        route, peer = row.get('route'), row.get('peer')
        if not isinstance(route, dict) or not isinstance(peer, dict):
            continue
        peer_id = route.get('peer_id')
        if (type(peer_id) is not int or route.get('hostname') != target
                or type(route.get('cost')) is not int or route['cost'] != 1
                or route.get('next_hop_peer_id') != peer_id
                or peer.get('peer_id') != peer_id):
            continue
        selected = connection_id(peer.get('default_conn_id'))
        direct = {connection_id(item) for item in peer.get('directly_connected_conns', [])}
        if selected is None or selected not in direct:
            continue
        for conn in peer.get('conns', []):
            if (not isinstance(conn, dict) or conn.get('conn_id') != selected
                    or conn.get('peer_id') != peer_id or conn.get('is_closed') is not False):
                continue
            tunnel = conn.get('tunnel')
            if not isinstance(tunnel, dict) or tunnel.get('tunnel_type') != transport:
                continue
            address = tunnel.get('resolved_remote_addr')
            if not isinstance(address, dict):
                continue
            try:
                parsed = urlsplit(address.get('url', ''))
                if (parsed.scheme != transport or parsed.username is not None
                        or parsed.password is not None or not parsed.port
                        or parsed.path or parsed.query or parsed.fragment):
                    continue
                remote = str(ipaddress.ip_address(parsed.hostname))
            except (ValueError, TypeError):
                continue
            if remote in approved:
                return True
    return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--peer-json', type=Path, required=True)
    parser.add_argument('--target', required=True)
    parser.add_argument('--approved-native', action='append', required=True)
    parser.add_argument('--transport', choices=['tcp', 'udp'], required=True)
    args = parser.parse_args()
    if args.peer_json.stat().st_size > 4 * 1024 * 1024:
        raise ValueError('BOUNDED_PEER_SNAPSHOT_REQUIRED')
    verified = native_peer_verified(json.loads(args.peer_json.read_text(encoding='utf8')),
                                    args.target, args.approved_native, args.transport)
    print(json.dumps({'selected_native_peer_verified': verified}))
    raise SystemExit(0 if verified else 1)
