"""Dependency-free bounded ICE metadata validation for the control plane."""
import json

from .config import direct_address, schema
from .transport import format_address


def validate(value, allowed_ips):
    schema(value, ('parameters', 'candidates', 'strategy') if isinstance(value, dict) and 'strategy' in value else ('parameters', 'candidates'))
    if value.get('strategy', 'ice') not in ('ice', 'predict'):
        raise ValueError('INVALID_UDP_STRATEGY')
    if len(json.dumps(value, separators=(',', ':')).encode()) > 2048:
        raise ValueError('ICE_METADATA_LIMIT')
    parameters = value['parameters']
    schema(parameters, ('usernameFragment', 'password', 'iceLite'))
    if any(not isinstance(parameters[field], str) or not 1 <= len(parameters[field]) <= 256
           for field in ('usernameFragment', 'password')) or parameters['iceLite'] is not False:
        raise ValueError('INVALID_ICE_PARAMETERS')
    candidates = value['candidates']
    if not isinstance(candidates, list) or not 1 <= len(candidates) <= 8:
        raise ValueError('UDP_CANDIDATE_LIMIT')
    fields = ('component', 'foundation', 'ip', 'port', 'priority', 'protocol', 'type',
              'relatedAddress', 'relatedPort', 'sdpMid', 'sdpMLineIndex', 'tcpType')
    for candidate in candidates:
        schema(candidate, fields)
        if candidate['type'] not in ('host', 'srflx') or candidate['protocol'] != 'udp' or type(candidate['component']) is not int or candidate['component'] != 1:
            raise ValueError('RELAY_OR_NON_UDP_CANDIDATE_DENIED')
        if type(candidate['port']) is not int or type(candidate['priority']) is not int or not 0 <= candidate['priority'] < 2**32:
            raise ValueError('INVALID_ICE_CANDIDATE')
        if not isinstance(candidate['foundation'], str) or not 1 <= len(candidate['foundation']) <= 64:
            raise ValueError('INVALID_ICE_CANDIDATE')
        ip, _ = direct_address(format_address((candidate['ip'], candidate['port'])))
        if ip not in allowed_ips:
            raise ValueError('UNAPPROVED_UDP_CANDIDATE')
        if candidate['tcpType'] is not None or candidate['sdpMid'] is not None or candidate['sdpMLineIndex'] is not None:
            raise ValueError('INVALID_ICE_CANDIDATE')
        if candidate['relatedAddress'] is not None:
            direct_address(format_address((candidate['relatedAddress'], candidate['relatedPort'])))
        elif candidate['relatedPort'] is not None:
            raise ValueError('INVALID_ICE_CANDIDATE')
    return value
