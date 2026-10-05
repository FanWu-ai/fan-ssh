"""Selected-path evidence gates; no EasyTier binary or network is contacted."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('peer_check',
    Path(__file__).resolve().parents[2] / 'scripts' / 'easytier_peer_check.py')
peer_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(peer_check)

CID = {'part1': 1, 'part2': 2, 'part3': 3, 'part4': 4}
CONN = peer_check.connection_id(CID)


class SelectedPathTests(unittest.TestCase):
    def snapshot(self):
        return [{'route': {'peer_id': 42, 'hostname': 'target', 'cost': 1,
                           'next_hop_peer_id': 42},
                 'peer': {'peer_id': 42, 'default_conn_id': CID,
                          'directly_connected_conns': [CID],
                          'conns': [{'conn_id': CONN, 'peer_id': 42, 'is_closed': False,
                                     'tunnel': {'tunnel_type': 'udp', 'resolved_remote_addr':
                                                {'url': 'udp://203.0.113.7:45678'}}}]}}]

    def verify(self, rows, protocol='udp'):
        return peer_check.native_peer_verified(rows, 'target', ['203.0.113.7'], protocol)

    def test_selected_native_path(self):
        self.assertTrue(self.verify(self.snapshot()))

    def test_advertised_two_hop_route_is_not_a_connection(self):
        rows = self.snapshot()
        rows[0]['route'].update(cost=2, next_hop_peer_id=99)
        rows[0]['peer'] = None
        self.assertFalse(self.verify(rows))

    def test_unused_native_connection_does_not_override_selected_overlay(self):
        rows = self.snapshot()
        extra = copy.deepcopy(rows[0]['peer']['conns'][0])
        extra['conn_id'] = '00000005-0000-0006-0000-000700000008'
        rows[0]['peer']['conns'].append(extra)
        rows[0]['peer']['conns'][0]['tunnel']['resolved_remote_addr']['url'] = 'udp://100.64.0.6:45678'
        self.assertFalse(self.verify(rows))

    def test_selected_connection_must_be_direct_and_live(self):
        for field, value in [('directly_connected_conns', []), ('default_conn_id', {}),
                             ('peer_id', 99)]:
            with self.subTest(field=field):
                rows = self.snapshot()
                rows[0]['peer'][field] = value
                self.assertFalse(self.verify(rows))
        rows = self.snapshot()
        rows[0]['peer']['conns'][0]['is_closed'] = True
        self.assertFalse(self.verify(rows))

    def test_wrong_protocol_or_embedded_native_ip_rejected(self):
        self.assertFalse(self.verify(self.snapshot(), 'tcp'))
        for url in ('udp://203.0.113.7.example:45678', 'udp://203.0.113.7@100.64.0.6:45678',
                    'udp://100.64.0.6:45678?peer=203.0.113.7'):
            with self.subTest(url=url):
                rows = self.snapshot()
                rows[0]['peer']['conns'][0]['tunnel']['resolved_remote_addr']['url'] = url
                self.assertFalse(self.verify(rows))

    def test_wrong_next_hop_or_target_rejected(self):
        for field, value in [('next_hop_peer_id', 99), ('hostname', 'cloud'), ('cost', True)]:
            with self.subTest(field=field):
                rows = self.snapshot()
                rows[0]['route'][field] = value
                self.assertFalse(self.verify(rows))


if __name__ == '__main__':
    unittest.main()
