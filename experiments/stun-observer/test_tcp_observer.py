"""Wire interoperability of the data-free TCP reference observer."""
import importlib.util
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[2] / 'scripts'


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


observer, probe = module('tcp_stun_observer'), module('stun_probe')


class TcpBindingCases(unittest.TestCase):
    def test_modern_client_decodes_its_actual_tuple(self):
        tid = bytes(range(12))
        request = struct.pack('!HHI', 1, 0, 0x2112A442) + tid
        response = observer.binding_response(request, ('203.0.113.7', 45678))
        self.assertEqual(probe.decode_binding(response, tid), ['203.0.113.7', 45678])

    def test_classic_transaction_bytes_remain_unchanged(self):
        transaction = bytes(range(16))
        request = struct.pack('!HH', 1, 0) + transaction
        response = observer.binding_response(request, ('203.0.113.7', 45678))
        self.assertEqual(response[4:20], transaction)
        self.assertEqual(response[20:], bytes.fromhex('000100080001b26ecb007107'))

    def test_wrong_type_length_or_oversize_is_not_answered(self):
        for packet in (b'x' * 19, b'x' * 257,
                       struct.pack('!HH', 0x101, 0) + b'x' * 16,
                       struct.pack('!HH', 1, 8) + b'x' * 16):
            with self.subTest(packet=packet[:20].hex()):
                self.assertIsNone(observer.binding_response(packet, ('203.0.113.7', 45678)))


if __name__ == '__main__':
    unittest.main()
