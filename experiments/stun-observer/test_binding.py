"""Independent STUN wire cases for trustworthy diagnostic observations."""
import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location('stun_probe',
    Path(__file__).resolve().parents[2] / 'scripts' / 'stun_probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

TID = bytes.fromhex('000102030405060708090a0b')
# 203.0.113.7:45678, encoded independently as MAPPED and XOR-MAPPED.
MAPPED = bytes.fromhex('000100080001b26ecb007107')
XOR = bytes.fromhex('002000080001937cea12d545')


def message(body):
    return struct.pack('!HHI', 0x101, len(body), 0x2112A442) + TID + body


class BindingCases(unittest.TestCase):
    def test_real_world_mapped_only_server(self):
        self.assertEqual(probe.decode_binding(message(MAPPED), TID), ['203.0.113.7', 45678])

    def test_xor_address_and_attribute_order(self):
        for body in (XOR, MAPPED + XOR, XOR + MAPPED):
            with self.subTest(body=body.hex()):
                self.assertEqual(probe.decode_binding(message(body), TID), ['203.0.113.7', 45678])

    def test_wrong_message_identity_and_truncation(self):
        packet = message(XOR)
        for invalid in (packet[:19], packet[:-1], packet + b'\0',
                        b'\0\x01' + packet[2:], packet[:4] + b'\0' * 4 + packet[8:],
                        packet[:8] + b'x' * 12 + packet[20:]):
            with self.subTest(packet=invalid.hex()):
                self.assertIsNone(probe.decode_binding(invalid, TID))

    def test_malformed_attribute_does_not_leave_partial_success(self):
        self.assertIsNone(probe.decode_binding(message(MAPPED + bytes.fromhex('802c0008')), TID))


if __name__ == '__main__':
    unittest.main()
