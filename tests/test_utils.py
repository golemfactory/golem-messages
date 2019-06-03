import unittest
from uuid import UUID

from golem_messages import factories
from golem_messages import utils


class UtilsTestCase(unittest.TestCase):
    def test_bytes_uuid(self):
        uuid = UUID(bytes=b'0123456789012345')
        b = utils.uuid_to_bytes32(uuid)
        self.assertEqual(len(b), 32)
        self.assertEqual(utils.bytes32_to_uuid(b), uuid)

    def test_copy_and_sign(self):
        msg = factories.base.HelloFactory()
        self.assertIsNone(msg.sig)
        copied_msg = utils.copy_and_sign(msg, utils.decode_hex('deadbeef'))
        self.assertIsNotNone(copied_msg.sig)
        self.assertIsNot(copied_msg, msg)
        copied_msg.sig = None
        self.assertEqual(copied_msg, msg)

    def test_hex_pubkey_to_address(self):
        hex_pubkey = 'd029f6c7fe83148774dec2f19cc095b3' \
                         '75a362e7684a5cdab7ac4587fc146a72' \
                         '6494f96ddc38635ceccdeba4ec14784d' \
                         '735511acccabc29effdf584a3589a86e'
        self.assertEqual(
            utils.pubkey_to_address(hex_pubkey),
            '0xA2B1b6644F953d3d8488C35132045CC235A568E4'
        )

    def test_0x_hex_pubkey_to_address(self):
        hex_pubkey = '0xd029f6c7fe83148774dec2f19cc095b3' \
                         '75a362e7684a5cdab7ac4587fc146a72' \
                         '6494f96ddc38635ceccdeba4ec14784d' \
                         '735511acccabc29effdf584a3589a86e'
        self.assertEqual(
            utils.pubkey_to_address(hex_pubkey),
            '0xA2B1b6644F953d3d8488C35132045CC235A568E4'
        )

    def test_bytes_pubkey_to_address(self):
        bytes_pubkey = b"1\xd1\x11\x02\xaeM\x84\xb0#\x02\xcd(\xddg\xc2e" \
                       b"\x90\xac\x93\x83*;/\x16),\xa2\xdb\xc2\xad\x99G" \
                       b"\xac~\x88t\x8dwQ\x0c\xb1`\x8d\xc7\x8f.\xe4MPT" \
                       b"\xea\xc7\xedb\xac'\xf3\xe7\x00\xf1\x1d\xf0\xe4\xfb"
        self.assertEqual(
            utils.pubkey_to_address(bytes_pubkey),
            '0xF74a023B90AA8Af867E8ad56afeBfF66E2fDBd46'
        )

    def test_int_pubkey_to_address(self):
        int_pubkey = int('2609110495624912638150583483236841806553203533339234'
                         '9069053650983433801754752954860010295385868748581009'
                         '61903958556513559452241970505204661562102403622139')
        self.assertEqual(
            utils.pubkey_to_address(int_pubkey),
            '0xF74a023B90AA8Af867E8ad56afeBfF66E2fDBd46'
        )
