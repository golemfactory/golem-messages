from uuid import UUID
import unittest

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
