import datetime
import struct
import unittest
import unittest.mock as mock

from golem_messages import exceptions
from golem_messages.message import base


class MessageTestCase(unittest.TestCase):
    def test_decryptions_fails(self):
        # See https://github.com/golemfactory/golem-messages/issues/121
        decrypt = mock.Mock(side_effect=UnboundLocalError)
        header = struct.pack(
            base.Message.HDR_FORMAT,
            base.RandVal.TYPE,
            int(datetime.datetime.utcnow().timestamp()),
            True,
        )
        with self.assertRaises(exceptions.DecryptionError):
            base.Message.deserialize(
                header+b'*' * 100,
                decrypt,
                check_time=False,
            )
        decrypt.assert_called_once_with(mock.ANY)
