import unittest
import unittest.mock as mock

from golem_messages import exceptions
from golem_messages.message import base


class MessageTestCase(unittest.TestCase):
    @mock.patch('golem_messages.message.base.Message.deserialize_header')
    def test_decryptions_fails(self, des_hdr_mock):
        # See https://github.com/golemfactory/golem-messages/issues/121
        decrypt = mock.Mock(side_effect=UnboundLocalError)
        with self.assertRaises(exceptions.DecryptionError):
            base.Message.deserialize('*' * 100, decrypt)
        des_hdr_mock.assert_called_once_with(mock.ANY)
