import golem_messages
import golem_messages.message
import unittest

class BasicTestCase(unittest.TestCase):
    def setUp(self):
        self.ecc = golem_messages.ECCx(None)
        self.ecc2 = golem_messages.ECCx(None)

    def test_total_basic(self):
        msg = golem_messages.message.MessagePing()
        payload = golem_messages.dump(msg, self.ecc.raw_privkey, self.ecc.raw_pubkey)
        msg2 = golem_messages.load(payload, self.ecc.raw_privkey, self.ecc.raw_pubkey)
        self.assertEqual(msg, msg2)
