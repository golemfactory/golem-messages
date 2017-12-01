from golem_messages import message
from golem_messages import serializer
import unittest


class EqualityMixIn:
    def equal_after_processing(self, o):
        s = serializer.dumps(o)
        o2 = serializer.loads(s)
        self.assertEqual(o, o2)


class EnumTestCase(unittest.TestCase):
    def test_disconnect_reason(self):
        r = message.Disconnect.REASON.TooManyPeers
        s = serializer.dumps(r)
        r2 = serializer.loads(s)
        self.assertIs(r, r2)


class MessageTestCase(unittest.TestCase, EqualityMixIn):
    def test_message(self):
        m = message.Ping()
        self.equal_after_processing(m)

    def test_message_list(self):
        aList = [message.Ping()]
        self.equal_after_processing(aList)

    def test_message_dict(self):
        d = {'m': message.Ping()}
        self.equal_after_processing(d)
