import cbor2
from golem_messages import message
from golem_messages import serializer
import unittest


class EnumTestCase(unittest.TestCase):
    def test_disconnect_reason(self):
        r = message.MessageDisconnect.REASON.TooManyPeers
        encoders = {
            object: serializer.encode,
        }
        s = cbor2.dumps(
            r,
            encoders=encoders,
        )
        decoders = {
            serializer.CODER_TAG: serializer.decode,
        }
        r2 = cbor2.loads(s, semantic_decoders=decoders)
        self.assertIs(r, r2)
