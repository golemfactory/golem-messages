import unittest
import unittest.mock as mock
import uuid

from golem_messages import cryptography
from golem_messages import idgenerator
from golem_messages import utils


class IDGeneratorBase(unittest.TestCase):
    PRIVKEY = None

    def setUp(self):
        keys = cryptography.ECCx(self.PRIVKEY)
        self.node_bytes: bytes = keys.raw_pubkey
        self.node_id: str = utils.encode_hex(self.node_bytes)


class CheckIDSeedTest(IDGeneratorBase):
    def setUp(self):
        super().setUp()
        self.id = idgenerator.generate_id(self.node_bytes)

    def test_invalid_uuid(self):
        self.assertFalse(idgenerator.check_id_seed('invalid', self.node_bytes))

    def test_invalid_node(self):
        self.id = self.id[:-12] + '0' * 12
        self.assertFalse(idgenerator.check_id_seed(self.id, self.node_bytes))

    def test_valid(self):
        self.assertTrue(idgenerator.check_id_seed(self.id, self.node_bytes))


class SeedToNodeTest(IDGeneratorBase):
    PRIVKEY = b'\x90\xea\xbdH\xe8\x12 z\xa6\xeab\xb5U\x81C\xc2\xcao\xbf\xcc\x89V\xc8\xc9\xe8IR\x1a\xf4\x8d!Y'  # noqa pylint: disable=line-too-long

    def test_it(self):
        self.assertEqual(
            77362412866330,
            idgenerator.seed_to_node(self.node_bytes),
        )


class IDGeneratorTest(IDGeneratorBase):
    def test_generate_id(self):
        id_: uuid.UUID = uuid.UUID(idgenerator.generate_id(self.node_bytes))
        node = idgenerator.seed_to_node(self.node_bytes)
        self.assertEqual(id_.node, node)

    @mock.patch('golem_messages.idgenerator.generate_id')
    def test_generate_id_from_hex(self, generate_mock):
        idgenerator.generate_id_from_hex(self.node_id)
        generate_mock.assert_called_once_with(self.node_bytes)

    def test_generate_new_id_from_id(self):
        # node part of uuid is last 48 bits = 6 bytes
        # 6 hex encoded bytes = 12 characters
        id_ = idgenerator.generate_id(self.node_bytes)
        node1 = id_[-12:]
        node2 = idgenerator.generate_new_id_from_id(id_)[-12:]
        self.assertEqual(node1, node2)

    @mock.patch('golem_messages.idgenerator.check_id_seed')
    def test_check_id_hexseed(self, check_mock):
        id_ = idgenerator.generate_id(self.node_bytes)
        idgenerator.check_id_hexseed(id_, self.node_id)
        check_mock.assert_called_once_with(id_, self.node_bytes)

    @mock.patch('golem_messages.idgenerator.seed_to_node')
    def test_hexseed_to_node(self, stn_mock):
        idgenerator.hexseed_to_node(self.node_id)
        stn_mock.assert_called_once_with(self.node_bytes)
