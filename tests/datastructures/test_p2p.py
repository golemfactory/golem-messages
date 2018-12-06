import unittest


from golem_messages.factories.datastructures import p2p as dt_p2p_factory


class TestNode(unittest.TestCase):
    def test_str(self):
        n = dt_p2p_factory.Node(node_name="Blabla", key="ABC")
        self.assertNotIn("at", str(n))
        self.assertNotIn("at", "{}".format(n))
        self.assertIn("Blabla", str(n))
        self.assertIn("Blabla", "{}".format(n))
        self.assertIn("ABC", str(n))
        self.assertIn("ABC", "{}".format(n))

    def test_update_public_info_invalid(self):
        node = dt_p2p_factory.Node(
            node_name="Node 1",
            key="key_1"
        )

        self.assertIsNone(node.pub_addr)
        self.assertIsNone(node.pub_port)
        self.assertIsNone(node.p2p_pub_port)
        self.assertIsNone(node.hyperdrive_pub_port)

        node.update_public_info()

        self.assertIsNone(node.pub_addr)
        self.assertIsNone(node.pub_port)
        self.assertIsNone(node.p2p_pub_port)
        self.assertIsNone(node.hyperdrive_pub_port)

    def test_update_public_info(self):
        node = dt_p2p_factory.Node(
            node_name="Node 1",
            key="key_1",
            prv_addr='10.0.0.10',
            prv_port=40103,
            p2p_prv_port=40102,
            hyperdrive_prv_port=3282
        )

        self.assertIsNone(node.pub_addr)
        self.assertIsNone(node.pub_port)
        self.assertIsNone(node.p2p_pub_port)
        self.assertIsNone(node.hyperdrive_pub_port)

        node.update_public_info()

        self.assertEqual(node.pub_addr, node.prv_addr)
        self.assertEqual(node.pub_port, node.pub_port)
        self.assertEqual(node.p2p_pub_port, node.p2p_pub_port)
        self.assertEqual(node.hyperdrive_pub_port, node.hyperdrive_pub_port)
