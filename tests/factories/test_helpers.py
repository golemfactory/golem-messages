import unittest

from eth_utils import is_checksum_address

from golem_messages.factories.helpers import random_eth_address


class HelpersTest(unittest.TestCase):

    def test_random_eth_address(self):
        addr = random_eth_address()
        self.assertTrue(is_checksum_address(addr))
