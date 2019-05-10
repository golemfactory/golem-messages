import unittest

from golem_messages.factories.tasks import WantToComputeTaskFactory
from golem_messages.utils import pubkey_to_address


class HelpersTest(unittest.TestCase):

    # provider_ethereum_address is not bound to provider_public_key
    # below binding is only for compatibility with Concent tests
    def test_WTCT_factory_pubkey_bound_to_addr(self):
        wtct = WantToComputeTaskFactory()
        self.assertEqual(wtct.provider_ethereum_address,
                         pubkey_to_address(wtct.provider_public_key))
