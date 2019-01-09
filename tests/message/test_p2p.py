import unittest
from golem_messages.factories import p2p
from tests.message import mixins


class WantToStartSessionTest(mixins.SerializationMixin, unittest.TestCase):
    FACTORY = p2p.WantToStartTaskSessionFactory


class SetTaskSessionTest(mixins.SerializationMixin, unittest.TestCase):
    FACTORY = p2p.SetTaskSessionFactory
